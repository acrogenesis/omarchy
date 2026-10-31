"""Exercise the real controller's races and inherited-pipe transport."""

import json
import os
from pathlib import Path
import shlex
import sys
import tempfile

from gi.repository import Gio, GLib

root = Path(os.environ['ROOT'])
sys.path.insert(0, str(root / 'default/slack'))
from launcher import Slack

with tempfile.TemporaryDirectory() as directory:
    scratch = Path(directory)
    stylesheet = scratch / 'slack.css'
    stylesheet.write_text('first')
    app = Slack(scratch)
    requests = []
    app.send = lambda method, params=None, session=None, callback=None: requests.append((method, params, session, callback))
    app.frame('one', {'id': 'old'})
    create = requests.pop()
    assert create[:3] == ('CSS.createStyleSheet', {'frameId': 'old'}, 'one')
    create[3]({'result': {'styleSheetId': 'old-sheet'}})
    first = requests.pop()
    assert first[1]['text'] == 'first'
    app.css = 'second'
    app.apply('one')
    app.css = 'latest'
    app.apply('one')
    assert requests == [], 'a delayed update serializes and coalesces later changes'
    first[3]({'result': {}})
    latest = requests.pop()
    assert latest[1] == {'styleSheetId': 'old-sheet', 'text': 'latest'}
    app.frame('one', {'id': 'new'})
    new = requests.pop()
    latest[3]({'error': {'message': 'old document disappeared'}})
    assert app.sessions['one']['busy'], 'an old response cannot clear the new document update'
    new[3]({'result': {'styleSheetId': 'new-sheet'}})
    requests.pop()[3]({'result': {}})
    assert app.sessions['one']['sheet'] == 'new-sheet' and not app.sessions['one']['busy']
    # A document-ready event received while its first sheet was being created
    # must retry a transient navigation failure without a polling timer.
    app.frame('two', {'id': 'loading'})
    create = requests.pop()
    app.dispatch({'method': 'Page.domContentEventFired', 'sessionId': 'two'})
    create[3]({'error': {'message': 'No target stylesheet found'}})
    assert requests.pop()[0] == 'CSS.createStyleSheet'
    app.dispatch({'method': 'Target.detachedFromTarget', 'params': {'sessionId': 'two'}})
    assert 'two' not in app.sessions
    print('ok - live pipe updates serialize, keep the latest palette and ignore old navigation responses')

    # A separate process speaks CDP on descriptors 3/4. No Slack installation,
    # socket server or simulated file watcher is involved in this transport test.
    server = scratch / 'server.py'
    server.write_text('''
import json,os
from pathlib import Path
root=Path(os.environ['TEST_PIPE_ROOT'])
reader=os.fdopen(3,'rb',buffering=0)
writer=os.fdopen(4,'wb',buffering=0)
buffer=b'';stage=0;count=0

def emit(message):
    writer.write(json.dumps(message).encode()+b'\\0')

def attach(session):
    emit({'method':'Target.attachedToTarget','params':{'sessionId':session,'targetInfo':{'type':'page'}}})

while True:
    chunk=reader.read(65536)
    if not chunk:break
    buffer+=chunk
    while b'\\0' in buffer:
        raw,buffer=buffer.split(b'\\0',1);m=json.loads(raw)
        with (root/'events').open('a') as f:f.write(json.dumps(m)+'\\n')
        result={};session=m.get('sessionId');method=m['method']
        if method=='Page.getFrameTree':result={'frameTree':{'frame':{'id':session}}}
        if method=='CSS.createStyleSheet':
            count+=1;result={'styleSheetId':'sheet-'+str(count)}
        emit({'id':m['id'],'result':result})
        if method=='Target.setAutoAttach':attach('one')
        if method=='CSS.setStyleSheetText':
            text=m['params']['text']
            if stage==0:
                assert text=='first';stage=1
                (root/'slack.next').write_text('second');(root/'slack.next').replace(root/'slack.css')
            elif stage==1:
                assert text=='second';stage=2;attach('two')
            elif stage==2 and session=='two':
                assert text=='second';stage=3
                emit({'method':'Page.frameNavigated','sessionId':'one','params':{'frame':{'id':'navigated'}}})
            elif stage==3 and session=='one':
                assert text=='second';(root/'complete').touch();raise SystemExit(0)
''')
    binary = scratch / 'slack'
    binary.write_text('#!/bin/bash\nprintf "%s\\0" "$@" >"$TEST_PIPE_ROOT/arguments"\nexec /usr/bin/python ' + shlex.quote(str(server)) + '\n')
    binary.chmod(0o755)
    os.environ['TEST_PIPE_ROOT'] = str(scratch)
    stylesheet.write_text('first')
    app = Slack(scratch)
    app.start(['--user-data-dir=' + str(scratch / 'profile with spaces')], str(binary))
    timed_out = []
    def deadline():
        timed_out.append(True)
        app.child.force_exit()
        return GLib.SOURCE_REMOVE
    timeout = GLib.timeout_add_seconds(5, deadline)
    app.loop.run()
    if not timed_out:
        GLib.source_remove(timeout)
    assert not timed_out and app.child.get_successful(), (scratch / 'events').read_text()
    assert (scratch / 'complete').exists()
    arguments = (scratch / 'arguments').read_bytes().split(b'\0')[:-1]
    assert arguments == [b'--remote-debugging-pipe', ('--user-data-dir=' + str(scratch / 'profile with spaces')).encode()]
    assert app.monitor.is_cancelled()
    assert not (scratch / '.cache').exists()
    print('ok - packaged-app transport uses inherited pipes, observes atomic CSS writes, themes new windows and navigation, and exits with Slack')
