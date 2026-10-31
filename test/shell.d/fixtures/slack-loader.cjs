const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'slack-loader-'));
const directory = path.join(home, '.local/state/omarchy/slack');
const stylesheet = path.join(directory, 'slack.css');
fs.mkdirSync(directory, { recursive: true });
const app = new EventEmitter(), windows = [], warnings = [];
let changed, closed = false;
const settle = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

// Only Electron's boundary is simulated: insertion completion is controlled
// separately from requests, and navigation invalidates old document keys.
class Contents extends EventEmitter {
  constructor() { super(); this.document = 0; this.requests = []; this.active = new Map(); this.destroyed = false; }
  isDestroyed() { return this.destroyed; }
  insertCSS(css, options) {
    assert.equal(options.cssOrigin, 'user');
    const document = this.document, key = 'key-' + this.requests.length;
    return new Promise(resolve => this.requests.push({ css, complete: () => {
      if (document === this.document) this.active.set(key, css);
      resolve(key);
    } }));
  }
  async removeInsertedCSS(key) {
    assert(this.active.delete(key), 'only remove a key from the current document');
  }
  navigate() { this.document++; this.active.clear(); this.emit('dom-ready'); }
}
function window() {
  const contents = new Contents();
  windows.push(contents);
  app.emit('web-contents-created', {}, contents);
  contents.navigate();
  return contents;
}
function publish(css, filename = 'slack.css') {
  // Exercise the loader's parent-directory subscription on atomic replacement.
  fs.writeFileSync(stylesheet + '.next', css);
  fs.renameSync(stylesheet + '.next', stylesheet);
  changed('rename', filename);
}
function onlyCSS(contents, css) { assert.deepEqual([...contents.active.values()], [css]); }

(async () => {
  try {
    fs.writeFileSync(stylesheet, 'initial');
    vm.runInNewContext(fs.readFileSync(path.join(process.env.ROOT, 'default/slack/loader.cjs'), 'utf8'), {
      console: { warn: (...args) => warnings.push(args) },
      require: name => {
        if (name === 'electron') return { app, webContents: { getAllWebContents: () => windows } };
        if (name === 'node:os') return { homedir: () => home };
        if (name === 'node:path') return path;
        if (name === 'node:fs') return {
          promises: { readFile: async (...args) => fs.readFileSync(...args) },
          watch: (watched, callback) => {
            assert.equal(watched, directory);
            changed = callback;
            return Object.assign(new EventEmitter(), { close: () => { closed = true; } });
          },
        };
        throw new Error('Unexpected dependency: ' + name);
      },
    });

    const first = window();
    await settle();
    assert.equal(first.requests[0].css, 'initial');
    first.requests[0].complete();
    await settle();
    onlyCSS(first, 'initial');

    publish('second', Buffer.from('slack.css'));
    await settle();
    assert.equal(first.requests[1].css, 'second');
    publish('third', null);
    await settle();
    assert.equal(first.requests.length, 2, 'a slow insertion serializes later updates');
    first.requests[1].complete();
    await settle();
    assert.equal(first.requests[2].css, 'third');
    first.requests[2].complete();
    await settle();
    onlyCSS(first, 'third');

    publish('old document');
    await settle();
    publish('queued before navigation');
    first.navigate();
    publish('new document');
    first.requests[3].complete();
    await settle();
    assert.equal(first.requests[4].css, 'new document', 'stale queued generations are skipped');
    first.requests[4].complete();
    await settle();
    first.requests[5].complete();
    await settle();
    onlyCSS(first, 'new document');
    assert.equal(warnings.length, 0, 'navigation never removes a key from the previous document');

    const second = window();
    await settle();
    assert.equal(second.requests[0].css, 'new document');
    second.requests[0].complete();
    await settle();
    onlyCSS(second, 'new document');

    first.destroyed = true;
    const count = first.requests.length;
    fs.unlinkSync(stylesheet);
    changed('rename', 'slack.css');
    await settle();
    assert.equal(warnings.length, 1, 'a missing stylesheet is reported without stopping the loader');
    publish('recovered');
    await settle();
    second.requests[1].complete();
    await settle();
    onlyCSS(second, 'recovered');
    assert.equal(first.requests.length, count, 'destroyed windows receive no more insertions');
    changed('rename', 'unrelated');
    await settle();
    assert.equal(second.requests.length, 2);
    app.emit('will-quit');
    assert(closed, 'the filesystem watcher closes on exit');
    console.log('ok - real Slack loader serializes live updates, handles navigation and new windows, and recovers from read failures');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
