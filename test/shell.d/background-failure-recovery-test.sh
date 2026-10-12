#!/bin/bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/base-test.sh"
run_node_test <<'JS'
const fs = require('fs'), vm = require('vm')
const qml = fs.readFileSync(path.join(root, 'shell/plugins/background/Background.qml'), 'utf8')
function load(name, context) {
  const fn = qml.match(new RegExp('function '+name+'\\([^]*?\\n'+(name==='finishTransitionWithoutReveal'?'  ':'      ')+'}'))
  assert(fn, name+' exists')
  vm.runInContext(fn[0], context)
}
const recovery = vm.createContext({panel:{lastDisplayedPath:'/image@wide.png'}, displayedResolver:{canonicalOnly:false}, root:{displayedBackground:'/image.png', recoverBackground(path) { this.recovered=path }}})
load('recoverDisplayedImage', recovery)
recovery.recoverDisplayedImage()
assert(recovery.displayedResolver.canonicalOnly && !recovery.root.recovered, 'a failed variant retries the canonical on that panel')
recovery.recoverDisplayedImage()
assertEqual(recovery.root.recovered, '/image.png', 'a failed canonical uses the ordinary missing-background recovery')
const lockCalls = []
const fallback = vm.createContext({root:{incomingBackground:'/snapshot.png', finishTransitionWithoutReveal(){this.finished=true}}, maskReady:false, incomingFallbackTried:false, incomingLockedVersion:9, lastDisplayedFill:'fit', lastDisplayedBackdrop:'blur', lastDisplayedFillColor:'#123456', lastDisplayedFocalX:.5,lastDisplayedFocalY:.5,incomingResolver:{ready:false}, incomingFallbackTimer:{restart(){this.restarted=true}}, lockIncoming(...args){lockCalls.push(args)}})
load('tryIncomingFallback', fallback)
fallback.tryIncomingFallback()
assertEqual(lockCalls[0][0], '/snapshot.png', 'a slow resolver can reveal the available snapshot')
assert(fallback.incomingFallbackTimer.restarted, 'the snapshot decode has a second bounded deadline')
fallback.tryIncomingFallback()
assert(fallback.root.finished, 'an undecodable snapshot cannot keep the reveal pending forever')
fallback.root.finished=false;fallback.maskReady=true
fallback.tryIncomingFallback()
assert(!fallback.root.finished, 'a ready revealing panel keeps its transition layers until settlement')
const resolve = fs.readFileSync(path.join(root, 'shell/Ui/BackgroundResolver.qml'),'utf8')
assert(resolve.includes('"timeout", "--kill-after=2", "45",'), 'resolver execution is bounded even if a helper hangs')
JS
