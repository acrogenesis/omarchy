#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/base-test.sh"
run_node_test <<'JS'
const fs = require('fs')
const vm = require('vm')
const backgroundQml = fs.readFileSync(path.join(root, 'shell/plugins/background/Background.qml'), 'utf8')
const resolverQml = fs.readFileSync(path.join(root, 'shell/Ui/BackgroundResolver.qml'), 'utf8')
const wallpaperQml = fs.readFileSync(path.join(root, 'shell/Ui/WallpaperImage.qml'), 'utf8')
function blockAfter(source, marker, description) {
  const start = source.indexOf(marker)
  if (start < 0) fail(description, `marker not found: ${marker}`)
  const indent = source.slice(source.lastIndexOf('\n', start) + 1, start)
  const closerIndent = marker.startsWith('function') ? indent : indent.slice(0, -2)
  const rest = source.slice(start)
  const end = rest.indexOf('\n' + closerIndent + '}')
  if (end < 0) fail(description, `unterminated block for marker: ${marker}`)
  return rest.slice(0, end)
}

const startBlock = blockAfter(resolverQml, 'function startResolve', 'resolver entry point')
const lockBlock = blockAfter(backgroundQml, 'function lockIncoming', 'incoming frame lock')
const settledBlock = blockAfter(backgroundQml, 'function baseSettled', 'settlement state')
const context = vm.createContext({
  Commons: { Color: { background: 'fallback' } },
  Qt: { rgba: (...channels) => channels },
  canonicalPath: '/theme/art.svg', screenWidth: 1920, screenHeight: 1080,
  devicePixelRatio: 2, canonicalOnly: false, metadataOnly: false, requestSeq: 1, resolveProc: {}, resolvePending: false
})
vm.runInContext(blockAfter(resolverQml, 'function parseFillColor', 'color parser exists') + '\n}', context)
assertDeepEqual(Array.from(context.parseFillColor('#ff000080')), [1, 0, 0, 128 / 255], 'RGBA metadata renders translucent red')
assertDeepEqual(Array.from(context.parseFillColor('#12345600')), [18 / 255, 52 / 255, 86 / 255, 0], 'zero alpha remains transparent')
assertDeepEqual(Array.from(context.parseFillColor('#abcdef')), [171 / 255, 205 / 255, 239 / 255, 1], 'six-digit colors remain opaque')
assertEqual(context.parseFillColor('#bad'), 'fallback', 'invalid colors retain the theme fallback')
vm.runInContext(startBlock + '\n}', context)
context.startResolve()
assertEqual(context.resolveProc.command[context.resolveProc.command.indexOf('--screen') + 1], '3840x2160', 'scale 2 resolves SVGs at physical output resolution')
context.devicePixelRatio = 1.25
context.startResolve()
assertEqual(context.resolveProc.command[context.resolveProc.command.indexOf('--screen') + 1], '2400x1350', 'fractional scale resolves at physical output resolution')
const blurActive = wallpaperQml.match(/blurBackdropActive: (.*)/)[1]
const backdropSource = wallpaperQml.match(/source: (.*)/)[1]
for (const fill of ['crop', 'fit', 'center', 'tile']) {
  for (const backdrop of ['solid', 'edge', 'blur']) {
    const surface = { fill, backdrop, path: '/art.png', renderPath: '/art.png', sourceVersion: 0, decodeReady: true }
    const scope = vm.createContext({ ...surface, root: surface, Util: { fileUrl: p => 'file://' + p } })
    surface.blurBackdropActive = vm.runInContext(blurActive, scope)
    assertEqual(vm.runInContext(backdropSource, scope) !== '', fill !== 'crop' && backdrop === 'blur',
      `${fill}/${backdrop} only loads the backdrop when needed`)
  }
}
const outgoing = vm.createContext({
  currentBackground: '/old/art.svg', displayedBackground: '/old/art.svg',
  displayedVersion: 3, backgroundVersion: 3, preparedBackground: '', lastTransitionPath: '',
  isVideo: () => false,
  revealAnimation: { stop() {} },
  preparedBackgroundTimer: { stop() {} }, requestNativeSize() {}
})
vm.runInContext(blockAfter(backgroundQml, 'function transitionBackground(', 'transition function exists') + '\n}', outgoing)
outgoing.transitionBackground('/snapshots/canonical.svg', '/snapshots/new.png', '/new/art.svg', false, true)
assertEqual(outgoing.displayedBackground, '/old/art.svg', 'theme snapshots leave the per-panel base source intact during reveal')
assertEqual(outgoing.displayedVersion, 3, 'arming a theme transition never requests a fresh decode of the outgoing wallpaper')

const decode = vm.createContext({
  sized: true, decodeWidth: 3840, decodeHeight: 2160,
  root: { nativeSizes: { '/small.png': { width: 640, height: 480 }, '/large.png': { width: 7680, height: 4320 } } },
  Qt: { size: (width, height) => ({width, height}) }
})
vm.runInContext(blockAfter(backgroundQml, 'function decodeSize', 'decode size function exists') + '\n}', decode)
assertEqual(decode.decodeSize('/small.png').width, 640, 'a small wallpaper keeps its native decode size')
assertEqual(decode.decodeSize('/large.png').width, 3840, 'a large wallpaper decodes only at the screen size')
assertEqual(decode.decodeSize('/pending.png').width, 0, 'an unprobed wallpaper waits instead of decoding at full size')
decode.sized = false
assertEqual(decode.decodeSize('/large.png').width, 0, 'an unsized panel waits before decoding')

const locked = vm.createContext({
  incomingLockedVersion: -1, incomingAbandoned: false,
  root: { backgroundVersion: 9, requestNativeSize() {} },
  incomingFallbackTimer: { stop() {} },
  starts: 0
})
vm.runInContext('function maybeStartReveal() { starts += 1 }\n' + lockBlock + '\n}', locked)
locked.lockIncoming('/prepared.png', 'fit', 'blur', '#123456', 0.6, 0.4)
assertEqual(locked.starts, 1, 'a frame decoded during prepare starts the reveal when its metadata locks')
locked.lockIncoming('/late.png', 'crop', 'solid', '#ffffff', 0.5, 0.5)
assertEqual(locked.incomingPath, '/prepared.png', 'a late resolution cannot replace a locked transition source')
assertEqual(locked.starts, 1, 'a locked transition is only started once')

const settling = vm.createContext({
  root: { displayedBackground: '/final.png' },
  displayedResolver: { ready: true }, lastDisplayedCanonical: '/final.png',
  base: { status: 0 }, Image: { Null: 0, Loading: 1, Ready: 2, Error: 3 }
})
vm.runInContext(settledBlock + '\n}', settling)
assertEqual(settling.baseSettled(), false, 'a final frame awaiting its header keeps the incoming layer visible')
settling.base.status = settling.Image.Loading
assertEqual(settling.baseSettled(), false, 'a decoding final frame keeps the incoming layer visible')
settling.base.status = settling.Image.Ready
assertEqual(settling.baseSettled(), true, 'a decoded final frame can release its incoming layer')
const renderPathExpression = wallpaperQml.match(/renderPath: (.*)/)[1]
for (const filename of ['/prepare.svg', '/FAILED.SVG']) {
  assertEqual(vm.runInNewContext(renderPathExpression, {path: filename}), '', 'raw SVG cannot enter Qt image loading: ' + filename)
}
assertEqual(vm.runInNewContext(renderPathExpression, {path: '/cache/render.png'}), '/cache/render.png', 'bounded SVG raster enters Qt image loading')

JS

run_node_test <<'JS'
const fs = require('fs')
const vm = require('vm')
const resolver = fs.readFileSync(path.join(root, 'shell/Ui/BackgroundResolver.qml'), 'utf8')
const body = resolver.match(/  function retryCanonical\(failedPath\) \{[^]*?\n  }/)[0]
const context = {ready: true, canonicalOnly: false, resolvedPath: '/variant.png'}
vm.createContext(context)
vm.runInContext(body, context)
context.retryCanonical('/obsolete.png')
assertEqual(context.canonicalOnly, false, 'stale image failures cannot change the current lock resolution')
context.retryCanonical('/variant.png')
assertEqual(context.canonicalOnly, true, 'a failed current variant requests the canonical wallpaper')
context.canonicalOnly = false; context.ready = false
context.retryCanonical('/variant.png')
assertEqual(context.canonicalOnly, false, 'in-flight resolution does not retry an obsolete decode')
JS
