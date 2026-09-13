import test from 'node:test';
import assert from 'node:assert/strict';
import { MAC_DOCK_ICON_KEYS } from '../assets/js/mac-dock.js';
import { createComputerScreens, researchPlayback, researchOperationTime } from '../assets/js/computer-screens.js';

function referenceImages() {
  const sizes = {
    'codex-empty': [1455, 1427], 'codex-working': [1379, 1381], 'codex-completed': [899, 526], 'codex-computer': [775, 126], edge: [1331, 1044],
    ghidra: [1542, 1110], 'ghidra-function': [634, 378], 'ghidra-variable': [476, 242], 'ghidra-references': [621, 376],
    ...Object.fromEntries(['history', 'replay', 'history-menu', 'history-dialog', 'replay-menu', 'replay-dialog'].map(name => [`caido-${name}`, [1912, 1242]])),
  };
  return Object.fromEntries(Object.entries(sizes).map(([name, [width, height]]) => [`ref-${name}`, Object.freeze({ name: `ref-${name}`, width, height })]));
}

function recordingCanvases() {
  const contexts = [], images = new Map();
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'document');
  const finite = values => { for (const value of values) if (typeof value === 'number') assert.ok(Number.isFinite(value), 'Non-finite drawing coordinate'); };
  const id = image => { if (!images.has(image)) images.set(image, images.size); return images.get(image); };
  Object.defineProperty(globalThis, 'document', { configurable: true, value: { createElement(name) {
    assert.equal(name, 'canvas');
    const c = { operations: [], appOperations: [], app: null, texts: [], blits: [], fills: [], globalAlpha: 1, globalCompositeOperation: 'source-over', sx: 1, sy: 1, tx: 0, ty: 0, font: '10px sans-serif', textAlign: 'start', textBaseline: 'alphabetic' }, stack = [];
    contexts.push(c);
    const props = ['app', 'sx', 'sy', 'tx', 'ty', 'globalAlpha', 'globalCompositeOperation', 'fillStyle', 'strokeStyle', 'font', 'lineWidth', 'textAlign', 'textBaseline'];
    const record = (name, args) => {
      finite(args);
      const op = [name, ...args.map(value => value?.stops ? { gradient: value.points, stops: [...value.stops] } : value)];
      c.operations.push(op);
      if (c.app && c.app !== 'codex') c.appOperations.push([c.app, ...op]);
    };
    c.save = () => { stack.push(Object.fromEntries(props.map(key => [key, c[key]]))); };
    c.restore = () => Object.assign(c, stack.pop());
    c.scale = (x, y) => { finite([x, y]); c.sx *= x; c.sy *= y; };
    c.getTransform = () => ({ a: c.sx, b: 0, c: 0, d: c.sy, e: c.tx, f: c.ty });
    c.setTransform = (a,b,dummy,d,e,f) => { finite([a,b,dummy,d,e,f]); assert.equal(b,0); assert.equal(dummy,0); Object.assign(c,{sx:a,sy:d,tx:e,ty:f}); };
    c.translate = (x, y) => {
      finite([x, y]); c.tx += x * c.sx; c.ty += y * c.sy;
      const app = [[19, 21, 'rdp'], [202, 143, 'ghidra'], [775, 14, 'codex'], [1660, 16, 'edge'], [1343, 108, 'caido']].find(([left, top]) => left === x && top === y);
      if (app) c.app = app[2];
    };
    for (const name of ['beginPath', 'moveTo', 'lineTo', 'bezierCurveTo', 'closePath', 'roundRect', 'arc', 'rect', 'clip', 'rotate']) c[name] = (...args) => record(name, args);
    c.fill = () => record('fill', [c.fillStyle, c.globalAlpha]);
    c.stroke = () => record('stroke', [c.strokeStyle, c.lineWidth, c.globalAlpha, c.sx, c.sy, c.tx, c.ty]);
    c.fillText = (value, x, y) => { c.texts.push(value); record('text', [value, x, y, c.font, c.globalAlpha, c.sx, c.sy, c.tx, c.ty, c.fillStyle, c.textAlign, c.textBaseline]); };
    c.fillRect = (x, y, w, h) => { const values = [x, y, w, h, c.fillStyle, c.globalAlpha]; c.fills.push(values); record('rectFill', values); };
    c.measureText = value => ({ width: value.length * (parseFloat(c.font.split(' ')[1]) || 10) * .61, actualBoundingBoxAscent: 11, actualBoundingBoxDescent: 2 });
    c.drawImage = (image, ...args) => {
      finite(args);
      if (image.name?.startsWith('ref-')) {
        assert.equal(args.length, 8, `${image.name} uses an explicit source crop`);
        const [x, y, width, height] = args;
        assert.ok(x >= 0 && y >= 0 && width > 0 && height > 0 && x + width <= image.width && y + height <= image.height, `${image.name} crop stays inside the unmodified original`);
      }
      c.blits.push({ image, args, alpha: c.globalAlpha, composite: c.globalCompositeOperation, sx: c.sx, sy: c.sy, tx: c.tx, ty: c.ty }); record('image', [id(image), ...args, c.globalAlpha, c.sx, c.sy, c.tx, c.ty, c.fillStyle, c.globalCompositeOperation]);
    };
    c.createLinearGradient = (...args) => { finite(args); return { points: args, stops: [], addColorStop(offset, color) { finite([offset]); this.stops.push([offset, color]); } }; };
    return { width: 0, height: 0, getContext: () => c };
  } } });
  return { contexts, restore() { if (descriptor) Object.defineProperty(globalThis, 'document', descriptor); else delete globalThis.document; } };
}

const reset = c => { c.operations = []; c.appOperations = []; c.texts = []; c.blits = []; c.fills = []; };
// Keep storyboard checkpoints readable while checking the first rendered frame at or after each event.
const realTime = storyMs => {
  const cycle = Math.floor(storyMs / 30000), phase = storyMs % 30000;
  const elapsed = (cycle * researchPlayback(30) + researchPlayback(phase / 1000)) * 1000;
  return Math.ceil(elapsed * 30 / 1000 - 1e-7) * 1000 / 30;
};

// App checkpoints keep their authored operation time while the Codex transcript owns story time.
const operationStory = operationMs => {
  const cycle = Math.floor(operationMs / 30000), phase = operationMs % 30000 / 1000;
  let low = 0, high = 30;
  for (let i = 0; i < 48; i++) {
    const middle = (low + high) / 2;
    if (researchOperationTime(middle) < phase) low = middle; else high = middle;
  }
  return cycle * 30000 + high * 1000;
};
const grayIntervals = [[3.6, 4.3], [6.2, 7.7], [9.8, 11.2], [13.5, 14.8], [15.6, 18], [22.25, 24.5], [24.5, 26.6], [26.6, 26.8]];

test('native application layout, readable synchronized storyboard, direct raster copies and a seamless sequential cycle', () => {
  const recorder = recordingCanvases();
  try {
    const coast = Object.freeze({ width: 1200, height: 400 });
    const references = referenceImages(), usedReferences = new Set();
    const icons = { ...Object.fromEntries(MAC_DOCK_ICON_KEYS.map(name => [name, Object.freeze({ name, width: 512, height: 512 })])), ...references };
    const rdpImages = { desktop: Object.freeze({ width: 1529, height: 932 }), calculator: Object.freeze({ width: 322, height: 533 }) };
    const screens = createComputerScreens(coast, icons, rdpImages), appScreens = createComputerScreens(coast, icons, rdpImages);
    let research = screens.maps.research.image.getContext('2d');
    assert.deepEqual(Object.keys(screens.maps), ['research']);
    assert.deepEqual([screens.maps.research.image.width, screens.maps.research.image.height], [5120, 1440]);
    const artwork = recorder.contexts.flatMap(c => c.texts);
    for (const label of ['CodeBrowser: message_demo.exe', 'New chat', 'Desk Messages']) assert.ok(artwork.includes(label), label);
    const rdpBlit = recorder.contexts.flatMap(c => c.blits).find(blit => blit.image === rdpImages.desktop);
    assert.ok(rdpBlit, 'The supplied RDP window is used directly');
    assert.ok(Math.abs(rdpBlit.args[2] / rdpBlit.args[3] - 1529 / 932) < 1e-12, 'The native RDP aspect is preserved');
    assert.ok(artwork.includes('Codex') && !artwork.includes('ghidra_public'), 'The menubar shows the active app and the bottom-right Finder window is gone');
    assert.ok(!artwork.includes('Weekly 70% left'), 'Edge replaces the usage popup');
    assert.ok(!artwork.some(value => value.includes('192.168.') || value.includes('Cookie:')));
    assert.ok(artwork.some(value => value.includes('messages.kawakatz.com')) && !artwork.some(value => value.includes('messages.example.test')), 'The initial artwork also uses the requested domain');
    for (const key of MAC_DOCK_ICON_KEYS) assert.ok(recorder.contexts.some(c => c.blits.some(blit => blit.image === icons[key])), `Native Dock icon not used: ${key}`);
    const coastBlit = recorder.contexts.flatMap(c => c.blits).find(blit => blit.image === coast);
    const [sx, sy, sw, sh, , , dw, dh] = coastBlit.args;
    assert.ok(Math.abs(sw / sh - dw / dh) < 1e-9);
    assert.ok(Math.abs(sx - (1200 - sw) / 2) < 1e-9 && Math.abs(sy - (400 - sh) / 2) < 1e-9);
    for (const time of [0, 1000 / 30 - .001, NaN, Infinity, -1]) assert.equal(screens.update(time), false);
    const refBlits = name => research.blits.filter(blit => blit.image === references[`ref-${name}`]);
    const nativeX = blit => blit.args[4] + (blit.tx - 775 * 2.4) / blit.sx;
    const composer = () => refBlits('codex-empty').find(({ args }) => [360, 1239, 736, 12].every((value, i) => args[i] === value));
    const sidebar = () => refBlits('codex-working').find(({ args }) => [1028, 84, 302, 88].every((value, i) => args[i] === value));
    const historyIds = () => research.appOperations.filter(op => op[0] === 'caido' && op[1] === 'text' && op[3] === 245 && op[4] >= 166 && op[4] <= 397).map(op => Number(op[2]));
    const edgeTexts = () => research.appOperations.filter(op => op[0] === 'edge' && op[1] === 'text').map(op => op.slice(1));
    const authorSpacing = x => {
      const author = edgeTexts().find(op => op[1] === 'kawakatz' && op[2] === x);
      const stamp = edgeTexts().find(op => op[1].startsWith('10:') && op[3] === author?.[3] && op[8] === author?.[8] && op[9] === author?.[9]);
      const width = author && author[1].length * parseFloat(author[4].split(' ')[1]) * .61;
      assert.ok(author && stamp && stamp[2] >= author[2] + width + 10 - 1e-8, 'The timestamp stays clear of the longer current-user display name');
    };
    const actionRows = () => refBlits('codex-completed').filter(({ args }) => [90, 488, 136, 25].every((value, i) => args[i] === value));
    const sendControl = active => {
      const stop = refBlits('codex-working').some(({ args }) => [862, 1285, 32, 32].every((value, i) => args[i] === value));
      assert.equal(stop, active, 'Only a running turn has the native Stop control');
      assert.ok(!refBlits('codex-empty').some(({ args }) => args[0] === 1058 && args[1] === 1299), 'A submitted turn never reverts to the fresh-chat voice control');
      if (!active) {
        assert.ok(research.operations.some(op => op[0] === 'arc' && op[1] === 824 && op[3] === 13), 'A completed turn has the circular send button');
        assert.ok(research.operations.some((op, i, ops) => op[0] === 'moveTo' && op[1] === 8 && op[2] === 2 && ops[i + 1]?.[0] === 'lineTo' && ops[i + 1][1] === 8 && ops[i + 1][2] === 14 && ops[i + 2]?.[0] === 'stroke' && ops[i + 2][1] === '#303030'), 'The send button contains the upright arrow');
      }
    };
    const workHeaders = () => research.texts.filter(value => /^(?:Working|Worked) for (?:\d+m )?\d+s$/.test(value));
    const responseText = () => research.operations.filter(op => op[0] === 'text' && op[2] === 128 && op[10] === '#ededed').map(op => op[1]).join('').replace(/\s/g, '');
    const workDivider = label => {
      const header = research.operations.find(op => op[0] === 'text' && op[1] === label);
      assert.ok(header, label);
      assert.ok(research.fills.some(([x, y, width, height]) => x === header[2] && y > header[3] && y < header[3] + 24 && width === 720 && height === 1), 'The work summary has a divider across the response column');
    };
    const inFront = (front, back) => {
      const first = research.blits.findLastIndex(blit => blit.image === references[`ref-${front}`]);
      const second = research.blits.findLastIndex(blit => blit.image === references[`ref-${back}`]);
      assert.ok(second >= 0 && first > second, `${front} is painted after ${back}`);
    };
    const manualCursorAt = (x, y, label, investigating = true) => {
      const cursor = research.operations.find(op => op[0] === 'stroke' && op[1] === '#ffffff' && Math.abs(op[4] - 2.4 * .3) < 1e-9);
      assert.ok(cursor && cursor[4] === cursor[5], 'The manual pointer is smaller than the blue Computer Use pointer');
      assert.ok(research.operations.some(op => op[0] === 'fill' && op[1] === '#101010'), 'Manual selection uses a black cursor with a white edge');
      assert.ok(Math.abs(cursor[6] / 2.4 - x) < 1e-6 && Math.abs(cursor[7] / 2.4 - y) < 1e-6, label);
      assert.equal(research.operations.some(op => op[0] === 'text' && op[10]?.stops), investigating, investigating ? 'Manual selection happens while the gray operation is active' : 'Opening the next chat remains a silent manual action');
    };
    const caido = (mode, overlay = null) => {
      assert.ok(refBlits(`caido-${mode}`).length, `Caido uses the ${mode} reference`);
      assert.deepEqual(refBlits(`caido-${mode}`)[0].args.slice(0, 4), [56, 38, 1800, 1130], 'Caido retains the complete original window chrome');
      const regions = { 'replay-menu': [508, 221, 175, 136], 'replay-dialog': [689, 534, 534, 170], 'history-menu': [701, 247, 191, 463], 'history-dialog': [740, 534, 433, 170] };
      const overlays = Object.entries(regions).filter(([name, bounds]) => refBlits(`caido-${name}`).some(({ args }) => bounds.every((value, i) => args[i] === value))).map(([name]) => name);
      assert.deepEqual(overlays, overlay ? [overlay] : [], 'Only the current Caido popup crop is visible, apart from reused control sprites');
    };
    const render = (time, target = screens) => {
      research = target.maps.research.image.getContext('2d');
      reset(research); assert.equal(target.update(realTime(time)), true);
      for (const { image } of research.blits) if (image.name?.startsWith('ref-')) usedReferences.add(image.name);
      const fullFrameCopies = research.blits.filter(({ image }) => image.width === 5120 && image.height === 1440);
      assert.equal(fullFrameCopies.length, 1, 'Only the desktop background is copied as a full frame');
      assert.equal(fullFrameCopies[0].alpha, 1, 'Full-screen redraws never crossfade');
      assert.ok(research.blits.some(blit => blit.image === rdpImages.desktop), 'The RDP image is drawn directly, including during the initial hold');
      assert.ok(!research.texts.some(value => value.includes('messages.example.test')), 'The story uses the requested message-service domain');
      assert.ok(!research.texts.some(value => ['Atlas', 'Lyra', 'Nova'].includes(value)), 'Subagent rows use compact icons rather than name pills');
      for (const op of research.operations.filter(op => op[0] === 'text' && op[2] === 128 && op[10] === '#ededed')) {
        const width = op[1].length * parseFloat(op[4].split(' ')[1]) * .61;
        assert.ok(width <= 720, 'Each response line fits the composer width without clipping or horizontal compression');
      }
      const pointer = research.operations.filter(op => op[0] === 'fill' && op[1] === '#e5f2ff');
      const story = time % 30000 / 1000, operation = researchOperationTime(story >= 29.3 ? 0 : story);
      const caidoFront = operation >= 17.05 && operation < 26.9;
      const caidoBase = operation >= 17.3 && operation < 25.1 ? 'caido-replay' : 'caido-history';
      inFront(caidoFront ? caidoBase : 'edge', caidoFront ? 'edge' : caidoBase);
      const cleanupActive = grayIntervals.some(([start, end]) => story >= start && story < end) && operation >= 21.85 && operation < 27.6;
      assert.equal(pointer.length, cleanupActive ? 1 : 0, 'The blue cleanup cursor appears only during gray cleanup operations');
      if (pointer.length) {
        const edge = research.operations.find(op => op[0] === 'stroke' && op[1] === '#82b9f1');
        assert.ok(edge, 'The cleanup cursor has a pale blue edge');
        assert.ok(Math.abs(edge[4] - 2.4 * .5) < 1e-9 && Math.abs(edge[5] - edge[4]) < 1e-9, 'The cursor is uniformly reduced to 50 percent without moving its hotspot');
      }
      assert.ok(edgeTexts().some(op => op[1] === 'kawakatz') && !edgeTexts().some(op => op[1] === 'You'), 'Edge uses kawakatz for current-user display names in every visible state');
      return research.texts;
    };
    const frame = time => render(time);
    const operationFrame = time => render(operationStory(time), appScreens);
    frame(1000 / 30); const firstFrame = [...research.operations];
    caido('history');
    assert.deepEqual(refBlits('ghidra')[0].args.slice(0, 4), [56, 38, 1430, 906], 'The original Ghidra title, menus, toolbar and sidebars form the static base');
    assert.deepEqual(refBlits('edge')[0].args.slice(0, 4), [56, 38, 1219, 80], 'The original Edge tab and address chrome are retained');
    frame(600); assert.deepEqual(research.operations, firstFrame, 'The opening hold lasts through 0.6 seconds');
    let current = frame(1900); const partial = current.find(value => value.startsWith('Find an'));
    assert.ok(partial && 'Find an RCE vulnerability.'.startsWith(partial) && partial !== 'Find an RCE vulnerability.');
    assert.ok(current.includes('New chat'));
    assert.ok(research.operations.some(op => op[0] === 'roundRect' && op[3] === 720 && op[4] === 96), 'The composer remains compact');
    assert.ok(Math.abs(nativeX(composer()) + composer().args[6] / 2 - 640) < 1e-8, 'The fresh composer is centered in the full Codex window');
    const welcome = refBlits('codex-empty').find(({ args }) => [498, 570, 462, 115].every((value, i) => args[i] === value));
    assert.ok(welcome && Math.abs(nativeX(welcome) + welcome.args[6] / 2 - 640) < 1e-8, 'The fresh welcome artwork shares the composer center');
    assert.equal(sidebar(), undefined, 'The initial chat has no working sidebar');
    const model = refBlits('codex-empty').find(({ args }) => args[0] === 883 && args[1] === 1302);
    assert.ok(model, 'The model and purple Ultra label use the original screenshot pixels');
    assert.equal(model.args[4], 620, 'The model control stays clear of the microphone');
    current = frame(2600); assert.ok(current.includes('Find an RCE vulnerability.') && current.includes('New chat'), 'Typing completes before submission');
    current = frame(2800); assert.ok(current.includes('Message application review') && !current.includes('New chat'), 'The prompt submits at 2.75 seconds');
    const enteringX = nativeX(composer());
    assert.ok(enteringX > 128 && enteringX < 280 && sidebar().alpha > 0 && sidebar().alpha < 1, 'Submission starts the leftward composer shift and sidebar entrance');
    frame(2900);
    assert.ok(nativeX(composer()) < enteringX && nativeX(composer()) > 128, 'The composer continues smoothly left rather than jumping into place');
    frame(3040);
    assert.ok(Math.abs(nativeX(composer()) - 128) < 1e-8 && sidebar().alpha === 1 && Math.abs(nativeX(sidebar()) - 962) < 1e-8, 'Composer and sidebar finish moving before the first white reply');
    assert.equal(responseText(), '', 'The first white reply waits until the entrance has settled');
    const firstReply = 'I’ll review messages.kawakatz.com and follow the message handling code in Ghidra.';
    const secondReply = 'The message flow is mapped. I’m checking how the remote session presents each result.';
    current = frame(3200);
    const firstPrefix = responseText(), compactFirst = firstReply.replace(/\s/g, '');
    assert.ok(firstPrefix.length > 0 && firstPrefix.length < compactFirst.length && compactFirst.startsWith(firstPrefix), 'The opening reply starts as a left-to-right prefix');
    const startingWork = workHeaders();
    assert.equal(startingWork.length, 1); assert.match(startingWork[0], /^Working for (?:\d+m )?\d+s$/);
    workDivider(startingWork[0]);
    current = frame(3900); const firstStoryFrame = [...research.operations];
    assert.ok(responseText() === compactFirst, 'The opening reply is complete before Researching appears');
    assert.ok(current.includes('Find an RCE vulnerability.'));
    for (const source of ['Ghidra MCP', 'Caido MCP', 'Playwright', 'messages.kawakatz.com']) assert.ok(current.includes(source), source);
    const status = research.operations.find(op => op[0] === 'text' && op[1] === 'Researching the application and project context');
    assert.deepEqual(status?.[10]?.stops, [[0, '#d0d0d0'], [.15, '#777'], [.35, '#777'], [.5, '#d0d0d0'], [.65, '#777'], [.85, '#777'], [1, '#d0d0d0']], 'Active status text uses a repeating gray shimmer without a blank gap');
    const statusIcon = refBlits('codex-working').find(({ args }) => args[0] === 164 && args[1] === 191 && args[2] === 16 && args[3] === 16);
    const metrics = research.measureText(status[1]);
    assert.ok(statusIcon && statusIcon.args[4] + statusIcon.args[6] + 4 <= status[2] && Math.abs(statusIcon.args[5] + statusIcon.args[7] / 2 - (status[3] - (metrics.actualBoundingBoxAscent - metrics.actualBoundingBoxDescent) / 2)) < .01, 'The native status icon is centered beside the visible glyphs using the font metrics');
    sendControl(true); assert.equal(actionRows().length, 0, 'Response actions appear only after completion');
    assert.ok(Number(workHeaders()[0].match(/\d+/)[0]) > Number(startingWork[0].match(/\d+/)[0]), 'Working time advances with playback');
    current = frame(4400);
    assert.ok(current.includes('Message handlers and desktop review updated') && current.includes('2 working') && current.includes('0 done'));
    assert.ok(refBlits('codex-working').some(({ args, composite }) => args[0] === 164 && args[1] === 153 && args[2] === 16 && args[3] === 16 && composite === 'lighten'), 'Subagent rows reuse the native icon sprite without its dark background rectangle');
    frame(4600); assert.equal(responseText(), compactFirst, 'The opening reply reaches its complete text before the next reply starts');
    current = operationFrame(4550);
    assert.deepEqual(historyIds(), [], 'History remains empty during Ghidra-only work');
    for (const label of ['Rename Function at 140001120', 'Enter Name:']) assert.ok(current.includes(label), label);
    assert.deepEqual(refBlits('ghidra-function')[0].args.slice(0, 4), [56, 38, 522, 266], 'The function dialog keeps its native fields, checkboxes and buttons');
    assert.ok(current.includes('FUN_140001120') && research.fills.some(fill => fill[4] === '#456589'), 'The native dialog first selects the original function name');
    assert.ok(research.operations.some(op => op[0] === 'text' && op[1] === 'FUN_140001120' && op[10] === '#fff'), 'Selected names use white text on the muted blue selection');
    const functionDialog = research.operations.find(op => op[0] === 'roundRect' && op[3] === 522 && op[4] === 266);
    assert.ok(functionDialog, 'Rename Function has the native reference proportions');
    current = operationFrame(5000); assert.ok(current.includes('read_message'));
    assert.ok(!research.fills.some(fill => fill[4] === '#456589'), 'Typing replaces the old selection with the new name');
    current = operationFrame(5200);
    assert.ok(!current.some(value => value.startsWith('Rename Function at ')) && current.includes('INFO  Renamed FUN_140001120 to read_message'), 'The function rename commits when the dialog closes');
    current = frame(5650);
    const secondPrefix = responseText().slice(compactFirst.length), compactSecond = secondReply.replace(/\s/g, '');
    assert.ok(secondPrefix.length > 0 && secondPrefix.length < compactSecond.length && compactSecond.startsWith(secondPrefix), 'The next reply also streams instead of appearing all at once');
    const updateRow = research.operations.find(op => op[0] === 'text' && op[1] === 'Message handlers and desktop review updated');
    const nextReply = research.operations.findLast(op => op[0] === 'text' && op[2] === 128 && op[10] === '#ededed');
    assert.ok(nextReply[3] - updateRow[3] <= 40 && updateRow[10] === '#999', 'A compact gray subagent update occupies one line before the next reply');
    current = frame(6250);
    assert.ok(current.includes('Reading references and clarifying function names'), 'Gray status labels still appear as complete labels');
    frame(7100); assert.equal(responseText(), compactFirst + compactSecond, 'The second reply finishes at the same character rate while preserving earlier text');
    current = frame(7800);
    assert.ok(current.includes('Message handler review updated') && current.includes('1 working') && current.includes('1 done'));
    current = operationFrame(8000); assert.ok(current.includes('format_preview'));
    const codeBlit = research.blits.find(({ image }) => image.getContext?.('2d').texts.includes('Preview'));
    assert.ok(codeBlit, 'The benign function body is drawn');
    for (const { image, args, sx, sy, tx, ty } of research.blits.filter(({ image }) => image.getContext)) {
      if (args.length === 8) {
        assert.ok(Math.abs(args[6] * sx - args[2]) < 1e-8 && Math.abs(args[7] * sy - args[3]) < 1e-8, 'Desktop restoration remains a 1:1 pixel copy');
      } else {
        assert.equal(args.length, 2, 'Text caches use native-size drawImage with no scaling arguments');
        assert.equal(sx, 1); assert.equal(sy, 1);
        assert.equal(tx, Math.round(tx)); assert.equal(ty, Math.round(ty));
      }
      assert.ok(image.width > 0);
    }
    const ghidraText = codeBlit.image.getContext('2d').operations.find(op => op[0] === 'text' && op[4].includes('13px'));
    assert.ok(ghidraText && parseFloat(ghidraText[4].split(' ')[1]) * ghidraText[6] < 14, 'Reference-sized code remains about 13 native texture pixels at 5K');
    current = operationFrame(9300);
    assert.ok(current.includes('References to format_badge') && current.includes('format_preview') && current.includes('present_message'), 'Ghidra opens cross references with both callers');
    assert.deepEqual(refBlits('ghidra-references')[0].args.slice(0, 4), [56, 38, 508, 264], 'References keeps the native screenshot frame, toolbar and filter controls');
    operationFrame(10340); assert.deepEqual(historyIds(), [], 'No requests appear before the first Edge operation');
    operationFrame(10640); assert.deepEqual(historyIds(), [], 'Opening search alone does not invent a request');
    current = operationFrame(10660);
    assert.deepEqual(historyIds(), [1]); assert.ok(current.includes('/api/search?q=desk'), 'The first search request starts with ID1');
    operationFrame(10800); assert.deepEqual(historyIds(), [1], 'History does not grow between meaningful browser actions');
    operationFrame(10920); assert.deepEqual(historyIds(), [2, 1], 'The completed search appends the next ID');
    current = operationFrame(11500);
    assert.deepEqual(historyIds(), Array.from({ length: 9 }, (_, i) => 9 - i), 'Channel loading and opening its thread append consecutive request IDs');
    authorSpacing(63); assert.ok(current.includes('Your next note will show up there.'), 'Grammatical Your remains unchanged');
    current = frame(11400);
    assert.ok(current.includes('Browser and response review updated') && current.includes('2 working') && current.includes('1 done'));
    current = operationFrame(13500); assert.ok(current.includes('https://messages.kawakatz.com/inbox'));
    assert.ok(!current.some(value => /^(?:GET|POST) .* HTTP\/1\.1$|^HTTP\/1\.1|^Host:|^Content-Type:/.test(value)), 'Unselected History leaves the request and response editors empty');
    assert.ok(!research.appOperations.some(op => op[0] === 'caido' && op[1] === 'rectFill' && ['#5c6069', '#d9a84a'].includes(op[6])), 'Accumulating History rows never select themselves');
    assert.ok(current.includes('/api/typing') && current.includes('/api/threads/desk-01'), 'History reflects the thread view and composer actions');
    assert.deepEqual(historyIds(), Array.from({ length: 11 }, (_, i) => 11 - i), 'Typing appends a request without unrelated background traffic');
    inFront('edge', 'caido-history');
    const browserPointer = research.operations.find(op => op[0] === 'stroke' && op[1] === '#92c1ea');
    assert.ok(browserPointer && Math.abs(browserPointer[4] - 2.4 * 455 / 1280 * .8) < 1e-9 && browserPointer[4] === browserPointer[5], 'The browser pointer is smaller while its native hotspot remains unchanged');
    current = operationFrame(13800);
    assert.ok(current.includes('Function Call Trees: present_message') && current.includes('4 outgoing calls'), 'Ghidra follows the presentation function into its call tree');
    current = operationFrame(15500);
    assert.ok(current.includes('Rename Local Variable') && current.includes('Rename local_18:') && current.includes('local_18'));
    assert.deepEqual(refBlits('ghidra-variable')[0].args.slice(0, 4), [56, 38, 364, 130], 'The local variable dialog retains its native compact frame');
    assert.ok(research.fills.some(fill => fill[4] === '#456589'), 'The old local variable is selected before replacement');
    assert.ok(research.operations.some(op => op[0] === 'roundRect' && op[3] === 364 && op[4] === 130), 'Rename Local Variable stays compact');
    assert.ok(!current.includes('Namespace') && !current.includes('Properties'), 'The compact variable dialog has no function-only controls');
    current = operationFrame(15700); assert.ok(current.includes('Rename Local Variable'));
    authorSpacing(537);
    assert.ok(research.blits.some(({ image }) => image.getContext?.('2d').texts.includes('local_18')), 'The original local name is visible during its rename dialog');
    current = operationFrame(15950); assert.ok(current.includes('preview'));
    assert.ok(!research.fills.some(fill => fill[4] === '#456589'));
    current = operationFrame(16200); assert.ok(current.includes('INFO  Renamed local_18 to preview'));
    assert.ok(!current.includes('Rename Local Variable'), 'The local-variable dialog closes after confirmation');
    assert.ok(!research.blits.some(({ image }) => image.getContext?.('2d').texts.includes('local_18')), 'All decompiler occurrences use the new local name after confirmation');
    current = operationFrame(16900);
    caido('history'); inFront('edge', 'caido-history');
    assert.deepEqual(historyIds(), Array.from({ length: 12 }, (_, i) => 17 - i), 'All17 action requests retain sequential IDs while only twelve rows are visible');
    const badgeIndex = research.operations.findIndex(op => op[0] === 'arc' && op[1] === 200 && op[2] === 371 && op[3] === 9);
    assert.ok(badgeIndex >= 0 && research.operations[badgeIndex + 1][0] === 'fill' && research.operations[badgeIndex + 1][1] === '#e25563', 'Replay uses a red circular badge');
    const badge = research.operations.find(op => op[0] === 'text' && op[1] === '1' && op[2] === 200 && op[3] === 371);
    assert.ok(badge && badge[10] === '#fff' && badge[11] === 'center' && badge[12] === 'middle', 'The badge numeral is white and centered on both axes');
    assert.ok(!current.some(value => /^(?:GET|POST) .* HTTP\/1\.1$|^HTTP\/1\.1/.test(value)), 'The ready session does not automatically open its editors');
    current = operationFrame(17050);
    caido('history'); inFront('caido-history', 'edge');
    assert.ok(research.operations.some(op => op[0] === 'text' && op[1] === '1' && op[2] === 200 && op[3] === 371) && !current.includes('POST /scene/preview HTTP/1.1'), 'Activating Caido leaves the badge pending until Replay is explicitly selected');
    manualCursorAt(1343 + 300 * 748 / 1536, 108 + 17 * 748 / 1536, 'Manual activation clicks the exposed Caido title bar to the left of Edge');
    current = operationFrame(17300);
    caido('replay'); inFront('caido-replay', 'edge');
    manualCursorAt(1343 + 70 * 748 / 1536, 108 + 263 * 748 / 1536, 'The following click selects the Replay sidebar');
    assert.deepEqual(research.operations.filter(op => op[0] === 'text' && op[2] >= 551 && op[2] <= 675 && op[3] === 145).map(op => op[1]), ['1'], 'Manual Replay selection opens exactly one tab');
    assert.deepEqual(research.operations.filter(op => op[0] === 'text' && op[2] === 286 && op[3] >= 252 && op[3] <= 312).map(op => op[1]), ['1'], 'Replay contains exactly one session');
    assert.ok(current.includes('POST /scene/preview HTTP/1.1') && current.includes('HTTP/1.1 200 OK') && current.includes('History (1/1)  ⌄'), 'Opening the session reveals its already completed request and response');
    assert.ok(!current.includes('Waiting for response…') && !current.includes('Sending…'), 'Manual selection does not start another Replay request');
    assert.ok(!research.operations.some(op => op[0] === 'text' && op[1] === '1' && op[2] === 200 && op[3] === 371), 'Opening Replay clears its unread badge');
    current = operationFrame(17550);
    assert.ok(current.includes('POST /scene/preview HTTP/1.1') && current.includes('  "mode": "preview"'));
    assert.ok(!current.includes('Message received') && !research.blits.some(blit => blit.image === rdpImages.calculator));
    operationFrame(17800);
    manualCursorAt(19 + 620 * 636 / 1529, 21 + 16 * 636 / 1529, 'The next manual click selects the exposed RDP title bar above Ghidra');
    assert.equal(research.blits.filter(blit => blit.image === rdpImages.desktop).length, 2, 'The remote desktop comes forward on the title-bar click');
    operationFrame(17830);
    const arrivingIndex = research.operations.findLastIndex(op => op[0] === 'roundRect' && op[3] === 380 && op[4] === 148);
    const arriving = research.operations[arrivingIndex], arrivalAlpha = research.operations[arrivingIndex + 1][2];
    assert.ok(arriving[1] > 1133 && arriving[1] < 1165 && arrivalAlpha > 0 && arrivalAlpha < 1, 'The notification slides in from the right while fading in');
    current = operationFrame(17900);
    const settledToastIndex = research.operations.findLastIndex(op => op[0] === 'roundRect' && op[3] === 380 && op[4] === 148);
    assert.ok(research.operations[settledToastIndex][1] === 1133 && research.operations[settledToastIndex + 1][2] === 1, 'The notification completes its short entrance by operation17.9');
    current = operationFrame(18300); assert.ok(current.includes('Message received')); assert.ok(current.includes('Delivered'));
    assert.ok(!research.blits.some(blit => blit.image === rdpImages.calculator), 'The notification arrives before Calculator');
    const toast = research.operations.findLast(op => op[0] === 'roundRect' && op[3] === 380 && op[4] === 148);
    assert.equal(toast[1] + toast[3], 1529 - 16, 'The notification has a 16 px right margin inside RDP');
    assert.equal(toast[2] + toast[4], 884 - 16, 'The notification sits 16 px above the original taskbar');
    assert.ok(current.lastIndexOf('Message received') > current.lastIndexOf('CodeBrowser: message_demo.exe'), 'The visible notification is painted after Ghidra');
    assert.equal(research.blits.filter(blit => blit.image === rdpImages.desktop).length, 2, 'The complete RDP window comes to the foreground for the notification');
    operationFrame(18400);
    const firstCalculator = research.blits.filter(blit => blit.image === rdpImages.calculator);
    assert.ok(firstCalculator.length && firstCalculator.every(blit => blit.alpha === 1), 'Calculator is fully opaque in its first visible frame');
    current = operationFrame(18800); assert.ok(current.includes('  "scene": "workspace"'));
    const calculatorBlit = research.blits.find(blit => blit.image === rdpImages.calculator);
    assert.deepEqual(calculatorBlit.args, [120, 100, 322, 533], 'Calculator uses its original screenshot dimensions');
    const lastCalculator = research.blits.findLastIndex(blit => blit.image === rdpImages.calculator);
    const lastCaido = research.blits.findLastIndex(blit => blit.image === references['ref-caido-replay']);
    assert.ok(lastCalculator > lastCaido, 'RDP comes forward so Calculator is visible');
    current = frame(18000);
    assert.ok(current.includes('0 working') && current.includes('3 done'));
    assert.match(workHeaders()[0], /^Working for (?:\d+m )?\d+s$/, 'The turn remains active while its final reply is being prepared');
    current = frame(18600);
    assert.deepEqual(workHeaders(), ['Worked for 1m 32s']); workDivider('Worked for 1m 32s');
    assert.equal(actionRows().length, 0, 'Worked appears before the answer and its actions'); sendControl(false);
    assert.equal(responseText(), '');
    const answer = ['RCE confirmed.', 'Untrusted message data reached a privileged execution path.', 'Impact: remote code execution in the message service.', 'Under the program guidelines, this vulnerability qualifies for the $10,000 reward tier.', 'Fix: validate message fields and isolate privileged operations.'];
    const fullAnswer = answer.join('').replace(/\s/g, '');
    let streamed = '';
    for (const at of [18800, 19400, 20000]) {
      frame(at); const next = responseText();
      assert.ok(next.length > streamed.length && next.startsWith(streamed) && fullAnswer.startsWith(next) && next.length < fullAnswer.length, 'The final answer grows from left to right, in paragraph order');
      assert.equal(actionRows().length, 0, 'Actions remain hidden while the answer streams'); streamed = next;
    }
    frame(20440); assert.equal(responseText(), fullAnswer); assert.equal(actionRows().length, 0);
    current = frame(20550); assert.equal(actionRows().length, 1, 'The native action row appears after the last paragraph');
    for (const paragraph of answer) assert.ok(current.join(' ').includes(paragraph), paragraph);
    assert.ok(!current.some(value => value.endsWith('review updated')) && !current.join(' ').includes(firstReply) && !current.includes('Researching the application and project context'), 'Completion collapses intermediate responses, statuses and agent updates while retaining the final answer');
    current = frame(21300);
    assert.ok(current.some(value => value.startsWith('Please clean up @')), 'Cleanup types the explicit Computer mention');
    const pickerDescription = 'Interact with apps and websites on your computer.';
    const pickerTop = 548 * 1280 / 558 - 116 - 96;
    const pickerText = research.operations.filter(op => op[0] === 'text' && op[2] >= 140 && op[2] <= 836 && op[3] >= pickerTop + 12 && op[3] <= pickerTop + 72 && Math.abs(op[6] - 2.4 * 558 / 1280) < 1e-9 && Math.abs(op[8] - 775 * 2.4) < 1e-9).map(op => op[1]);
    assert.deepEqual(pickerText, ['Computer', pickerDescription, '↵'], 'Autocomplete offers only the Computer tool, without files or paths');
    const mentionIcons = () => refBlits('codex-computer').filter(({ args }) => [137, 30, 16, 16].every((value, i) => args[i] === value));
    assert.equal(mentionIcons().length, 1, 'The selected autocomplete row reuses the supplied Computer icon');
    current = frame(21500); assert.ok(current.includes('Please clean up @Computer'));
    current = frame(21700);
    assert.ok(current.includes('Please clean up ') && current.includes('Computer') && !current.includes(pickerDescription) && !current.some(value => value.includes('@Computer')), 'Selection replaces the typed mention with the icon and clean label');
    assert.equal(mentionIcons().length, 1);
    current = frame(21800); assert.deepEqual(workHeaders(), ['Worked for 1m 32s'], 'The completed duration stays fixed while the cleanup prompt is typed');
    current = frame(22100); assert.ok(research.blits.some(blit => blit.image === rdpImages.calculator));
    assert.ok(current.includes('Please clean up ') && current.includes('Computer') && !current.some(value => value.includes('@Computer')), 'The sent cleanup bubble keeps the clean Computer mention');
    assert.equal(mentionIcons().length, 1, 'The sent bubble retains its Computer icon');
    assert.ok(workHeaders().includes('Worked for 1m 32s') && workHeaders().some(value => value.startsWith('Working for ')), 'Submitting cleanup starts a separate running turn without reopening the first turn');
    sendControl(true);
    current = frame(22200);
    assert.ok(current.includes('1 working') && current.includes('2 done'), 'Lyra continues the cleanup while the other agents remain done');
    operationFrame(22100);
    const closingCalculator = research.blits.filter(blit => blit.image === rdpImages.calculator);
    assert.ok(closingCalculator.length && closingCalculator.every(blit => blit.alpha > 0 && blit.alpha < 1), 'Calculator retains its short closing fade');
    current = operationFrame(22200);
    assert.ok(!research.blits.some(blit => blit.image === rdpImages.calculator) && current.includes('Message received'), 'Calculator closes before the notification is dismissed');
    current = operationFrame(22500); assert.ok(current.includes('Message received'));
    current = operationFrame(22600); assert.ok(!current.includes('Message received'));
    current = operationFrame(23000);
    inFront('ghidra', 'caido-replay');
    const activation = research.operations.find(op => op[0] === 'stroke' && op[1] === '#82b9f1');
    const clickX = activation[6] / 2.4, clickY = activation[7] / 2.4;
    assert.ok(Math.abs(clickX - (202 + 1300 * 558 / 1400)) < 1e-8 && Math.abs(clickY - (143 + 15 * 558 / 1400)) < 1e-8, 'Ghidra activation clicks the exposed right side of its title bar');
    assert.ok(clickX >= 202 && clickX <= 760 && clickY >= 143 && clickY <= 562, 'The activation hotspot stays inside Ghidra');
    assert.ok(clickX < 19 || clickX > 655 || clickY < 21 || clickY > 21 + 636 * 932 / 1529, 'The activation hotspot is outside the foreground RDP window');
    assert.ok(current.includes('Decompile: present_message') && !current.includes('Decompile: render_card'));
    current = operationFrame(23600);
    inFront('caido-replay', 'ghidra');
    current = operationFrame(24000); caido('replay', 'replay-menu'); assert.ok(current.includes('POST /scene/preview HTTP/1.1'));
    assert.ok(current.includes('Delete session (1)') && !current.includes('Delete sessions (3)'), 'Replay cleanup names the single remaining session');
    current = operationFrame(24500); caido('replay', 'replay-dialog');
    assert.ok(current.includes('Are you sure you want to delete 1 session?'), 'The native confirmation also reflects the one-session cleanup');
    assert.ok(current.includes('POST /scene/preview HTTP/1.1'), 'The confirmation replaces the menu before sessions are removed');
    current = frame(24500);
    assert.ok(current.includes('1 working') && current.includes('2 done'));
    assert.deepEqual(current.filter(value => value.endsWith('review updated')), [], 'Cleanup retains the collapsed first turn rather than replaying its intermediate agent updates');
    current = operationFrame(24800);
    caido('replay');
    assert.ok(!current.includes('POST /scene/preview HTTP/1.1') && !refBlits('caido-replay-menu').length, 'Empty Replay retains the original empty-state artwork without session controls or request overlays');
    current = operationFrame(25200);
    caido('history');
    assert.ok(current.includes('/api/messages/scene-01'), 'History entries remain until their own cleanup');
    current = operationFrame(25600); caido('history', 'history-menu'); assert.ok(current.includes('/api/messages/scene-01'));
    current = operationFrame(26200); caido('history', 'history-dialog'); assert.ok(current.includes('/api/messages/scene-01'));
    current = operationFrame(26500);
    caido('history');
    assert.ok(!current.includes('/api/messages/scene-01') && !refBlits('caido-history-menu').length, 'Empty History shows the original empty state without request or editor overlays');
    current = frame(26500);
    assert.ok(current.includes('0 working') && current.includes('3 done'), 'All agents finish after History is cleared');
    current = operationFrame(27300);
    assert.ok(current.includes('Welcome to Desk Messages') && current.includes('Decompile: FUN_140001120')); inFront('edge', 'caido-history');
    current = frame(27650);
    assert.deepEqual(workHeaders(), ['Worked for 1m 32s', 'Worked for 26s']); workDivider('Worked for 26s');
    assert.equal(responseText(), fullAnswer, 'Cleanup changes to Worked before revealing its answer');
    assert.equal(actionRows().length, 1, 'Only the first answer has actions during cleanup streaming'); sendControl(false);
    assert.ok(!current.includes('Clearing Replay sessions and HTTP History') && !current.join(' ').includes('Sure. I’ll close the temporary windows'), 'The cleanup completion also collapses its intermediate work');
    inFront('edge', 'caido-history');
    const cleanupAnswer = 'Cleaned up.Calculator and the notification are closed.Replay and HTTP History are clear.'.replace(/\s/g, '');
    streamed = '';
    for (const at of [27850, 28200]) {
      frame(at); const next = responseText().slice(fullAnswer.length);
      assert.ok(next.length > streamed.length && next.startsWith(streamed) && cleanupAnswer.startsWith(next) && next.length < cleanupAnswer.length, 'Cleanup uses the same left-to-right reveal');
      assert.equal(actionRows().length, 1); streamed = next;
      assert.deepEqual(workHeaders(), ['Worked for 1m 32s', 'Worked for 26s'], 'Both completed durations remain fixed while the answer streams');
    }
    frame(28550); assert.equal(responseText(), fullAnswer + cleanupAnswer); assert.equal(actionRows().length, 1);
    frame(28650); assert.equal(actionRows().length, 2, 'Each response gains its actions only after its final text');
    current = frame(28750);
    assert.equal(actionRows().length, 2, 'Completed result actions remain visible before opening the next chat');
    assert.ok(!current.includes('Opening a new chat') && !research.operations.some(op => op[0] === 'text' && op[10]?.stops), 'The post-result new-chat transition adds no gray output');
    assert.ok(research.operations.some(op => op[0] === 'stroke' && op[1] === '#ffffff') && !research.operations.some(op => op[0] === 'stroke' && op[1] === '#82b9f1'), 'New-chat navigation uses the small manual cursor instead of the blue Computer Use cursor');
    operationFrame(28900);
    manualCursorAt(775 + 120 * 558 / 1280, 14 + 23 * 558 / 1280, 'The manual cursor clicks the new-chat control', false);
    current = frame(29000);
    assert.ok(current.includes('New chat') && current.includes('Ask anything') && !current.includes('Cleaned up.') && !current.includes('Message application review'));
    current = frame(29266.667);
    assert.ok(current.includes('New chat') && current.includes('Decompile: FUN_140001120') && current.includes('Welcome to Desk Messages'));
    caido('history'); assert.ok(!current.includes('/api/messages/scene-01'));
    assert.ok(!recorder.contexts.flatMap(c => c.texts).some(value => /illustrated|Fictional demo scene|Canvas demonstration|same demonstration|Demo account/.test(value)), 'Visible apps do not describe their illustration implementation');
    assert.deepEqual([...usedReferences].sort(), Object.keys(references).sort(), 'Every supplied chrome, icon and dialog reference is exercised');
    frame(29300); assert.deepEqual(research.operations, firstFrame, 'The completed cleanup enters the original held frame');
    frame(30000 - 1000 / 30 * 27 / 87); assert.deepEqual(research.operations, firstFrame, 'The final rendered frame matches the initial frame without a crossfade');
    frame(30000); assert.deepEqual(research.operations, firstFrame);
    frame(30600); assert.deepEqual(research.operations, firstFrame);
    frame(33900); assert.deepEqual(research.operations, firstStoryFrame, 'The next cycle reproduces the same in-progress frame');
    assert.equal(screens.update(realTime(33900)), false); assert.equal(screens.update(realTime(33000)), false);
    const before = screens.maps.research.version;
    for (let tick = 1; tick <= 30; tick++) screens.update(realTime(33900) + tick * 1000 / 60);
    assert.equal(screens.maps.research.version - before, 15, 'The caller cadence remains 30fps');
    const phaseText = research.texts.includes('Decompiling FUN_140001120…');
    assert.equal(screens.refreshDate(new Date(2032, 1, 28, 12)), true);
    assert.equal(research.texts.includes('Decompiling FUN_140001120…'), phaseText);
    const version = screens.maps.research.version;
    assert.equal(screens.refreshDate(new Date(2032, 1, 28, 12, 0, 0, 999)), false);
    assert.equal(screens.maps.research.version, version);
    reset(research); assert.equal(screens.refreshDate(new Date(2032, 1, 29, 0)), true);
    assert.ok(research.texts.includes('FEB') && research.texts.includes('29'), 'Calendar advances while animation time is paused');
    appScreens.dispose(); screens.dispose(); assert.equal(screens.refreshDate(new Date()), false);
  } finally { recorder.restore(); }
});

test('each reply or gray investigation finishes before the next output starts', () => {
  const recorder = recordingCanvases(); let screens;
  try {
    screens = createComputerScreens();
    const research = screens.maps.research.image.getContext('2d');
    let characters = 0;
    const render = elapsed => {
      reset(research); assert.equal(screens.update(elapsed), true);
      const white = research.operations.filter(op => op[0] === 'text' && op[2] === 128 && op[10] === '#ededed');
      assert.ok(white.every(op => op[5] === 1), 'White reply text is revealed by characters, never an opacity fade');
      characters = white.reduce((sum, op) => sum + op[1].length, 0);
      return white.map(op => op[1]).join('').replace(/\s/g, '');
    };
    const frame = time => render(realTime(time));
    const replies = [
      [3050, 'I’ll review messages.kawakatz.com and follow the message handling code in Ghidra.'],
      [5500, 'The message flow is mapped. I’m checking how the remote session presents each result.'],
      [8800, 'The function and variable names are clearer now. I’ll compare the browser response with the desktop state.'],
      [12600, 'The browser and remote session are responding consistently. I’m checking the visible result before summarizing.'],
      [14800, 'The notification is ready for a final check. I’m validating the result in the remote desktop.'],
      [18000, 'RCE confirmed.'],
      [22000, 'Sure. I’ll close the temporary windows and clear the review activity from Replay and HTTP History.'],
      [26800, 'Replay and HTTP History are clear.'],
    ];
    for (const [at, reply] of replies) {
      const earlier = frame(at - 40), full = reply.replace(/\s/g, '');
      const priorCharacters = characters, duration = reply.length / 17 * 1000, start = researchPlayback(at / 1000) * 1000;
      let prefix = '';
      for (const offset of [duration * .2, duration * .6]) {
        const text = render(start + offset);
        assert.ok(text.startsWith(earlier), 'A new reply preserves all earlier white text');
        const next = text.slice(earlier.length);
        assert.ok(next.length > prefix.length && next.startsWith(prefix) && full.startsWith(next) && next.length < full.length, `Reply at ${at}ms grows from its beginning`);
        assert.ok(Math.abs(characters - priorCharacters - offset * 17 / 1000) <= 2, 'Every ordinary reply uses 17 characters per real second, allowing frame rounding and wrapped spaces');
        assert.ok(!research.operations.some(op => op[0] === 'text' && op[10]?.stops), 'No investigation is active while a white reply is still streaming');
        prefix = next;
      }
      assert.equal(render(start + duration + 40), earlier + full, `Reply at ${at}ms finishes without missing characters`);
    }
    const statuses = [
      [4300, 'Researching the application and project context'],
      [7700, 'Reading references and clarifying function names'],
      [11200, 'Inspecting the message view'],
      [14800, 'Tracing message delivery across the open windows'],
      [18000, 'Validating the Replay response and desktop state'],
      [24500, 'Closing Calculator and dismissing the notification'],
      [26600, 'Clearing Replay sessions and HTTP History'],
      [26800, 'Checking the desktop state'],
    ];
    const statusRow = label => research.operations.find(op => op[0] === 'text' && op[1] === label);
    const shimmerColors = row => {
      const { gradient: [left, , right], stops } = row[10], width = row[1].length * parseFloat(row[4].split(' ')[1]) * .61;
      assert.ok(Math.abs(right - left - width * 2) < 1e-8, 'The shimmer scales to the measured text instead of a fixed sweep width');
      const gray = color => parseInt(color.length === 4 ? color[1].repeat(2) : color.slice(1, 3), 16);
      return Array.from({ length: 33 }, (_, i) => {
        const x = Math.max(0, Math.min(1, (row[2] + width * i / 32 - left) / (right - left)));
        const upper = stops.findIndex(([at]) => at >= x);
        if (upper === 0) return gray(stops[0][1]);
        const [a, ca] = stops[upper - 1], [b, cb] = stops[upper];
        return gray(ca) + (gray(cb) - gray(ca)) * (x - a) / (b - a);
      });
    };
    const cycle = researchPlayback(30) * 1000;
    render(cycle + 9600 - 1000 / 30); const beforeWrap = shimmerColors(statusRow(statuses[0][1]));
    render(cycle + 9600); const atWrap = shimmerColors(statusRow(statuses[0][1]));
    render(cycle + 12000); const nextWrap = shimmerColors(statusRow(statuses[0][1]));
    assert.ok(atWrap.every((value, i) => Math.abs(value - nextWrap[i]) < 1e-8), 'The same text colors repeat after 2.4 seconds of real playback');
    assert.ok(atWrap.every((value, i) => Math.abs(value - beforeWrap[i]) < 5), 'The sweep crosses its cycle boundary without a flash or blank gap');
    for (const [end, label] of statuses) {
      frame(30000 + end - 40);
      const visible = statuses.map(([, value]) => statusRow(value)).filter(Boolean);
      assert.deepEqual(visible.filter(op => op[10]?.stops).map(op => op[1]), [label], 'The current gray investigation remains active until the next output');
      for (const row of visible) if (row[1] !== label) assert.equal(row[10], '#848484', 'Older statuses are static gray');
      shimmerColors(statusRow(label));
      frame(30000 + end + 40);
      assert.equal(statusRow(label)?.[10], '#848484', 'The previous investigation has finished when the next white, gray or agent output starts');
      if (end <= 18000) assert.ok(!research.texts.some(value => /^(?:Rename Function at |Rename Local Variable$|Decompiling |Sending…$|Waiting for response…$|References to |Function Call Trees:)/.test(value)), 'Investigation pauses only after dialogs, decompilation and pending replies have completed');
    }
  } finally { screens?.dispose(); recorder.restore(); }
});

test('decorative tool operations follow gray statuses and reserve a silent tail for the next chat', () => {
  const recorder = recordingCanvases(); let screens;
  try {
    screens = createComputerScreens(null, referenceImages());
    const research = screens.maps.research.image.getContext('2d');
    const frame = story => {
      reset(research); assert.equal(screens.update(realTime(story * 1000)), true);
      return [...research.appOperations];
    };
    const phases = [
      [3.05, 3.6, false], [3.6, 4.3, true], [5.5, 6.2, false], [6.2, 7.7, true],
      [8.8, 9.8, false], [9.8, 11.2, true], [12.6, 13.5, false], [13.5, 14.8, true],
      [14.8, 15.6, false], [15.6, 18, true], [18, 22.25, false], [22.25, 24.5, true],
      [24.5, 26.6, true], [26.6, 26.8, true], [26.8, 28.7, false], [28.7, 28.9, 'navigation'],
    ];
    for (const [start, end, active] of phases) {
      const a = start + (end - start) * .15, b = start + (end - start) * .85;
      const before = frame(a), after = frame(b);
      assert.ok(before.length && after.length, 'The comparison includes actual window drawing operations');
      assert.deepEqual([...new Set(before.map(op => op[0]))].sort(), ['caido', 'edge', 'ghidra', 'rdp']);
      if (active === 'navigation') {
        assert.ok(researchOperationTime(b) > researchOperationTime(a), 'The silent navigation action still advances');
        assert.ok(!research.texts.includes('Opening a new chat') && !research.operations.some(op => op[0] === 'text' && op[10]?.stops), 'The finished cleanup gains no additional gray output');
        assert.deepEqual(after, before, 'The new-chat cursor does not reorder or modify completed app windows');
      } else if (active) {
        assert.ok(researchOperationTime(b) > researchOperationTime(a), 'The shared operation clock advances during investigation');
        assert.ok(research.operations.some(op => op[0] === 'text' && op[10]?.stops), 'The operation interval has a visible shimmering status');
        if (start < 28) assert.notDeepEqual(after, before, 'An active gray interval visibly advances the app storyboard');
      } else {
        assert.equal(researchOperationTime(b), researchOperationTime(a), 'The shared operation clock stops for white replies and inter-message gaps');
        assert.deepEqual(after, before, 'Every app retains its exact visual state while Codex writes or waits');
      }
    }
  } finally { screens?.dispose(); recorder.restore(); }
});

test('resolution changes preserve research texture identity and phase, and release the old GPU source and pixels', () => {
  const recorder = recordingCanvases();
  try {
    const screens = createComputerScreens(), researchMap = screens.maps.research;
    const oldResearch = researchMap.image;
    let researchDisposals = 0;
    researchMap.addEventListener('dispose', () => researchDisposals++);
    researchMap.anisotropy = 16;
    screens.update(realTime(operationStory(10900)));
    assert.ok(oldResearch.getContext('2d').texts.includes('Decompiling FUN_140001590…'));
    assert.equal(screens.setResolution('research', 8192), true);
    assert.equal(screens.maps.research, researchMap);
    assert.deepEqual([researchMap.image.width, researchMap.image.height], [8192, 2304]);
    assert.equal(researchMap.anisotropy, 16);
    assert.equal(oldResearch.width, 0);
    assert.equal(researchDisposals, 1);
    assert.ok(researchMap.image.getContext('2d').texts.includes('Decompiling FUN_140001590…'), 'Re-rasterization continues the same analysis phase');
    const contexts = recorder.contexts.length;
    assert.equal(screens.setResolution('research', 8200), false, 'An unchanged rounded size is not recreated');
    for (const [name, width] of [['unknown', 4096], ['windows', 3840], ['research', NaN], ['research', Infinity], ['research', 0], ['research', 20000]]) assert.equal(screens.setResolution(name, width), false);
    assert.equal(recorder.contexts.length, contexts);
    screens.dispose(); screens.dispose();
    assert.equal(researchDisposals, 2);
    assert.equal(screens.update(90000), false); assert.equal(screens.setResolution('research', 5120), false);
    assert.ok(recorder.contexts.length > 0);
  } finally { recorder.restore(); }
});

test('paused desktop clock and RDP retain Japan time and the current phase through loop reset and zoom', () => {
  const recorder = recordingCanvases();
  const desktop = { width: 1529, height: 932 }, references = referenceImages();
  let screens;
  try {
    screens = createComputerScreens(null, references, { desktop });
    const research = screens.maps.research.image.getContext('2d');
    const otherCaches = recorder.contexts.filter(c => c !== research).map(c => [c, c.operations.length]);
    reset(research);
    assert.equal(screens.refreshDate(new Date('2032-12-31T14:59:01Z')), true);
    assert.ok(research.texts.includes('11:59 PM') && research.texts.includes('12/31/2032'));
    const version = screens.maps.research.version, operations = research.operations.length;
    assert.equal(screens.refreshDate(new Date('2032-12-31T14:59:01.999Z')), false);
    assert.equal(screens.maps.research.version, version); assert.equal(research.operations.length, operations);
    reset(research); assert.equal(screens.refreshDate(new Date('2032-12-31T14:59:02Z')), true);
    assert.ok(research.texts.includes('Fri Dec 31 23:59:02') && research.texts.includes('11:59 PM'), 'The desktop seconds advance while the RDP minute remains unchanged');
    reset(research);
    assert.equal(screens.refreshDate(new Date('2032-12-31T15:00:00Z')), true);
    assert.ok(research.texts.includes('12:00 AM') && research.texts.includes('1/1/2033'), 'The paused first frame must not retain yesterday’s date');
    for (const [cache, count] of otherCaches) assert.equal(cache.operations.length, count, 'Date changes do not rebuild unrelated Ghidra caches');
    const midnightFrame = [...research.operations];
    for (const time of [realTime(30000) - 1000 / 30, realTime(30000)]) {
      reset(research); assert.equal(screens.update(time), true);
      assert.deepEqual(research.operations, midnightFrame, 'Direct initial frames preserve the latest minute across the loop boundary');
    }
    assert.equal(screens.setResolution('research', 8192), true);
    const zoomed = screens.maps.research.image.getContext('2d');
    assert.ok(zoomed.texts.includes('12:00 AM') && zoomed.texts.includes('1/1/2033'), 'Zoom retains the latest wallclock date');
    const map = screens.maps.research, menu = map.image.getContext('2d');
    const hasHistoryMenu = context => context.blits.some(({ image, args }) => image === references['ref-caido-history-menu'] && [701, 247, 191, 463].every((value, i) => args[i] === value));
    reset(menu); assert.equal(screens.update(realTime(operationStory(55600))), true);
    assert.ok(hasHistoryMenu(menu) && menu.texts.includes('/api/messages/scene-01'), 'The next cycle can pause with the original History cleanup menu open');
    reset(menu); assert.equal(screens.refreshDate(new Date('2032-12-31T15:01:00Z')), true);
    assert.ok(menu.texts.includes('12:01 AM') && hasHistoryMenu(menu) && !menu.texts.includes('POST /scene/preview HTTP/1.1'), 'Minute refresh preserves the menu and the already-cleared Replay sessions');
    const heldText = [...menu.texts];
    assert.equal(screens.setResolution('research', 5120), true);
    assert.equal(screens.maps.research, map);
    assert.deepEqual(map.image.getContext('2d').texts, heldText, 'Zoom preserves every visible label and the current cleanup phase');
    assert.ok(hasHistoryMenu(map.image.getContext('2d')), 'Zoom also preserves the source screenshot crop for the open menu');
    assert.equal(screens.update(realTime(operationStory(55600))), false, 'Resolution changes do not rewind the animation clock');
    assert.equal(screens.refreshDate(new Date('invalid')), false);
  } finally { screens?.dispose(); recorder.restore(); }
});

test('photographed Dell desktop keeps native menubar icons, active app focus, and a stable Notes Dock origin', () => {
  const recorder = recordingCanvases(); let screens;
  try {
    const coast = { width: 5120, height: 1440 };
    const icons = { ...referenceImages(), ...Object.fromEntries(MAC_DOCK_ICON_KEYS.map(name => [name, { name, width: 512, height: 512 }])) };
    screens = createComputerScreens(coast, icons);
    const map = screens.maps.research, research = map.image.getContext('2d');
    const photo = recorder.contexts.flatMap(c => c.blits).find(({ image, args }) => image === coast && args[3] > 24);
    assert.ok(photo && photo.args[1] === 24 && photo.args[1] + photo.args[3] === 1340, 'The wallpaper excludes the recorded menubar and Dock');
    assert.ok(Math.abs(photo.args[2] / photo.args[3] - photo.args[6] / photo.args[7]) < 1e-12, 'The photograph is not stretched');
    const focus = () => research.operations.findLast(op => op[0] === 'text' && Math.abs(op[2] - 55 / 2.4) < 1e-9 && op[3] === 7.5)?.[1];
    assert.equal(focus(), 'Codex');
    const origin = { ...screens.dockOrigin };
    const dockFill = research.operations.findIndex(op => op[0] === 'fill' && op[1] === 'rgba(130,148,163,.30)');
    const [, dockX, dockY, dockWidth, dockHeight] = research.operations[dockFill - 1];
    for (const x of [202, 775]) {
      const frame = research.operations.find(op => op[0] === 'roundRect' && op[1] === x && op[3] === 558);
      assert.equal(dockY, frame[2] + frame[4], 'The Dock top aligns with both Ghidra and Codex bottom edges');
    }
    assert.equal(dockY + dockHeight, 598, 'Resizing retains the Dock bottom');
    assert.equal(dockX + dockWidth / 2, 1087.5, 'Resizing retains the Dock center');
    assert.ok(Math.abs(dockWidth / dockHeight - 1225 / 41) < 1e-12, 'The Dock keeps its original proportions');
    assert.ok(origin.x > .5 && origin.y > .9 && origin.w > 0 && origin.h > 0 && origin.x + origin.w < 1 && origin.y + origin.h < 1);
    for (const [time, name] of [[3900, 'Ghidra'], [11500, 'Microsoft Edge'], [17300, 'Caido'], [18300, 'Windows App'], [21870, 'Codex'], [23000, 'Ghidra'], [24500, 'Caido']]) {
      reset(research); assert.equal(screens.update(realTime(operationStory(time))), true); assert.equal(focus(), name);
    }
    const heldBlits = research.blits.filter(({ image }) => image.name?.startsWith('ref-')).map(({ image, args }) => [image.name, ...args]);
    const version = map.version;
    reset(research); assert.equal(screens.setMenuProgress(.01), true);
    assert.equal(focus(), 'Chrome'); assert.ok(map.version > version, 'Opening Notes redraws a paused desktop');
    assert.ok(!research.texts.includes('Notes') && research.blits.filter(({ image }) => image === icons.chrome).length === 1, 'The minimized Notes window disappears while its app icon remains');
    assert.deepEqual(research.blits.filter(({ image }) => image.name?.startsWith('ref-')).map(({ image, args }) => [image.name, ...args]), heldBlits, 'Notes focus does not advance the background app animation');
    assert.equal(screens.setMenuProgress(.01), false); assert.equal(screens.setMenuProgress(NaN), false);
    reset(research); assert.equal(screens.setMenuProgress(0), true); assert.equal(focus(), 'Caido');
    assert.ok(!research.texts.includes('Notes') && research.blits.filter(({ image }) => image === icons.chrome).length === 2, 'The restored thumbnail uses color blocks and an app badge without miniature text');
    reset(research); screens.refreshDate(new Date('2032-09-29T14:59:59Z'));
    assert.ok(research.blits.some(({ image, args }) => image === coast && args.slice(0, 4).join() === '0,0,5120,24'), 'Native menubar icons are copied intact');
    const datePatch = research.blits.find(({ image, args }) => image === coast && args[0] === 4957);
    assert.ok(datePatch && Math.abs(datePatch.args[4] * 2.4 - 4968) < 1e-8 && Math.abs((datePatch.args[4] + datePatch.args[6]) * 2.4 - 5120) < 1e-8, 'The replacement covers all recorded clock ink at native x4977..5100');
    const clock = research.operations.find(op => op[0] === 'text' && op[1] === 'Wed Sep 29 23:59:59');
    assert.ok(clock, 'The full Japan-time clock includes seconds');
    const width = clock[1].length * parseFloat(clock[4].split(' ')[1]) * .61;
    assert.ok(clock[2] - width >= 4972 / 2.4 && clock[2] <= 5116 / 2.4, 'Even a long clock string stays inside the replacement without touching Control Center');
    assert.equal(screens.setResolution('research', 8192), true); assert.deepEqual(screens.dockOrigin, origin);
    assert.equal(map.image.getContext('2d').blits.filter(({ image }) => image === icons.chrome).length, 2, 'Zoom retains the restored thumbnail');
    screens.dispose(); assert.equal(screens.setMenuProgress(1), false);
  } finally { screens?.dispose(); recorder.restore(); }
});
