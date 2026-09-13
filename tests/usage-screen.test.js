import test from 'node:test';
import assert from 'node:assert/strict';
import { createUsageScreen } from '../assets/js/usage-screen.js';

test('split Usage artwork preserves its aspect, fixed values and paused-clock contract', () => {
  const previousDocument = globalThis.document;
  const canvases = [], labels = [], translations = [], scales = [], draws = [];
  globalThis.document = { createElement(name) {
    assert.equal(name, 'canvas');
    const element = { width: 0, height: 0 };
    const methods = ['fillRect', 'beginPath', 'roundRect', 'fill', 'stroke', 'moveTo', 'lineTo', 'closePath', 'arc', 'save', 'restore', 'clip', 'ellipse'];
    const ctx = Object.fromEntries(methods.map(method => [method, () => {}]));
    ctx.fillText = (value, x, y) => { assert.ok(Number.isFinite(x) && Number.isFinite(y)); labels.push(value); };
    ctx.measureText = value => ({ width: value.length * 7 });
    ctx.translate = (x, y) => translations.push([x, y]);
    ctx.scale = (x, y) => scales.push([x, y]);
    ctx.drawImage = (...args) => draws.push(args);
    element.getContext = () => ctx; canvases.push(element); return element;
  } };
  let screen;
  try {
    screen = createUsageScreen();
    assert.ok(screen.map.isCanvasTexture);
    assert.deepEqual([screen.map.image.width, screen.map.image.height], [1536, 998]);
    assert.ok(Math.abs(screen.map.image.width / screen.map.image.height - 3024 / 1964) < .001);
    assert.equal(screen.map.colorSpace, 'srgb');
    for (const label of ['ChatGPT', 'Claude', 'Usage', 'Weekly limit', '76% left', 'Usage limit resets', 'Credits', 'Current session', '30% used', 'All models', '32% used', 'Fable', '0% used']) assert.ok(labels.includes(label), `Missing reference content: ${label}`);
    assert.ok(scales.every(([x, y]) => x === y), 'Artwork must not squash type or icons horizontally');
    const labelCount = labels.length;
    assert.equal(screen.update(0), false);
    assert.equal(screen.update(16), false);
    assert.equal(screen.update(34), true);
    const version = screen.map.version;
    assert.equal(screen.update(34), false, 'A stopped elapsed clock freezes the screen');
    assert.equal(screen.map.version, version);
    assert.equal(screen.update(10), false);
    assert.equal(screen.update(NaN), false);
    assert.equal(screen.update(-1), false);
    screen.update(37999); const beforeLoop = translations.at(-1);
    screen.update(38001); assert.deepEqual(translations.at(-1), beforeLoop, 'Cursor loop must not jump');
    assert.equal(labels.length, labelCount, 'Usage values must stay fixed in cached artwork');
    assert.ok(draws.every(args => args.length === 3 && args[1] === 0 && args[2] === 0), 'Background is copied at its native resolution');
    let disposals = 0; screen.map.addEventListener('dispose', () => disposals++);
    screen.dispose(); screen.dispose();
    assert.equal(disposals, 1);
    assert.ok(canvases.every(canvas => canvas.width === 1 && canvas.height === 1));
    assert.equal(screen.update(40000), false);
  } finally {
    screen?.dispose();
    if (previousDocument === undefined) delete globalThis.document; else globalThis.document = previousDocument;
  }
});
