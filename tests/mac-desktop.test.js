import test from 'node:test';
import assert from 'node:assert/strict';
import { createMacDesktop } from '../assets/js/mac-desktop.js';

test('the native Mac screenshot keeps Japan dates, low-rate usage and the reversible Notes slide at every resolution', () => {
  const previousDocument = globalThis.document, canvases = [];
  globalThis.document = { createElement(name) {
    assert.equal(name, 'canvas');
    const canvas = { width: 0, height: 0 };
    const ctx = new Proxy({
      texts: [], blits: [],
      fillText(value, ...position) { this.texts.push({ value, position }); },
      drawImage(...args) { this.blits.push(args); },
    }, { get: (target, key) => key in target ? target[key] : () => {} });
    canvas.getContext = () => ctx; canvases.push(canvas); return canvas;
  } };
  let desktop;
  try {
    const source = { width: 3600, height: 2338 };
    const sprites = { width: 1536, height: 1872 };
    desktop = createMacDesktop(source, sprites);
    const map = desktop.map, output = map.image.getContext('2d'), art = canvases[1].getContext('2d');
    const lastDesktop = () => output.blits.filter(args => args[0] === canvases[1]).at(-1);
    const lastPet = () => output.blits.filter(args => args[0] === sprites).at(-1);
    assert.deepEqual([map.image.width, map.image.height], [3840, 2494]);
    assert.equal(canvases.length, 2, 'The clean screenshot needs no water restoration canvas');
    assert.deepEqual(art.blits[0], [source, 0, 0, 3600, 2338], 'The sanitized screenshot is drawn directly at its native aspect');
    assert.ok(art.blits.every(args => args[0] === source), 'Only the screenshot supplies desktop pixels');
    const date = new Date('2026-09-11T14:59:59Z');
    assert.equal(desktop.refreshDate(date), true);
    const values = () => art.texts.map(item => item.value);
    assert.ok(values().includes('Fri Sep 11  23:59:59'));
    assert.ok(values().includes('FRIDAY, SEP 11'));
    assert.ok(art.texts.every(item => item.position[1] <= 166 || item.position[1] >= 1038), 'No event or weather-location text is added');
    assert.deepEqual(art.texts.filter(item => item.position[1] === 1038).slice(-6).map(item => item.value), ['23', '0', '1', '2', '3', '4']);
    assert.equal(desktop.refreshDate(new Date(date.getTime() + 900)), false, 'Multiple calls within the same Japan second do not repaint');
    art.texts.length = 0;
    assert.equal(desktop.refreshDate(new Date('2026-09-11T15:00:00Z')), true);
    assert.ok(values().includes('Sat Sep 12  00:00:00') && values().includes('SATURDAY, SEP 12'));
    assert.deepEqual(art.texts.filter(item => item.position[1] >= 1220).map(item => item.value), ['Sun', 'Mon', 'Tue', 'Wed', 'Thu']);
    art.texts.length = 0;
    desktop.refreshDate(new Date('2026-12-31T15:00:00Z'));
    assert.ok(values().includes('Fri Jan 1  00:00:00') && values().includes('FRIDAY, JAN 1'));
    assert.ok(values().some(value => value.includes('Jan 7 at 0:00')), 'Weekly reset dates also cross the year in Japan time');
    assert.equal(desktop.refreshDate(new Date(NaN)), false);

    const version = map.version;
    for (const elapsed of [0, 16, 999, NaN, -1]) assert.equal(desktop.update(elapsed), false);
    assert.equal(desktop.update(1000), true);
    assert.equal(map.version, version + 1);
    assert.equal(desktop.update(1001), false); assert.equal(desktop.update(900), false);
    assert.ok(values().some(value => value.endsWith('12:48')), 'The decorative countdown advances once per second');
    const textCount = art.texts.length;
    assert.equal(desktop.update(1680), true);
    assert.deepEqual(lastPet().slice(1,5), [192,0,192,208], 'The pet advances to the official blink frame');
    assert.equal(art.texts.length, textCount, 'Changing only the pet frame reuses the cached desktop');

    const body = () => output.blits.filter(args => args.length === 9 && args[4] > map.image.height / 2).at(-1);
    art.texts.length = 0;
    desktop.setMenuProgress(.12); assert.equal(values().includes('Chrome'), false);
    desktop.setMenuProgress(.13); assert.ok(values().includes('Chrome'));
    desktop.setMenuProgress(.35);
    assert.deepEqual(lastDesktop(), [canvases[1], 0, 0], 'Desktop stays at its origin during the initial browser launch');
    desktop.setMenuProgress(.55);
    assert.ok(Math.abs(body()[5] + map.image.width / 2) < 1e-8, 'The desktop is halfway left at the center of the slide');
    assert.ok(Math.abs(lastPet()[5]-1436) < 1e-8, 'The pet follows the same leftward desktop slide');
    desktop.setMenuProgress(.75); assert.equal(body()[5], -map.image.width);
    desktop.setMenuProgress(1); assert.equal(body()[5], -map.image.width, 'Viewport handoff keeps the desktop fully left');
    desktop.setMenuProgress(.55);
    let disposals = 0; map.addEventListener('dispose', () => disposals++);
    assert.equal(desktop.setResolution(4608), true);
    assert.equal(desktop.map, map); assert.equal(disposals, 1, 'Resizing releases the GPU storage while retaining the texture reference');
    assert.ok(Math.abs(body()[5] + 2304) < 1e-8, 'A resolution change retains the slide position');
    assert.equal(desktop.setResolution(4608), false);
    assert.equal(desktop.update(1999), false, 'Resizing preserves elapsed animation time');
    desktop.setMenuProgress(0);
    assert.deepEqual(lastDesktop(), [canvases[1], 0, 0]);
    assert.equal(desktop.setMenuProgress(0), false); assert.equal(desktop.setMenuProgress(NaN), false);
    for (const [time,frame] of [[2340,2],[3000,3],[3840,4],[4680,5],[6600,0],[19800,24],[19940,25],[20080,26],[20220,27],[20500,24],[21900,0]]) {
      desktop.update(time);
      assert.deepEqual(lastPet().slice(1,5), [(frame%8)*192,Math.floor(frame/8)*208,192,208]);
    }
    const paused = lastPet(); desktop.refreshDate(new Date('2027-01-02T00:00:00Z'));
    assert.deepEqual(lastPet(),paused,'Updating a wall clock does not advance a paused pet');
    desktop.dispose(); desktop.dispose(); assert.equal(disposals, 2);
    assert.equal(desktop.update(2000), false); assert.equal(desktop.refreshDate(new Date()), false);
    assert.equal(desktop.setMenuProgress(1), false); assert.equal(desktop.setResolution(3840), false);
  } finally {
    desktop?.dispose();
    if (previousDocument === undefined) delete globalThis.document; else globalThis.document = previousDocument;
  }
});
