import test from 'node:test';
import assert from 'node:assert/strict';
import { createScreens } from '../assets/js/screens.js?v=test-build';

test('screen coordination preserves native desktops, Notes transitions, paused clocks and texture lifetimes', async () => {
  const previous = { document: globalThis.document, Image: globalThis.Image };
  const contexts = [], images = [], sizes = {
    'mac-desktop.png': [3600, 2338], 'dell-desktop.png': [5120, 1440],
    'rdp-desktop.webp': [1529, 932], 'rdp-calculator.png': [322, 533],
    'codex-empty.png': [1455, 1427], 'codex-working.png': [1379, 1381], 'codex-completed.png': [899, 526],
    'edge.png': [1331, 1044], 'ghidra.png': [1542, 1110], 'ghidra-function.png': [634, 378], 'ghidra-variable.png': [476, 242],
    ...Object.fromEntries(['history', 'replay', 'history-menu', 'history-dialog', 'replay-menu', 'replay-dialog'].map(name => [`caido-${name}.png`, [1912, 1242]])),
  };
  let draws = 0;
  const check = (...args) => { for (const value of args) if (typeof value === 'number') assert.ok(Number.isFinite(value), 'Invalid drawing coordinate'); draws++; };
  globalThis.Image = class {
    constructor() { images.push(this); }
    set src(value) {
      this.url = value;
      const filename = new URL(value).pathname.split('/').at(-1), reference = value.includes('/app-reference/');
      [this.width, this.height] = reference || filename.endsWith('.webp') || filename === 'rdp-calculator.png' ? sizes[filename] || [512, 512] : [512, 512];
      this.naturalWidth = this.width; this.naturalHeight = this.height;
    }
    get src() { return this.url; }
    async decode() {}
    removeAttribute(name) { if (name === 'src') this.url = undefined; }
  };
  globalThis.document = {
    createElement(name) {
      if (name === 'video') return new class extends EventTarget {
        videoWidth = 1918; videoHeight = 1078; readyState = 2; paused = true;
        load() {}
        async play() { this.paused = false; }
        pause() { this.paused = true; }
        removeAttribute(key) { delete this[key]; }
      }();
      assert.equal(name, 'canvas');
      const element = { width: 0, height: 0 };
      const stack = [], state = {
        canvas: element, blits: [], texts: [], fills: [], globalAlpha: 1, globalCompositeOperation: 'source-over', font: '14px sans-serif',
        fillRect(...args) { check(...args); this.fills.push([this.fillStyle, ...args]); },
        save() { stack.push(Object.fromEntries(['globalAlpha', 'globalCompositeOperation', 'font', 'fillStyle', 'textAlign'].map(key => [key, this[key]]))); },
        restore() { Object.assign(this, stack.pop()); },
        getTransform: () => ({ a: 1, d: 1, e: 0, f: 0 }),
        measureText: value => ({ width: value.length * 8, actualBoundingBoxAscent: 11, actualBoundingBoxDescent: 2 }),
        fillText(value, ...args) { check(...args); this.texts.push(value); },
        drawImage(...args) { check(...args); this.blits.push({ image: args[0], alpha: this.globalAlpha, args }); },
      };
      const ctx = new Proxy(state, {
        get(target, key) {
          if (key in target) return target[key];
          if (key === 'createLinearGradient' || key === 'createRadialGradient') return (...args) => { check(...args); return { addColorStop: check }; };
          return check;
        },
      });
      contexts.push(ctx); element.getContext = () => ctx; return element;
    },
  };
  let screens;
  try {
    screens = await createScreens();
    assert.ok(draws > 0);
    const versions = Object.fromEntries(Object.entries(screens.maps).map(([key, map]) => [key, map.version]));
    for (const name of ['mac', 'screen']) assert.ok(screens.maps[name].isCanvasTexture && screens.maps[name].image.width >= 1024);
    assert.ok(screens.maps.windows.isVideoTexture);
    assert.deepEqual([screens.maps.windows.image.videoWidth, screens.maps.windows.image.videoHeight], [1918, 1078]);
    assert.deepEqual([screens.maps.mac.image.width, screens.maps.mac.image.height], [3840, 2494]);
    assert.equal(screens.maps.youtube.image.width / screens.maps.youtube.image.height, 4 / 3);
    assert.deepEqual(screens.maps.youtube.image.getContext('2d').fills, [['#000', 0, 0, 4, 3]], 'The iPad has only an opaque black screen');
    assert.ok(images.every(image => !image.src.includes('tablet-')), 'Retired iPad images are not requested');
    assert.deepEqual([screens.maps.screen.image.width, screens.maps.screen.image.height], [5120, 1440]);
    assert.equal(screens.update(0), false);
    assert.equal(screens.update(16), false);
    for (let i = 1; i <= 30; i++) assert.equal(screens.update(i * 1000 / 30), true);
    for (const [key, map] of Object.entries(screens.maps)) assert.equal(map.version - versions[key], key === 'windows' || key === 'youtube' ? 0 : key === 'mac' ? 1 : 30, `${key} must respect its static, one-second, decoded-video or 30fps update contract`);
    assert.equal(screens.update(10), false);
    assert.equal(screens.update(NaN), false);
    assert.equal(await screens.setPlaying(true), true);
    assert.equal(await screens.setPlaying(false), false);
    const research = screens.maps.screen.image;
    assert.deepEqual([research.width, research.height], [5120, 1440], 'Research desktop is composited without stretching');
    assert.ok(images.every(image => new URL(image.src).search === '?v=test-build'), 'Every screen image inherits the build version instead of reusing an older screenshot URL');
    const desktopReferences = ['mac-desktop.png', 'dell-desktop.png'].map(filename => images.find(image => new URL(image.src).pathname.endsWith(`/app-reference/${filename}`)));
    for (const image of desktopReferences) {
      assert.ok(image && contexts.some(ctx => ctx.blits.some(blit => blit.image === image)), 'Both supplied desktop screenshots are loaded and drawn at their own native dimensions');
    }
    const { x, y, w, h } = screens.dockOrigin;
    assert.ok([x, y, w, h].every(Number.isFinite) && x >= 0 && y >= 0 && w > 0 && h > 0 && x + w <= 1 && y + h <= 1, 'The Chrome restore origin is a usable normalized rectangle inside Dell');
    const versionsBeforeMenu = Object.fromEntries(Object.entries(screens.maps).map(([key, map]) => [key, map.version]));
    const mac = screens.maps.mac.image.getContext('2d');
    const slideBlit = ctx => ctx.blits.find(({ image, args }) => image.getContext && image.width === ctx.canvas.width && image.height === ctx.canvas.height && (args.length === 3 || args[8] > ctx.canvas.height * .8));
    for (const progress of [.5, 1, 0]) {
      mac.blits = [];
      screens.setMenuProgress(progress);
      if (progress < 1) {
        const blit = slideBlit(mac);
        assert.ok(blit, 'The complete Mac desktop remains the moving surface');
        const destinationX = blit.args.length === 9 ? blit.args[5] : blit.args[1];
        assert.ok(progress ? destinationX < 0 : destinationX === 0, 'Opening Notes slides the desktop left and closing restores its origin');
        assert.equal(blit.alpha, 1, 'The desktop slides without an opacity fade');
      }
      assert.equal(mac.globalAlpha, 1);
    }
    assert.equal(screens.maps.mac.version - versionsBeforeMenu.mac, 3);
    assert.equal(screens.maps.screen.version - versionsBeforeMenu.screen, 3, 'Notes also restores Chrome from the Dell Dock while playback is paused');
    for (const key of ['windows', 'youtube']) assert.equal(screens.maps[key].version, versionsBeforeMenu[key], `${key} stays paused during the Notes transition`);
    assert.equal(screens.maps.screen.image, research, 'The Chrome restore does not resize or replace Dell');
    screens.setMenuProgress(0); screens.setMenuProgress(NaN); screens.setMenuProgress(Infinity);
    for (const key of ['mac', 'screen']) assert.equal(screens.maps[key].version - versionsBeforeMenu[key], 3, 'Unchanged or invalid transitions do not repaint either desktop');
    screens.setMenuProgress(.5);
    const pausedVersions = () => Object.fromEntries(Object.entries(screens.maps).map(([key, map]) => [key, map.version]));
    for (const date of [new Date('2032-12-31T14:59:59.100Z'), new Date('2032-12-31T15:00:00.100Z'), new Date('2032-12-31T15:00:01.100Z')]) {
      const before = pausedVersions();
      assert.equal(screens.refreshDate(date), true, 'Wallclock updates continue while animation time is paused');
      for (const key of ['mac', 'screen']) assert.equal(screens.maps[key].version, before[key] + 1, `${key} receives each new JST second, including midnight`);
      for (const key of ['windows', 'youtube']) assert.equal(screens.maps[key].version, before[key], 'Date refresh does not advance the video or redraw the blank tablet');
      const after = pausedVersions();
      assert.equal(screens.refreshDate(new Date(date.getTime() + 700)), false, 'Refreshing within the same second is a no-op');
      assert.deepEqual(pausedVersions(), after);
    }
    const dated = pausedVersions();
    for (const value of [new Date('invalid'), null, NaN]) assert.equal(screens.refreshDate(value), false);
    assert.deepEqual(pausedVersions(), dated, 'Invalid dates do not redraw or erase the current clocks');
    const identity = { ...screens.maps };
    assert.equal(screens.setResolution('windows', 3840), false, 'Zoom never resamples the recorded video');
    assert.equal(screens.maps.windows, identity.windows);
    assert.equal(screens.setResolution('youtube', 3072), false, 'A blank tablet does not allocate a larger texture on zoom');
    assert.equal(screens.maps.youtube, identity.youtube);
    for (const [name, width] of [['mac', 4608], ['screen', 6144]]) {
      screens.maps[name].image.getContext('2d').blits = [];
      assert.equal(screens.setResolution(name, width), true);
      assert.equal(screens.maps[name], identity[name], 'Re-rasterizing preserves the material map reference');
      assert.equal(screens.maps[name].image.width, width);
      assert.equal(screens.setResolution(name, width), false, 'Settled zoom must not allocate repeatedly');
    }
    for (const [name, width] of [['unknown', 4096], ['mac', NaN], ['screen', Infinity], ['youtube', 0]]) assert.equal(screens.setResolution(name, width), false);
    const resizedMac = screens.maps.mac.image.getContext('2d'), resizedSlide = slideBlit(resizedMac);
    assert.ok(resizedSlide && (resizedSlide.args.length === 9 ? resizedSlide.args[5] : resizedSlide.args[1]) < 0, 'Zoom retains an in-progress desktop slide');
    screens.setMenuProgress(0);
    assert.ok(screens.update(1500), 'Animation keeps its monotonic clock after resolution changes');
    let disposed = 0;
    for (const map of Object.values(screens.maps)) map.addEventListener('dispose', () => disposed++);
    screens.dispose(); screens.dispose(); assert.equal(disposed, 4);
    assert.equal(screens.update(2000), false);
    assert.equal(screens.refreshDate(new Date()), false);
    assert.equal(screens.setResolution('mac', 5120), false);
    assert.equal(await screens.setPlaying(true), false);
    const disposedMacVersion = screens.maps.mac.version;
    screens.setMenuProgress(1); assert.equal(screens.maps.mac.version, disposedMacVersion);
    assert.ok(desktopReferences.every(image => image.src === undefined), 'Desktop screenshot references are released on disposal');
  } finally {
    screens?.dispose();
    for (const key of ['document', 'Image']) { if (previous[key] === undefined) delete globalThis[key]; else globalThis[key] = previous[key]; }
  }
});
