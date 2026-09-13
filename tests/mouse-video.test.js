import test from 'node:test';
import assert from 'node:assert/strict';
import { MeshBasicMaterial, ShaderLib, SRGBColorSpace, VideoTexture } from 'three';
import { createMouseVideo } from '../assets/js/mouse-video.js';

function mediaDocument(t, loadError = false) {
  const previous = globalThis.document, texts = [], canvases = [];
  class Video extends EventTarget {
    readyState = 0; paused = true; calls = []; callbacks = new Map(); nextId = 0; pauses = 0;
    load() {
      if (this.src) queueMicrotask(() => {
        if (loadError) this.dispatchEvent(new Event('error'));
        else { this.readyState = 2; this.dispatchEvent(new Event('loadeddata')); }
      });
    }
    pause() { this.paused = true; this.pauses++; }
    play() {
      return new Promise((resolve, reject) => this.calls.push({
        resolve: () => { this.paused = false; resolve(); }, reject,
      }));
    }
    removeAttribute(name) { if (name === 'src') this.src = ''; }
    requestVideoFrameCallback(callback) { const id = ++this.nextId; this.callbacks.set(id, callback); return id; }
    cancelVideoFrameCallback(id) { this.callbacks.delete(id); }
  }
  const video = new Video();
  globalThis.document = { createElement(name) {
    if (name === 'video') return video;
    assert.equal(name, 'canvas');
    const ctx = { setTransform() {}, fillRect() {}, fillText(value, x, y) { texts.push({ value, x, y, color: this.fillStyle }); } };
    const canvas = { width: 0, height: 0, getContext: () => ctx }; canvases.push(canvas); return canvas;
  } };
  t.after(() => { if (previous === undefined) delete globalThis.document; else globalThis.document = previous; });
  return { video, texts, canvases };
}

test('Mouse preserves the native video and updates only its JST clock patch', async t => {
  const { video, texts, canvases } = mediaDocument(t);
  const screen = await createMouseVideo(); t.after(() => screen.dispose());
  assert.ok(screen.map instanceof VideoTexture && screen.map.image === video);
  assert.equal(screen.map.generateMipmaps, false);
  assert.equal(screen.map.colorSpace, SRGBColorSpace);
  assert.equal(screen.map.flipY, false);
  assert.ok(video.loop && video.muted && video.playsInline && !video.autoplay);
  assert.equal(video.calls.length, 0, 'Loading the first frame must not start playback');
  assert.deepEqual(canvases.map(canvas => [canvas.width, canvas.height]), [[296, 144]], 'Only the small date region has a canvas');
  assert.ok(video.src.endsWith('/scene/mouse-desktop.mp4'));

  const material = new MeshBasicMaterial(), originalCompile = material.onBeforeCompile;
  assert.equal(screen.configureMaterial(material), true);
  const hook = material.onBeforeCompile;
  screen.configureMaterial(material);
  assert.ok(material.onBeforeCompile === hook, 'Configuring a material twice does not stack overlays');
  const shader = { uniforms: {}, fragmentShader: ShaderLib.basic.fragmentShader };
  material.onBeforeCompile(shader);
  const patch = shader.uniforms.mouseDateMap.value;
  assert.equal(patch.colorSpace, SRGBColorSpace); assert.equal(patch.flipY, false);
  assert.ok(shader.fragmentShader.indexOf('#include <map_fragment>') < shader.fragmentShader.indexOf('vec2 dateUv'), 'The native video decode runs before the date overlay');
  assert.equal(shader.fragmentShader.match(/#include <map_fragment>/g).length, 1);
  assert.ok(!shader.fragmentShader.includes('sRGBTransferEOTF('), 'The patch must not decode an already-linear canvas a second time');
  assert.deepEqual(shader.uniforms.mouseDateRect.value.toArray(), [1810 / 1918, 1038 / 1078, 74 / 1918, 36 / 1078]);
  assert.deepEqual(shader.uniforms.mouseEdgeMask.value.toArray(), [1910 / 1918, 0, 8 / 1918, 18 / 1078]);
  assert.equal(screen.refreshDate(new Date('2032-12-31T14:59:01Z')), true);
  assert.deepEqual(texts.slice(-2).map(text => text.value), ['11:59 PM', '12/31/2032']);
  const version = patch.version, count = texts.length;
  assert.equal(screen.refreshDate(new Date('2032-12-31T14:59:59Z')), false);
  assert.equal(patch.version, version); assert.equal(texts.length, count);
  assert.equal(screen.refreshDate(new Date('2032-12-31T15:00:00Z')), true);
  assert.deepEqual(texts.slice(-2).map(text => text.value), ['12:00 AM', '1/1/2033']);
  assert.equal(screen.refreshDate(new Date('invalid')), false);
  let textureDisposals = 0;
  for (const map of [screen.map, patch]) map.addEventListener('dispose', () => textureDisposals++);
  screen.dispose(); screen.dispose();
  assert.equal(textureDisposals, 2); assert.equal(video.callbacks.size, 0); assert.equal(video.src, '');
  assert.deepEqual(canvases.map(canvas => [canvas.width, canvas.height]), [[1, 1]]);
  assert.ok(material.onBeforeCompile === originalCompile); assert.equal(material.map, null);
  assert.equal(screen.refreshDate(new Date()), false); assert.equal(await screen.setPlaying(true), false);
  material.dispose();
});

test('latest playback intent wins across pending play, pause, restart and disposal', async t => {
  const { video } = mediaDocument(t), screen = await createMouseVideo(); t.after(() => screen.dispose());
  const first = screen.setPlaying(true);
  assert.ok(first === screen.setPlaying(true), 'Repeated play requests share their pending attempt');
  assert.equal(await screen.setPlaying(false), false);
  const resumed = screen.setPlaying(true);
  video.calls[0].resolve(); assert.equal(await first, false);
  video.calls[1].resolve(); assert.equal(await resumed, true); assert.equal(video.paused, false);
  assert.equal(await screen.setPlaying(false), false);
  const stopped = screen.setPlaying(true);
  await screen.setPlaying(false); video.calls[2].resolve();
  assert.equal(await stopped, false); assert.equal(video.paused, true, 'A late play resolution cannot undo pause');
  const removed = screen.setPlaying(true);
  screen.dispose(); video.calls[3].resolve();
  assert.equal(await removed, false); assert.equal(video.paused, true); assert.equal(video.callbacks.size, 0);
});

test('load errors release the video without allocating a texture or date canvas', async t => {
  const fixture = mediaDocument(t, true);
  await assert.rejects(createMouseVideo(), /could not be loaded/);
  assert.equal(fixture.video.src, ''); assert.equal(fixture.video.paused, true); assert.equal(fixture.canvases.length, 0);
});

test('playback denial can be retried and a media error stops further playback', async t => {
  const { video } = mediaDocument(t), screen = await createMouseVideo(); t.after(() => screen.dispose());
  const denied = screen.setPlaying(true); video.calls[0].reject(new Error('Playback denied'));
  assert.equal(await denied, false);
  const retry = screen.setPlaying(true); video.calls[1].resolve(); assert.equal(await retry, true);
  video.dispatchEvent(new Event('error'));
  assert.equal(video.paused, true); assert.equal(await screen.setPlaying(true), false);
});
