import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { displayFrame, displayPose } from '../assets/js/device-focus.js';
import { screenViewPose, screenViewFov } from '../assets/js/screen-view.js';
import { quadTransform } from '../assets/js/navigation.js';
import { createIPadVideo, videoViewport } from '../assets/js/ipad-video.js';

test('the actual iPad projection preserves player corners on desktop and mobile', async t => {
  const bytes = await readFile(new URL('../assets/scene/workstation.glb', import.meta.url));
  const { scene } = await new GLTFLoader().parseAsync(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), '');
  t.after(() => scene.traverse(object => {
    if (!object.isMesh) return;
    object.geometry.dispose();
    for (const material of Array.isArray(object.material) ? object.material : [object.material]) material.dispose();
  }));
  let screen;
  scene.traverse(object => { if (object.userData.dynamic === 'ipad-screen') screen = object; });
  const frame = displayFrame(screen), right = new THREE.Vector3(1, 0, 0).applyQuaternion(frame.rotation);
  for (const [width, height] of [[1440, 900], [390, 844]]) {
    const camera = new THREE.PerspectiveCamera(screenViewFov(width / height), width / height, 1.15, 30);
    const normal = { ...screenViewPose(), fov: camera.fov };
    for (const pose of [normal, displayPose(frame, camera, height)]) {
      camera.position.copy(pose.position); camera.quaternion.copy(pose.rotation);
      camera.fov = pose.fov; camera.near = pose.near;
      camera.updateProjectionMatrix(); camera.updateMatrixWorld(true);
      const corners = [[-.5, .5], [.5, .5], [.5, -.5], [-.5, -.5]].map(([x, y]) => {
        const point = frame.center.clone().addScaledVector(right, x * frame.width)
          .addScaledVector(frame.up, y * frame.width * 9 / 16).project(camera);
        return { x: (point.x + 1) * width / 2, y: (1 - point.y) * height / 2 };
      });
      const size = videoViewport(corners);
      assert.ok(size, 'Default and focused iPad displays remain eligible at either viewport size');
      if (width === 390 && pose === normal) {
        assert.ok(Math.hypot(corners[0].x - corners[3].x, corners[0].y - corners[3].y) < 200,
          'The mobile overview covers a projected edge below 200 pixels');
      }
      const matrix = quadTransform(corners, size.width, size.height);
      assert.ok(matrix.every(Number.isFinite));
      [[0, 0], [size.width, 0], [size.width, size.height], [0, size.height]].forEach(([x, y], i) => {
        const w = matrix[3] * x + matrix[7] * y + 1;
        assert.ok(Math.hypot((matrix[0] * x + matrix[4] * y + matrix[12]) / w - corners[i].x,
          (matrix[1] * x + matrix[5] * y + matrix[13]) / w - corners[i].y) < 1e-7);
      });
    }
  }
});

test('player dimensions allow small projections and reject degenerate or non-finite edges', () => {
  const rect = (width, height) => [{ x: 0, y: 0 }, { x: width, y: 0 }, { x: width, y: height }, { x: 0, y: height }];
  for (const [width, height] of [[1, 1], [120, 70], [199.99, 300], [200, 200]]) {
    assert.deepEqual(videoViewport(rect(width, height)), { width: 356, height: 201 });
  }
  assert.deepEqual(videoViewport(rect(400, 199.99)), { width: 400, height: 225 });
  for (const [width, height] of [[0, 300], [400, 0], [NaN, 300], [400, Infinity]]) {
    assert.equal(videoViewport(rect(width, height)), null);
  }
});

test('iPad keeps looping out of view while preserving manual controls and reduced motion', t => {
  const keys = ['window', 'document', 'location'];
  const previous = Object.fromEntries(keys.map(key => [key, globalThis[key]]));
  const players = [], scripts = [], controls = [];
  globalThis.location = { origin: 'https://example.test' };
  globalThis.document = {
    hidden: false,
    createElement() { return { remove() { this.removed = true; } }; },
    head: { append(script) { scripts.push(script); } },
  };
  globalThis.window = { YT: { Player: class {
    constructor(iframe, { events }) { this.events = events; this.calls = []; this.captionOptions = []; this.captionChanges = []; players.push(this); }
    getOptions() { return this.captionOptions; }
    setOption(...args) { this.captionChanges.push(args); }
    mute() { this.calls.push('mute'); }
    playVideo() { assert.ok(!this.destroyed); this.calls.push('play'); }
    loadVideoById(clip) { assert.ok(!this.destroyed); this.calls.push({ load: { ...clip } }); }
    pauseVideo() { assert.ok(!this.destroyed); this.calls.push('pause'); }
    destroy() { assert.ok(!this.destroyed); this.destroyed = true; }
    emit(data) { this.events.onStateChange({ data, target: this }); }
  } } };
  t.after(() => {
    controls.forEach(control => control.dispose());
    for (const key of keys) {
      if (previous[key] === undefined) delete globalThis[key]; else globalThis[key] = previous[key];
    }
  });
  const create = autoplay => {
    const iframe = { hidden: false, src: '', getAttribute() { return this.src; }, removeAttribute() { this.src = ''; } };
    const control = createIPadVideo(iframe); controls.push(control);
    control.setPlaying(autoplay);
    const player = players.at(-1);
    if (window.YT) player.events.onReady({ target: player });
    return { control, iframe, player };
  };

  const normal = create(true);
  assert.deepEqual(normal.player.calls, ['mute', 'play']);
  const captionsChanged = player => player.events.onApiChange({ target: player });
  captionsChanged(normal.player);
  assert.equal(normal.player.captionChanges.length, 0, 'Missing caption capability leaves playback alone');
  normal.player.captionOptions = ['track'];
  captionsChanged(normal.player); captionsChanged(normal.player);
  assert.deepEqual(normal.player.captionChanges, [['captions', 'track', {}]], 'Captions are initialized once when available');
  normal.player.emit(1); normal.player.emit(2);
  captionsChanged(normal.player);
  assert.equal(normal.player.captionChanges.length, 1, 'Later caption changes preserve the user choice');
  document.hidden = normal.iframe.hidden = true; normal.control.setPlaying(true);
  document.hidden = normal.iframe.hidden = false; normal.control.setPlaying(true);
  assert.equal(normal.player.calls.filter(call => call === 'play').length, 1, 'User pause survives tab and viewport changes');

  const looping = create(true);
  looping.player.captionOptions = ['track']; captionsChanged(looping.player);
  const clip = { videoId: '7A5YWn33eps', startSeconds: 0, endSeconds: 31 };
  for (let repeat = 0; repeat < 3; repeat++) {
    document.hidden = looping.iframe.hidden = repeat !== 0;
    looping.control.setPlaying(true);
    looping.player.emit(1); looping.player.emit(0);
    assert.deepEqual(looping.player.calls.at(-1), { load: clip }, 'Every repeat reapplies the clip boundary, even offscreen or in another tab');
    assert.equal(looping.player.calls.filter(call => call.load).length, repeat + 1);
    looping.player.emit(-1); looping.player.emit(0);
    assert.equal(looping.player.calls.filter(call => call.load).length, repeat + 1, 'A duplicate end while loading cannot start another reload');
    captionsChanged(looping.player);
    assert.equal(looping.player.captionChanges.length, 1, 'Looping does not reset a manual caption choice');
  }
  document.hidden = looping.iframe.hidden = false;
  looping.control.setPlaying(true);
  assert.ok(!looping.player.calls.includes('pause'), 'Visibility changes never issue a pause command');
  looping.player.emit(1);
  const commands = looping.player.calls.length;
  looping.player.emit(2);
  looping.control.setPlaying(true);
  assert.equal(looping.player.calls.length, commands, 'A manual pause is not overridden');
  looping.control.dispose(); looping.player.emit(0);
  assert.equal(looping.player.calls.length, commands, 'A late end cannot restart a disposed player');

  const reduced = create(false);
  assert.ok(!reduced.player.calls.includes('play'), 'Reduced motion disables autoplay');
  reduced.player.emit(3); reduced.player.emit(1);
  reduced.player.captionOptions = ['track']; captionsChanged(reduced.player);
  assert.equal(reduced.player.captionChanges.length, 0, 'First enabling captions after playback starts remains a user choice');
  reduced.control.setPlaying(false);
  const pauses = reduced.player.calls.filter(call => call === 'pause').length;
  for (const hidden of [true, false]) {
    document.hidden = reduced.iframe.hidden = hidden;
    reduced.control.setPlaying(false);
    reduced.player.emit(0);
    assert.deepEqual(reduced.player.calls.at(-1), { load: clip }, 'Explicit manual playback keeps looping regardless of visibility');
    reduced.player.emit(1);
  }
  assert.equal(reduced.player.calls.filter(call => call === 'pause').length, pauses);

  const pending = create(true);
  pending.control.setPlaying(false);
  pending.player.emit(1);
  assert.equal(pending.player.calls.at(-1), 'pause', 'A late autoplay event cannot override reduced motion');
  pending.player.emit(2);
  pending.player.emit(1);
  pending.control.dispose(); pending.player.emit(1);
  pending.player.events.onReady({ target: pending.player });
  pending.control.setPlaying(true);
  assert.ok(pending.player.destroyed);
  assert.equal(pending.iframe.src, '');

  delete window.YT;
  const fallback = create(false), script = scripts.at(-1), lateMount = window.onYouTubeIframeAPIReady;
  script.onerror();
  assert.ok(fallback.iframe.src.startsWith('https://www.youtube-nocookie.com/embed/'));
  const fallbackSource = fallback.iframe.src;
  document.hidden = fallback.iframe.hidden = true;
  fallback.control.setPlaying(false);
  assert.equal(fallback.iframe.src, fallbackSource, 'The fallback player is not unloaded when hidden');
  fallback.control.dispose(); lateMount(); script.onerror();
  assert.equal(fallback.iframe.src, '');
  assert.ok(script.removed);
  assert.equal(window.onYouTubeIframeAPIReady, undefined);
});
