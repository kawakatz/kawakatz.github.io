import test from 'node:test';
import assert from 'node:assert/strict';
import * as THREE from 'three';
import { createRoomRenderer } from '../assets/js/room-renderer.js';

function fixture(t, configure = () => {}) {
  const scene = new THREE.Scene(), camera = new THREE.PerspectiveCamera();
  const screen = new THREE.Mesh(new THREE.PlaneGeometry(), new THREE.MeshBasicMaterial());
  const room = new THREE.Mesh(new THREE.BoxGeometry(), new THREE.MeshBasicMaterial());
  const glass = new THREE.Mesh(new THREE.PlaneGeometry(), new THREE.MeshBasicMaterial({ transparent: true, depthWrite: false }));
  const light = new THREE.HemisphereLight();
  scene.add(room, screen, glass, light);
  const state = { target: null, scissor: false, size: [200, 200], viewport: [0, 0, 100, 100], attributes: { preserveDrawingBuffer: true, stencil: true }, clears: 0, draws: [] };
  const renderer = {
    autoClear: true, shadowMap: { enabled: false }, domElement: new EventTarget(),
    getContext: () => ({ getContextAttributes: () => state.attributes }),
    getRenderTarget: () => state.target, getScissorTest: () => state.scissor,
    getDrawingBufferSize: vector => vector.fromArray(state.size), getViewport: vector => vector.fromArray(state.viewport),
    setSize() {}, setDrawingBufferSize() {}, clear() { state.clears++; },
    render(scene, camera) {
      state.draws.push(scene.children.filter(object => camera.layers.test(object.layers)).map(object => ({
        object, stencilWrite: object.material?.stencilWrite, stencilRef: object.material?.stencilRef,
        stencilFunc: object.material?.stencilFunc, stencilZPass: object.material?.stencilZPass,
      })));
    },
  };
  configure({ scene, camera, screen, room, glass, light, renderer, state });
  const originalSize = renderer.setSize;
  const cached = createRoomRenderer(renderer, scene, [screen]);
  t.after(() => {
    cached.dispose();
    for (const mesh of [screen, room, glass]) { mesh.geometry.dispose(); mesh.material.dispose(); }
  });
  return { scene, camera, screen, room, glass, light, renderer, state, cached, originalSize };
}

test('retained samples redraw opaque screens and transparent overlays with the same scene and lights', t => {
  const { camera, screen, room, glass, light, renderer, state, cached } = fixture(t);
  cached.render(camera);
  assert.equal(state.clears, 0, 'The initial view uses the ordinary renderer');
  for (const item of state.draws.at(-1).slice(0, 3)) assert.equal(item.stencilWrite, false);
  cached.render(camera);
  const full = state.draws.at(-1);
  assert.deepEqual(full.map(item => item.object), [room, screen, glass, light]);
  assert.equal(full[0].stencilRef, 0, 'Static opaque winners erase previous screen ownership');
  assert.equal(full[1].stencilRef, 1);
  assert.equal(full[1].stencilZPass, THREE.ReplaceStencilOp);
  assert.equal(full[2].stencilWrite, false, 'Transparent layers preserve opaque ownership');
  for (let i = 0; i < 3; i++) cached.render(camera);
  const reused = state.draws.at(-1);
  assert.deepEqual(reused.map(item => item.object), [screen, glass, light]);
  for (const item of reused.slice(0, 2)) {
    assert.equal(item.stencilFunc, THREE.EqualStencilFunc);
    assert.equal(item.stencilRef, 1);
    assert.equal(item.stencilZPass, THREE.KeepStencilOp);
  }
  assert.equal(state.clears, 1, 'Reuse keeps native color, depth and stencil samples');
  assert.equal(renderer.autoClear, true);
  for (const object of [camera, screen, room, glass, light]) assert.equal(object.layers.mask, 1);
  for (const mesh of [screen, room, glass]) assert.equal(mesh.material.stencilWrite, false);
});

test('even tiny camera changes, same-size buffer resets and context restoration rebuild the room', t => {
  const { camera, screen, renderer, state, cached, originalSize } = fixture(t);
  cached.render(camera); cached.render(camera);
  const changes = [
    () => { camera.position.x += 1e-12; },
    () => { camera.projectionMatrix.elements[8] += 1e-12; },
    () => { state.viewport[2]++; },
    () => { state.size[0]++; },
    () => { renderer.setSize(100, 100); },
    () => { renderer.setDrawingBufferSize(100, 100, 2); },
    () => { renderer.domElement.dispatchEvent(new Event('webglcontextlost')); },
    () => { renderer.domElement.dispatchEvent(new Event('webglcontextrestored')); },
    () => cached.invalidate(),
  ];
  for (const change of changes) {
    const before = state.clears;
    cached.render(camera); assert.equal(state.clears, before, 'Unchanged state reuses the room');
    change(); cached.render(camera);
    assert.equal(state.clears, before, 'A changed view uses ordinary rendering without stencil stamping');
    for (const item of state.draws.at(-1).filter(item => item.object.isMesh)) assert.equal(item.stencilWrite, false);
    cached.render(camera); assert.equal(state.clears, before + 1, 'The next identical view stamps once');
  }
  for (const change of [() => { screen.position.x++; }, () => { screen.visible = false; }]) {
    const before = state.clears;
    change(); cached.render(camera); assert.equal(state.clears, before + 1, 'A changed surface rebuilds ownership even with a stable camera');
    cached.render(camera); assert.equal(state.clears, before + 1);
  }
  const beforeMotion = state.clears;
  for (let i = 0; i < 3; i++) {
    camera.position.x += 1e-12; cached.render(camera);
    assert.equal(state.clears, beforeMotion, 'Continuous motion never stamps samples');
    for (const item of state.draws.at(-1).filter(item => item.object.isMesh)) assert.equal(item.stencilWrite, false);
  }
  cached.dispose(); assert.equal(renderer.setSize, originalSize);
});

test('unsupported buffers, depth or alpha paths retain the ordinary renderer', t => {
  for (const configure of [
    ({ state }) => { state.attributes.stencil = false; },
    ({ state }) => { state.attributes.preserveDrawingBuffer = false; },
    ({ screen }) => { screen.material.transparent = true; },
    ({ screen }) => { screen.material.opacity = .5; },
    ({ screen }) => { screen.material.colorWrite = false; },
    ({ screen }) => { screen.material.depthFunc = THREE.LessDepth; },
    ({ glass }) => { glass.material.depthWrite = true; },
  ]) {
    const { camera, renderer, state, cached } = fixture(t, configure);
    renderer.render = () => { assert.equal(renderer.autoClear, true); };
    cached.render(camera); cached.render(camera); assert.equal(state.clears, 0);
  }
  const { camera, screen, renderer, state, cached } = fixture(t);
  cached.render(camera); cached.render(camera);
  const fullRender = renderer.render;
  renderer.render = () => { assert.equal(screen.material.stencilWrite, false); };
  state.target = {}; cached.render(camera); state.target = null;
  renderer.render = fullRender; cached.render(camera); cached.render(camera); assert.equal(state.clears, 2);
  screen.geometry.attributes.position.needsUpdate = true;
  renderer.render = () => { assert.equal(screen.material.stencilWrite, false); };
  cached.render(camera); assert.equal(state.clears, 2);
});

test('a failed render restores material and camera state and invalidates retained pixels', t => {
  const { camera, screen, renderer, state, cached } = fixture(t);
  cached.render(camera); cached.render(camera);
  const original = renderer.render;
  renderer.render = () => { throw new Error('render failed'); };
  assert.throws(() => cached.render(camera), /render failed/);
  assert.equal(screen.material.stencilWrite, false);
  assert.equal(screen.layers.mask, 1); assert.equal(camera.layers.mask, 1); assert.equal(renderer.autoClear, true);
  renderer.render = original; cached.render(camera); cached.render(camera);
  assert.equal(state.clears, 2);
});
