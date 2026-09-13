import test from 'node:test';
import assert from 'node:assert/strict';
import * as THREE from 'three';
import { readFile } from 'node:fs/promises';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { createWorkstation, overview } from '../assets/js/workstation.js';
import { displayFrame, displayPose, displayPixelWidth, displayZoomMinimum, displayPixelRatio, displayTextureWidth } from '../assets/js/device-focus.js';
import { screenViewPose, screenViewFov } from '../assets/js/screen-view.js';

test('default display supersampling increases detail within a pixel budget and preserves inspector density', () => {
  assert.equal(displayPixelRatio(1280, 720), 3);
  for (const [width, height] of [[839, 1173], [1440, 900], [1920, 1080], [3840, 2160]]) {
    const ratio = displayPixelRatio(width, height);
    assert.ok(ratio >= 2 && ratio <= 3);
    if (ratio > 2) assert.ok(width * height * ratio * ratio <= 12e6 + 1);
    assert.equal(displayPixelRatio(width, height, true), 2, 'Overview and inspection retain the existing zoom texture budget');
  }
  for (const [width, height] of [[390, 844], [844, 390], [0, 720], [NaN, 720], [Infinity, 720]]) assert.equal(displayPixelRatio(width, height), 2);
});

test('screen raster floors remain bounded by GPU dimensions and the 64 MP canvas budget', () => {
  for (const gpuLimit of [4096, 8192, 16384]) for (const aspect of [32 / 9, 3072 / 1996, 1]) {
    for (const projected of [0, 1600, 12000, 100000]) {
      const width = displayTextureWidth(projected, aspect, 8192, gpuLimit);
      assert.ok(width <= gpuLimit && width <= 12288);
      assert.ok(width * Math.round(width / aspect) <= 64e6);
      assert.equal(width % 256, 0);
    }
  }
  assert.equal(displayTextureWidth(1600, 32 / 9, 8192, 16384), 8192, 'Desktop density never falls back to native 5120 pixels after zoom or resize');
  assert.equal(displayTextureWidth(1600, 32 / 9, 5120, 16384), 5120, 'Small screens retain their existing lower floor');
  assert.equal(displayTextureWidth(1600, 32 / 9, 8192, 4096), 4096, 'Hardware support takes priority over the fidelity floor');
});

test('device close-ups face the real display and keep every edge visible after export and resize', () => {
  const model = createWorkstation();
  // Moving the whole desk must not leave the focus camera at old world coordinates.
  model.position.set(-.19, .13, -.28);
  model.rotation.set(.04, -.12, .025);
  model.updateMatrixWorld(true);
  for (const name of ['macbook-screen', 'mouse-laptop-screen', 'ipad-screen']) {
    const screen = model.getObjectByName(name);
    const original = displayFrame(screen);
    const geometry = screen.geometry.clone().applyMatrix4(screen.matrixWorld).toNonIndexed();
    // Blender's glTF export flips V while baking the hierarchy into the vertices.
    for (let i = 0; i < geometry.attributes.uv.count; i++) geometry.attributes.uv.setY(i, 1 - geometry.attributes.uv.getY(i));
    const baked = new THREE.Mesh(geometry, screen.material);
    const frame = displayFrame(baked);
    assert.ok(frame.center.distanceTo(original.center) < 1e-6, `${name}: exported center`);
    assert.ok(frame.rotation.angleTo(original.rotation) < 1e-6, `${name}: exported orientation`);
    assert.ok(frame.up.y > .5, `${name}: view stays upright`);
    for (const [width, height] of [[320, 932], [390, 844], [844, 390], [932, 320], [1440, 900]]) {
      const aspect = width / height;
      const camera = new THREE.PerspectiveCamera(overview.fov, aspect, .1, 30);
      const pose = displayPose(frame, camera, height);
      assert.ok(pose.position.distanceTo(displayPose(frame, camera).position) < 1e-10, `${name}: toolbar clearance must not move the camera behind furniture`);
      camera.fov = pose.fov; camera.updateProjectionMatrix();
      camera.position.copy(pose.position); camera.quaternion.copy(pose.rotation); camera.updateMatrixWorld(true);
      const towardsScreen = frame.center.clone().sub(camera.position).normalize();
      assert.ok(towardsScreen.dot(frame.outward) < -.999999, `${name}: approach is perpendicular`);
      assert.ok(camera.getWorldDirection(new THREE.Vector3()).dot(towardsScreen) > .999999, `${name}: center in view`);
      const projected = [];
      for (let i = 0; i < geometry.attributes.position.count; i++) {
        const point = new THREE.Vector3().fromBufferAttribute(geometry.attributes.position, i).project(camera);
        assert.ok(Math.abs(point.x) <= .88001 && Math.abs(point.y) <= .75001 && Math.abs(point.z) < 1, `${name}: no clipped edge at aspect ${aspect}`);
        projected.push(point);
      }
      const box = new THREE.Box3().setFromPoints(projected);
      assert.ok((1 - box.max.y) * height / 2 >= 92 - 1e-4, `${name}: screen must stay below the Back toolbar at ${width}×${height}`);
      assert.ok((1 + box.min.y) * height / 2 >= 92 - 1e-4, `${name}: screen must stay above the footer`);
      const pixelsRatio = (box.max.x - box.min.x) * aspect / (box.max.y - box.min.y);
      assert.ok(Math.abs(pixelsRatio - frame.width / frame.height) < 1e-5, `${name}: readable aspect is preserved`);
      const nativePixels = displayPixelWidth(frame, camera, width, height);
      assert.ok(Math.abs(nativePixels - (box.max.x - box.min.x) * width / 2) < .001, 'Raster density follows the actual display projection');
      const originalFov = camera.fov;
      camera.fov = THREE.MathUtils.radToDeg(2 * Math.atan(Math.tan(THREE.MathUtils.degToRad(originalFov / 2)) / 4));
      camera.updateProjectionMatrix();
      assert.ok(Math.abs(displayPixelWidth(frame, camera, width, height) / nativePixels - 4) < .00001, '4x lens zoom needs 4x source pixels');
      camera.fov = originalFov; camera.updateProjectionMatrix();
      const verticalSpace = Math.min(height * .75, height - 184);
      assert.ok(Math.max((box.max.x - box.min.x) / 1.76, (box.max.y - box.min.y) * height / (2 * verticalSpace)) > .999, `${name}: camera uses the available space`);
      const right = new THREE.Vector3(1, 0, 0).applyQuaternion(frame.rotation);
      for (const x of [-.47, -.31, -.16, 0, .16, .31, .47]) for (const y of [-.47, -.45, -.31, -.16, 0, .16, .31, .47]) {
        const point = frame.center.clone().addScaledVector(right, x * frame.width).addScaledVector(frame.up, y * frame.height);
        const ray = new THREE.Raycaster(pose.position, point.sub(pose.position).normalize(), camera.near, camera.far);
        const hit = ray.intersectObject(model, true)[0]?.object.name;
        // The upright tablet's real rack lip covers only the bottom-center strip.
        const rackLip = name === 'ipad-screen' && y === -.47 && Math.abs(x) <= .16;
        assert.equal(hit, rackLip ? 'ipad-stand-rib' : name, `${name}: unexpected occlusion at ${x},${y}, aspect ${aspect}`);
      }
    }
    geometry.dispose();
  }
  model.traverse(object => { if (object.isMesh) { object.geometry.dispose(); object.material.dispose(); } });
});


test('Dell starts with dense default artwork and preserves readable maximum zoom across viewport changes', async () => {
  const bytes = await readFile(new URL('../assets/scene/workstation.glb', import.meta.url));
  const { scene } = await new GLTFLoader().parseAsync(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), '');
  let screen;
  scene.traverse(object => { if (object.userData.dynamic === 'monitor-screen') screen = object; });
  const frame = displayFrame(screen);
  for (const [width, height] of [[716, 1173], [1280, 720], [1440, 900], [2560, 1440]]) {
    const initial = screenViewPose();
    const defaultCamera = new THREE.PerspectiveCamera(screenViewFov(width / height), width / height, initial.near, 30);
    defaultCamera.position.copy(initial.position); defaultCamera.quaternion.copy(initial.rotation); defaultCamera.updateMatrixWorld(true);
    const defaultPixels = displayPixelWidth(frame, defaultCamera, width, height) * displayPixelRatio(width, height);
    assert.equal(displayTextureWidth(defaultPixels, 32 / 9, 8192, 16384), 8192, 'The actual unzoomed Dell projection retains its 8192-pixel floor at each viewport');
    const camera = new THREE.PerspectiveCamera(40, width / height, .1, 30);
    const pose = displayPose(frame, camera, height);
    const minimum = displayZoomMinimum(frame, camera, height, 5120);
    assert.ok(minimum > 0 && minimum <= 1);
    if (width === 716) {
      assert.ok(pose.fov < 90, 'The longer inspection distance avoids an extreme portrait lens');
      assert.ok(1 / minimum > 8.2 && 1 / minimum < 8.4, 'The frontal fit still reaches 5120 CSS pixels with about 8.27x portrait magnification');
    }
    camera.position.copy(pose.position); camera.quaternion.copy(pose.rotation);
    camera.fov = THREE.MathUtils.radToDeg(2 * Math.atan(Math.tan(THREE.MathUtils.degToRad(pose.fov / 2)) * minimum));
    camera.updateProjectionMatrix(); camera.updateMatrixWorld(true);
    const projected = displayPixelWidth(frame, camera, width, height);
    assert.ok(Math.abs(projected - 5120) < .001, 'Full display projection reaches the same readable size at every viewport');
    assert.ok(displayTextureWidth(projected * 2, 32 / 9, 8192, 16384) >= projected * 2, 'Inspector resolution still covers every DPR2 display pixel');
    assert.ok(Math.abs(displayZoomMinimum(frame, camera, height, 5120) - minimum) < 1e-12, 'The bound does not feed back from the already zoomed camera FOV');
  }
  scene.traverse(object => { if (object.isMesh) { object.geometry.dispose(); for (const material of Array.isArray(object.material) ? object.material : [object.material]) material.dispose(); } });
});
