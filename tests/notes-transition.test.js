import test from 'node:test';
import assert from 'node:assert/strict';
import * as THREE from 'three';
import { ease, notesFlight, quadTransform } from '../assets/js/navigation.js';
import { displayPose, displayPixelWidth } from '../assets/js/device-focus.js';
import { screenViewPose, screenViewFov, lensFov } from '../assets/js/screen-view.js';

test('Chrome travels from its Dock thumbnail through the Mac display into the actual Notes viewport', () => {
  const rect = (x,y,w,h) => [{x,y},{x:x+w,y},{x:x+w,y:y+h},{x,y:y+h}];
  const dock = rect(970,320,18,12), floating = rect(430,400,500,310);
  const display = [{x:385,y:330},{x:1070,y:345},{x:1060,y:785},{x:370,y:765}];
  const viewport = rect(0,0,1280,800);
  for (const [p, expected] of [[0,dock],[.35,floating],[.75,display],[1,viewport]]) {
    const quad = notesFlight(p,dock,floating,display,viewport);
    quad.forEach((point,i) => assert.ok(Math.hypot(point.x-expected[i].x,point.y-expected[i].y)<1e-8));
  }
  for (let i=0;i<=100;i++) {
    const quad=notesFlight(i/100,dock,floating,display,viewport), m=quadTransform(quad,1280,800);
    assert.ok(m.every(Number.isFinite));
    [[0,0],[1280,0],[1280,800],[0,800]].forEach(([x,y],corner) => {
      const w=m[3]*x+m[7]*y+1;
      assert.ok(Math.hypot((m[0]*x+m[4]*y+m[12])/w-quad[corner].x,(m[1]*x+m[5]*y+m[13])/w-quad[corner].y)<1e-7);
    });
  }
  // Reversing the same progress restores the same artwork without jumping to an initial pose.
  assert.deepEqual(notesFlight(0,dock,floating,display,viewport),dock);
});

test('Notes camera size and center move continuously and reverse from their current projection on cancellation', () => {
  const rotation = new THREE.Quaternion().setFromEuler(new THREE.Euler(-.17, 0, 0));
  const display = {
    center: new THREE.Vector3(-.25245, .90, -.33), width: .3024, height: .1964, depth: 0, rotation,
    up: new THREE.Vector3(0, 1, 0).applyQuaternion(rotation),
    outward: new THREE.Vector3(0, 0, 1).applyQuaternion(rotation),
  };
  for (const [width, height] of [[1440, 900], [716, 900], [390, 844]]) {
    const cameraAt = pose => {
      const camera = new THREE.PerspectiveCamera(pose.fov, width / height, pose.near, 30);
      camera.position.copy(pose.position); camera.quaternion.copy(pose.rotation); camera.updateMatrixWorld(true);
      camera.projectionMatrix.elements[8] = pose.projectionShift?.x ?? 0;
      camera.projectionMatrix.elements[9] = pose.projectionShift?.y ?? 0;
      camera.projectionMatrixInverse.copy(camera.projectionMatrix).invert();
      return camera;
    };
    const initial = { ...screenViewPose(), fov: screenViewFov(width / height) };
    const start = cameraAt(initial), destination = { ...displayPose(display, start), near: .1 };
    const pixelWidth = camera => displayPixelWidth(display, camera, width, height);
    const center = camera => display.center.clone().project(camera);
    const sample = (from, to, progress) => {
      const camera = cameraAt(from), t = ease(progress);
      const end = cameraAt(to), desired = THREE.MathUtils.lerp(pixelWidth(camera), pixelWidth(end), t);
      const desiredCenter = center(camera).lerp(center(end), t);
      camera.position.lerpVectors(from.position, to.position, t);
      camera.quaternion.slerpQuaternions(from.rotation, to.rotation, t);
      camera.fov = THREE.MathUtils.lerp(from.fov, to.fov, t);
      camera.near = THREE.MathUtils.lerp(from.near, to.near, t);
      camera.updateProjectionMatrix(); camera.updateMatrixWorld(true);
      const current = pixelWidth(camera);
      assert.ok(current > 0 && desired > 0, 'The display stays measurable throughout the dolly');
      camera.fov = lensFov(camera.fov, current / desired); camera.updateProjectionMatrix();
      const unshifted = center(camera);
      camera.projectionMatrix.elements[8] += unshifted.x - desiredCenter.x;
      camera.projectionMatrix.elements[9] += unshifted.y - desiredCenter.y;
      camera.projectionMatrixInverse.copy(camera.projectionMatrix).invert();
      assert.ok(Number.isFinite(camera.fov) && camera.fov > 0 && camera.fov < 180);
      assert.ok(Math.abs(pixelWidth(camera) - desired) < 1e-6, 'Focal correction preserves the intended on-screen size at every pose');
      const actual = center(camera);
      assert.ok(Math.hypot(actual.x - desiredCenter.x, actual.y - desiredCenter.y) < 1e-10, 'The screen center follows the eased endpoint line without overshooting');
      assert.ok(actual.clone().unproject(camera).distanceTo(display.center) < 1e-8, 'The inverse projection agrees with the shifted camera');
      return camera;
    };
    const opened = Array.from({ length: 301 }, (_, i) => sample(initial, destination, i / 300));
    for (let i = 1; i < opened.length; i++) assert.ok(pixelWidth(opened[i]) >= pixelWidth(opened[i - 1]) - 1e-6, `Mac never shrinks while opening at ${width}×${height}`);
    assert.ok(Math.abs(pixelWidth(opened[0]) - pixelWidth(start)) < 1e-6);
    assert.ok(Math.abs(opened.at(-1).fov - destination.fov) < 1e-9, 'The final frame matches the focused camera without a lens jump');

    const halfway = opened[117];
    const interrupted = {
      position: halfway.position.clone(), rotation: halfway.quaternion.clone(), fov: halfway.fov, near: halfway.near,
      projectionShift: new THREE.Vector2(halfway.projectionMatrix.elements[8], halfway.projectionMatrix.elements[9]),
    };
    const closed = Array.from({ length: 301 }, (_, i) => sample(interrupted, initial, i / 300));
    assert.ok(Math.abs(pixelWidth(closed[0]) - pixelWidth(halfway)) < 1e-6, 'Cancellation starts at the current magnification');
    assert.ok(center(closed[0]).distanceTo(center(halfway)) < 1e-10, 'The saved projection shift keeps cancellation at the exact visible center');
    for (let i = 1; i < closed.length; i++) assert.ok(pixelWidth(closed[i]) <= pixelWidth(closed[i - 1]) + 1e-6, 'Cancellation returns continuously without first zooming farther in');
    assert.ok(Math.abs(pixelWidth(closed.at(-1)) - pixelWidth(start)) < 1e-6);
    assert.ok(Math.abs(closed.at(-1).fov - initial.fov) < 1e-9, 'Returning restores the original lens');
    for (const endpoint of [opened.at(-1), closed.at(-1)]) assert.ok(Math.hypot(endpoint.projectionMatrix.elements[8], endpoint.projectionMatrix.elements[9]) < 1e-10, 'Both endpoints restore the unshifted projection');
  }
});
