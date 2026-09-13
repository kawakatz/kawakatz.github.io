import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { displayFrame, displayPose } from '../assets/js/device-focus.js';
import { screenView, screenViewPose, screenViewFov, lensFov, inspectedScreenPose } from '../assets/js/screen-view.js';

test('screen view looks around from one chair position and retains portrait fitting', async () => {
  const eye = new THREE.Vector3(...screenView.position);
  assert.deepEqual(eye.toArray(), [-.25245, .98, 1.4]);
  const defaultPose = screenViewPose();
  assert.equal(defaultPose.near, 1.15);
  const aims = [new THREE.Vector3(...screenView.target)];
  for (const x of screenView.lookX) for (const y of screenView.lookY) aims.push(new THREE.Vector3(x, y, screenView.target[2]));

  const bytes = await readFile(new URL('../assets/scene/workstation.glb', import.meta.url));
  const { scene } = await new GLTFLoader().parseAsync(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), '');
  scene.updateMatrixWorld(true);
  const screens = {};
  scene.traverse(object => { if (object.isMesh && ['monitor-screen', 'macbook-screen', 'mouse-laptop-screen', 'ipad-screen'].includes(object.userData.dynamic)) screens[object.userData.dynamic] = object; });
  const grid = [-.47, -.31, -.16, 0, .16, .31, .47];
  const lookAtPoint = point => point.clone().sub(eye).multiplyScalar((screenView.target[2] - eye.z) / (point.z - eye.z)).add(eye);
  const cameraAt = (target, width, height) => {
    const camera = new THREE.PerspectiveCamera(screenViewFov(width / height), width / height, screenView.near, 30);
    const pose = screenViewPose(target);
    camera.position.copy(pose.position); camera.quaternion.copy(pose.rotation); camera.updateMatrixWorld(true);
    assert.deepEqual(camera.position.toArray(), eye.toArray(), 'Changing direction or aspect must not translate the chair camera');
    assert.ok(camera.fov >= screenView.fov, 'Portrait fitting must not narrow the desktop lens');
    return camera;
  };
  const surfacePoint = (mesh, frame, right, x, y) => {
    const probe = frame.center.clone().addScaledVector(right, x * frame.width).addScaledVector(frame.up, y * frame.height).addScaledVector(frame.outward, 1);
    const point = new THREE.Raycaster(probe, frame.outward.clone().negate(), 0, 2).intersectObject(mesh, false)[0]?.point;
    assert.ok(point, `${mesh.userData.dynamic}: missing display sample`);
    return point;
  };
  const viewports = [[1440, 900], [716, 900], [716, 1173], [716, 1440], [390, 844], [320, 932]];
  try {
    const current = cameraAt(new THREE.Vector3(...screenView.target), 1440, 900);
    const projectedRange = (mesh, camera) => {
      let min = Infinity, max = -Infinity;
      for (let i = 0; i < mesh.geometry.attributes.position.count; i++) {
        const point = new THREE.Vector3().fromBufferAttribute(mesh.geometry.attributes.position, i).applyMatrix4(mesh.matrixWorld).project(camera);
        min = Math.min(min, point.x); max = Math.max(max, point.x);
      }
      return [min, max];
    };
    const projectedWidth = (mesh, camera) => { const [min, max] = projectedRange(mesh, camera); return (max - min) * 720; };
    const stretch = (mesh, camera) => {
      const frame = displayFrame(mesh), right = new THREE.Vector3(1, 0, 0).applyQuaternion(frame.rotation);
      const pixels = point => { const p = point.project(camera); return new THREE.Vector2(p.x * 720, p.y * 450); };
      const scale = axis => pixels(frame.center.clone().addScaledVector(axis, .001)).distanceTo(pixels(frame.center.clone().addScaledVector(axis, -.001)));
      return scale(right) / scale(frame.up);
    };
    const mac = screens['macbook-screen'], dell = screens['monitor-screen'], mouse = screens['mouse-laptop-screen'];
    const macWidth = projectedWidth(mac, current);
    assert.ok(macWidth > 515 && macWidth < 540, 'The new default frames the Mac at the previous one-step zoom');
    assert.ok(projectedWidth(dell, current) / macWidth > 3.5, 'Dell retains its relative presence without stretching either mesh');
    assert.ok(stretch(mouse, current) > .9 && stretch(mouse, current) < 1.1, 'The longer lens keeps Mouse pixels proportionate');
    assert.ok((projectedRange(dell, current)[1] - projectedRange(screens['ipad-screen'], current)[1]) * 720 > 50, 'Dell extends clearly beyond the iPad screen at the right');
    const dellFrame = displayFrame(dell), dellRight = new THREE.Vector3(1, 0, 0).applyQuaternion(dellFrame.rotation);
    for (const [width, height] of [...viewports, [844, 390], [932, 320]]) {
      const camera = new THREE.PerspectiveCamera(40, width / height, .1, 30), base = displayPose(dellFrame, camera, height);
      const approach = base.position.clone().sub(dellFrame.center);
      assert.ok(Math.abs(approach.dot(dellFrame.up)) < 1e-10, 'Dell inspection stays centered at display height');
      assert.ok(Math.abs(approach.dot(dellFrame.outward) - 1.32) < 1e-10, 'The inspector stays 1.32 m in front of the larger display to reduce wide-angle distortion');
      assert.ok(new THREE.Vector3(0, 0, 1).applyQuaternion(base.rotation).dot(dellFrame.outward) > .999999, 'Dell zoom faces the screen squarely without overhead distortion');
      for (const look of [new THREE.Vector2(), new THREE.Vector2(-.46, -.46), new THREE.Vector2(.46, .46)]) {
        const pose = inspectedScreenPose(dellFrame, base, look, look.lengthSq() ? .25 : 1);
        const offset = dellRight.clone().multiplyScalar(look.x * dellFrame.width).addScaledVector(dellFrame.up, look.y * dellFrame.height);
        assert.ok(pose.position.distanceTo(base.position.clone().add(offset)) < 1e-10 && pose.rotation.angleTo(base.rotation) < 1e-10, 'Dell panning translates parallel to the screen without tilting it');
        camera.position.copy(pose.position); camera.quaternion.copy(pose.rotation); camera.fov = pose.fov; camera.near = pose.near; camera.updateProjectionMatrix(); camera.updateMatrixWorld(true);
        if (!look.lengthSq()) for (let i = 0; i < dell.geometry.attributes.position.count; i++) {
          const point = new THREE.Vector3().fromBufferAttribute(dell.geometry.attributes.position, i).applyMatrix4(dell.matrixWorld).project(camera);
          assert.ok(Math.abs(point.x) <= .88001 && Math.abs(point.z) < 1, `Dell ${width}×${height}: every curved edge fits`);
          assert.ok((1 - Math.abs(point.y)) * height / 2 >= 92 - 1e-4, `Dell ${width}×${height}: toolbar and footer keep 92 px clearance`);
        }
        // Include the outermost pixels: the original 49 points alone miss the Mouse's upper bezel.
        const edges = [-.499, ...grid, .499];
        const samples = edges.flatMap(x => edges.map(y => [x, y]));
        for (const [x, y] of samples) {
          const point = surfacePoint(dell, dellFrame, dellRight, x, y);
          assert.ok(point.clone().applyMatrix4(camera.matrixWorldInverse).z < -camera.near, 'The Dell near plane preserves every edge even after panning');
          const direction = point.clone().sub(camera.position).normalize(), forward = direction.dot(camera.getWorldDirection(new THREE.Vector3()));
          const ray = new THREE.Raycaster(camera.position, direction, camera.near / forward, camera.far / forward);
          const hit = ray.intersectObject(scene, true)[0]?.object;
          assert.ok(hit === dell, `Dell inspector ${width}×${height} at ${x},${y}: ${hit?.name || 'no mesh'} obscures content`);
        }
      }
    }
    for (const [name, screen] of Object.entries(screens)) {
      const frame = displayFrame(screen), target = lookAtPoint(frame.center);
      assert.ok(target.x >= screenView.lookX[0] && target.x <= screenView.lookX[1], `${name}: reachable horizontal direction`);
      assert.ok(target.y >= screenView.lookY[0] && target.y <= screenView.lookY[1], `${name}: reachable vertical direction`);
      aims.push(target);
      const right = new THREE.Vector3(1, 0, 0).applyQuaternion(frame.rotation);
      const departure = cameraAt(new THREE.Vector3(...screenView.target), 1440, 900);
      const arrival = displayPose(frame, departure, 900);
      for (const amount of [0, .25, .5, .75, 1]) {
        const travel = departure.clone();
        travel.position.lerpVectors(departure.position, arrival.position, amount);
        travel.quaternion.slerpQuaternions(departure.quaternion, arrival.rotation, amount);
        travel.near = THREE.MathUtils.lerp(departure.near, arrival.near, amount);
        travel.updateMatrixWorld(true);
        for (let i = 0; i < screen.geometry.attributes.position.count; i++) {
          const point = new THREE.Vector3().fromBufferAttribute(screen.geometry.attributes.position, i).applyMatrix4(screen.matrixWorld).applyMatrix4(travel.matrixWorldInverse);
          assert.ok(-point.z > travel.near, `${name}: the interpolated near plane must not cut the screen during approach or return`);
        }
      }
      for (const [width, height] of viewports) {
        const camera = cameraAt(target, width, height);
        assert.ok(frame.center.clone().project(camera).length() < 1, `${name}: center remains visible`);
        for (let i = 0; i < screen.geometry.attributes.position.count; i++) {
          const point = new THREE.Vector3().fromBufferAttribute(screen.geometry.attributes.position, i).applyMatrix4(screen.matrixWorld).project(camera);
          assert.ok(Math.abs(point.y) <= 1 && Math.abs(point.z) < 1, `${name}: vertical field at ${width}×${height}`);
          // The ultrawide extends past the viewport and is explored by looking around.
          if (name !== 'monitor-screen') assert.ok(Math.abs(point.x) <= 1, `${name}: full width at ${width}×${height}`);
        }
      }
      for (const x of grid) for (const y of grid) {
        // The physical rack's front lip covers a little of the iPad's bottom edge.
        if (name === 'ipad-screen' && y === grid[0] && Math.abs(x) <= .16) continue;
        const point = surfacePoint(screen, frame, right, x, y);
        const camera = cameraAt(target, 1440, 900), direction = point.sub(eye).normalize();
        const forward = direction.dot(camera.getWorldDirection(new THREE.Vector3()));
        const ray = new THREE.Raycaster(eye, direction, camera.near / forward, camera.far / forward);
        const collision = ray.intersectObject(scene, true)[0], hit = collision?.object;
        if (name === 'monitor-screen' && (x === grid[0] || x === grid[1]) && (y === grid[0] || y === grid[1])) {
          assert.ok(y === grid[0] ? hit === screens['mouse-laptop-screen'] : hit?.material.name === 'rubber-baked', 'Only the real Mouse display and its bezel overlap the four lower-left Dell samples');
        } else if (name === 'monitor-screen' && x === 0 && y === grid[0]) {
          assert.ok(hit?.material.name === 'display-glass-baked', 'The upright MacBook camera cutout exposes its bezel glass at the central bottom Dell sample');
          const macFrame = displayFrame(screens['macbook-screen']), relative = collision.point.clone().sub(macFrame.center);
          assert.ok(Math.abs(relative.dot(new THREE.Vector3(1, 0, 0).applyQuaternion(macFrame.rotation))) < .015 && Math.abs(relative.dot(macFrame.up) - macFrame.height / 2) < .007, 'The overlap stays at the MacBook upper-center notch');
          const above = surfacePoint(screen, frame, right, 0, -.43).sub(eye).normalize();
          ray.set(eye, above);
          assert.ok(ray.intersectObject(scene, true)[0]?.object === screen, 'Dell remains clear immediately above the MacBook top edge');
        } else assert.ok(hit === screen, `${name}: ${hit?.name || 'no mesh'} obscures the useful screen area`);
      }
      if (name === 'monitor-screen') for (const side of [-.33, .33]) {
        const point = frame.center.clone().addScaledVector(right, side * frame.width), look = lookAtPoint(point);
        assert.ok(look.x >= screenView.lookX[0] && look.x <= screenView.lookX[1], 'Both side applications on Dell remain reachable');
        aims.push(look);
        for (const [width, height] of viewports) {
          const projected = point.clone().project(cameraAt(look, width, height));
          assert.ok(Math.abs(projected.x) < 1e-6 && Math.abs(projected.y) < 1e-6, 'Look direction can center each Dell application');
        }
      }
    }
    for (const target of aims) {
      const original = target.clone(), pose = screenViewPose(target);
      assert.deepEqual(pose.position.toArray(), eye.toArray());
      assert.ok(target.equals(original), 'Building a pose must not mutate the retained look target');
      const forward = new THREE.Vector3(0, 0, -1).applyQuaternion(pose.rotation);
      assert.ok(forward.distanceTo(target.clone().sub(eye).normalize()) < 1e-12, 'Only orientation follows the look target');
    }
    for (const [width, height] of viewports) {
      const camera = cameraAt(new THREE.Vector3(...screenView.target), width, height);
      const position = camera.position.clone();
      const baseFov = camera.fov;
      for (const scale of [1.75, 1.25, 1, .5, .25]) {
        camera.fov = lensFov(baseFov, scale); camera.updateProjectionMatrix();
        assert.ok(Number.isFinite(camera.fov) && camera.fov > 0 && camera.fov < 180);
        assert.ok(camera.position.equals(position), 'Lens zoom leaves the chair position fixed');
        assert.equal(camera.near, screenView.near, 'Screen zoom retains the foreground clipping plane');
        assert.ok(Math.abs(Math.tan(THREE.MathUtils.degToRad(baseFov / 2)) / Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) - 1 / scale) < 1e-10, 'Lens magnification agrees with the zoom controls');
      }
      for (const [name, mesh] of Object.entries(screens)) {
        if (name === 'macbook-screen') continue; // Mac retains its existing Notes transition.
        const frame = displayFrame(mesh);
        const base = displayPose(frame, camera, height);
        const right = new THREE.Vector3(1, 0, 0).applyQuaternion(frame.rotation);
        for (const look of [new THREE.Vector2(), new THREE.Vector2(-.46, .46), new THREE.Vector2(.46, -.46)]) {
          const pose = inspectedScreenPose(frame, base, look, .25);
          if (name === 'monitor-screen') {
            assert.ok(pose.rotation.angleTo(base.rotation) < 1e-10, 'Dell panning retains its frontal view');
            assert.equal(pose.near, base.near, 'Dell retains its foreground clipping plane while panning');
          } else {
            assert.ok(pose.position.equals(base.position), `${name}: inspection pans the direction, not the position`);
            assert.equal(pose.near, .1, 'Other device inspections retain the ordinary near plane');
          }
          camera.position.copy(pose.position); camera.quaternion.copy(pose.rotation); camera.fov = pose.fov; camera.near = pose.near; camera.updateProjectionMatrix(); camera.updateMatrixWorld(true);
          const selected = frame.center.clone().addScaledVector(right, look.x * frame.width).addScaledVector(frame.up, look.y * frame.height).project(camera);
          assert.ok(Math.abs(selected.x) < 1e-6 && Math.abs(selected.y) < 1e-6 && Math.abs(selected.z) < 1, `${name}: zoomed app details remain reachable`);
        }
        const reset = inspectedScreenPose(frame, base);
        assert.ok(Math.abs(reset.fov - base.fov) < 1e-10, 'Reset restores the fitted lens within floating-point precision');
        assert.ok(reset.rotation.angleTo(base.rotation) < 1e-6, 'Reset returns to the complete screen pose');
      }
    }
    for (const [width, height] of viewports) {
      const camera = cameraAt(new THREE.Vector3(...screenView.target), width, height), screen = screens['macbook-screen'];
      for (let i = 0; i < screen.geometry.attributes.position.count; i++) {
        const point = new THREE.Vector3().fromBufferAttribute(screen.geometry.attributes.position, i).applyMatrix4(screen.matrixWorld).project(camera);
        assert.ok(Math.abs(point.x) <= .84 && Math.abs(point.y) <= 1, `Initial Mac Notes entry remains fully visible at ${width}×${height}`);
      }
    }
  } finally {
    scene.traverse(object => {
      if (!object.isMesh) return;
      object.geometry.dispose();
      for (const material of Array.isArray(object.material) ? object.material : [object.material]) material.dispose();
    });
  }
});
