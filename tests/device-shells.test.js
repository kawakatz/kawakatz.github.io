import test from 'node:test';
import assert from 'node:assert/strict';
import * as THREE from 'three';
import { createWorkstation } from '../assets/js/workstation.js';
import { createRoom } from '../assets/js/room.js';
import { screenView } from '../assets/js/screen-view.js';
import { keyLayout, createKeyboardTextures } from '../assets/js/keyboard.js';

test('device shells retain their dimensions while modelling the opening and curved underside', () => {
  const model = createWorkstation(); model.updateMatrixWorld(true);
  for (const [name, width, depth] of [['macbook-unibody', .3126, .2212], ['mouse-laptop-unibody', .378, .267], ['ipad-aluminum-shell', .2506, .1741]]) {
    const geometry = model.getObjectByName(name).geometry;
    geometry.computeBoundingBox();
    const size = geometry.boundingBox.getSize(new THREE.Vector3());
    assert.ok(Math.abs(size.x - width) < 1e-6 && Math.abs(size.z - depth) < 1e-6);
    const positions = geometry.attributes.position;
    let lowerWidth = 0;
    for (let i = 0; i < positions.count; i++) if (Math.abs(positions.getY(i) - geometry.boundingBox.min.y) < 1e-6) lowerWidth = Math.max(lowerWidth, Math.abs(positions.getX(i)) * 2);
    assert.ok(width - lowerWidth > .003, `${name} needs an inset underside`);
    for (let i = 0; i < geometry.index.count; i += 3) {
      const [a, b, c] = [0, 1, 2].map(offset => new THREE.Vector3().fromBufferAttribute(positions, geometry.index.getX(i + offset)));
      assert.ok(b.sub(a).cross(c.sub(a)).length() > 1e-12, `${name} has a degenerate face`);
    }
  }
  const shell = model.getObjectByName('macbook-unibody');
  function height(x, z) {
    const ray = new THREE.Raycaster(shell.localToWorld(new THREE.Vector3(x, .04, z)), new THREE.Vector3(0, -1, 0));
    const hit = ray.intersectObject(shell)[0];
    assert.ok(hit, 'The recess must retain a solid floor');
    return shell.worldToLocal(hit.point).y;
  }
  assert.ok(height(.05, .109) - height(0, .109) > .0015, 'The front opening must be cut into the chassis');
  assert.ok(height(0, -.09) - height(0, -.101) > .003, 'The hinge needs clearance below it');
  model.traverse(object => object.geometry?.dispose());
});

test('SEIKO keeps thin control wings around a tapering central body with exposed shoulder vents', () => {
  const model = createWorkstation(); model.updateMatrixWorld(true);
  const get = name => { const object = model.getObjectByName(name); assert.ok(object, name); return object; };
  const clock = get('clock'), back = get('clock-rear-controls'), housing = get('clock-housing');
  assert.deepEqual(clock.scale.toArray(), [.9, .9, .9]);
  assert.equal(clock.rotation.y, THREE.MathUtils.degToRad(13));
  assert.equal(housing.material.color.getHex(), 0x35332f);
  const lcd = get('clock-screen'), face = lcd.parent, carrier = get('clock-front-carrier'), snooze = get('clock-snooze-button');
  assert.deepEqual(face.position.toArray(), [0, .044, .0179]);
  assert.equal(face.rotation.x, -.16);
  assert.equal(carrier.parent, face); assert.equal(snooze.parent, face);
  const bounds = object => { object.geometry.computeBoundingBox(); return object.geometry.boundingBox.clone(); };
  const front = bounds(carrier).translate(carrier.position), body = bounds(housing), bodySize = body.getSize(new THREE.Vector3());
  const frontSize = front.getSize(new THREE.Vector3()), button = bounds(snooze).translate(snooze.position);
  assert.ok(Math.abs(frontSize.x - .148) < 1e-6 && Math.abs(frontSize.y - .080) < 1e-6, 'The thin front retains the clock silhouette');
  assert.ok(frontSize.z < bodySize.z / 2 && bodySize.z < bodySize.y / 2, 'The front panel stays slimmer than the compact rear housing');
  assert.ok(bodySize.x < frontSize.x - .010 && bodySize.y < frontSize.y - .005, 'The body is inset from the front panel');
  const positions = housing.geometry.attributes.position, nearFace = new THREE.Box3(), rearCap = new THREE.Box3();
  for (let i = 0; i < positions.count; i++) {
    const point = new THREE.Vector3().fromBufferAttribute(positions, i);
    if (point.z < body.min.z + bodySize.z * .1) nearFace.expandByPoint(point);
    if (point.z > body.max.z - bodySize.z * .1) rearCap.expandByPoint(point);
    face.worldToLocal(housing.localToWorld(point));
    assert.ok(point.z < front.max.z - .004 && Math.abs(point.x) < front.max.x - .005, 'The body stays behind the front panel and inside its side edges');
  }
  assert.ok(rearCap.max.x < nearFace.max.x && rearCap.min.x > nearFace.min.x, 'Broad shoulders narrow into the battery cap');
  assert.ok(rearCap.max.y < nearFace.max.y && rearCap.min.y > nearFace.min.y, 'The central roof slopes down and the underside rises toward the rear');
  assert.ok(button.min.x > front.min.x && button.max.x < front.max.x && button.min.z >= front.min.z && button.max.z <= front.max.z, 'Snooze fits the thin top edge without protruding forward or backward');
  assert.ok(button.min.y >= front.max.y && button.min.y - front.max.y < .001, 'Snooze meets the top of the front panel');
  for (const [x, y] of [[0, 0], [-.05, -.024], [.05, .024]]) {
    const ray = new THREE.Raycaster(face.localToWorld(new THREE.Vector3(x, y, .03)), new THREE.Vector3(0, 0, -1).transformDirection(face.matrixWorld));
    assert.equal(ray.intersectObject(clock, true)[0]?.object, lcd, 'The unchanged LCD clears the new front carrier');
  }
  assert.equal(get('clock-brand').parent, face);
  assert.deepEqual(get('clock-brand').position.toArray(), [.0001, -.0325, .00108]);
  assert.equal(back.rotation.y, Math.PI, 'Rear-left and rear-right labels match the photographed viewpoint');
  assert.equal(back.parent, face); assert.equal(housing.parent, back);
  assert.equal(model.getObjectByName('clock-rear-housing'), undefined, 'A second deep shell must not fill the control wings');
  assert.ok(get('clock-adjust-plus').position.x < 0 && get('clock-button-set').position.x > 0);
  const count = name => { let total = 0; clock.traverse(object => { if (object.name === name) total++; }); return total; };
  assert.equal(count('clock-screw-mount'), 4);
  assert.equal(count('clock-rear-vent'), 14); assert.equal(count('clock-side-vent'), 0);
  const rearHit = (x, y) => new THREE.Raycaster(back.localToWorld(new THREE.Vector3(x, y, housing.position.z + body.max.z + .02)), new THREE.Vector3(0, 0, -1).transformDirection(back.matrixWorld)).intersectObject(clock, true)[0]?.object;
  for (const [name, x, y] of [
    ['clock-battery-cover', 0, .020], ['clock-battery-latch', 0, get('clock-battery-latch').position.y], ['clock-battery-latch-recess', 0, get('clock-battery-latch-recess').position.y],
    ['clock-alarm-slider', -.064, .0325], ['clock-button-set', .064, .060],
    ['clock-button-wave', .064, .049], ['clock-button-monitor', .064, .032], ['clock-reset', .064, .022],
  ]) assert.equal(rearHit(x, y), get(name), `${name} must not be buried inside the moulded housing`);
  for (const [x, y] of [[-.064, .044], [.064, .042]]) assert.equal(rearHit(x, y), carrier, 'The exposed control wings are the back of the thin front panel');
  clock.traverse(vent => {
    if (vent.name !== 'clock-rear-vent') return;
    const sample = bounds(vent).getSize(new THREE.Vector3()).x * .4;
    for (const x of [-sample, 0, sample]) {
      const ray = new THREE.Raycaster(vent.localToWorld(new THREE.Vector3(x, 0, .02)), new THREE.Vector3(0, 0, -1).transformDirection(vent.matrixWorld));
      const hit = ray.intersectObject(clock, true)[0], shoulder = ray.intersectObject(housing)[0];
      assert.equal(hit?.object, vent, 'Each vent remains exposed across the sloping shoulder');
      assert.ok(shoulder && shoulder.distance - hit.distance < .001 * clock.scale.x, 'The vent rests on the shoulder instead of floating above it');
    }
  });
  const feet = clock.children.filter(object => object.geometry && object.material?.name === 'rubber');
  assert.equal(feet.length, 4);
  for (const foot of feet) {
    const footBounds = bounds(foot).translate(foot.position);
    assert.ok(Math.abs(footBounds.min.y) < 1e-6, 'Each foot rests on the support plane');
    const ray = new THREE.Raycaster(clock.localToWorld(new THREE.Vector3(foot.position.x, -.02, foot.position.z)), new THREE.Vector3(0, 1, 0).transformDirection(clock.matrixWorld));
    const shell = ray.intersectObject(clock, true).find(hit => hit.object.material?.name === 'clock-plastic');
    assert.ok(shell && clock.worldToLocal(shell.point).y <= footBounds.max.y + .00001, 'The feet reach the shell instead of floating below it');
  }
  const mark = get('clock-adjust-minus-mark').geometry; mark.computeBoundingBox();
  const size = mark.boundingBox.getSize(new THREE.Vector3());
  assert.ok(size.x < .0018 && size.y < .0003, 'The minus mark stays proportional instead of scaling by glyph height');
  model.traverse(object => object.geometry?.dispose());
});

test('Mac USB-C accessories stay seated, legible and joined by a clear continuous Thunderbolt cable', () => {
  const model = createWorkstation(); model.updateMatrixWorld(true);
  const get = name => { const object = model.getObjectByName(name); assert.ok(object, name); return object; };
  const bounds = (object, parent = object) => {
    object.geometry.computeBoundingBox();
    return object.geometry.boundingBox.clone().applyMatrix4(parent.matrixWorld.clone().invert().multiply(object.matrixWorld));
  };
  const mac = get('macbook'), dock = get('dock'), nano = get('macbook-yubikey'), macPlug = get('caldigit-mac-connector'), dockPlug = get('caldigit-ts4-connector');
  const frontPort = get('macbook-left-usbc-front'), rearPort = get('macbook-left-usbc-rear'), host = get('dock-thunderbolt-host-port');
  assert.ok(frontPort.position.z > rearPort.position.z && frontPort.position.x < 0, 'The Nano occupies the forward left port and the cable the rearward one');
  assert.ok(get('macbook-magsafe-port').position.z < rearPort.position.z && get('macbook-headphone-port').position.z > frontPort.position.z, 'MagSafe and headphones remain outside the USB-C pair');
  const keys = keyLayout('macbook');
  for (const [port, label] of [[get('macbook-magsafe-port'), 'esc'], [rearPort, '`'], [frontPort, 'tab'], [get('macbook-headphone-port'), 'caps lock']]) {
    assert.ok(Math.abs(port.position.z - keys.find(key => key.label === label).z) < .003, `The ${label} key anchors the photographed port-row alignment`);
  }
  assert.equal(mac.children.filter(object => object.name === 'macbook-magsafe-contact').length, 5);
  const side = bounds(get('macbook-unibody')).min.x;
  for (const [plug, port, bladeName] of [[nano, frontPort, 'yubikey-usbc-blade'], [macPlug, rearPort, 'caldigit-mac-connector-blade']]) {
    assert.equal(plug.parent, mac); assert.equal(plug.position.z, port.position.z); assert.equal(plug.position.y, port.position.y);
    const blade = bounds(get(bladeName), mac), aperture = bounds(port, mac);
    assert.ok(blade.min.x < side && blade.max.x > side, 'The metal blade enters the Mac enclosure');
    for (const axis of ['y', 'z']) assert.ok(blade.min[axis] >= aperture.min[axis] && blade.max[axis] <= aperture.max[axis], 'The blade fits the USB-C opening');
  }
  assert.equal(dockPlug.parent, dock); assert.ok(host.position.z < 0 && dockPlug.position.z < host.position.z, 'The cable uses the TS4 rear host socket');
  const dockBlade = bounds(get('caldigit-ts4-connector-blade'), dock), socket = bounds(host, dock);
  for (const axis of ['x', 'y']) assert.ok(dockBlade.min[axis] >= socket.min[axis] && dockBlade.max[axis] <= socket.max[axis], 'The TS4 blade fits its host socket');
  assert.ok(dockBlade.min.z < host.position.z && dockBlade.max.z > host.position.z);
  assert.equal(get('dock-rear').children.filter(object => /^dock-rear-screw-\d$/u.test(object.name)).length, 4);
  for (const [portName, visible] of [['ethernet', 'recess'], ['usb-c-data', 'tongue']]) {
    const recess = get(`dock-rear-${portName}-recess`), center = bounds(recess).getCenter(new THREE.Vector3()); center.z += .02;
    const ray = new THREE.Raycaster(recess.localToWorld(center), new THREE.Vector3(0, 0, -1).transformDirection(recess.matrixWorld));
    assert.equal(ray.intersectObject(dock, true)[0]?.object, get(`dock-rear-${portName}-${visible}`), 'Rear sockets remain exposed through the inset panel');
  }
  for (const name of ['yubikey-nano-head', 'caldigit-mac-connector-housing', 'caldigit-ts4-connector-housing']) {
    const object = get(name), box = bounds(object), flat = new THREE.Box3(), { position, normal } = object.geometry.attributes;
    for (let i = 0; i < position.count; i++) if (normal.getY(i) > .999 && Math.abs(position.getY(i) - box.max.y) < 1e-6) flat.expandByPoint(new THREE.Vector3().fromBufferAttribute(position, i));
    const size = box.getSize(new THREE.Vector3()), plateau = flat.getSize(new THREE.Vector3());
    assert.ok(plateau.x > size.x * .4 && plateau.z > size.z * .25, 'Rounded connector edges retain a broad flat top for touch and print');
  }
  const gold = get('yubikey-touch-strip');
  assert.ok(gold.material.metalness > .5 && gold.material.color.r > gold.material.color.b, 'The Nano touch strip remains gold metal');
  const goldRay = new THREE.Raycaster(gold.localToWorld(new THREE.Vector3(0, .02, 0)), new THREE.Vector3(0, -1, 0).transformDirection(gold.matrixWorld));
  assert.equal(goldRay.intersectObject(nano, true)[0]?.object, gold);
  for (const name of ['yubikey-wordmark', 'caldigit-mac-logo', 'caldigit-ts4-thunderbolt-mark', 'caldigit-ts4-generation']) {
    const print = get(name), { position } = print.geometry.attributes, index = print.geometry.index;
    const normal = new THREE.Vector3(0, 0, 1).transformDirection(print.matrixWorld);
    assert.ok(name === 'yubikey-wordmark' ? normal.x < -.999 : normal.y > .999, 'Connector ink faces its exposed surface');
    for (let i = 0; i < index.count; i += Math.max(3, Math.ceil(index.count / 30) * 3)) {
      const center = new THREE.Vector3();
      for (let j = 0; j < 3; j++) center.add(new THREE.Vector3().fromBufferAttribute(position, index.getX(i + j)));
      center.multiplyScalar(1 / 3).z += .01;
      const ray = new THREE.Raycaster(print.localToWorld(center), new THREE.Vector3(0, 0, -1).transformDirection(print.matrixWorld));
      assert.equal(ray.intersectObject(print.parent, true)[0]?.object, print, 'The complete print clears the connector surface');
    }
  }
  assert.ok(new THREE.Vector3(0, 1, 0).transformDirection(get('caldigit-mac-logo').matrixWorld).z > .999, 'The CalDigit baseline faces the back of the desk');
  const cable = get('macbook-ts4-cable'), { path, radius } = cable.geometry.parameters;
  for (const [plug, t, sign] of [[macPlug, 0, -1], [dockPlug, 1, 1]]) {
    const relief = get(`${plug.name}-strain-relief`), end = relief.localToWorld(new THREE.Vector3(0, -relief.geometry.parameters.height / 2, 0));
    assert.ok(cable.localToWorld(path.getPoint(t)).distanceTo(end) < 1e-9, 'The cable begins exactly at the strain relief');
    assert.ok(path.getTangent(t).transformDirection(cable.matrixWorld).dot(new THREE.Vector3(0, sign, 0).transformDirection(relief.matrixWorld)) > .99, 'The cable leaves each connector without a sharp kink');
    assert.ok(plug.getWorldScale(new THREE.Vector3()).distanceTo(new THREE.Vector3(1, 1, 1)) < 1e-9, 'Both connectors retain their physical proportions');
  }
  for (let i = 1; i < path.curves.length; i++) {
    const previous = path.curves[i - 1], next = path.curves[i];
    assert.ok(previous.getPoint(1).distanceTo(next.getPoint(0)) < 1e-9, 'Cable sections meet without gaps');
    assert.ok(previous.getTangent(1).dot(next.getTangent(0)) > .999999, 'Adjacent cable sections retain a smooth tangent');
  }
  const obstacles = ['macbook-unibody', 'mouse-laptop-unibody', 'dock-finned-shell', 'clock-housing', 'desk-frame-rail', 'desk-cable-tray-base', 'desk-cable-tray-lip'].map(name => {
    const object = get(name), scale = object.getWorldScale(new THREE.Vector3());
    return [object, bounds(object).expandByScalar(radius / Math.min(scale.x, scale.y, scale.z))];
  });
  for (let i = 0; i <= 300; i++) {
    const point = cable.localToWorld(path.getPoint(i / 300));
    assert.ok(point.toArray().every(Number.isFinite));
    for (const [object, box] of obstacles) assert.ok(!box.containsPoint(object.worldToLocal(point.clone())), `The cable clears ${object.name}`);
  }
  const table = get('desk').children.find(object => object.material?.name === 'oak'), tableBounds = new THREE.Box3().setFromObject(table, true), top = tableBounds.max.y;
  const room = createRoom(); room.updateMatrixWorld(true);
  const rearWall = new THREE.Box3().setFromObject(room.getObjectByName('back-wall'), true), cableBounds = new THREE.Box3().setFromObject(cable, true);
  assert.ok(cableBounds.min.z > rearWall.max.z + .010, 'The hanging slack retains room behind it instead of touching the wall');
  const trayBounds = new THREE.Box3().setFromObject(get('desk-cable-tray'), true), railTop = new THREE.Box3().setFromObject(get('desk-frame-rail'), true).max.y;
  assert.ok(cableBounds.min.y > trayBounds.min.y + .010 && cableBounds.min.y < top - .05, 'The spare length hangs close to the case instead of below it');
  room.traverse(object => object.geometry?.dispose());
  const frontEye = new THREE.Vector3(...screenView.position), occluders = [get('desk'), get('desk-cable-tray')];
  const vertices = cable.geometry.attributes.position;
  for (let i = 0; i < vertices.count; i++) {
    const point = cable.localToWorld(new THREE.Vector3().fromBufferAttribute(vertices, i));
    const hit = new THREE.Raycaster(new THREE.Vector3(point.x, top + .1, point.z), new THREE.Vector3(0, -1, 0)).intersectObject(table)[0];
    assert.ok(!hit || point.y >= hit.point.y - 1e-6, 'The complete cable surface clears the actual beveled tabletop');
    if (point.y < tableBounds.min.y) {
      const sight = point.clone().sub(frontEye), distance = sight.length();
      assert.ok(new THREE.Raycaster(frontEye, sight.normalize(), 0, distance - radius).intersectObjects(occluders, true).length, 'The hanging slack is physically hidden from the default front view');
    }
    if (point.y < railTop - .0001) assert.ok(new THREE.Raycaster(point, new THREE.Vector3(0, 0, 1), radius, 2).intersectObjects(occluders, true).length, 'The lower slack stays behind the actual case lip or rail in a level front view');
  }
  model.traverse(object => object.geometry?.dispose());
});

test('COFO controls retain the left mounting position and the photographed three-column layout', () => {
  const model = createWorkstation(); model.updateMatrixWorld(true);
  const panel = model.getObjectByName('desk-controls');
  assert.equal(panel.position.x, -.68);
  assert.ok(panel.rotation.x < 0, 'The control face tilts upward towards the seated user');
  for (const name of ['desk-control-mount', 'desk-control-bracket']) {
    const bounds = new THREE.Box3().setFromObject(model.getObjectByName(name), true);
    assert.ok(Math.abs(bounds.max.y - .720) < 1e-6, 'The mount meets the tabletop underside');
  }
  const center = name => new THREE.Box3().setFromObject(model.getObjectByName(`desk-control-${name}`), true).getCenter(new THREE.Vector3());
  assert.ok(center('display').x < center('up').x && center('up').x < center('one').x && center('one').x < center('three').x);
  for (const [upper, lower] of [['up', 'down'], ['one', 'two'], ['three', 'memory']]) assert.ok(center(upper).y > center(lower).y);
  for (const i of [1, 2, 3]) assert.ok(model.getObjectByName(`desk-control-column-${i}`) && model.getObjectByName(`desk-control-separator-${i}`));
  model.traverse(object => object.geometry?.dispose());
});

test('small printed legends retain their counters and clear the front of their housing', () => {
  const model = createWorkstation(); model.updateMatrixWorld(true);
  for (const name of ['desk-control-one', 'desk-control-two', 'desk-control-three', 'desk-control-memory', 'dock-brand', 'dock-print-data', 'dock-print-power', 'clock-brand']) {
    const print = model.getObjectByName(name), { geometry } = print;
    geometry.computeBoundingBox();
    assert.ok(geometry.boundingBox.max.z - geometry.boundingBox.min.z < 1e-8, `${name} is flat printed ink`);
    const normals = geometry.attributes.normal;
    for (let i = 0; i < normals.count; i++) assert.ok(normals.getZ(i) > .999, `${name} faces outwards`);
    let housing = print.parent;
    while (!housing.userData.label && housing.parent) housing = housing.parent;
    const positions = geometry.attributes.position, indices = geometry.index;
    const stride = Math.max(3, Math.ceil(indices.count / 36) * 3);
    for (let i = 0; i < indices.count; i += stride) {
      const center = new THREE.Vector3();
      for (let j = 0; j < 3; j++) center.add(new THREE.Vector3().fromBufferAttribute(positions, indices.getX(i + j)));
      center.multiplyScalar(1 / 3).z += .01;
      const ray = new THREE.Raycaster(print.localToWorld(center), new THREE.Vector3(0, 0, -1).transformDirection(print.matrixWorld), 0, .02);
      assert.ok(ray.intersectObject(housing, true)[0]?.object === print, `${name} must not sink into its housing`);
    }
  }
  for (const [name, counters] of [['dock-brand', 3], ['clock-brand', 1]]) {
    const shapes = model.getObjectByName(name).geometry.parameters.shapes;
    assert.equal(shapes.reduce((count, shape) => count + shape.holes.length, 0), counters, `${name} retains open letter counters`);
  }
  assert.equal(model.getObjectByName('clock-brand').material.name, 'clock-print', 'The entire SEIKO wordmark uses one uniform print material');
  model.traverse(object => object.geometry?.dispose());
});

test('the US Mac and JIS Mouse keep distinct keyboards, readable ink and physical controls', () => {
  const mac = keyLayout('macbook'), mouse = keyLayout('mouse-laptop');
  assert.equal(mac.length, 78, 'US MacBook has 78 keys including Touch ID and the inverse-T arrows');
  assert.ok(mac.every(cap => !/[ぁ-んァ-ン一-龯]/u.test(cap.label + (cap.secondary || ''))), 'US keys do not retain kana or conversion legends');
  assert.equal(mac.filter(cap => cap.label === 'command').length, 2);
  assert.equal(mac.filter(cap => cap.label === 'option').length, 2);
  const enter = mac.find(cap => cap.label === 'return'), letter = mac.find(cap => cap.label === 'A');
  assert.ok(enter.w > letter.w * 1.7 && enter.d === letter.d, 'ANSI Return is wide and one row tall');
  assert.ok(mouse.some(cap => cap.label === '無変換') && mouse.some(cap => cap.label === '7' && cap.secondary === 'Home'), 'Mouse retains Japanese conversion keys and its numeric keypad');
  for (const caps of [mac, mouse]) for (let i = 0; i < caps.length; i++) for (let j = i + 1; j < caps.length; j++) {
    const a = caps[i], b = caps[j];
    assert.ok(Math.abs(a.x - b.x) >= (a.w + b.w) / 2 || Math.abs(a.z - b.z) >= (a.d + b.d) / 2, `Keycaps ${a.label}/${b.label} must not overlap`);
  }

  // Exercise the actual Canvas drawing path without needing a browser or a font rasterizer.
  const originalDocument = globalThis.document, texts = [];
  globalThis.document = { createElement() {
    const calls = []; texts.push(calls);
    const context = new Proxy({ fillText(text) { calls.push({ text, font: this.font, color: this.fillStyle }); } }, { get: (target, name) => name in target ? target[name] : () => {} });
    return { getContext: () => context };
  } };
  try {
    const maps = createKeyboardTextures();
    const a = texts[0].find(item => item.text === 'A');
    assert.equal(a.color, '#f7f7f5', 'Mac lettering is neutral white');
    assert.ok(Number(a.font.match(/([\d.]+)px/u)[1]) >= 26, 'The 4.1 mm main print retains detail in a close-up');
    assert.equal(texts[1].find(item => item.text === 'Fn').color, '#72a6d6', 'Mouse function markings remain blue');
    for (const map of Object.values(maps)) map.dispose();
  } finally { if (originalDocument === undefined) delete globalThis.document; else globalThis.document = originalDocument; }

  const model = createWorkstation();
  const get = name => { const item = model.getObjectByName(name); assert.ok(item, name); return item; };
  assert.equal(get('macbook-lid').rotation.x, -THREE.MathUtils.degToRad(30));
  assert.ok(get('macbook-key-A').material.color.getHex() < get('macbook-unibody').material.color.getHex(), 'Keycaps are darker than Space Black aluminum');
  assert.ok(get('macbook-touch-id-ring').geometry && get('macbook-touch-id').geometry);
  model.updateMatrixWorld(true);
  const lid = get('macbook-lid');
  const lidHit = (x, y) => new THREE.Raycaster(lid.localToWorld(new THREE.Vector3(x, y, .1)), new THREE.Vector3(0, 0, -1).transformDirection(lid.matrixWorld)).intersectObject(lid, true)[0]?.object;
  assert.equal(lidHit(.006, .2071), get('macbook-cover-glass'), 'The notch reveals the continuous bezel glass instead of a different black patch');
  assert.equal(lidHit(.006, .212), get('macbook-cover-glass'), 'The notch and adjacent bezel share a single physical glass face');
  assert.equal(lidHit(.016, .2071), get('macbook-screen'), 'The display remains intact beside the camera cutout');
  assert.equal(lidHit(0, .202), get('macbook-screen'), 'The display remains intact below the camera cutout');
  for (const name of ['dc', 'ethernet', 'vga', 'hdmi', 'usb-c', 'usb-a-left', 'sd']) assert.ok(get(`mouse-port-${name}`).position.x < 0, `${name} belongs on the left edge`);
  for (const name of ['headphone', 'microphone', 'usb2-right', 'usb3-right', 'security-lock']) assert.ok(get(`mouse-port-${name}`).position.x > 0, `${name} belongs on the right edge`);
  assert.ok(get('mouse-exhaust-slot').position.x > 0, 'Exhaust belongs on the right, not over the left video ports');
  const leftButton = get('mouse-trackpad-left-button'), rightButton = get('mouse-trackpad-right-button');
  assert.ok(leftButton.position.x < rightButton.position.x && leftButton.position.z > get('mouse-laptop-trackpad').position.z, 'Separate click buttons sit below the touch surface');
  const decals = get('mouse-palmrest-decals').geometry;
  decals.computeBoundingBox();
  assert.ok(decals.boundingBox.max.x < -.095 && decals.boundingBox.min.x > -.188, 'Both stickers sit on the palmrest left of the trackpad');
  assert.ok(decals.boundingBox.min.y > .0226 && decals.boundingBox.max.y < .023, 'The thin decals clear the level palmrest');
  for (let i = 0; i < decals.attributes.uv.count; i++) {
    assert.ok(decals.attributes.uv.getX(i) >= 0 && decals.attributes.uv.getX(i) <= 1);
    assert.ok(decals.attributes.uv.getY(i) >= 0 && decals.attributes.uv.getY(i) <= 1);
  }
  assert.equal(decals.attributes.uv.getY(0), 1, 'Sound Blaster occupies the first image cell with its top toward the keyboard');
  assert.equal(decals.attributes.uv.getY(4), .5, 'NVIDIA occupies the second image cell');
  get('mouse-power-button').geometry.computeBoundingBox();
  const buttonFront = get('mouse-power-button').position.z + get('mouse-power-button').geometry.boundingBox.max.z;
  assert.ok(buttonFront < Math.min(...mouse.map(cap => cap.z - cap.d / 2)), 'The centered power button clears the first row of keys');
  assert.equal(get('mouse-power-button').geometry.parameters.shapes.getPoints().length, 5, 'The power button has the photographed five-sided outline');
  assert.ok(get('mouse-power-button').material === get('mouse-laptop-unibody').material, 'The button uses the same dark plastic as the body');
  const buttonTop = get('mouse-power-button').position.y + get('mouse-power-button').geometry.boundingBox.max.y;
  get('mouse-power-symbol').geometry.computeBoundingBox();
  assert.ok(get('mouse-power-symbol').geometry.boundingBox.min.y > buttonTop, 'The complete white power mark stays above the button face');
  for (const i of [1, 2]) {
    const lamp = get(`mouse-status-light-${i}`);
    assert.ok(lamp.position.x < -.09 && lamp.position.z > .133, 'Both status lamps belong at the front left');
    assert.equal(lamp.material.name, 'mouse-status-led');
  }
  model.updateMatrixWorld(true);
  const mouseBody = get('mouse-laptop-unibody');
  const underside = z => {
    const ray = new THREE.Raycaster(get('mouse-laptop').localToWorld(new THREE.Vector3(.12, -.1, z)), new THREE.Vector3(0, 1, 0));
    const hit = ray.intersectObject(mouseBody, false)[0];
    assert.ok(hit, 'The tapered chassis retains a closed underside');
    return get('mouse-laptop').worldToLocal(hit.point).y;
  };
  assert.ok(Math.abs(underside(.099) - .0028) < 1e-6, 'Front feet and ports keep the original flat lower shell before the taper');
  assert.ok(.0226 - underside(.132) < .005, 'The final front edge tapers to under 5 mm while the deck stays level');
  for (const letter of ['o', 'e']) assert.equal(get(`mouse-brand-${letter}`).geometry.parameters.shapes[0].holes.length, 1, 'Filled lowercase logos retain their counters');
  model.traverse(object => object.geometry?.dispose());
});
