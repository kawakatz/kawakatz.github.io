import test from 'node:test';
import assert from 'node:assert/strict';
import * as THREE from 'three';
import { createRoom } from '../assets/js/room.js';
import { createWorkstation } from '../assets/js/workstation.js';

test('the bed leaves working space behind the chair and furnishings rest inside the room', () => {
  const room = createRoom(), desk = createWorkstation();
  const bed = new THREE.Box3().setFromObject(room.getObjectByName('simmons-bed'));
  const chair = new THREE.Box3().setFromObject(desk.getObjectByName('chair'));
  assert.ok(bed.min.z - chair.max.z > .30, 'The bed must clear the chair');
  assert.ok(bed.min.x > room.position.x - 1.42 && bed.max.x < room.position.x + 1.42 && bed.max.z < 3.30);
  assert.ok(Math.abs(bed.min.y) < .002, 'Bed legs must touch the floor');
  const wall = new THREE.Box3().setFromObject(room.getObjectByName('bed-wall-below-window'));
  assert.ok(wall.min.z - bed.max.z > .015 && wall.min.z - bed.max.z < .08, 'The bedding must lie close to the wall without intersecting it');
  const deskBox = new THREE.Box3().setFromObject(desk.getObjectByName('desk'));
  const backWall = new THREE.Box3().setFromObject(room.getObjectByName('back-wall'));
  assert.ok(Math.abs(deskBox.min.z - backWall.max.z - .05) < .001, 'Desk sits 5 cm from the wall');
  const mainWindow = new THREE.Box3().setFromObject(room.getObjectByName('window-glow'));
  assert.ok(mainWindow.max.z - mainWindow.min.z > 3.1, 'The floor-height window remains broad beside the solid outlet corner');
  assert.ok(Math.abs(deskBox.min.x - mainWindow.max.x - .28) < .001, 'The desk must sit close to the left window');
  const curtain = new THREE.Box3().setFromObject(room.getObjectByName('pleated-curtain'));
  assert.ok(deskBox.min.x - curtain.max.x > .075, 'The desk must leave room for the curtain folds');
  const frame = desk.getObjectByName('desk'), feet = frame.children.filter(part => part.name === 'desk-foot');
  assert.equal(feet.length, 2);
  assert.equal(desk.getObjectByName('desk-leveling-foot'), undefined, 'The white feet rest on the floor without raised black pads');
  for (const foot of feet) {
    const bounds = new THREE.Box3().setFromObject(foot), size = bounds.getSize(new THREE.Vector3());
    assert.ok(Math.abs(bounds.min.y) < 1e-6 && size.y > .025 && size.y < .035 && size.z > .60, 'The low foot has the photographed rounded shoulder and rests on the floor');
    assert.ok(foot.material.metalness < .01, 'Painted white feet remain dielectric');
    const column = frame.children.find(part => part.name === 'desk-column-lower' && part.position.x === foot.position.x);
    assert.ok(new THREE.Box3().setFromObject(column).min.y < bounds.max.y, 'The lower column meets the foot');
    for (const z of [-.025, .025]) {
      const start = foot.localToWorld(new THREE.Vector3(0, .1, z));
      const hit = new THREE.Raycaster(start, new THREE.Vector3(0, -1, 0)).intersectObject(foot)[0];
      assert.ok(hit && hit.normal.y > .999, 'The foot preserves a level seat beneath the column');
    }
    for (const z of [-.24, .24]) {
      const top = new THREE.Raycaster(foot.localToWorld(new THREE.Vector3(0, .1, z)), new THREE.Vector3(0, -1, 0)).intersectObject(foot)[0];
      const side = new THREE.Raycaster(foot.localToWorld(new THREE.Vector3(.1, .010, z)), new THREE.Vector3(-1, 0, 0)).intersectObject(foot)[0];
      const halfWidth = side && Math.abs(foot.worldToLocal(side.point.clone()).x);
      assert.ok(top && bounds.max.y - top.point.y > .002 && bounds.max.y - top.point.y < .007, 'The far shoulders are subtly lower than the column seat');
      assert.ok(halfWidth > size.x * .40 && halfWidth < size.x * .48, 'The foot narrows gently before its rounded tip');
      assert.ok(top.normal.y > .99 && top.normal.z * Math.sign(z) > .005, 'Surface normals follow the shallow slope toward each tip');
    }
    const shoulder = new THREE.Raycaster(foot.localToWorld(new THREE.Vector3(size.x / 2 - .005, .1, 0)), new THREE.Vector3(0, -1, 0)).intersectObject(foot)[0];
    assert.ok(shoulder && shoulder.point.y < bounds.max.y - .001 && shoulder.normal.y > .5 && shoulder.normal.y < .98, 'The upper edge rolls smoothly into the side');
  }
  for (const name of ['bed-wall-below-window', 'bed-window-frame', 'bed-window-curtain']) {
    const surface = room.getObjectByName(name);
    const normal = new THREE.Vector3().fromBufferAttribute(surface.geometry.attributes.normal, 0).transformDirection(surface.matrixWorld);
    assert.ok(normal.z < -.85 && surface.material.side === THREE.FrontSide, 'The cutaway must hide the near wall from the exterior view');
  }
  room.traverse(surface => {
    if (surface.name !== 'bed-window-curtain') return;
    const normals = surface.geometry.attributes.normal;
    for (let i = 0; i < normals.count; i++) {
      const normal = new THREE.Vector3().fromBufferAttribute(normals, i);
      for (const yaw of [.05, .76, 1.10]) {
        const exterior = new THREE.Vector3(Math.sin(yaw), Math.sin(.7), Math.cos(yaw));
        assert.ok(normal.dot(exterior) < 0, 'Pleats must not appear as floating strips from the exterior cutaway');
      }
    }
  });
  for (const name of ['pillow-top', 'duvet']) {
    const surface = room.getObjectByName(name);
    const normal = new THREE.Vector3().fromBufferAttribute(surface.geometry.attributes.normal, 0).transformDirection(surface.matrixWorld);
    assert.ok(normal.y > 0, `${name} needs an upward facing fabric surface`);
  }
  const duvet = room.getObjectByName('duvet').geometry.attributes.position;
  const duvetBounds = new THREE.Box3().setFromObject(room.getObjectByName('duvet'));
  const pillowBase = new THREE.Box3().setFromObject(room.getObjectByName('pillow-underside'));
  assert.ok(Math.abs(pillowBase.min.y - .598) < .001, 'The pillow must rest on the mattress');
  assert.ok(duvetBounds.min.y > .25, 'Overlapping side and foot folds must not create dangling corner spikes');
  assert.equal(duvetBounds.intersectsBox(new THREE.Box3().setFromObject(room.getObjectByName('pillow-top'))), false, 'Duvet edge must clear the pillow');
  for (let i = 0; i < duvet.count; i++) {
    const x = duvet.getX(i), z = duvet.getZ(i);
    const dx = Math.max(0, Math.abs(x) - .547), dz = Math.max(0, Math.abs(z) - .922);
    if (dx * dx + dz * dz <= .053 ** 2) {
      const mattressTop = .545 + Math.sqrt(.053 ** 2 - dx * dx - dz * dz);
      assert.ok(duvet.getY(i) > mattressTop + .011, 'Duvet folds must not intersect the mattress');
    }
  }
  for (const model of [room, desk]) model.traverse(object => {
    if (!object.isMesh) return;
    assert.ok([...object.geometry.attributes.position.array].every(Number.isFinite));
    object.geometry.dispose();
  });
});

test('Mouse and desk power routes stay seated and clear the room through their bundled leads', () => {
  const model = createWorkstation(), room = createRoom(); model.updateMatrixWorld(true); room.updateMatrixWorld(true);
  const get = name => { const object = model.getObjectByName(name) || room.getObjectByName(name); assert.ok(object, name); return object; };
  const names = ['mouse-power-connector', 'mouse-power-brick', 'mouse-power-wall-plug', 'mouse-power-dc-cable', 'mouse-power-ac-cable', 'desk-controller-cable', 'desk-extension-cable', 'desk-extension-wall-plug'];
  const charging = []; model.traverse(object => { if (names.includes(object.name)) charging.push(object.name); });
  assert.deepEqual(charging.sort(), [...names].sort(), 'Each connected power route is represented once');
  const mouse = get('mouse-laptop'), plug = get('mouse-power-connector'), dcPort = get('mouse-port-dc');
  assert.equal(plug.parent, mouse); assert.equal(plug.position.y, dcPort.position.y); assert.equal(plug.position.z, dcPort.position.z);
  assert.ok(plug.position.x < dcPort.position.x, 'The charger enters the Mouse left-side DC socket');
  const shaft = new THREE.Vector3(0, 0, 1).transformDirection(plug.matrixWorld);
  const exit = new THREE.Vector3(0, -1, 0).transformDirection(get('mouse-power-plug-relief').matrixWorld);
  assert.ok(Math.abs(shaft.dot(exit)) < 1e-6, 'The charging lead leaves through a right-angle elbow');
  for (const [socketName, plugName] of [['tessan-right-ac', 'mouse-power-wall-plug'], ['wall-spare-ac', 'desk-extension-wall-plug']]) {
    const socket = get(socketName), wallPlug = get(plugName), seat = socket.worldToLocal(wallPlug.getWorldPosition(new THREE.Vector3()));
    assert.ok(Math.hypot(seat.x, seat.y) < 1e-6 && seat.z >= 0 && seat.z < .001, 'The plug seats on the actual room socket after both model transforms');
    assert.ok(new THREE.Vector3(0, 0, 1).transformDirection(socket.matrixWorld).dot(new THREE.Vector3(0, 0, 1).transformDirection(wallPlug.matrixWorld)) < -.999, 'The plug points into its wall socket');
  }
  assert.equal(get('wall-spare-ac').children.filter(part => part.name.includes('-blade-')).length, 2);
  assert.equal(room.getObjectByName('wall-spare-ac-ground'), undefined, 'The lower outlet has only two blade slots');
  room.traverse(part => assert.ok(!part.name.startsWith('wall-coax-'), 'The lower module is a power socket'));
  for (const name of ['tessan-front-ac-blade-1', 'tessan-left-ac-blade-1', 'tessan-usb-1-recess', 'tessan-usb-2-recess', 'tessan-usb-3-recess']) {
    const slot = get(name); slot.geometry.computeBoundingBox();
    const center = slot.geometry.boundingBox.getCenter(new THREE.Vector3()); center.z += .04;
    const ray = new THREE.Raycaster(slot.localToWorld(center), new THREE.Vector3(0, 0, -1).transformDirection(slot.matrixWorld));
    assert.equal(ray.intersectObjects([model, room], true)[0]?.object, slot, 'The unused outlets remain visibly empty');
  }
  const shell = get('desk-extension-plug-body'), bowl = get('desk-extension-plug-finger-recess');
  const shellPoints = [...new Set(shell.geometry.index.array)].map(i => shell.localToWorld(new THREE.Vector3().fromBufferAttribute(shell.geometry.attributes.position, i)));
  const bowlPoints = bowl.geometry.attributes.position, rimHeight = bowl.geometry.parameters.points.at(-1).y;
  for (let i = 0; i < bowlPoints.count; i++) if (Math.abs(bowlPoints.getY(i) - rimHeight) < 1e-8) {
    const rim = bowl.localToWorld(new THREE.Vector3().fromBufferAttribute(bowlPoints, i));
    assert.ok(shellPoints.some(point => point.distanceTo(rim) < 1e-7), 'The finger bowl meets the shell opening without a gap');
  }
  const shellSide = shell.material.side; shell.material.side = THREE.DoubleSide;
  try {
    for (let i = 0; i < 8; i++) {
      const angle = i * Math.PI / 4;
      const ray = new THREE.Raycaster(shell.localToWorld(new THREE.Vector3(0, -.015, .0003)), new THREE.Vector3(Math.cos(angle), Math.sin(angle), 0).transformDirection(shell.matrixWorld));
      assert.ok((ray.intersectObject(shell)[0]?.distance ?? Infinity) > .007, 'No hidden tunnel wall traps a dark rim behind the finger bowl');
    }
  } finally { shell.material.side = shellSide; }
  for (const [name, t, reliefName, end] of [
    ['mouse-power-dc-cable', 0, 'mouse-power-plug-relief', -1], ['mouse-power-dc-cable', 1, 'mouse-power-brick-dc-relief', 1],
    ['mouse-power-ac-cable', 0, 'mouse-power-wall-relief', -1], ['mouse-power-ac-cable', 1, 'mouse-power-brick-ac-relief', -1],
    ['desk-controller-cable', 0, 'desk-controller-relief', -1], ['desk-controller-cable', 1, 'desk-controller-tray-relief', 1],
    ['desk-extension-cable', 0, 'desk-extension-wall-relief', -1], ['desk-extension-cable', 1, 'desk-extension-strip-relief', 1],
  ]) {
    const cable = get(name), relief = get(reliefName);
    const terminal = relief.localToWorld(new THREE.Vector3(0, end * relief.geometry.parameters.height / 2, 0));
    const { path } = cable.geometry.parameters;
    assert.ok(cable.localToWorld(path.getPoint(t)).distanceTo(terminal) < 1e-9, `${name} meets its strain relief without a gap`);
    assert.ok(path.getTangent(t).transformDirection(cable.matrixWorld).dot(new THREE.Vector3(0, end * (t ? -1 : 1), 0).transformDirection(relief.matrixWorld)) > .99, `${name} follows its connector axis`);
  }
  assert.equal(get('desk-controller-relief').parent, get('desk-controls'));
  assert.equal(get('desk-controller-tray-relief').parent, get('desk-cable-tray'));
  assert.equal(get('desk-extension-strip-relief').parent, get('desk-cable-tray'));
  const trayRelief = get('desk-controller-tray-relief'), trayBase = get('desk-cable-tray-base');
  trayBase.geometry.computeBoundingBox();
  assert.ok(Math.abs(trayRelief.position.x - trayBase.geometry.boundingBox.min.x) < .025
    && new THREE.Vector3(0, 1, 0).applyQuaternion(trayRelief.quaternion).x < -.999, 'The controller cable enters the cable case through its left opening');
  const controllerZ = get('desk-controller-relief').getWorldPosition(new THREE.Vector3()).z;
  const trayZ = get('desk-controller-tray-relief').getWorldPosition(new THREE.Vector3()).z;
  assert.ok(Math.abs(get('desk-controller-bundle').getWorldPosition(new THREE.Vector3()).z - (controllerZ + trayZ) / 2) < Math.abs(controllerZ - trayZ) * .15, 'The black bundle hangs midway between the controller and rear tray');
  for (const name of ['desk-controller', 'desk-extension']) {
    const bundle = get(`${name}-bundle`), cable = get(`${name}-cable`), { path, radius, crossSection } = cable.geometry.parameters;
    const strap = get(`${name}-bundle-strap`);
    const band = new THREE.Box3().setFromBufferAttribute(strap.geometry.attributes.position)
      .applyMatrix4(new THREE.Matrix4().multiplyMatrices(bundle.matrixWorld.clone().invert(), strap.matrixWorld));
    const waists = path.curves.map(curve => bundle.worldToLocal(cable.localToWorld(curve.getPoint(0))))
      .filter(point => Math.abs(point.y) < 1e-7 && point.x > band.min.x && point.x < band.max.x);
    assert.ok(waists.length >= 4 && waists.some(point => point.x < 0) && waists.some(point => point.x > 0), 'The folded cord gathers into two columns under the band');
    const section = crossSection || [radius * 2, radius * 2];
    const gathered = new THREE.Box3().setFromPoints(waists).expandByVector(new THREE.Vector3(section[0] / 2, 0, section[1] / 2));
    assert.ok(gathered.min.x >= band.min.x - .0005 && gathered.max.x <= band.max.x + .0005
      && gathered.min.z >= band.min.z - .0005 && gathered.max.z <= band.max.z + .0005, 'The band wraps around the gathered cable cross sections');
    assert.ok(band.max.x - band.min.x < gathered.max.x - gathered.min.x + section[0] * 2, 'The tie stays close to its gathered cords');
    if (!crossSection) {
      const samples = path.getSpacedPoints(1800), skip = Math.ceil(radius * 4 * 1800 / path.getLength());
      let clearanceSquared = Infinity;
      for (let i = 0; i < samples.length; i++) for (let j = i + skip; j < samples.length; j++) {
        clearanceSquared = Math.min(clearanceSquared, samples[i].distanceToSquared(samples[j]));
      }
      assert.ok(clearanceSquared > (radius * 2) ** 2, `${name} coil turns and exit stay separated along the sampled route`);
      continue;
    }
    assert.ok(crossSection[0] > crossSection[1] * 1.8, 'The white extension keeps its flat twin-cord profile');
    assert.ok(new THREE.Box3().setFromObject(cable, true).min.y < .0002, 'The white folded cord rests on the floor');
    const firstPass = path.curves.findIndex(curve => band.containsPoint(bundle.worldToLocal(cable.localToWorld(curve.getPoint(0)))));
    assert.ok(firstPass > 0, 'The loose lead reaches the band before the folded turns');
    const entryCurves = path.curves.slice(0, firstPass), dc = get('mouse-power-dc-cable');
    assert.ok(entryCurves.reduce((length, curve) => length + curve.getLength(), 0) > 1.04, 'The wall-to-bundle lead retains loose length on the floor');
    const dcPoints = dc.geometry.parameters.path.getSpacedPoints(300).map(point => dc.localToWorld(point));
    const nearby = ['mouse-power-brick', 'back-wall'].map(name => new THREE.Box3().setFromObject(get(name), true));
    for (const curve of entryCurves) {
      const points = curve.getPoints(100);
      for (const point of points) {
        const world = cable.localToWorld(point.clone());
        assert.ok(nearby.every(box => box.distanceToPoint(world) > .005), 'The loose lead clears the charger brick and rear wall');
        assert.ok(dcPoints.every(sample => sample.distanceTo(world) > .015), 'The loose white lead stays separate from the Mouse DC cable');
      }
      for (let i = 1; i < points.length - 1; i++) {
        const a = points[i].clone().sub(points[i - 1]), b = points[i + 1].clone().sub(points[i]);
        const cross = a.clone().cross(b).length();
        const radius = a.length() * b.length() * points[i - 1].distanceTo(points[i + 1]) / (2 * cross);
        assert.ok(radius > .020, 'The stiff white lead approaches the band through broad bends, without a tight kink');
      }
    }
    const { tubularSegments: count, radialSegments: sides } = cable.geometry.parameters, index = cable.geometry.index.array;
    const vertices = Array.from({ length: cable.geometry.attributes.position.count }, (_, i) => new THREE.Vector3().fromBufferAttribute(cable.geometry.attributes.position, i));
    const spans = Array.from({ length: count }, (_, i) => new THREE.Box3().setFromPoints(vertices.slice(i * (sides + 1), (i + 2) * (sides + 1))));
    const skip = Math.ceil(crossSection[0] * 2 * count / path.getLength()), ray = new THREE.Ray(), hit = new THREE.Vector3();
    for (let i = 0; i < count; i++) for (let j = i + skip; j < count; j++) {
      if (!spans[i].intersectsBox(spans[j])) continue;
      for (let a = i * sides * 6; a < (i + 1) * sides * 6; a += 3) for (let b = j * sides * 6; b < (j + 1) * sides * 6; b += 3) {
        for (const [edge, triangle] of [[a, b], [b, a]]) for (let k = 0; k < 3; k++) {
          const start = vertices[index[edge + k]], end = vertices[index[edge + (k + 1) % 3]], length = start.distanceTo(end);
          ray.set(start, end.clone().sub(start).normalize());
          const crossing = ray.intersectTriangle(vertices[index[triangle]], vertices[index[triangle + 1]], vertices[index[triangle + 2]], false, hit);
          assert.ok(!crossing || hit.distanceTo(start) <= 1e-7 || hit.distanceTo(start) >= length - 1e-7, `The flat cord surfaces must not intersect between spans ${i} and ${j}`);
        }
      }
    }
  }
  const dcCable = get('mouse-power-dc-cable'), ferrite = get('mouse-power-ferrite');
  const straight = dcCable.geometry.parameters.path.curves.find(curve => curve.isLineCurve3);
  assert.ok(straight, 'The rigid ferrite contains a straight cable section');
  const axis = new THREE.Line3(dcCable.localToWorld(straight.getPoint(0)), dcCable.localToWorld(straight.getPoint(1)));
  for (const collar of ferrite.children.filter(part => part.geometry.type === 'CylinderGeometry')) for (const end of [-1, 1]) {
    const center = collar.localToWorld(new THREE.Vector3(0, end * collar.geometry.parameters.height / 2, 0));
    assert.ok(axis.closestPointToPoint(center, true, new THREE.Vector3()).distanceTo(center) < 1e-9, 'The straight cable passes through both ferrite collars along their center axis');
  }
  const desk = get('desk'), table = desk.children.find(object => object.material?.name === 'oak');
  const tableBox = new THREE.Box3().setFromObject(table, true), floor = new THREE.Box3().setFromObject(get('floorboard'), true).max.y;
  const obstacles = desk.children.filter(object => object.geometry && object !== table).map(object => new THREE.Box3().setFromObject(object, true));
  const wallBoundaries = [];
  room.traverse(object => { if (object.name.endsWith('skirting') || ['back-wall', 'outlet-side-wall'].includes(object.name)) wallBoundaries.push(new THREE.Box3().setFromObject(object, true)); });
  room.traverse(object => { if (object.name === 'pleated-curtain') obstacles.push(new THREE.Box3().setFromObject(object, true)); });
  const hanging = new THREE.Box3().setFromObject(get('mouse-power-dc-cable'), true);
  assert.ok(hanging.min.x < tableBox.min.x && hanging.min.y < .02 && hanging.max.y > tableBox.max.y, 'The DC lead hangs over the left edge and reaches the floor');
  for (const name of ['mouse-power-dc-cable', 'mouse-power-ac-cable', 'mouse-power-earth-lead', 'desk-controller-cable', 'desk-extension-cable']) {
    const cable = get(name), vertices = cable.geometry.attributes.position;
    const curves = cable.geometry.parameters.path.curves || [];
    for (let i = 1; i < curves.length; i++) {
      assert.ok(curves[i - 1].getPoint(1).distanceTo(curves[i].getPoint(0)) < 1e-9, `${name} sections meet without gaps`);
      assert.ok(curves[i - 1].getTangent(1).dot(curves[i].getTangent(0)) > .99999, `${name} sections have aligned tangents`);
    }
    for (let i = 0; i < vertices.count; i++) {
      const point = cable.localToWorld(new THREE.Vector3().fromBufferAttribute(vertices, i));
      assert.ok(point.toArray().every(Number.isFinite) && point.y >= floor - 1e-6, `${name} stays above the room floor at vertex ${i}`);
      assert.ok(obstacles.every(box => !box.containsPoint(point)), `${name} clears the desk frame, feet and curtains at vertex ${i}`);
      if (name === 'desk-extension-cable') assert.ok(wallBoundaries.every(box => box.distanceToPoint(point) >= .003), `The flat white cord keeps at least 3 mm clear of walls and skirting at vertex ${i}`);
      if (!tableBox.containsPoint(point)) continue;
      const upper = new THREE.Raycaster(new THREE.Vector3(point.x, tableBox.max.y + .1, point.z), new THREE.Vector3(0, -1, 0)).intersectObject(table)[0];
      const lower = new THREE.Raycaster(new THREE.Vector3(point.x, tableBox.min.y - .1, point.z), new THREE.Vector3(0, 1, 0)).intersectObject(table)[0];
      assert.ok(!upper || !lower || point.y >= upper.point.y - 1e-6 || point.y <= lower.point.y + 1e-6, 'The lead curves around the actual beveled edge without crossing the tabletop');
    }
  }
  const brick = get('mouse-power-brick'), body = get('mouse-power-brick-housing');
  const feet = brick.children.filter(object => object.name === 'mouse-power-brick-foot');
  assert.equal(feet.length, 4);
  for (const foot of feet) {
    const box = new THREE.Box3().setFromObject(foot, true), center = box.getCenter(new THREE.Vector3());
    assert.ok(Math.abs(box.min.y - floor) < 1e-6, 'The adapter rests on the floor');
    const contact = new THREE.Raycaster(new THREE.Vector3(center.x, floor - .01, center.z), new THREE.Vector3(0, 1, 0)).intersectObject(body)[0];
    assert.ok(contact && contact.point.y <= box.max.y + 1e-6, 'The adapter feet meet the housing');
  }
  for (const object of [model, room]) object.traverse(part => part.geometry?.dispose());
});
