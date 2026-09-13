import test from 'node:test';
import assert from 'node:assert/strict';
import * as THREE from 'three';
import { readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { createWorkstation, fitCamera, monitorView, monitorScreen, overview } from '../assets/js/workstation.js';
import { keyLayout } from '../assets/js/keyboard.js';
import { screenView, screenViewPose, screenViewFov, lensFov } from '../assets/js/screen-view.js';
import { ease, matchesNote, previewPosition } from '../assets/js/navigation.js';

test('Others previews stay inside the viewport and flip above links near the bottom', () => {
  const size = { width: 320, height: 240 };
  assert.deepEqual(previewPosition({ left: 200, top: 100, bottom: 120 }, size, { width: 1200, height: 800 }), { left: 200, top: 130 });
  assert.deepEqual(previewPosition({ left: 350, top: 650, bottom: 675 }, size, { width: 375, height: 700 }), { left: 43, top: 400 });
  assert.deepEqual(previewPosition({ left: -20, top: 20, bottom: 40 }, size, { width: 375, height: 260 }), { left: 12, top: 12 });
});

test('the workstation matches the photo layout and frames correctly on narrow and wide screens', () => {
  const model = createWorkstation();
  const get = name => model.getObjectByName(name);
  assert.ok(get('mouse-laptop').position.x < get('macbook').position.x);
  assert.ok(get('mouse-laptop').rotation.y > .5 && get('mouse-laptop').rotation.y < 1, 'Mouse PC should sit diagonally');
  assert.ok(get('desk-controls').position.x < -.5, 'Height controls belong on the left');
  assert.equal(get('macbook').position.x, get('monitor').position.x, 'MacBook and monitor must share their centerline');
  assert.equal(get('chair').rotation.y, 0, 'Chair should face the desk squarely');
  assert.equal(get('chair').position.x, get('macbook').position.x);
  assert.ok(get('macbook').position.x < get('ipad').position.x);
  assert.ok(get('monster-can').position.z > get('ipad').position.z);
  const can = get('can-body').geometry;
  for (let i = 0; i < can.attributes.position.count; i++) assert.ok(Math.abs(can.attributes.uv.getY(i) - can.attributes.position.getY(i) / .153) < 1e-6, 'Can artwork must track physical height, not profile point index');
  const canFacing = new THREE.Vector3(0, 0, 1).transformDirection(get('can-body').matrixWorld);
  const canToCamera = new THREE.Vector3(...screenView.position).sub(get('monster-can').getWorldPosition(new THREE.Vector3())).setY(0).normalize();
  assert.ok(canFacing.dot(canToCamera) > .9999, 'The can front faces the default chair camera');
  assert.ok(Math.abs(get('monster-can').position.x - get('ipad').position.x) < .18);
  assert.ok(get('can-opening').position.z > 0, 'The can opening faces the front of the desk');
  const strawPath = get('can-straw').geometry.parameters.path;
  const inserted = strawPath.getPoint(0);
  assert.ok(inserted.y < get('can-opening').position.y, 'Straw extends into the opening');
  const shaft = strawPath.curves[0], opening = get('can-opening').position;
  const passage = shaft.getPoint((opening.y - shaft.v1.y) / (shaft.v2.y - shaft.v1.y));
  assert.ok(passage.distanceTo(opening) < 1e-6, 'The leaning straw passes through the actual can opening');
  assert.ok(Math.abs(strawPath.getLength() - .25) < .0001 && get('can-straw').geometry.parameters.radius === .003, 'The reference straw is 25 cm long and 6 mm wide');
  const tip = strawPath.getPoint(1), towardChair = get('chair').position.clone().sub(get('monster-can').position).setY(0).normalize();
  assert.ok(tip.clone().sub(inserted).setY(0).normalize().dot(towardChair) > .98, 'Drinking end points toward the chair');
  assert.ok(tip.y - get('can-opening').position.y < .10, 'Exposed straw stays a natural drinking length');
  assert.equal(get('clock').scale.x, .9);
  const clockFacing = new THREE.Vector3(0, 0, 1).transformDirection(get('clock').matrixWorld);
  const towardCamera = new THREE.Vector3(...screenView.position).sub(get('clock').getWorldPosition(new THREE.Vector3())).setY(0).normalize();
  assert.ok(clockFacing.dot(towardCamera) > .96 && get('clock').rotation.y > 0 && get('dock').rotation.y === 0, 'Clock faces slightly right and remains readable from the default camera without turning the dock');
  assert.ok(Math.abs(get('mouse-power-button').position.x) < .001, 'Power button is centered above the keyboard');
  assert.ok(get('mouse-power-button').position.z < Math.min(...keyLayout('mouse-laptop').map(k => k.z-k.d/2)));
  const standSize = new THREE.Box3().setFromObject(get('ipad-stand')).getSize(new THREE.Vector3());
  assert.ok(standSize.y < .019, 'tower 5274 is a low rack, not an elevated support');
  assert.equal(get('ipad-stand').children.filter(part=>part.name==='ipad-stand-rib').length,7);

  // Test the actual tilted shell against the rack, not its much larger axis-aligned box.
  const ipad = get('ipad'), shell = get('ipad-aluminum-shell');
  const contactMaterial = new THREE.MeshBasicMaterial({ side: THREE.DoubleSide });
  const contactMesh = object => { const mesh = new THREE.Mesh(object.geometry, contactMaterial); mesh.matrixWorld.copy(object.matrixWorld); return mesh; };
  const tabletContact = contactMesh(shell), standContacts = get('ipad-stand').children.filter(part=>part.isMesh).map(contactMesh);
  const ribContacts = get('ipad-stand').children.filter(part=>part.name==='ipad-stand-rib').map(contactMesh);
  const backwards = new THREE.Vector3(0,0,-1).transformDirection(ipad.matrixWorld);
  for (const x of [-.035,0,.035]) for (const y of [.006,.010,.014,.017,.0183]) {
    const ray = new THREE.Raycaster(ipad.localToWorld(new THREE.Vector3(x,y,.1)), backwards, 0, .2);
    const section = mesh => ray.intersectObject(mesh,false).map(hit=>ipad.worldToLocal(hit.point.clone()).z);
    const body = section(tabletContact);
    if (!body.length) continue;
    for (const rib of ribContacts) {
      const rack = section(rib);
      if (rack.length) assert.ok(Math.min(Math.max(...body),Math.max(...rack))-Math.max(Math.min(...body),Math.min(...rack)) < .00015, 'iPad shell penetrates a stand rib');
    }
  }
  let bottom = new THREE.Vector3(0,Infinity,0);
  const shellVertices = shell.geometry.attributes.position;
  for (let i=0;i<shellVertices.count;i++) {
    const point = ipad.worldToLocal(new THREE.Vector3().fromBufferAttribute(shellVertices,i).applyMatrix4(shell.matrixWorld));
    if (Math.abs(point.x)<.048 && point.y<bottom.y) bottom.copy(point);
  }
  const supportRay = new THREE.Raycaster(ipad.localToWorld(bottom.clone().add(new THREE.Vector3(0,.002,0))),new THREE.Vector3(0,-1,0),0,.02);
  const support = supportRay.intersectObjects(standContacts,false)[0];
  assert.ok(support && Math.abs(support.distance-.002)<.0002, 'iPad bottom must rest on the silicone slot floor');

  assert.ok(get('monitor').position.z < get('macbook').position.z);
  for (const [name, ratio] of [['macbook-screen', 3024 / 1964], ['mouse-laptop-screen', 16 / 9], ['ipad-screen', 4 / 3]]) {
    get(name).geometry.computeBoundingBox();
    const size = get(name).geometry.boundingBox.getSize(new THREE.Vector3());
    assert.ok(Math.abs(size.x / size.y - ratio) < .001, `${name} must preserve the real display aspect ratio`);
  }
  for (const kind of ['macbook', 'mouse-laptop']) {
    const caps = keyLayout(kind);
    assert.ok(caps.length >= (kind === 'macbook' ? 75 : 100));
    for (let i = 0; i < caps.length; i++) for (let j = i + 1; j < caps.length; j++) {
      const a = caps[i], b = caps[j];
      assert.ok(Math.abs(a.x - b.x) >= (a.w + b.w) / 2 || Math.abs(a.z - b.z) >= (a.d + b.d) / 2, `${kind} keycaps overlap`);
    }
    const underside = new THREE.Box3().setFromObject(get(kind)).min.y;
    assert.ok(Math.abs(underside - .750) < .0003, `${kind} feet must rest on the desktop`);
  }

  const body = new THREE.Box3().setFromObject(get('monitor'));
  const panel = new THREE.Box3().setFromObject(get('monitor-screen'));
  const base = new THREE.Box3().setFromObject(get('monitor-base'));
  assert.ok(Math.abs(body.getCenter(new THREE.Vector3()).x - get('macbook').position.x) < .0001, 'The enlarged Dell remains centered over the MacBook');
  assert.ok(Math.abs(body.getSize(new THREE.Vector3()).x - 1.2151 * 1.1) < .0001, 'The Dell shell grows ten percent sideways without shifting its center');
  const macBounds = new THREE.Box3().setFromObject(get('macbook'), true);
  const ipadBounds = new THREE.Box3().setFromObject(get('ipad-body'), true);
  assert.ok(macBounds.max.y > .95 && macBounds.max.y < .96, 'MacBook stands more upright, with visual readability taking priority over the measured fully-open pose');
  assert.ok(ipadBounds.max.y > .92 && ipadBounds.max.y < .93, 'iPad stands more upright while staying in its low rack');
  assert.ok(Math.abs(body.min.y - .907) < .0005, 'Dell lower bezel follows the measured 15.7 cm above the tabletop');
  assert.ok(Math.abs(monitorScreen.width / monitorScreen.height - 32 / 9) < 1e-8, 'The larger Dell keeps its 32:9 display aspect');
  assert.ok(panel.min.y > body.min.y, 'The display remains inside the lower bezel');
  const deckBounds = new THREE.Box3().setFromObject(get('macbook-unibody'));
  assert.ok(deckBounds.min.z - base.max.z > .03 && deckBounds.max.z < -.02, 'The MacBook deck keeps at least 3 cm of clearance from the Dell base');
  const lidContact = contactMesh(get('macbook-display-housing'));
  const lidStart = Math.max(new THREE.Box3().setFromObject(get('macbook-display-housing'), true).min.z, base.min.z);
  for (const t of [.1, .5, 1]) {
    const z = THREE.MathUtils.lerp(lidStart, base.max.z, t);
    const ray = new THREE.Raycaster(new THREE.Vector3(monitorScreen.center[0], base.max.y, z), new THREE.Vector3(0, 1, 0), 0, .3);
    const hit = ray.intersectObject(lidContact, false)[0];
    assert.ok(hit && hit.distance > .04, 'The open lid passes above the Dell base without touching it');
  }
  contactMaterial.dispose();
  assert.ok(Math.abs(body.getSize(new THREE.Vector3()).y - .371 * 1.1) < .0001);
  assert.ok(Math.abs(base.getSize(new THREE.Vector3()).x - .3803) < .0001);
  assert.ok(base.min.z >= -.57 && base.max.z <= .13, 'The full-size Dell base fits the desktop');
  const mouseBounds = new THREE.Box3().setFromObject(get('mouse-laptop'));
  for (const name of ['clock', 'dock']) {
    const accessory = new THREE.Box3().setFromObject(get(name));
    assert.ok(accessory.min.z > -.57 && accessory.max.z < -.40, `${name} belongs toward the back of the desktop`);
    assert.ok(accessory.max.x <= base.min.x - .008, `${name} keeps at least 8 mm beside the Dell base`);
    assert.equal(mouseBounds.intersectsBox(accessory), false, `${name} must not penetrate the Mouse PC`);
    assert.equal(base.intersectsBox(accessory), false, `${name} must clear the monitor base`);
  }

  for (const x of [-.55, -.3, 0, .3, .55]) {
    const ray = new THREE.Raycaster(new THREE.Vector3(x + monitorScreen.center[0], monitorScreen.center[1], .5), new THREE.Vector3(0, 0, -1));
    assert.equal(ray.intersectObject(get('monitor'), true)[0]?.object.name, 'monitor-screen', 'Curved chassis must not cover the display');
  }
  const thunderbolt = get('macbook-ts4-cable'), cablePoint = new THREE.Vector3();
  for (let i = 0; i < thunderbolt.geometry.attributes.position.count; i++) {
    cablePoint.fromBufferAttribute(thunderbolt.geometry.attributes.position, i).applyMatrix4(thunderbolt.matrixWorld);
    assert.ok(cablePoint.y >= .75 - 1e-5 || cablePoint.z < -.57, 'The Thunderbolt cable descends only beyond the rear tabletop edge');
  }
  for (const name of ['mouse-power-dc-cable', 'mouse-power-ac-cable', 'desk-extension-cable']) {
    const cable = get(name), path = cable.geometry.parameters.path;
    for (let i = 1; i < path.curves.length; i++) {
      const previous = path.curves[i - 1], next = path.curves[i];
      assert.ok(previous.getPoint(1).distanceTo(next.getPoint(0)) < 1e-8, `${name} must stay connected`);
      assert.ok(previous.getTangent(1).dot(next.getTangent(0)) > .999, `${name} must join without a corner`);
    }
    for (let i = 0; i < cable.geometry.attributes.position.count; i++) {
      cablePoint.fromBufferAttribute(cable.geometry.attributes.position, i).applyMatrix4(cable.matrixWorld);
      assert.ok(cablePoint.y >= -1e-5 && cablePoint.z >= -.602, `${name} must clear the floor and rear skirting`);
    }
  }
  const acLead = get('mouse-power-ac-cable').geometry.parameters.path;
  assert.ok(acLead.getLength() > acLead.getPoint(0).distanceTo(acLead.getPoint(1)) * 1.8, 'The adapter lead needs spare length on the floor');
  const cableLook = new THREE.Vector3(-.97, .276, -.25);
  assert.ok(cableLook.x >= screenView.lookX[0] && cableLook.x <= screenView.lookX[1] && cableLook.y >= screenView.lookY[0] && cableLook.y <= screenView.lookY[1]);
  for (const [width, height] of [[1280, 800], [847, 1173]]) {
    const camera = new THREE.PerspectiveCamera(lensFov(screenViewFov(width / height), 1.75), width / height, screenView.near, 100);
    const pose = screenViewPose(cableLook);
    camera.position.copy(pose.position); camera.quaternion.copy(pose.rotation); camera.updateMatrixWorld(true);
    for (const name of ['mouse-power-dc-cable', 'mouse-power-ac-cable', 'mouse-power-brick', 'mouse-power-connector', 'mouse-power-wall-plug', 'mouse-power-ferrite']) get(name).traverse(part => {
      if (!part.isMesh) return;
      for (let i = 0; i < part.geometry.attributes.position.count; i++) {
        cablePoint.fromBufferAttribute(part.geometry.attributes.position, i).applyMatrix4(part.matrixWorld).project(camera);
        assert.ok(Math.abs(cablePoint.x) < .95 && Math.abs(cablePoint.y) < .95 && Math.abs(cablePoint.z) < 1, 'Zooming out must fit the complete Mouse charging assembly');
      }
    });
  }
  const drop = get('mouse-power-dc-cable').geometry.parameters.path.getSpacedPoints(1600);
  for (let i = 1; i < drop.length - 1; i++) {
    const [a, b, c] = [drop[i - 1], drop[i], drop[i + 1]];
    if (b.y < .025 || b.y > .60) continue;
    const cross = b.clone().sub(a).cross(c.clone().sub(a)).length();
    const radius = a.distanceTo(b) * b.distanceTo(c) * a.distanceTo(c) / (2 * cross);
    assert.ok(radius > .03, 'The hanging Mouse lead must ease into the floor instead of bending sharply');
  }
  const monitorBounds = new THREE.Box3().setFromObject(get('monitor'));
  for (const name of ['mouse-laptop', 'macbook', 'ipad']) assert.equal(monitorBounds.intersectsBox(new THREE.Box3().setFromObject(get(name))), false, `${name} intersects the ultrawide`);
  assert.equal(get('lacie'), undefined);
  assert.equal(get('ssd'), undefined);
  assert.equal(get('drive-lead'), undefined);
  const seat = get('chair-seat-mesh');
  const seatNormal = new THREE.Vector3().fromBufferAttribute(seat.geometry.attributes.normal, 820).transformDirection(seat.matrixWorld);
  assert.ok(seatNormal.y > .9, 'Seat fabric must receive light on its upward-facing side');
  for (const column of get('desk').children.filter(part => part.name === 'desk-column-upper')) {
    assert.ok(new THREE.Box3().setFromObject(column).max.y < .72, 'Lift columns must stop below the desktop');
  }
  const deskBounds = new THREE.Box3().setFromObject(get('desk'));
  assert.ok(new THREE.Box3().setFromObject(seat).min.z < deskBounds.max.z - .2, 'Seat tucks under the desktop');
  for (const side of ['left', 'right']) {
    const arm = new THREE.Box3().setFromObject(get(`chair-armrest-${side}`));
    assert.ok(arm.min.z < deskBounds.max.z && arm.max.y < .715, 'Tucked armrests clear the underside');
  }
  const deskParts = [];
  get('desk').traverse(part => { if (part.isMesh) deskParts.push(new THREE.Box3().setFromObject(part)); });
  const chairMaterials = new Set();
  get('chair').traverse(part => {
    if (!part.isMesh) return;
    assert.ok(deskParts.every(box => !box.intersectsBox(new THREE.Box3().setFromObject(part))), 'Chair must not penetrate the desk');
    assert.ok(part.geometry.attributes.normal.array.every(Number.isFinite), 'Chair surfaces need finite normals');
    const mat = part.material;
    chairMaterials.add(mat.name);
    if (mat.name === 'chair-steel') {
      assert.ok(mat.metalness >= .8 && mat.roughness < .4, 'Lift hardware keeps its dedicated metal finish');
    } else if (mat.name !== 'woven' && mat.name !== 'brushed-aluminum') {
      assert.ok(mat.name.startsWith('chair-') && mat.metalness === 0 && mat.roughness >= .6, 'Chair plastics need dedicated matte materials');
    }
  });
  assert.ok(['chair-graphite', 'chair-chassis', 'chair-rubber', 'chair-steel'].every(name => chairMaterials.has(name)));
  const casters = get('chair').children.filter(part => /^chair-caster-\d+$/.test(part.name));
  assert.equal(casters.length, 5, 'Aeron has five twin-wheel casters');
  for (const caster of casters) {
    const wheels = caster.children.filter(part => part.name === 'chair-caster-wheel');
    assert.equal(wheels.length, 2, 'Each caster has two wheels');
    for (const wheel of wheels) {
      const bottom = new THREE.Box3().setFromObject(wheel, true).min.y;
      assert.ok(bottom >= -.0001 && bottom < .0005, 'Caster wheels rest on the floor without penetrating it');
    }
    const stem = caster.getObjectByName('chair-caster-stem');
    const top = new THREE.Box3().setFromObject(stem, true).max.y;
    const center = stem.getWorldPosition(new THREE.Vector3());
    const spoke = get(caster.name.replace('caster', 'base-spoke'));
    for (const [dx, dz] of [[0, 0], [.0055, 0], [-.0055, 0], [0, .0055], [0, -.0055]]) {
      const ray = new THREE.Raycaster(new THREE.Vector3(center.x + dx, .25, center.z + dz), new THREE.Vector3(0, -1, 0), 0, .25);
      const roof = ray.intersectObject(spoke, false)[0];
      assert.ok(roof && roof.point.y > top + .0001, 'The spoke covers the caster stem instead of letting it protrude above the foot');
    }
  }
  assert.equal(get('macbook-touch-id-ring').material.name, 'cast-graphite');
  assert.equal(get('macbook-touch-id-ring').material.metalness, .24, 'Chair finish must not change shared laptop materials');
  const bounds = new THREE.Box3().setFromObject(model);
  assert.ok(Math.abs(bounds.max.y - (.907 + .371 * 1.1)) < .001, 'The larger Dell grows upward from the fixed lower edge');
  const target = new THREE.Vector3(0, .635, .235);
  const direction = new THREE.Vector3(Math.sin(.43) * Math.cos(.3), Math.sin(.3), Math.cos(.43) * Math.cos(.3));
  for (const aspect of [.5, .8, 1.5, 2.5, 3.5]) {
    const camera = new THREE.PerspectiveCamera(overview.fov, aspect, .01, 100);
    assert.ok(Number.isFinite(fitCamera(camera, bounds, target, direction)));
    for (const x of [bounds.min.x, bounds.max.x]) for (const y of [bounds.min.y, bounds.max.y]) for (const z of [bounds.min.z, bounds.max.z]) {
      const p = new THREE.Vector3(x, y, z).project(camera);
      assert.ok(Math.abs(p.x) < .98 && Math.abs(p.y) < .97 && p.z < 1, `Clipped at aspect ${aspect}: ${p.toArray()}`);
    }
  }
  model.traverse(object => {
    if (!object.geometry) return;
    assert.ok([...object.geometry.attributes.position.array].every(Number.isFinite), 'Invalid mesh vertices');
    object.geometry.dispose();
  });
});

test('the monitor menu fits the visible screen on desktop and narrow viewports', () => {
  for (const [width, height] of [[390, 540], [1253, 1003], [1440, 620], [1920, 600]]) {
    const camera = new THREE.PerspectiveCamera(overview.fov, width / height, .01, 100);
    const pose = monitorView(camera.aspect);
    camera.position.copy(pose.position); camera.lookAt(pose.target); camera.updateMatrixWorld();
    for (const x of [-pose.menuWidth / 2, pose.menuWidth / 2]) for (const y of [-monitorScreen.height / 2 + .021, monitorScreen.height / 2 - .021]) {
      const p = new THREE.Vector3(x + monitorScreen.center[0], y + monitorScreen.center[1], monitorScreen.center[2] + .002).project(camera);
      assert.ok(Math.abs(p.x) <= .9 && Math.abs(p.y) <= .9, `Menu clipped at ${width}x${height}`);
    }
    const top = new THREE.Vector3(monitorScreen.center[0], monitorScreen.center[1] + monitorScreen.height / 2 - .021, monitorScreen.center[2] + .002).project(camera);
    assert.ok(top.y * height > 210, 'Menu needs enough height for article links and controls');
  }
});

test('search matches normalized title and body terms without interpreting regex or HTML', () => {
  const note = { title: 'NTLM / Kerberos', description: 'Research notes', body: 'macOS 認証 and [a-z] examples' };
  assert.ok(matchesNote(note, '  ＮＴＬＭ   macos  '));
  assert.ok(matchesNote(note, '認証'));
  assert.ok(matchesNote(note, '[a-z]'));
  assert.ok(matchesNote(note, ''));
  assert.equal(matchesNote(note, 'macos missing'), false);
  assert.equal(matchesNote(note, '.*'), false);
  assert.equal(matchesNote(note, '<script>'), false);
});

test('the camera transition is continuous, monotone and stops at its destination', () => {
  assert.equal(ease(0), 0);
  assert.equal(ease(1), 1);
  let last = 0;
  for (let i = 0; i <= 100; i++) { const value = ease(i / 100); assert.ok(value >= last && value <= 1); last = value; }
});


test('the published baked scene matches its source and has usable live surfaces', async () => {
  const root = new URL('../', import.meta.url);
  const source = await readFile(new URL('assets/js/workstation.js', root));
  const keyboardSource = await readFile(new URL('assets/js/keyboard.js', root));
  const roomSource = await readFile(new URL('assets/js/room.js', root));
  const hash = await readFile(new URL('assets/scene/source.sha256', root), 'utf8');
  assert.equal(createHash('sha256').update(source).update(keyboardSource).update(roomSource).digest('hex'), hash, 'Rebake the scene after changing its model source');
  for (const file of ['desk-daylight.jpg', 'desk-occlusion.jpg', 'room-daylight.webp', 'room-occlusion.jpg']) assert.ok((await stat(new URL(`assets/scene/${file}`, root))).size > 1000);
  const file = await readFile(new URL('assets/scene/workstation.glb', root));
  const { scene } = await new GLTFLoader().parseAsync(file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength), '');
  for (const name of ['monitor-screen', 'macbook-screen', 'mouse-laptop-screen', 'ipad-screen', 'clock-screen', 'can-body', 'macbook-key-legends', 'mouse-laptop-key-legends', 'mouse-palmrest-decals']) {
    assert.equal(scene.getObjectByName(name)?.userData.dynamic, name, `Missing live surface ${name}`);
  }
  const physical = new Map();
  scene.traverse(object => { if (object.isMesh && !object.userData.dynamic) physical.set(object.material.name, object.material); });
  assert.ok(physical.size >= 8, 'Preserve distinct hardware materials for reflections');
  assert.ok([...physical.values()].some(material => material.metalness > .5), 'Metal reflections need the authored metalness');
  assert.ok(physical.has('oak-baked'));
  assert.ok(['power-led-baked', 'mouse-status-led-baked', 'room-tessan-led-baked'].every(name => physical.has(name)), 'Power, status, and outlet LEDs retain their separate runtime materials');
  assert.ok(['desk-control-ink-baked', 'dock-print-baked', 'clock-print-baked', 'caldigit-cable-print-baked', 'yubikey-print-baked', 'mouse-power-print-baked', 'room-tessan-print-baked', 'inova-print-baked'].every(name => physical.has(name)), 'Printed glyphs retain separate materials so tiny atlas islands cannot blacken individual letters');
  const atlasBounds = new THREE.Box2();
  let outletFaceUvArea = 0;
  scene.traverse(object => {
    if (!object.isMesh || object.userData.dynamic) return;
    const uv = object.geometry.attributes.uv;
    for (let i = 0; i < uv.count; i++) atlasBounds.expandByPoint(new THREE.Vector2().fromBufferAttribute(uv, i));
    if (object.material.name === 'room-outlet-face-baked') {
      const index = object.geometry.index;
      for (let i = 0; i < (index?.count ?? uv.count); i += 3) {
        const [a, b, c] = [0, 1, 2].map(offset => new THREE.Vector2().fromBufferAttribute(uv, index ? index.getX(i + offset) : i + offset));
        outletFaceUvArea += Math.abs(b.sub(a).cross(c.sub(a))) / 2;
      }
    }
  });
  assert.ok(outletFaceUvArea * 4096 ** 2 > 8192, 'The outlet face needs enough baked pixels to preserve clean plastic and socket shadows');
  const span = atlasBounds.getSize(new THREE.Vector2());
  assert.ok(span.x > .95 && span.y > .95, 'Square atlas packing must not inherit a source texture aspect ratio');
  let fabricFound = false;
  scene.traverse(object => { if (object.material?.name === 'woven-baked') { fabricFound = true; assert.ok(object.geometry.attributes.uv1, 'Fabric needs independent weave coordinates'); } });
  assert.ok(fabricFound, 'Missing baked woven surface');
  const target = new THREE.Vector3(...overview.target);
  const direction = new THREE.Vector3(Math.sin(overview.yaw) * Math.cos(overview.pitch), Math.sin(overview.pitch), Math.cos(overview.yaw) * Math.cos(overview.pitch));
  for (const aspect of [.5, 1.25, 2.25]) for (const [yaw, pitch] of [[overview.yaw, overview.pitch], [-.4, .24], [1.1, .7]]) {
    direction.set(Math.sin(yaw) * Math.cos(pitch), Math.sin(pitch), Math.cos(yaw) * Math.cos(pitch));
    const camera = new THREE.PerspectiveCamera(overview.fov, aspect, .01, 100);
    fitCamera(camera, scene, target, direction);
    scene.traverse(object => {
      if (!object.isMesh) return;
      const positions = object.geometry.attributes.position;
      if (!object.userData.dynamic) {
        const uv = object.geometry.attributes.uv;
        assert.equal(uv?.count, positions.count, 'Every baked vertex needs an atlas coordinate');
        assert.ok([...uv.array].every(value => Number.isFinite(value) && value >= 0 && value <= 1), 'Invalid atlas UV');
      }
      const point = new THREE.Vector3();
      for (let i = 0; i < positions.count; i++) {
        point.fromBufferAttribute(positions, i).applyMatrix4(object.matrixWorld).project(camera);
        assert.ok(Math.abs(point.x) <= .99 && Math.abs(point.y) <= .98, `Baked mesh clipped at aspect ${aspect}`);
      }
    });
  }
});
