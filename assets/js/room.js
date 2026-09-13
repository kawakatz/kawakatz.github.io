import * as THREE from 'three';
import { RoundedBoxGeometry } from 'three/addons/geometries/RoundedBoxGeometry.js';

// A cutaway of the owner's room. The bed model is an authored approximation, not manufacturer CAD.
export function createRoom() {
  const room = new THREE.Group(); room.name = 'room';
  // Bring the left wall closer while keeping the desk and its camera coordinates fixed.
  room.position.x = .30;
  room.userData.label = 'A quiet room · window light and a SIMMONS bed behind the chair';
  const mat = (name, color, roughness = .8, metalness = 0) => {
    const value = new THREE.MeshStandardMaterial({ color, roughness, metalness }); value.name = name; return value;
  };
  const plaster = mat('room-plaster', '#c9c6bc'), edge = mat('room-trim', '#ece4d7', .55);
  const floorMat = mat('room-floor', '#ac8059', .54), darkWood = mat('bed-walnut', '#524138', .47);
  const linen = mat('bed-linen', '#92918c', .9), upholstery = mat('bed-upholstery', '#77766f', .9);
  const pillowMat = mat('pillow-linen', '#848681', .94), curtainMat = mat('room-curtain', '#cbcfc8', .92);
  function mesh(geometry, material, position, parent = room, name = material.name) {
    const object = new THREE.Mesh(geometry, material); object.position.set(...position); object.name = name;
    object.castShadow = object.receiveShadow = true; parent.add(object); return object;
  }
  const box = (w, h, d, radius, material, position, parent, name) => mesh(new RoundedBoxGeometry(w, h, d, 2, radius), material, position, parent, name);
  function surface(nu, nv, point, material, parent, name) {
    const positions = [], uv = [], indices = [];
    for (let j = 0; j <= nv; j++) for (let i = 0; i <= nu; i++) {
      positions.push(...point(i / nu, j / nv)); uv.push(i / nu, j / nv);
      if (i < nu && j < nv) { const a = j * (nu + 1) + i, b = a + nu + 1; indices.push(a, b, a + 1, b, b + 1, a + 1); }
    }
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
    geometry.setAttribute('uv', new THREE.Float32BufferAttribute(uv, 2)); geometry.setIndex(indices); geometry.computeVertexNormals();
    return mesh(geometry, material, [0, 0, 0], parent, name);
  }

  // Separate floorboards keep the grazing light and small joins in the finished bake.
  box(2.88, .105, 3.94, .022, darkWood, [0, -.060, 1.33], room, 'room-plinth');
  const boardWidth = 2.84 / 16;
  for (let row = 0; row < 16; row++) {
    const x = -1.42 + boardWidth * (row + .5), offset = (row % 3) * .39;
    for (let back = -.62 - offset; back < 3.30; back += 1.17) {
      const start = Math.max(-.62, back), end = Math.min(3.30, back + 1.17);
      if (end - start > .01) box(boardWidth - .0018, .016, end - start - .0015, .0011, floorMat, [x, -.008, (start + end) / 2], room, 'floorboard');
    }
  }
  box(2.88, 2.16, .10, .006, plaster, [0, 1.072, -.67], room, 'back-wall');
  box(2.78, .070, .016, .002, edge, [0, .035, -.61], room, 'back-skirting');
  // The owner's upside-down TESSAN tap plugs into the plate beside the curtain.
  const outletWhite = mat('room-outlet-plastic', '#ecece5', .47);
  const outletGray = mat('room-outlet-face', '#bbc3c1', .64);
  const outletDark = mat('room-outlet-recess', '#343b3e', .74);
  const outletMetal = mat('room-outlet-metal', '#b5b4a9', .38, .72);
  const outletInk = mat('room-tessan-print', '#687473', .84);
  const outlet = new THREE.Group(); outlet.name = 'wall-outlet'; outlet.position.set(-1.412, .355, -.300); outlet.rotation.y = Math.PI / 2; room.add(outlet);
  const wallPlate = box(.104, .149, .011, .009, outletWhite, [0, 0, 0], outlet, 'wall-outlet-plate');
  box(.091, .136, .003, .006, outletWhite, [0, 0, -.0067], outlet, 'wall-outlet-backing');
  box(.036, .049, .015, .003, outletWhite, [0, .036, .0105], outlet, 'wall-outlet-mount');
  function outletOutline(w, h, r) {
    const s = new THREE.Shape(), x = w / 2, y = h / 2;
    s.moveTo(-x + r, -y); s.lineTo(x - r, -y); s.quadraticCurveTo(x, -y, x, -y + r);
    s.lineTo(x, y - r); s.quadraticCurveTo(x, y, x - r, y);
    s.lineTo(-x + r, y); s.quadraticCurveTo(-x, y, -x, y - r);
    s.lineTo(-x, -y + r); s.quadraticCurveTo(-x, -y, -x + r, -y); s.closePath(); return s;
  }
  // Replace a casing's flat face with real panel openings, retaining its rounded edges.
  function openOutletFace(body, axis, coordinate, width, height, openings, name) {
    const geometry = body.geometry, positions = geometry.attributes.position;
    const source = geometry.index?.array || Array.from({ length: positions.count }, (_, i) => i), indices = [];
    for (let i = 0; i < source.length; i += 3) {
      const triangle = [source[i], source[i + 1], source[i + 2]];
      if (!triangle.every(index => Math.abs(positions.getComponent(index, axis) - coordinate) < 1e-7)) indices.push(...triangle);
    }
    geometry.setIndex(indices); geometry.clearGroups();
    const face = outletOutline(width, height, 0);
    for (const [outline, x, y] of openings) face.holes.push(new THREE.Path(outline.getPoints(8).map(p => new THREE.Vector2(p.x + x, p.y + y)).reverse()));
    const panel = mesh(new THREE.ShapeGeometry(face, 8), outletWhite, axis === 2 ? [0, 0, coordinate] : [coordinate, 0, 0], body.parent, name);
    if (axis === 0) panel.rotation.y = Math.sign(coordinate) * Math.PI / 2;
  }
  function acSocket(name, position, turn, width, height, radius, material, parent, bladeY = 0, grounded = true) {
    const socket = new THREE.Group(); socket.name = name; socket.position.set(...position); socket.rotation.y = turn; parent.add(socket);
    const face = outletOutline(width, height, radius);
    for (const [index, x] of [-.00635, .00635].entries()) {
      const hole = outletOutline(.0017, index ? .0064 : .0076, .00024);
      face.holes.push(new THREE.Path(hole.getPoints(5).map(p => new THREE.Vector2(p.x + x, p.y + bladeY)).reverse()));
      mesh(new THREE.ShapeGeometry(hole), outletDark, [x, bladeY, -.0012], socket, `${name}-blade-${index + 1}`);
    }
    if (grounded) {
      const ground = new THREE.Shape(); ground.moveTo(-.0021, .0118 + bladeY); ground.lineTo(.0021, .0118 + bladeY);
      ground.lineTo(.0021, .0089 + bladeY); ground.quadraticCurveTo(.0021, .0069 + bladeY, 0, .0069 + bladeY);
      ground.quadraticCurveTo(-.0021, .0069 + bladeY, -.0021, .0089 + bladeY); ground.closePath();
      face.holes.push(new THREE.Path(ground.getPoints(8).reverse()));
      mesh(new THREE.ShapeGeometry(ground), outletDark, [0, 0, -.0012], socket, `${name}-ground`);
    }
    mesh(new THREE.ExtrudeGeometry(face, { depth: .00135, bevelEnabled: false, curveSegments: 8, steps: 1 }), material, [0, 0, -.00055], socket, `${name}-face`);
    return socket;
  }
  // The second ordinary two-slot wall socket is directly below the expansion tap.
  acSocket('wall-spare-ac', [0, -.025, .0057], 0, .043, .037, .0015, outletWhite, outlet, 0, false);
  openOutletFace(wallPlate, 2, .0055, .093, .138, [[outletOutline(.043, .037, .0015), 0, -.025]], 'wall-outlet-front');

  const tessan = new THREE.Group(); tessan.name = 'tessan-expansion'; tessan.position.set(0, .050, .035); outlet.add(tessan);
  const tessanBody = box(.078, .109, .040, .008, outletWhite, [0, 0, 0], tessan, 'tessan-body');
  acSocket('tessan-front-ac', [0, -.020, .02004], 0, .054, .052, .012, outletGray, tessan, -.006);
  acSocket('tessan-left-ac', [-.039, -.015, .001], -Math.PI / 2, .021, .035, .003, outletWhite, tessan);
  // Stable cable endpoint on the left wall: world [-1.076, .390, -.339], outward normal -Z.
  acSocket('tessan-right-ac', [.039, -.015, .001], Math.PI / 2, .021, .035, .003, outletWhite, tessan);
  openOutletFace(tessanBody, 2, .020, .062, .093, [
    [outletOutline(.054, .052, .012), 0, -.020],
    ...[-.018, 0, .018].map(x => [outletOutline(.0064, .0150, .00055), x, .032]),
  ], 'tessan-front-shell');
  for (const side of [-1, 1]) openOutletFace(tessanBody, 0, side * .039, .024, .093, [[outletOutline(.021, .035, .003), -side * .001, -.015]], `tessan-${side < 0 ? 'left' : 'right'}-shell`);
  for (const [index, x] of [-.018, 0, .018].entries()) {
    const frame = outletOutline(.0064, .0150, .00055);
    frame.holes.push(new THREE.Path(outletOutline(.0047, .0124, .00015).getPoints(4).reverse()));
    mesh(new THREE.ExtrudeGeometry(frame, { depth: .0010, bevelEnabled: false, curveSegments: 5, steps: 1 }), outletWhite, [x, .032, .01965], tessan, `tessan-usb-${index + 1}-rim`);
    mesh(new THREE.PlaneGeometry(.0047, .0124), outletDark, [x, .032, .0188], tessan, `tessan-usb-${index + 1}-recess`);
    box(.0010, .0108, .00035, .00012, outletMetal, [x - .0012, .032, .0198], tessan, `tessan-usb-${index + 1}-tongue`);
  }
  const usbLed = mat('room-tessan-led', '#7394f7', .4); usbLed.emissive.set('#3d60d0'); usbLed.emissiveIntensity = .45;
  mesh(new THREE.CircleGeometry(.0005, 16), usbLed, [.009, .031, .02012], tessan, 'tessan-usb-led');
  // Small geometric wordmark, rotated with the actual upside-down installation.
  const tessanLetters = {
    T: [[0,1],[1,1],[1,.80],[.61,.80],[.61,0],[.39,0],[.39,.80],[0,.80]],
    E: [[0,0],[0,1],[.94,1],[.94,.80],[.22,.80],[.22,.59],[.83,.59],[.83,.39],[.22,.39],[.22,.20],[.94,.20],[.94,0]],
    S: [[.96,.98],[.22,.98],[.04,.80],[.04,.57],[.19,.44],[.71,.36],[.76,.25],[.69,.16],[.04,.16],[.04,0],[.80,0],[.98,.19],[.98,.44],[.82,.58],[.29,.66],[.25,.74],[.31,.82],[.96,.82]],
    A: [[0,0],[.36,1],[.64,1],[1,0],[.77,0],[.68,.27],[.32,.27],[.23,0]],
    N: [[0,0],[0,1],[.22,1],[.76,.35],[.76,1],[.98,1],[.98,0],[.76,0],[.22,.65],[.22,0]],
  };
  const wordmark = new THREE.Group(); wordmark.name = 'tessan-brand'; wordmark.position.set(0, .0155, .02012); wordmark.rotation.z = Math.PI; tessan.add(wordmark);
  for (const [index, letter] of [...'TESSAN'].entries()) {
    const shape = new THREE.Shape(tessanLetters[letter].map(([x,y]) => new THREE.Vector2(x * .00345, y * .0036)));
    if (letter === 'A') shape.holes.push(new THREE.Path([[.41,.48],[.59,.48],[.50,.76]].map(([x,y]) => new THREE.Vector2(x * .00345, y * .0036))));
    const ink = mesh(new THREE.ShapeGeometry(shape), outletInk, [index * .00405 - .01185, -.0018, 0], wordmark, 'tessan-brand-letter'); ink.castShadow = false;
  }
  // The rear corner is solid wall; the floor-height window starts beyond the outlet.
  box(.10, 2.16, .72, .004, plaster, [-1.47, 1.072, -.34], room, 'outlet-side-wall');
  box(.10, 2.16, .14, .004, plaster, [-1.47, 1.072, 3.23]);
  box(.10, .20, 3.14, .003, plaster, [-1.47, 2.052, 1.59]);
  box(.10, .11, 3.14, .003, plaster, [-1.47, .047, 1.59]);
  box(.035, .05, 3.14, .003, edge, [-1.395, .125, 1.59], room, 'window-sill');
  for (const z of [.03, 1.07, 2.11, 3.15]) box(.030, 1.80, .023, .002, edge, [-1.425, 1.04, z], room, 'window-frame');
  for (const y of [.145, 1.055, 1.945]) box(.030, .020, 3.14, .002, edge, [-1.425, y, 1.59], room, 'window-frame');
  const windowMat = mat('window-light', '#abc2cb', .7);
  const glass = mesh(new THREE.PlaneGeometry(3.14, 1.80), windowMat, [-1.48, 1.04, 1.59], room, 'window-glow'); glass.rotation.y = Math.PI / 2;
  for (const [start, width, phase] of [[.03, 1.48, .4], [1.67, 1.48, 1.5]]) {
    const fabric = surface(80, 60, (u, v) => {
      const z = start + u * width;
      const fold = Math.sin(u * Math.PI * 18 + phase) * .037 + Math.sin(u * Math.PI * 36 + phase) * .007;
      const y = .115 + v * 1.88 + .005 * Math.sin(u * Math.PI * 18);
      return [-1.335 + fold * (.55 + .45 * (1 - v)) + .009 * Math.sin(v * 6 + u * 11), y, z];
    }, curtainMat, room, 'pleated-curtain');
    fabric.material.side = THREE.DoubleSide;
  }
  box(.035, .035, 3.20, .007, edge, [-1.29, 2.025, 1.59], room, 'curtain-rail');
  // A compact indoor unit recalls the air conditioner above the curtains in the photo.
  box(.20, .23, .70, .024, edge, [-1.32, 2.105, .62], room, 'air-conditioner');
  box(.006, .029, .60, .004, mat('aircon-vent', '#9eaaa7', .5), [-1.214, 2.027, .62]);
  for (let i = 0; i < 9; i++) box(.004, .003, .59, .001, edge, [-1.21, 2.020 + i * .004, .62]);

  // The bed photo shows a second, raised window on the perpendicular wall.
  // Interior-facing surfaces keep this near wall open in the exterior cutaway view.
  function bedWallFace(w, h, x, y, z, material, name) {
    const face = mesh(new THREE.PlaneGeometry(w, h), material, [x, y, z], room, name);
    face.rotation.y = Math.PI; return face;
  }
  bedWallFace(2.88, .90, 0, .45, 3.20, plaster, 'bed-wall-below-window');
  bedWallFace(2.88, .12, 0, 2.10, 3.20, plaster, 'bed-wall-above-window');
  bedWallFace(.80, 1.14, -1.04, 1.47, 3.20, plaster, 'bed-wall-pillow-side');
  bedWallFace(.48, 1.14, 1.20, 1.47, 3.20, plaster, 'bed-wall-foot-side');
  bedWallFace(1.60, 1.14, .16, 1.47, 3.24, windowMat, 'window-glow');
  for (const x of [-.64, .16, .96]) bedWallFace(.030, 1.14, x, 1.47, 3.185, edge, 'bed-window-frame');
  for (const y of [.90, 2.04]) bedWallFace(1.64, .030, .16, y, 3.18, edge, 'bed-window-frame');
  bedWallFace(1.70, .045, .16, .8925, 3.15, darkWood, 'bed-window-sill');
  const bedCurtainMat = mat('room-bed-curtain', '#cbcfc8', .92);
  for (const [start, width, phase] of [[-.625, .74, .8], [.20, .74, 1.7]]) {
    surface(48, 44, (u, v) => [
      start + width * u,
      .965 + 1.045 * v + .004 * Math.sin(u * Math.PI * 14),
      3.12 + .005 * Math.sin(u * Math.PI * 14 + phase) * (.7 + .3 * (1 - v)),
    ], bedCurtainMat, room, 'bed-window-curtain');
  }

  const bed = new THREE.Group(); bed.name = 'simmons-bed'; bed.userData.label = 'SIMMONS · a quiet place behind the desk';
  bed.position.set(-.25, 0, 2.45); bed.rotation.y = Math.PI / 2; room.add(bed);
  for (const x of [-.48, .48]) for (const z of [-.80, .80]) box(.06, .14, .06, .008, darkWood, [x, .07, z], bed, 'bed-leg');
  box(1.23, .25, 2.00, .045, upholstery, [0, .245, 0], bed, 'bed-foundation');
  box(1.20, .24, 1.95, .053, pillowMat, [0, .478, 0], bed, 'simmons-mattress');
  // The grey pillow cover has a broad, low crown and a compressed perimeter.
  const pillow = new THREE.Group(); pillow.name = 'brain-sleep-pillow'; pillow.userData.label = 'BRAIN SLEEP · grey pillow cover';
  pillow.position.set(.00, .589, -.735); pillow.rotation.y = -.07; bed.add(pillow);
  const pillowPoint = (u, v, underside = false) => {
    const x = (u - .5) * .66 * (1 - .04 * Math.pow(Math.abs(2 * v - 1), 8));
    const z = (v - .5) * .39 * (1 - .055 * Math.pow(Math.abs(2 * u - 1), 8));
    const puff = Math.pow(Math.max(0, Math.sin(u * Math.PI) * Math.sin(v * Math.PI)), .30);
    const crease = .006 * Math.sin(u * 31 + v * 7) * Math.exp(-Math.min(v, 1 - v) * 15) + .003 * Math.sin(v * 36) * Math.exp(-Math.min(u, 1 - u) * 18);
    return [x, .025 + puff * (underside ? -.016 : .10) + crease, z];
  };
  surface(64, 36, pillowPoint, pillowMat, pillow, 'pillow-top');
  surface(64, 36, (u, v) => pillowPoint(u, 1 - v, true), pillowMat, pillow, 'pillow-underside');
  const duvetPoint = (u, v) => {
    const x = (u - .5) * 1.42, z = -.385 + v * 1.57;
    const side = Math.max(0, Math.abs(x) - .570) / .140, foot = Math.max(0, z - .910) / .275;
    let y = .640 - Math.hypot(.27 * Math.pow(side, 1.2), .24 * Math.pow(foot, 1.3));
    y += .042 * Math.exp(-((x + .19) ** 2 / .11 + (z - .30) ** 2 / .30));
    y += .018 * Math.sin(11 * x + 7 * z) * Math.sin(Math.PI * v) + .010 * Math.sin(22 * x - 4 * z);
    y += .012 * Math.cos(25 * z + x * 10) * Math.min(1, side * 2) + .007 * Math.sin(39 * x + 5 * z) * Math.exp(-v * 12);
    y += .025 * Math.exp(-((z + .40) ** 2) / .0025);
    const clothX = x + .01 * Math.sin(z * 12) * side;
    // Keep every fold outside the mattress's rounded upper surface.
    const cornerX = Math.max(0, Math.abs(clothX) - (.600 - .053));
    const cornerZ = Math.max(0, Math.abs(z) - (.975 - .053));
    const cornerSquared = cornerX * cornerX + cornerZ * cornerZ;
    if (cornerSquared <= .053 ** 2) y = Math.max(y, .598 - .053 + Math.sqrt(.053 ** 2 - cornerSquared) + .012);
    return [clothX, y, z];
  };
  const duvet = surface(96, 120, duvetPoint, linen, bed, 'duvet'); duvet.material.side = THREE.DoubleSide;

  room.updateMatrixWorld(true);
  return room;
}
