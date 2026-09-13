import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import * as THREE from 'three';
import { createWorkstation, fitCamera, overview } from '../assets/js/workstation.js';
import { createRoom } from '../assets/js/room.js';

const model = createWorkstation();
const deskBounds = new THREE.Box3().setFromObject(model);
model.add(createRoom());
model.updateMatrixWorld(true);
const meshes = [];
model.traverse(object => {
  if (!object.isMesh) return;
  const geometry = object.geometry.index ? object.geometry.toNonIndexed() : object.geometry;
  const count = object.isInstancedMesh ? object.count : 1;
  for (let instance = 0; instance < count; instance++) {
    const transform = object.matrixWorld.clone();
    if (object.isInstancedMesh) { const matrix = new THREE.Matrix4(); object.getMatrixAt(instance, matrix); transform.multiply(matrix); }
    const g = geometry.clone().applyMatrix4(transform);
    let parent = object;
    while (parent && !parent.userData.label) parent = parent.parent;
    const mat = object.material;
    meshes.push({
      name: object.name || `part-${meshes.length}`,
      dynamic: /-(screen|key-legends)$/.test(object.name) || ['can-body', 'mouse-palmrest-decals'].includes(object.name),
      label: parent?.userData.label || '',
      positions: Array.from(g.attributes.position.array),
      normals: Array.from(g.attributes.normal.array),
      uv: Array.from(g.attributes.uv?.array || []),
      ...(['desk-extension-cable', 'ipad-charge-cable'].includes(object.name) ? { lightmapStrip: {
        length: object.geometry.parameters.path.getLength(),
        perimeter: object.geometry.parameters.crossSection
          ? 2 * (object.geometry.parameters.crossSection[0] - object.geometry.parameters.crossSection[1]) + Math.PI * object.geometry.parameters.crossSection[1]
          : 2 * Math.PI * object.geometry.parameters.radius,
      } } : {}),
      material: { name: mat.name, color: mat.color.toArray(), roughness: mat.roughness ?? .8, metalness: mat.metalness ?? 0 },
    });
  }
});
await mkdir('.scene-build', {recursive:true});
await writeFile('.scene-build/source.json', JSON.stringify(meshes));
const roomBounds = new THREE.Box3().setFromObject(model);
await writeFile('assets/scene/layout.json', JSON.stringify({ desk: { min: deskBounds.min.toArray(), max: deskBounds.max.toArray() }, room: { min: roomBounds.min.toArray(), max: roomBounds.max.toArray() } }));
await writeFile('.scene-build/source.sha256', createHash('sha256').update(await readFile('assets/js/workstation.js')).update(await readFile('assets/js/keyboard.js')).update(await readFile('assets/js/room.js')).digest('hex'));
console.log(`Exported ${meshes.length} parts to the offline renderer`);

const roomPreview = !process.argv.includes('--desk');
const previews = [1.6, .58].map(aspect => {
  const camera = new THREE.PerspectiveCamera(overview.fov, aspect, .1, 30);
  const target = roomPreview ? new THREE.Vector3(0, .78, 1.1) : new THREE.Vector3(...overview.target);
  const yaw = roomPreview ? .76 : overview.yaw, pitch = roomPreview ? .49 : overview.pitch;
  const direction = new THREE.Vector3(Math.sin(yaw) * Math.cos(pitch), Math.sin(pitch), Math.cos(yaw) * Math.cos(pitch));
  fitCamera(camera, roomPreview ? model : deskBounds, target, direction);
  return { aspect, fov: overview.fov, position: camera.position.toArray(), target: target.toArray() };
});
await writeFile('.scene-build/cameras.json', JSON.stringify(previews));
