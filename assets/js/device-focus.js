import * as THREE from 'three';

// Extra samples help tiny text in the default desk composition. Keep the existing
// 2x budget for small screens, overview and inspection; the latter already zooms
// a 5120 CSS-pixel display into a texture capped at 12288 pixels.
export function displayPixelRatio(width, height, inspecting = false) {
  if (inspecting || !Number.isFinite(width * height) || Math.min(width, height) < 600) return 2;
  return Math.max(2, Math.min(3, Math.sqrt(12e6 / (width * height))));
}

export function displayTextureWidth(pixelWidth, aspect, minimumWidth, maxTextureSize) {
  // ponytail: full-surface canvases cap at 64 MP; tile the UI if larger displays need more.
  const limit = Math.floor(Math.min(maxTextureSize, 12288, Math.sqrt(64e6 * aspect)) / 256) * 256;
  return Math.min(limit, Math.max(minimumWidth, Math.ceil(pixelWidth * 1.1 / 256) * 256));
}

// Recover the display's frame after GLB export has flattened its transforms.
export function displayFrame(mesh) {
  mesh.updateWorldMatrix(true, false);
  const { position, normal, uv } = mesh.geometry.attributes;
  const indices = mesh.geometry.index;
  const vertices = Array.from({ length: position.count }, (_, i) => new THREE.Vector3().fromBufferAttribute(position, i).applyMatrix4(mesh.matrixWorld));
  const outward = new THREE.Vector3();
  for (let i = 0; i < normal.count; i++) outward.add(new THREE.Vector3().fromBufferAttribute(normal, i));
  outward.applyMatrix3(new THREE.Matrix3().getNormalMatrix(mesh.matrixWorld)).normalize();
  let largest = 0, right;
  for (let i = 0; i < (indices?.count ?? position.count); i += 3) {
    const [a, b, c] = [i, i + 1, i + 2].map(j => indices ? indices.getX(j) : j);
    const du1 = uv.getX(b) - uv.getX(a), dv1 = uv.getY(b) - uv.getY(a);
    const du2 = uv.getX(c) - uv.getX(a), dv2 = uv.getY(c) - uv.getY(a);
    const determinant = du1 * dv2 - du2 * dv1;
    if (Math.abs(determinant) <= largest) continue;
    largest = Math.abs(determinant);
    right = vertices[b].clone().sub(vertices[a]).multiplyScalar(dv2)
      .sub(vertices[c].clone().sub(vertices[a]).multiplyScalar(dv1)).divideScalar(determinant).normalize();
  }
  if (!right || largest < 1e-10) throw new Error('Display has no usable texture coordinates');
  const up = new THREE.Vector3().crossVectors(outward, right).normalize();
  right.crossVectors(up, outward).normalize();
  const box = new THREE.Box3().setFromPoints(vertices.map(vertex => new THREE.Vector3(vertex.dot(right), vertex.dot(up), vertex.dot(outward))));
  const middle = box.getCenter(new THREE.Vector3());
  const center = right.clone().multiplyScalar(middle.x).addScaledVector(up, middle.y).addScaledVector(outward, middle.z);
  return { center, outward, up, width: box.max.x - box.min.x, height: box.max.y - box.min.y, depth: box.max.z - box.min.z, rotation: new THREE.Quaternion().setFromRotationMatrix(new THREE.Matrix4().makeBasis(right, up, outward)) };
}

export function displayPose(frame, camera, viewportHeight = Infinity) {
  // Small displays stay ahead of the chair; the ultrawide uses a longer viewing distance.
  const tangent = Math.tan(THREE.MathUtils.degToRad(20));
  const ultrawide = frame.width / frame.height > 3;
  const distance = ultrawide ? 1.32 : Math.min(.45, Math.max(frame.width / (camera.aspect * .88), frame.height / .75) / (2 * tangent));
  const position = frame.center.clone().addScaledVector(frame.outward, distance);
  const rotation = new THREE.Quaternion().setFromRotationMatrix(new THREE.Matrix4().lookAt(position, frame.center, frame.up));
  // Keep that physical position; a wider lens makes space for the toolbar on short viewports.
  const availableHeight = Math.max(.01, Math.min(.75, 1 - 184 / viewportHeight));
  const right = new THREE.Vector3(1, 0, 0).applyQuaternion(frame.rotation), inverse = rotation.clone().invert();
  let requiredTangent = tangent;
  // Fit all corners of the curved display's oriented bounds in the final camera basis.
  for (const x of [-.5, .5]) for (const y of [-.5, .5]) for (const z of [-.5, .5]) {
    const corner = frame.center.clone().addScaledVector(right, x * frame.width).addScaledVector(frame.up, y * frame.height)
      .addScaledVector(frame.outward, z * (frame.depth ?? 0)).sub(position).applyQuaternion(inverse);
    requiredTangent = Math.max(requiredTangent, Math.abs(corner.x) / (-corner.z * camera.aspect * .88), Math.abs(corner.y) / (-corner.z * availableHeight));
  }
  const fov = THREE.MathUtils.radToDeg(2 * Math.atan(requiredTangent));
  // The frontal Dell view clips foreground laptops just before its curved surface.
  const near = ultrawide ? distance - (frame.depth ?? 0) / 2 - .020 : .1;
  return { position, rotation, fov, near };
}

// Limit lens zoom by the full display's projected CSS width, including its cropped area.
export function displayZoomMinimum(frame, camera, viewportHeight, pixelWidth) {
  const pose = displayPose(frame, camera, viewportHeight);
  const fitted = new THREE.PerspectiveCamera(pose.fov, camera.aspect, pose.near, camera.far);
  fitted.position.copy(pose.position); fitted.quaternion.copy(pose.rotation); fitted.updateMatrixWorld(true);
  const projected = displayPixelWidth(frame, fitted, viewportHeight * camera.aspect, viewportHeight);
  return Math.min(1, projected / pixelWidth);
}

export function displayPixelWidth(frame, camera, width, height) {
  if (frame.outward.dot(camera.position.clone().sub(frame.center)) <= 0) return 0;
  const right = new THREE.Vector3(1, 0, 0).applyQuaternion(frame.rotation);
  const points = [-.5, .5].flatMap(x => [-.5, .5].map(y => frame.center.clone()
    .addScaledVector(right, x * frame.width).addScaledVector(frame.up, y * frame.height).project(camera)));
  const box = new THREE.Box3().setFromPoints(points);
  if (box.max.x < -1 || box.min.x > 1 || box.max.y < -1 || box.min.y > 1 || box.min.z > 1 || box.max.z < -1) return 0;
  const length = (a, b) => Math.hypot((a.x - b.x) * width / 2, (a.y - b.y) * height / 2);
  return Math.max(length(points[0], points[2]), length(points[1], points[3]),
    length(points[0], points[1]) * frame.width / frame.height, length(points[2], points[3]) * frame.width / frame.height);
}
