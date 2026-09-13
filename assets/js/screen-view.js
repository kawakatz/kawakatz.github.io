import * as THREE from 'three';

export const screenView = {
  position: [-.25245, .98, 1.4],
  fov: 17.7970608,
  near: 1.15,
  target: [-.25245, .98, -.25],
  lookX: [-1.05, .55],
  lookY: [0.072618, 1.50],
};

export function screenViewPose(target = new THREE.Vector3(...screenView.target)) {
  const position = new THREE.Vector3(...screenView.position);
  const rotation = new THREE.Quaternion().setFromRotationMatrix(new THREE.Matrix4().lookAt(position, target, new THREE.Vector3(0, 1, 0)));
  return { position, rotation, near: screenView.near };
}

export function screenViewFov(aspect) {
  // Fit the 302.4 mm Mac display using its nearest lower edge at world Z = -0.24567 m.
  // Fitting the tilted display by its center can crop the lower corners.
  const depth = screenView.position[2] + .24567;
  return Math.max(screenView.fov, 2 * Math.atan(.3024 / (2 * depth * aspect * .82)) * 180 / Math.PI);
}

export function lensFov(fov, scale = 1) {
  return THREE.MathUtils.radToDeg(2 * Math.atan(Math.tan(THREE.MathUtils.degToRad(fov / 2)) * scale));
}

export function inspectedScreenPose(frame, pose, look = new THREE.Vector2(), scale = 1) {
  const right = new THREE.Vector3(1, 0, 0).applyQuaternion(frame.rotation);
  const offset = right.multiplyScalar(look.x * frame.width).addScaledVector(frame.up, look.y * frame.height);
  const target = frame.center.clone().add(offset), frontal = frame.width / frame.height > 3;
  return {
    position: frontal ? pose.position.clone().add(offset) : pose.position,
    rotation: frontal ? pose.rotation : new THREE.Quaternion().setFromRotationMatrix(new THREE.Matrix4().lookAt(pose.position, target, frame.up)),
    fov: lensFov(pose.fov, scale),
    near: pose.near ?? .1,
  };
}
