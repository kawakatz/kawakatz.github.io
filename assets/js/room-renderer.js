import { AlwaysStencilFunc, EqualStencilFunc, KeepStencilOp, ReplaceStencilOp, LessEqualDepth, NormalBlending, NoBlending, Matrix4, Vector2, Vector4 } from 'three';

// Retain the native MSAA color/depth/stencil samples while only screen pixels change.
// ponytail: scene geometry and lighting stay static; invalidate after changing either.
export function createRoomRenderer(renderer, scene, dynamicMeshes) {
  const dynamic = new Set(dynamicMeshes), objects = [], materials = new Map();
  const attributes = renderer.getContext().getContextAttributes();
  const preservesStencil = attributes?.preserveDrawingBuffer && attributes.stencil;
  const stencilKeys = ['stencilWrite', 'stencilWriteMask', 'stencilFunc', 'stencilRef', 'stencilFuncMask', 'stencilFail', 'stencilZFail', 'stencilZPass'];
  let compatible = true, valid = false, observed = false;
  scene.traverse(object => {
    if (object.layers.mask !== 1) compatible = false;
    if (object.isLight) objects.push({ object, partial: true, layers: object.layers.mask });
    if (!object.isMesh) return;
    const list = Array.isArray(object.material) ? object.material : [object.material];
    if (list.some(material => material.transparent) && list.some(material => !material.transparent)) compatible = false;
    if (dynamic.has(object) && list.some(material => material.transparent)) compatible = false;
    const partial = dynamic.has(object) || list.every(material => material.transparent);
    objects.push({ object, partial, layers: object.layers.mask, material: object.material });
    for (const material of list) {
      const role = material.transparent ? 'transparent' : dynamic.has(object) ? 'dynamic' : 'static';
      if (materials.has(material) && materials.get(material).role !== role) compatible = false;
      materials.set(material, { role, original: Object.fromEntries(stencilKeys.map(key => [key, material[key]])) });
    }
  });
  const world = new Matrix4(), projection = new Matrix4(), size = new Vector2(), previousSize = new Vector2(), viewport = new Vector4(), previousViewport = new Vector4();
  const shapes = [...dynamic].map(object => ({ object, geometry: object.geometry, position: object.geometry?.attributes.position, version: object.geometry?.attributes.position?.version, matrix: new Matrix4(), visible: object.visible }));
  const invalidate = () => { valid = observed = false; };
  const wrapped = ['setSize', 'setDrawingBufferSize'].map(name => {
    const original = renderer[name];
    renderer[name] = function (...args) { invalidate(); return original.apply(this, args); };
    return [name, original];
  });
  renderer.domElement.addEventListener('webglcontextlost', invalidate);
  renderer.domElement.addEventListener('webglcontextrestored', invalidate);

  function supported(camera) {
    if (!compatible || !preservesStencil) return false;
    if (renderer.getRenderTarget() || renderer.getScissorTest() || renderer.shadowMap.enabled || scene.background || camera.layers.mask !== 1) return false;
    for (const item of objects) if (item.material && item.material !== item.object.material) return false;
    for (const shape of shapes) {
      const { object } = shape;
      if (!object.isMesh || object.isSkinnedMesh || object.isInstancedMesh || object.morphTargetInfluences?.length || object.geometry !== shape.geometry || object.geometry.attributes.position !== shape.position || shape.position.version !== shape.version) return false;
      object.updateWorldMatrix(true, false);
      if (!shape.matrix.equals(object.matrixWorld) || shape.visible !== object.visible) invalidate();
    }
    for (const [material, { role }] of materials) {
      if (material.stencilWrite || material.transmission > 0 || !material.depthTest) return false;
      if (role === 'transparent' && (!material.transparent || material.depthWrite)) return false;
      if (role === 'static' && material.transparent) return false;
      if (role === 'dynamic' && (material.transparent || material.opacity !== 1 || !material.colorWrite || !material.depthWrite || material.depthFunc !== LessEqualDepth || material.alphaTest || material.alphaHash || material.alphaToCoverage || material.alphaMap || ![NormalBlending, NoBlending].includes(material.blending))) return false;
    }
    return true;
  }

  function render(camera) {
    if (camera.parent === null && camera.matrixWorldAutoUpdate) camera.updateMatrixWorld();
    renderer.getDrawingBufferSize(size);
    renderer.getViewport(viewport);
    const unchanged = observed && world.equals(camera.matrixWorld) && projection.equals(camera.projectionMatrix) && previousSize.equals(size) && previousViewport.equals(viewport);
    if (!unchanged) {
      // Moving views need an ordinary full render; stamp samples only once the
      // next view is exactly identical, without changing camera interpolation.
      invalidate();
      renderer.render(scene, camera); rememberView(camera); return;
    }
    if (!supported(camera)) {
      invalidate();
      renderer.render(scene, camera); return;
    }
    const reuse = valid;
    const autoClear = renderer.autoClear, cameraLayers = camera.layers.mask;
    try {
      for (const [material, { role }] of materials) {
        material.stencilWrite = reuse || role !== 'transparent';
        material.stencilWriteMask = reuse ? 0 : 0xff;
        material.stencilFunc = reuse ? EqualStencilFunc : AlwaysStencilFunc;
        material.stencilRef = reuse || role === 'dynamic' ? 1 : 0;
        material.stencilFuncMask = 0xff;
        material.stencilFail = material.stencilZFail = KeepStencilOp;
        material.stencilZPass = reuse ? KeepStencilOp : ReplaceStencilOp;
      }
      if (reuse) {
        // Keep the same scene, lights and transparent ordering; only its unchanged
        // opaque geometry is omitted. The original MSAA samples stay in place.
        for (const { object, partial } of objects) if (partial) object.layers.enable(1);
        camera.layers.set(1); renderer.autoClear = false;
      } else {
        renderer.autoClear = false;
        renderer.clear(true, true, true);
      }
      renderer.render(scene, camera);
      rememberView(camera);
      for (const shape of shapes) { shape.matrix.copy(shape.object.matrixWorld); shape.visible = shape.object.visible; }
      valid = true;
    } catch (error) {
      invalidate(); throw error;
    } finally {
      renderer.autoClear = autoClear; camera.layers.mask = cameraLayers;
      for (const { object, layers } of objects) object.layers.mask = layers;
      for (const [material, { original }] of materials) Object.assign(material, original);
    }
  }

  function rememberView(camera) {
    world.copy(camera.matrixWorld); projection.copy(camera.projectionMatrix); previousSize.copy(size); previousViewport.copy(viewport);
    observed = true;
  }

  return { render, invalidate, dispose() {
    invalidate();
    for (const [name, original] of wrapped) renderer[name] = original;
    renderer.domElement.removeEventListener('webglcontextlost', invalidate);
    renderer.domElement.removeEventListener('webglcontextrestored', invalidate);
  } };
}
