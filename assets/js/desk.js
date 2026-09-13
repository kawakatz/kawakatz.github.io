import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { screenView, screenViewPose, screenViewFov, lensFov, inspectedScreenPose } from './screen-view.js';
import { createKeyboardTextures } from './keyboard.js';
import { ease, notesFlight, quadTransform } from './navigation.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import { createScreens } from './screens.js';
import { createCanTexture } from './can.js';
import { createClockTexture, drawClock } from './clock.js';
import { displayFrame, displayPose, displayPixelWidth, displayZoomMinimum, displayPixelRatio, displayTextureWidth } from './device-focus.js';
import { createIPadVideo, videoViewport } from './ipad-video.js';

const host = document.querySelector('#workstation');
const status = document.querySelector('#scene-status');
const notesLink = document.querySelector('#nav-notes');
const notesCue = document.querySelector('#notes-cue');
const hint = document.querySelector('#scene-hint');
const reset = document.querySelector('#reset-view');
const notesBrowser = document.querySelector('#notes-browser');
const notesPreview = document.querySelector('#notes-preview');
const browserChrome = notesBrowser.querySelector('.notes-browser-chrome');
const deviceControls = document.querySelector('#device-closeup');
const leaveDevice = document.querySelector('#leave-device');
const deviceName = document.querySelector('#device-name');
const inspect = document.querySelector('#inspect-screens');
const deviceLabels = { 'monitor-screen': 'Dell U4919DW', 'macbook-screen': 'MacBook', 'mouse-laptop-screen': 'MouseComputer MB-K690', 'ipad-screen': 'iPad Air MUUQ2J/A' };
const defaultHint = 'Drag to look around · Scroll to zoom · MacBook opens Notes';
const zoomButtons = [...document.querySelectorAll('[data-camera-zoom]')];
const zoomValues = [...document.querySelectorAll('[data-camera-zoom-value]')];
const reduced = matchMedia('(prefers-reduced-motion: reduce)');

try {
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'low-power' });
  // Embedded previews can report DPR 1 even on Retina displays. Start at 2x;
  // the default composition gains extra samples once its viewport is known.
  renderer.setPixelRatio(2);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.AgXToneMapping;
  renderer.toneMappingExposure = 1.05;
  host.append(renderer.domElement);
  renderer.domElement.setAttribute('aria-hidden', 'true');
  const scene = new THREE.Scene();
  const assets = new URL('../../scene/', import.meta.url);
  const loader = new THREE.TextureLoader();
  const [{ scene: model }, daylight, occlusion, roomDaylight, roomOcclusion, mouseDecals] = await Promise.all([
    new GLTFLoader().loadAsync(new URL('workstation.glb', assets).href),
    loader.loadAsync(new URL('desk-daylight.jpg', assets).href),
    loader.loadAsync(new URL('desk-occlusion.jpg', assets).href),
    new THREE.ImageBitmapLoader().loadAsync(new URL('room-daylight.webp', assets).href).then(image => { const map = new THREE.Texture(image); map.needsUpdate = true; return map; }),
    loader.loadAsync(new URL('room-occlusion.jpg', assets).href),
    loader.loadAsync(new URL('mouse-palmrest-decals.svg', assets).href),
  ]);
  for (const map of [daylight, occlusion, roomDaylight, roomOcclusion]) {
    map.colorSpace = THREE.SRGBColorSpace; map.flipY = false;
    map.anisotropy = renderer.capabilities.getMaxAnisotropy();
  }
  function createReflections() {
    const environment = new RoomEnvironment();
    const pmrem = new THREE.PMREMGenerator(renderer);
    const target = pmrem.fromScene(environment, .06);
    environment.dispose(); pmrem.dispose();
    return target;
  }
  let reflections = createReflections();
  scene.environment = reflections.texture; scene.environmentIntensity = .65;
  const screens = await createScreens();
  mouseDecals.colorSpace = THREE.SRGBColorSpace;
  const maps = { ...screens.maps, clock: createClockTexture(), can: createCanTexture(), mouseDecals, ...createKeyboardTextures() };
  for (const map of Object.values(maps)) { map.flipY = false; map.anisotropy = renderer.capabilities.getMaxAnisotropy(); }
  // Cutout holes use the original cloth coordinates, independent of the lighting atlas.
  const weavePixels = new Uint8Array(32 * 32 * 4);
  for (let y = 0; y < 32; y++) for (let x = 0; x < 32; x++) {
    const solid = x % 8 < 5 || y % 8 < 2;
    weavePixels.fill(solid ? 255 : 0, (y * 32 + x) * 4, (y * 32 + x + 1) * 4);
  }
  const weave = new THREE.DataTexture(weavePixels, 32, 32);
  weave.wrapS = weave.wrapT = THREE.RepeatWrapping; weave.repeat.set(48, 24);
  weave.channel = 1; weave.magFilter = THREE.LinearFilter; weave.minFilter = THREE.LinearMipmapLinearFilter;
  weave.anisotropy = renderer.capabilities.getMaxAnisotropy();
  weave.generateMipmaps = true; weave.needsUpdate = true;
  const deviceMeshes = {};
  model.traverse(object => {
    if (object.userData.label?.startsWith('Dell U4919DW')) object.userData.label = 'Dell U4919DW · inspect screen';
    if (object.userData.label?.startsWith('MacBook')) object.userData.label = 'MacBook · open Notes';
    if (!object.isMesh) return;
    const name = object.userData.dynamic;
    if (name) {
      const ink = name.endsWith('-key-legends');
      const map = ink ? maps[name.replace('-key-legends', '')] : name === 'mouse-palmrest-decals' ? maps.mouseDecals : name === 'monitor-screen' ? maps.screen : name === 'clock-screen' ? maps.clock : name === 'can-body' ? maps.can : name === 'mouse-laptop-screen' ? maps.windows : name === 'macbook-screen' ? maps.mac : maps.youtube;
      if (name === 'can-body') {
        object.material = new THREE.MeshPhysicalMaterial({ map, roughness: .5, metalness: .65, clearcoat: .08, clearcoatRoughness: .4 });
      } else if (name === 'clock-screen') object.material = new THREE.MeshStandardMaterial({ map, roughness: .75, metalness: 0 });
      else if (name === 'mouse-palmrest-decals') object.material = new THREE.MeshStandardMaterial({ map, transparent: true, roughness: .52, metalness: .12, depthWrite: false, polygonOffset: true, polygonOffsetFactor: -1, polygonOffsetUnits: -1 });
      else if (ink) object.material = new THREE.MeshBasicMaterial({ map, transparent: true, depthWrite: false, toneMapped: false, polygonOffset: true, polygonOffsetFactor: -1 });
      // Keep the display in front of its cover glass at every view distance.
      else object.material = new THREE.MeshBasicMaterial({ map, toneMapped: false, polygonOffset: true, polygonOffsetFactor: -1, polygonOffsetUnits: -1 });
      if (name === 'mouse-laptop-screen') screens.configureMouseMaterial(object.material);
      if (deviceLabels[name]) {
        object.userData.action = name === 'macbook-screen' ? 'notes' : name;
        deviceMeshes[name] = object;
      }
    } else {
      const original = object.material;
      // Tiny printed glyphs cannot sample the room-scale light atlas reliably.
      if (original.name === 'desk-control-ink-baked' || original.name.endsWith('-print-baked')) {
        object.material = new THREE.MeshBasicMaterial({ color: original.color, toneMapped: false }); return;
      }
      if (['power-led-baked', 'mouse-status-led-baked', 'room-tessan-led-baked'].includes(original.name)) {
        object.material = new THREE.MeshBasicMaterial({ color: original.name === 'room-tessan-led-baked' ? '#7394f7' : original.name === 'power-led-baked' ? '#e4f3ff' : '#b7ef35', toneMapped: false }); return;
      }
      const strawOpacity = original.name === 'straw-plastic-baked' ? .55 : original.name === 'straw-inner-baked' ? .30 : 1;
      const fabric = original.name === 'woven-baked';
      const wood = ['oak-baked', 'room-floor-baked', 'bed-walnut-baked'].includes(original.name);
      const cloth = ['bed-linen-baked', 'room-curtain-baked'].includes(original.name);
      let owner = object;
      while (owner.parent && !owner.userData.atlas) owner = owner.parent;
      const roomAtlas = owner.userData.atlas === 'room';
      const mat = new THREE.MeshPhysicalMaterial({
        color: original.color, roughness: original.roughness, metalness: original.metalness,
        emissive: '#ffffff', emissiveIntensity: roomAtlas ? 32 : 4, emissiveMap: roomAtlas ? roomDaylight : daylight, aoMap: roomAtlas ? roomOcclusion : occlusion, aoMapIntensity: .85,
        side: fabric || cloth ? THREE.DoubleSide : THREE.FrontSide,
        alphaMap: fabric ? weave : null, transparent: fabric || strawOpacity < 1, opacity: strawOpacity, depthWrite: !fabric && strawOpacity === 1, forceSinglePass: fabric,
        sheen: fabric ? .15 : 0, sheenColor: '#323532', sheenRoughness: .85,
        clearcoat: wood ? .08 : 0, clearcoatRoughness: .45,
      });
      // Cycles supplies diffuse illumination; Three supplies only view-dependent specular light.
      mat.onBeforeCompile = shader => {
        if (roomAtlas) shader.fragmentShader = shader.fragmentShader.replace(
          '#include <emissivemap_fragment>',
          '#include <emissivemap_fragment>\n#ifdef USE_EMISSIVEMAP\ntotalEmissiveRadiance *= emissiveColor.a;\n#endif'
        );
        shader.fragmentShader = shader.fragmentShader.replace(
          'vec3 outgoingLight = totalDiffuse + totalSpecular + totalEmissiveRadiance;',
          'vec3 outgoingLight = totalSpecular + totalEmissiveRadiance;'
        );
      };
      mat.customProgramCacheKey = () => roomAtlas ? 'room-rgbm32-physical-v1' : 'desk-rgb4-physical-v1';
      object.material = mat;
      original.dispose();
    }
  });
  scene.add(model);
  const deviceFrames = Object.fromEntries(Object.entries(deviceMeshes).map(([name, mesh]) => [name, displayFrame(mesh)]));
  const surfaceNames = { 'monitor-screen': 'screen', 'mouse-laptop-screen': 'windows', 'macbook-screen': 'mac', 'ipad-screen': 'youtube' };
  const nativeWidths = { screen: 5120, mac: 3840, youtube: 2048 };
  // Cycles has already integrated static lighting into the texture atlas.
  scene.add(new THREE.HemisphereLight('#dce9ff', '#94785b', 1.8));
  const labelLight = new THREE.DirectionalLight('#ffe0c5', 3.0); labelLight.position.set(-2, 3, 2); scene.add(labelLight);
  const camera = new THREE.PerspectiveCamera(screenView.fov, 1, screenView.near, 30);
  const target = new THREE.Vector3(...screenView.target);
  const fit = camera.clone();
  const wantedTarget = target.clone();
  let zoom = 1, inspectionZoom = 1, viewTransition = null;
  const inspectionLook = new THREE.Vector2();
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  let frame = 0, visible = true, viewportWidth = 1, viewportHeight = 1;
  let contextAvailable = true, pageActive = true, playbackRequest = 0;
  let motionPaused = reduced.matches, animationTime = 0, lastFrameTime = 0;
  let dragging = null, hovered = null, transition = null, focused = null, returnPose = null, returnFocus = notesLink;
  let notesProgress = 0, navigatingToNotes = false;
  const ipadVideo = document.querySelector('#ipad-video');
  const tabletVideo = createIPadVideo(ipadVideo);
  let videoEye = '', videoOccluded = false;

  function requestRender() {
    if (!frame && visible && !document.hidden && contextAvailable && pageActive) frame = requestAnimationFrame(render);
  }
  function normalFov() {
    return lensFov(screenViewFov(camera.aspect), zoom);
  }
  function syncPlayback() {
    const request = ++playbackRequest;
    const shouldPlay = !motionPaused && visible && !document.hidden && contextAvailable && pageActive;
    tabletVideo.setPlaying(!reduced.matches);
    void screens.setPlaying(shouldPlay).then(playing => {
      if (request !== playbackRequest) return;
      if (shouldPlay && !playing) { motionPaused = true; lastFrameTime = 0; }
      requestRender();
    });
  }
  function resize() {
    const { width, height } = host.getBoundingClientRect();
    if (!width || !height) return;
    viewportWidth = width; viewportHeight = height;
    renderer.setSize(width, height);
    camera.aspect = width / height; camera.updateProjectionMatrix();
    if (focused === 'monitor-screen') inspectionZoom = Math.max(inspectionZoom, displayZoomMinimum(deviceFrames[focused], camera, height, nativeWidths.screen));
    if (returnPose && (focused || transition)) {
      target.copy(wantedTarget);
      returnPose = overviewPose();
    }
    measureNotesTransition();
    requestRender();
  }
  function overviewPose() {
    return { ...screenViewPose(target), fov: normalFov() };
  }
  function focusPose(view) {
    const frame = deviceFrames[view === 'notes' ? 'macbook-screen' : view];
    const pose = displayPose(frame, camera, view === 'notes' ? Infinity : viewportHeight);
    return view === 'notes' ? pose : inspectedScreenPose(frame, pose, inspectionLook, inspectionZoom);
  }
  function measureNotesTransition() {
    if (transition?.view !== 'notes') return;
    const destination = transition.open ? focusPose('notes') : returnPose;
    for (const [key, pose] of [['screenWidth',{ position:transition.from, rotation:transition.rotation, fov:transition.fov, near:transition.near }],['endScreenWidth',destination]]) {
      fit.position.copy(pose.position); fit.quaternion.copy(pose.rotation); fit.fov = pose.fov; fit.aspect = camera.aspect; fit.near = pose.near;
      fit.updateProjectionMatrix(); fit.updateMatrixWorld(true);
      if (key === 'screenWidth') { fit.projectionMatrix.elements[8] = transition.projectionShift.x; fit.projectionMatrix.elements[9] = transition.projectionShift.y; }
      transition[key] = displayPixelWidth(deviceFrames['macbook-screen'],fit,viewportWidth,viewportHeight);
      transition[key === 'screenWidth' ? 'screenCenter' : 'endScreenCenter'] = deviceFrames['macbook-screen'].center.clone().project(fit);
    }
  }
  function setOverviewInert(inert) {
    document.body.classList.toggle('is-entering', inert);
    document.body.classList.toggle('is-inspecting', inert && (transition?.view || focused) !== 'notes');
    for (const selector of ['.desk-controls', '.site-header', '#notes-cue']) document.querySelector(selector).inert = inert;
  }
  function projectedScreen(name, {x=0,y=0,w=1,h=1,offset=.002}={}) {
    const display = deviceFrames[name], right = new THREE.Vector3(1,0,0).applyQuaternion(display.rotation);
    return [[x,y],[x+w,y],[x+w,y+h],[x,y+h]].map(([u,v]) => {
      const point = display.center.clone().addScaledVector(right,(u-.5)*display.width)
        .addScaledVector(display.up,(.5-v)*display.height).addScaledVector(display.outward,offset).project(camera);
      return {x:(point.x+1)*viewportWidth/2,y:(1-point.y)*viewportHeight/2,z:point.z};
    });
  }
  function positionNotesCue() {
    if (focused || transition) return;
    const [anchor] = projectedScreen('macbook-screen', {x:.5,y:.5,w:0,h:0});
    notesCue.hidden = !contextAvailable || anchor.x < 96 || anchor.x > viewportWidth - 96 || anchor.y < 72 || anchor.y > viewportHeight - 60;
    notesCue.style.left = `${anchor.x}px`;
    notesCue.style.top = `${anchor.y}px`;
  }
  function positionIPadVideo() {
    const display = deviceFrames['ipad-screen'];
    const h = display.width * 9 / 16 / display.height;
    // Match the physical glass plane; a forward offset expands the video in close-up.
    const corners = projectedScreen('ipad-screen', { y: (1-h)/2, h, offset: 0 });
    const size = videoViewport(corners);
    const eligible = size && !transition && !viewTransition && (!focused || focused === 'ipad-screen')
      && corners.every(point => point.z >= -1 && point.z <= 1)
      && display.outward.dot(camera.position.clone().sub(display.center)) > 0;
    const eye = `${camera.position.toArray()},${camera.near}`;
    if (eligible && eye !== videoEye) {
      videoEye = eye;
      const right = new THREE.Vector3(1,0,0).applyQuaternion(display.rotation);
      const forward = camera.getWorldDirection(new THREE.Vector3());
      // Lens zoom and looking around keep the same eye, so check the static scene only once per pose.
      videoOccluded = [-.48,0,.48].some(x => [-.48,0,.48].some(y => {
        const point = display.center.clone().addScaledVector(right,x*display.width).addScaledVector(display.up,y*display.height*h);
        const direction = point.clone().sub(camera.position), distance = direction.length();
        raycaster.set(camera.position,direction.normalize());
        raycaster.near = camera.near / direction.dot(forward);
        raycaster.far = distance-.004;
        return raycaster.intersectObject(model,true).length > 0;
      }));
    }
    ipadVideo.hidden = !eligible || videoOccluded;
    if (!ipadVideo.hidden) {
      ipadVideo.style.width = `${size.width}px`; ipadVideo.style.height = `${size.height}px`;
      ipadVideo.style.transform = `matrix3d(${quadTransform(corners,size.width,size.height).join(',')})`;
    }
    tabletVideo.setPlaying(!reduced.matches);
  }
  function positionNotes() {
    camera.updateMatrixWorld(true);
    const handoff = ease(THREE.MathUtils.clamp((notesProgress-.75)/.25,0,1));
    const width = THREE.MathUtils.lerp(1280,viewportWidth,handoff);
    const barHeight = 82*(1-handoff), height = THREE.MathUtils.lerp(1280*1964/3024-82,viewportHeight,handoff);
    const corners = notesFlight(notesProgress,
      projectedScreen('monitor-screen',screens.dockOrigin),
      projectedScreen('macbook-screen',{x:.10,y:.12,w:.80,h:.80}),
      projectedScreen('macbook-screen',{x:0,y:.033,w:1,h:.967}),
      [{x:0,y:0},{x:viewportWidth,y:0},{x:viewportWidth,y:viewportHeight},{x:0,y:viewportHeight}]);
    notesBrowser.style.width = `${width}px`; notesBrowser.style.height = `${height+barHeight}px`;
    notesBrowser.style.transform = `matrix3d(${quadTransform(corners,width,height+barHeight).join(',')})`;
    notesBrowser.style.borderRadius = `${12*(1-handoff)}px`;
    notesBrowser.style.opacity = Math.min(1,notesProgress/.045);
    browserChrome.style.height = `${barHeight}px`;
    notesPreview.style.height = `${height}px`;
  }
  function sharpenVisibleScreens() {
    camera.updateMatrixWorld(true);
    const { width, height } = host.getBoundingClientRect(), dpr = renderer.getPixelRatio();
    const changes = [];
    for (const [device, frame] of Object.entries(deviceFrames)) {
      const name = surfaceNames[device], map = screens.maps[name];
      // Video already retains every recorded pixel; enlarging a canvas adds no detail.
      if (map.isVideoTexture) continue;
      const ratio = map.image.width / map.image.height;
      // Keep fine Dell text rasterized before zoom, including after resize or reset.
      const minimumWidth = name === 'screen' && Math.min(width, height) >= 600 ? 8192 : nativeWidths[name];
      const requested = displayTextureWidth(displayPixelWidth(frame, camera, width, height) * dpr, ratio, minimumWidth, renderer.capabilities.maxTextureSize);
      if (requested > map.image.width || requested < map.image.width * .65) changes.push({ name, requested, delta: requested - map.image.width });
    }
    // Release a previous close-up before allocating the next one.
    for (const { name, requested } of changes.sort((a, b) => a.delta - b.delta)) screens.setResolution(name, requested);
  }
  function render(time) {
    frame = 0;
    if (!visible || document.hidden || !contextAvailable || !pageActive) { lastFrameTime = 0; return; }
    if (!motionPaused) {
      animationTime += lastFrameTime ? Math.min(time - lastFrameTime, 100) : 0;
      screens.update(animationTime);
    }
    lastFrameTime = time;
    let focusSettling = false;
    if (viewTransition) {
      const t = reduced.matches ? 1 : Math.min(1, (time - viewTransition.time) / 1250);
      const pose = overviewPose();
      camera.position.lerpVectors(viewTransition.position, pose.position, ease(t));
      camera.quaternion.slerpQuaternions(viewTransition.rotation, pose.rotation, ease(t));
      camera.fov = THREE.MathUtils.lerp(viewTransition.fov, pose.fov, ease(t));
      camera.near = THREE.MathUtils.lerp(viewTransition.near, pose.near, ease(t)); camera.updateProjectionMatrix();
      if (t === 1) viewTransition = null;
    } else if (transition) {
      const t = reduced.matches ? 1 : Math.min(1, (time - transition.time) / (transition.view === 'notes' ? transition.open ? 2800 : 800 : 1250));
      const cameraProgress = ease(transition.view === 'notes' && transition.open ? Math.min(1,t/.75) : t);
      const pose = transition.open ? focusPose(transition.view) : returnPose;
      camera.position.lerpVectors(transition.from, pose.position, cameraProgress);
      camera.quaternion.slerpQuaternions(transition.rotation, pose.rotation, cameraProgress);
      camera.fov = THREE.MathUtils.lerp(transition.fov, pose.fov, cameraProgress);
      camera.near = THREE.MathUtils.lerp(transition.near, pose.near, cameraProgress); camera.updateProjectionMatrix();
      if (transition.view === 'notes') {
        // A linear dolly plus a wider lens otherwise shrinks the Mac halfway through.
        camera.updateMatrixWorld(true);
        const width = displayPixelWidth(deviceFrames['macbook-screen'],camera,viewportWidth,viewportHeight);
        const desiredWidth = THREE.MathUtils.lerp(transition.screenWidth,transition.endScreenWidth,cameraProgress);
        if (width > 0 && desiredWidth > 0) { camera.fov = lensFov(camera.fov,width/desiredWidth); camera.updateProjectionMatrix(); }
        // Keep the display on a direct screen-space path while the camera turns.
        const center = deviceFrames['macbook-screen'].center.clone().project(camera);
        const desiredCenter = transition.screenCenter.clone().lerp(transition.endScreenCenter,cameraProgress);
        camera.projectionMatrix.elements[8] += center.x-desiredCenter.x;
        camera.projectionMatrix.elements[9] += center.y-desiredCenter.y;
        camera.projectionMatrixInverse.copy(camera.projectionMatrix).invert();
        notesProgress = transition.open ? t : THREE.MathUtils.lerp(transition.menuProgress,0,ease(t));
        screens.setMenuProgress(notesProgress);
      }
      if (t >= 1) {
        focused = transition.open ? transition.view : null; transition = null;
        notesBrowser.hidden = focused !== 'notes';
        deviceControls.hidden = !focused || focused === 'notes';
        host.style.cursor = focused === 'notes' ? 'default' : 'grab';
        if (!focused) hint.textContent = defaultHint;
        setOverviewInert(Boolean(focused));
        document.body.classList.toggle('is-opening-notes',focused === 'notes');
        if (focused === 'notes') navigatingToNotes = true;
        else if (focused) leaveDevice.focus({ preventScroll: true });
        else returnFocus.focus({ preventScroll: true });
      }
    } else if (focused) {
      const pose = focusPose(focused);
      camera.position.copy(pose.position);
      camera.quaternion.slerp(pose.rotation, reduced.matches || focused === 'notes' ? 1 : .15);
      camera.fov = THREE.MathUtils.lerp(camera.fov, pose.fov, reduced.matches || focused === 'notes' ? 1 : .15);
      camera.near = pose.near; camera.updateProjectionMatrix();
      focusSettling = camera.quaternion.angleTo(pose.rotation) > .00001 || Math.abs(camera.fov - pose.fov) > .001;
    } else {
      target.lerp(wantedTarget, reduced.matches ? 1 : .12);
      const pose = screenViewPose(target);
      camera.position.copy(pose.position); camera.quaternion.copy(pose.rotation);
      camera.fov = THREE.MathUtils.lerp(camera.fov, normalFov(), reduced.matches ? 1 : .12);
      camera.near = screenView.near;
      camera.updateProjectionMatrix();
    }
    const active = viewTransition || transition || focusSettling || (!focused && (Math.abs(camera.fov - normalFov()) > .001 || target.distanceToSquared(wantedTarget) > .00000001));
    const pixelRatio = displayPixelRatio(viewportWidth, viewportHeight, Boolean(focused || transition || viewTransition));
    if (renderer.getPixelRatio() !== pixelRatio) renderer.setPixelRatio(pixelRatio);
    if (!active && !dragging) sharpenVisibleScreens();
    updateZoomControls();
    renderer.render(scene, camera);
    positionIPadVideo();
    positionNotesCue();
    if (!notesBrowser.hidden) positionNotes();
    if (navigatingToNotes) {
      navigatingToNotes = false;
      requestAnimationFrame(() => location.assign(notesLink.href));
    }
    if (active) requestRender();
  }
  function pick(event) {
    const rect = host.getBoundingClientRect();
    pointer.set((event.clientX - rect.left) / rect.width * 2 - 1, -((event.clientY - rect.top) / rect.height) * 2 + 1);
    camera.updateMatrixWorld(); raycaster.setFromCamera(pointer, camera);
    // Raycaster distances are radial; the camera clips against perpendicular planes.
    const forward = raycaster.ray.direction.dot(camera.getWorldDirection(new THREE.Vector3()));
    raycaster.near = camera.near / forward; raycaster.far = camera.far / forward;
    let object = raycaster.intersectObject(model, true)[0]?.object;
    while (object && !object.userData.action && !object.userData.label) object = object.parent;
    return object;
  }
  function moveToView(view, trigger = notesLink) {
    const open = Boolean(view);
    if (viewTransition || open && (focused || transition)) return;
    if (!open && (!focused && !transition || transition && !transition.open)) return;
    const previous = transition;
    const closingView = previous?.view || focused;
    if (open) {
      // Freeze the current look direction and zoom for an exact return.
      wantedTarget.copy(target);
      inspectionZoom = 1; inspectionLook.set(0, 0);
      if (view === 'monitor-screen') {
        const display = deviceFrames[view];
        const width = Math.min(nativeWidths.screen, Math.max(1, viewportHeight - 184) * 1.2 * display.width / display.height);
        inspectionZoom = displayZoomMinimum(display, camera, viewportHeight, width);
      }
      zoom = Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) / Math.tan(THREE.MathUtils.degToRad(screenViewFov(camera.aspect) / 2));
      returnPose = { position: camera.position.clone(), rotation: camera.quaternion.clone(), fov: camera.fov, near: camera.near };
      returnFocus = trigger;
      document.querySelector('.desk-stage').scrollIntoView({ block: 'start', behavior: 'instant' });
    }
    const now = performance.now();
    transition = { open, view: view || closingView, time: now, menuProgress: notesProgress, from: camera.position.clone(), rotation: camera.quaternion.clone(), fov: camera.fov, near: camera.near,
      projectionShift: new THREE.Vector2(camera.projectionMatrix.elements[8],camera.projectionMatrix.elements[9]) };
    measureNotesTransition();
    notesBrowser.hidden = transition.view !== 'notes';
    document.body.classList.toggle('is-opening-notes',transition.view === 'notes');
    deviceControls.hidden = transition.view === 'notes';
    if (!deviceControls.hidden) deviceName.textContent = deviceLabels[transition.view];
    dragging = null; notesCue.classList.remove('is-hovered'); host.style.cursor = 'default';
    setOverviewInert(true);
    requestRender();
  }
  leaveDevice.addEventListener('click', () => moveToView(null));
  notesCue.addEventListener('click', event => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0 || !contextAvailable) return;
    event.preventDefault(); moveToView('notes', notesCue);
  });
  for (const button of inspect.querySelectorAll('[data-focus-screen]')) {
    button.hidden = !deviceFrames[button.dataset.focusScreen];
    button.addEventListener('click', () => moveToView(button.dataset.focusScreen === 'macbook-screen' ? 'notes' : button.dataset.focusScreen, button));
  }
  inspect.hidden = false;
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && (focused || transition)) { event.preventDefault(); moveToView(null); }
    else if (event.key === 'Escape' && inspect.open) { inspect.open = false; inspect.querySelector('summary').focus(); }
  });
  host.addEventListener('pointerdown', event => {
    if (!contextAvailable || event.button !== 0 || viewTransition || transition || focused === 'notes') return;
    notesCue.classList.remove('is-hovered');
    dragging = { x: event.clientX, y: event.clientY, target: wantedTarget.clone(), look: inspectionLook.clone(), moved: false, action: focused ? null : pick(event)?.userData.action };
    host.setPointerCapture(event.pointerId);
  });
  host.addEventListener('pointermove', event => {
    if (!contextAvailable || viewTransition || transition || focused === 'notes') return;
    if (dragging) {
      const dx = event.clientX - dragging.x, dy = event.clientY - dragging.y;
      dragging.moved ||= Math.hypot(dx, dy) > 7;
      if (!dragging.moved) return;
      if (focused) {
        const frame = deviceFrames[focused];
        const scale = 2 * camera.position.distanceTo(frame.center) * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) / viewportHeight;
        inspectionLook.x = THREE.MathUtils.clamp(dragging.look.x - dx * scale / frame.width, -.46, .46);
        inspectionLook.y = THREE.MathUtils.clamp(dragging.look.y + dy * scale / frame.height, -.46, .46);
      } else {
        const scale = 2 * camera.position.distanceTo(dragging.target) * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) / viewportHeight;
        wantedTarget.x = THREE.MathUtils.clamp(dragging.target.x - dx * scale, ...screenView.lookX);
        wantedTarget.y = THREE.MathUtils.clamp(dragging.target.y + dy * scale, ...screenView.lookY);
      }
      if (!focused) reset.hidden = false;
      requestRender();
    } else if (focused) {
      host.style.cursor = 'grab';
    } else if (event.pointerType === 'mouse') {
      hovered = pick(event);
      notesCue.classList.toggle('is-hovered', hovered?.userData.action === 'notes');
      host.style.cursor = hovered?.userData.action ? 'pointer' : 'grab';
      hint.textContent = hovered?.userData.action === 'notes' ? 'MacBook · open Notes' : deviceLabels[hovered?.userData.action] ? `Inspect ${deviceLabels[hovered.userData.action]}` : hovered?.userData.label || defaultHint;
    }
  });
  host.addEventListener('pointerup', event => {
    const action = !focused && dragging && !dragging.moved && pick(event)?.userData.action;
    if (action && action === dragging.action) moveToView(action, action === 'notes' ? notesLink : inspect.querySelector('summary'));
    dragging = null;
    if (host.hasPointerCapture(event.pointerId)) host.releasePointerCapture(event.pointerId);
  });
  host.addEventListener('pointercancel', () => { dragging = null; });
  host.addEventListener('pointerleave', () => { notesCue.classList.remove('is-hovered'); if (!dragging) hint.textContent = defaultHint; });
  function resetView() {
    if (focused || transition) return;
    viewTransition = { time: performance.now(), position: camera.position.clone(), rotation: camera.quaternion.clone(), fov: camera.fov, near: camera.near };
    wantedTarget.set(...screenView.target); target.copy(wantedTarget); zoom = 1;
    reset.hidden = true; requestRender();
  }
  reset.addEventListener('click', resetView);
  function updateZoomControls() {
    const scale = focused ? inspectionZoom : zoom;
    const maximum = focused ? 1.25 : 1.75;
    const minimum = focused === 'monitor-screen' ? displayZoomMinimum(deviceFrames[focused], camera, viewportHeight, nativeWidths.screen) : .25;
    const locked = !contextAvailable || Boolean(viewTransition || transition) || focused === 'notes';
    const value = `${(1 / scale).toFixed(1)}×`;
    for (const output of zoomValues) if (output.textContent !== value) output.textContent = value;
    for (const button of zoomButtons) {
      const action = button.dataset.cameraZoom;
      const disabled = locked || (action === 'in' ? scale <= minimum + 1e-6 : action === 'out' ? scale >= maximum - 1e-6 : Math.abs(scale - 1) < 1e-6 && (!focused || inspectionLook.lengthSq() < 1e-12));
      if (button.disabled !== disabled) button.disabled = disabled;
    }
  }
  function changeZoom(value, resetLook = false) {
    if (!contextAvailable || viewTransition || transition || focused === 'notes' || !Number.isFinite(value)) return;
    if (focused) {
      const minimum = focused === 'monitor-screen' ? displayZoomMinimum(deviceFrames[focused], camera, viewportHeight, nativeWidths.screen) : .25;
      inspectionZoom = THREE.MathUtils.clamp(value, minimum, 1.25);
      if (resetLook) inspectionLook.set(0, 0);
    } else {
      zoom = THREE.MathUtils.clamp(value, .25, 1.75);
      reset.hidden = false;
    }
    updateZoomControls(); requestRender();
  }
  for (const button of zoomButtons) button.addEventListener('click', () => {
    const action = button.dataset.cameraZoom;
    changeZoom(action === 'reset' ? 1 : (focused ? inspectionZoom : zoom) * (action === 'in' ? .8 : 1.25), action === 'reset');
  });
  host.addEventListener('wheel', event => {
    if (!contextAvailable || viewTransition || focused === 'notes' || transition || event.ctrlKey) return;
    event.preventDefault();
    const delta = event.deltaY * (event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? host.clientHeight : 1);
    changeZoom((focused ? inspectionZoom : zoom) * Math.exp(delta * .001));
  }, { passive: false });
  reduced.addEventListener('change', () => { motionPaused = reduced.matches; lastFrameTime = 0; syncPlayback(); requestRender(); });
  document.addEventListener('visibilitychange', () => { lastFrameTime = 0; syncPlayback(); requestRender(); });
  window.addEventListener('pageshow', event => {
    pageActive = true; lastFrameTime = 0;
    if(event.persisted && focused === 'notes') { focused = null; transition = null; notesProgress = 0; screens.setMenuProgress(0); notesBrowser.hidden = true; document.body.classList.remove('is-opening-notes'); setOverviewInert(false); }
    syncPlayback(); requestRender();
  });
  new ResizeObserver(resize).observe(host);
  new IntersectionObserver(entries => { visible = entries[0].isIntersecting; lastFrameTime = 0; syncPlayback(); if (visible) requestRender(); }, { threshold: .01 }).observe(host);
  const screenTimer = setInterval(() => { if (!motionPaused) requestRender(); }, 1000 / 30);
  const clockTimer = setInterval(() => {
    if (!visible || document.hidden || !contextAvailable) return;
    screens.refreshDate(new Date());
    const canvas = maps.clock.image;
    drawClock(canvas.getContext('2d'), canvas.width, canvas.height);
    maps.clock.needsUpdate = true; requestRender();
  }, 1000);
  host.addEventListener('webglcontextlost', event => {
    event.preventDefault(); contextAvailable = false; syncPlayback(); cancelAnimationFrame(frame); frame = 0; lastFrameTime = 0;
    notesCue.hidden = true;
    ipadVideo.hidden = true;
    const notes = document.createElement('a'); notes.href = notesLink.href; notes.textContent = 'Read the notes →';
    status.replaceChildren(document.createTextNode('The desk paused. '), notes); status.hidden = false;
  }, true);
  renderer.domElement.addEventListener('webglcontextrestored', () => {
    try {
      reflections.dispose(); reflections = createReflections(); scene.environment = reflections.texture;
      contextAvailable = true; status.hidden = true; syncPlayback(); requestRender();
    } catch (error) { console.warn('Desk reflections could not restore:', error); }
  });
  window.addEventListener('pagehide', event => { pageActive = false; lastFrameTime = 0; syncPlayback(); if (!event.persisted) { tabletVideo.dispose(); clearInterval(clockTimer); clearInterval(screenTimer); cancelAnimationFrame(frame); screens.dispose(); maps.clock.dispose(); mouseDecals.dispose(); renderer.dispose(); daylight.dispose(); occlusion.dispose(); roomDaylight.dispose(); roomDaylight.image.close(); roomOcclusion.dispose(); reflections.dispose(); weave.dispose(); } });
  resize();
  syncPlayback();
  const initial = overviewPose();
  camera.position.copy(initial.position); camera.quaternion.copy(initial.rotation); camera.fov = initial.fov; camera.near = initial.near; camera.updateProjectionMatrix();
  renderer.setPixelRatio(displayPixelRatio(viewportWidth, viewportHeight));
  sharpenVisibleScreens();
  renderer.render(scene, camera);
  positionIPadVideo();
  positionNotesCue();
  host.classList.add('is-ready');
  status.hidden = true;
} catch (error) {
  status.textContent = 'The 3D desk is unavailable here. The notes are ready to read.';
  hint.textContent = '';
  console.warn('Desk could not initialize:', error);
}
