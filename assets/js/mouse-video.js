import { CanvasTexture, SRGBColorSpace, Vector4, VideoTexture } from 'three';

// Coordinates in the original 1918 × 1078 recording; only the taskbar date is replaced.
const FRAME = [1918, 1078], CLOCK = { x: 1810, y: 1038, w: 74, h: 36 };
const timeFormat = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Tokyo', hour: 'numeric', minute: '2-digit', hour12: true });
const dateFormat = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Tokyo', year: 'numeric', month: 'numeric', day: 'numeric' });

export async function createMouseVideo() {
  const video = document.createElement('video');
  video.muted = true; video.defaultMuted = true; video.loop = true; video.playsInline = true;
  video.preload = 'auto'; video.autoplay = false;
  let map, patch, canvas, disposed = false, failed = false, wanted = false, revision = 0, pending;
  const materials = new Map();
  const onError = () => { failed = true; wanted = false; revision++; video.pause(); };
  function dispose() {
    if (disposed) return;
    disposed = true; wanted = false; revision++;
    video.removeEventListener('error', onError); video.pause();
    map?.dispose(); patch?.dispose();
    video.removeAttribute('src'); video.load();
    if (canvas) { canvas.width = 1; canvas.height = 1; }
    for (const [material, previous] of materials) {
      material.onBeforeCompile = previous.compile;
      material.customProgramCacheKey = previous.cacheKey;
      if (material.map === map) material.map = null;
      material.needsUpdate = true;
    }
    materials.clear();
  }
  try {
    await new Promise((resolve, reject) => {
      const finish = error => {
        clearTimeout(timer);
        video.removeEventListener('loadeddata', loaded);
        video.removeEventListener('error', loadError);
        if (error) reject(error); else resolve();
      };
      const loaded = () => finish();
      const loadError = () => finish(new Error('The Mouse desktop recording could not be loaded'));
      const timer = setTimeout(() => finish(new Error('The Mouse desktop recording timed out')), 15000);
      video.addEventListener('loadeddata', loaded);
      video.addEventListener('error', loadError);
      video.src = new URL('../../scene/mouse-desktop.mp4', import.meta.url).href;
      video.load();
      if (video.readyState >= 2) loaded();
    });
    video.addEventListener('error', onError);
    map = new VideoTexture(video); map.colorSpace = SRGBColorSpace; map.flipY = false;
    canvas = document.createElement('canvas'); canvas.width = CLOCK.w * 4; canvas.height = CLOCK.h * 4;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('The Mouse taskbar date could not be drawn');
    ctx.setTransform(4, 0, 0, 4, 0, 0);
    patch = new CanvasTexture(canvas); patch.colorSpace = SRGBColorSpace; patch.flipY = false;
    const rectangle = new Vector4(CLOCK.x / FRAME[0], CLOCK.y / FRAME[1], CLOCK.w / FRAME[0], CLOCK.h / FRAME[1]);
    // The recording's last two frames contain a pointer at this otherwise black screen edge.
    const edgeMask = new Vector4(1910 / FRAME[0], 0, 8 / FRAME[0], 18 / FRAME[1]);
    let previousDate = '';
    function refreshDate(date) {
      if (disposed || !(date instanceof Date) || !Number.isFinite(date.getTime())) return false;
      const parts = Object.fromEntries(timeFormat.formatToParts(date).map(part => [part.type, part.value]));
      const time = `${parts.hour}:${parts.minute} ${parts.dayPeriod}`, day = dateFormat.format(date), key = `${day} ${time}`;
      if (key === previousDate) return false;
      previousDate = key;
      ctx.fillStyle = '#1f1f1f'; ctx.fillRect(0, 0, CLOCK.w, CLOCK.h);
      ctx.fillStyle = '#f5f5f5'; ctx.font = '12px "Segoe UI", Arial, sans-serif';
      ctx.textAlign = 'right'; ctx.textBaseline = 'alphabetic';
      ctx.fillText(time, CLOCK.w - 8, 14); ctx.fillText(day, CLOCK.w - 8, 32);
      patch.needsUpdate = true;
      return true;
    }
    function configureMaterial(material) {
      if (disposed || !material.isMeshBasicMaterial) return false;
      if (materials.has(material)) return true;
      const previous = { compile: material.onBeforeCompile, cacheKey: material.customProgramCacheKey };
      const cacheKey = material.customProgramCacheKey(); materials.set(material, previous);
      material.map = map; material.toneMapped = false;
      material.onBeforeCompile = function (shader, renderer) {
        previous.compile.call(this, shader, renderer);
        shader.uniforms.mouseDateMap = { value: patch };
        shader.uniforms.mouseDateRect = { value: rectangle };
        shader.uniforms.mouseEdgeMask = { value: edgeMask };
        // Keep Three's video sRGB decoding intact. The sRGB canvas sampler is already linear.
        shader.fragmentShader = 'uniform sampler2D mouseDateMap;\nuniform vec4 mouseDateRect;\nuniform vec4 mouseEdgeMask;\n' + shader.fragmentShader.replace('#include <map_fragment>', `#include <map_fragment>
          #ifdef USE_MAP
            vec2 dateUv = (vMapUv - mouseDateRect.xy) / mouseDateRect.zw;
            if (all(greaterThanEqual(dateUv, vec2(0.0))) && all(lessThanEqual(dateUv, vec2(1.0)))) {
              vec4 dateColor = texture2D(mouseDateMap, dateUv);
              diffuseColor.rgb = mix(diffuseColor.rgb, dateColor.rgb * diffuse, dateColor.a);
            }
            vec2 edgeUv = (vMapUv - mouseEdgeMask.xy) / mouseEdgeMask.zw;
            if (all(greaterThanEqual(edgeUv, vec2(0.0))) && all(lessThanEqual(edgeUv, vec2(1.0)))) diffuseColor.rgb = vec3(0.0);
          #endif`);
      };
      material.customProgramCacheKey = () => `${cacheKey}|mouse-date-v1`;
      material.needsUpdate = true;
      return true;
    }
    function setPlaying(value) {
      if (disposed || failed) return Promise.resolve(false);
      if (!value) { wanted = false; revision++; video.pause(); return Promise.resolve(false); }
      if (wanted && pending) return pending;
      if (wanted && !video.paused) return Promise.resolve(true);
      wanted = true;
      const request = ++revision;
      const attempt = (async () => {
        try { await video.play(); }
        catch { if (request === revision) wanted = false; return false; }
        if (disposed || failed || !wanted) { video.pause(); return false; }
        return request === revision && !video.paused;
      })();
      pending = attempt;
      void attempt.then(() => { if (pending === attempt) pending = null; });
      return attempt;
    }
    refreshDate(new Date());
    return { map, configureMaterial, setPlaying, refreshDate, dispose };
  } catch (error) { dispose(); throw error; }
}
