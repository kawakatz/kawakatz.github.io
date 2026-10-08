import { createComputerScreens } from './computer-screens.js';
import { CanvasTexture, SRGBColorSpace } from 'three';
import { createMacDesktop } from './mac-desktop.js';
import { createMouseVideo } from './mouse-video.js';
import { MAC_DOCK_ICON_KEYS } from './mac-dock.js';

// Carry the build version into image URLs so replaced screenshots cannot reuse an older build's cache.
const screenAsset = file => new URL(`../../scene/${file}`, import.meta.url).href + new URL(import.meta.url).search;

// Opaque, untagged screenshots are lossless WebP; the rest keep PNG for their alpha edges or colour chunks.
const references = ['codex-empty.png', 'codex-working.webp', 'codex-completed.webp', 'codex-computer.webp', 'edge.png', 'ghidra.png', 'ghidra-function.png', 'ghidra-variable.png', 'ghidra-references.png',
  'caido-history.png', 'caido-replay.png', 'caido-history-menu.png', 'caido-history-dialog.png', 'caido-replay-menu.png', 'caido-replay-dialog.png'];

// Starts every screen download and decode; createScreens draws once the desk can size them.
export async function loadScreens() {
  const wallpaper = new Image(), macDesktop = new Image(), companion = new Image();
  wallpaper.src = screenAsset('app-reference/dell-desktop.webp');
  macDesktop.src = screenAsset('app-reference/mac-desktop.webp');
  companion.src = screenAsset('codex-spritesheet-v4.webp');
  const rdpImages = {};
  for (const [name, file] of [['desktop', 'rdp-desktop.webp'], ['calculator', 'rdp-calculator.webp']]) {
    const image = new Image(); image.src = screenAsset(file);
    rdpImages[name] = image;
  }
  const referenceImages = Promise.all(references.map(async file => {
    const image = new Image(); image.src = screenAsset(`app-reference/${file}`);
    await image.decode(); return [`ref-${file.replace(/\.\w+$/, '')}`, image];
  }));
  const [entries, mouse, referenceEntries] = await Promise.all([
    Promise.all(MAC_DOCK_ICON_KEYS.map(async name => {
      const image = new Image(); image.src = screenAsset(`macos-icons/${name}.png`);
      await image.decode(); return [name, image];
    })),
    createMouseVideo(),
    referenceImages,
    wallpaper.decode(),
    macDesktop.decode(),
    companion.decode(),
    ...Object.values(rdpImages).map(image => image.decode()),
  ]);
  return { wallpaper, macDesktop, companion, rdpImages, mouse, icons: Object.fromEntries([...entries, ...referenceEntries]) };
}

export async function createScreens(initialResearchWidth, loading = loadScreens()) {
  const { wallpaper, macDesktop, companion, rdpImages, mouse, icons } = await loading;
  const computers = createComputerScreens(wallpaper, icons, rdpImages, initialResearchWidth?.());
  const mac = createMacDesktop(macDesktop, companion);
  const tablet = document.createElement('canvas');
  tablet.width = 4; tablet.height = 3;
  const tabletContext = tablet.getContext('2d');
  tabletContext.fillStyle = '#000'; tabletContext.fillRect(0, 0, 4, 3);
  const tabletMap = new CanvasTexture(tablet); tabletMap.colorSpace = SRGBColorSpace;
  let previous = -1, disposed = false;
  function update(elapsedMs) {
    if (disposed || !Number.isFinite(elapsedMs) || elapsedMs < 0) return false;
    const bucket = Math.floor(elapsedMs * 30 / 1000 + 1e-7);
    if (bucket <= previous) return false;
    previous = bucket;
    computers.update(elapsedMs); mac.update(elapsedMs);
    return true;
  }
  update(0);
  return {
    maps: { screen: computers.maps.research, mac: mac.map, windows: mouse.map, youtube: tabletMap }, update,
    dockOrigin: computers.dockOrigin,
    configureMouseMaterial: mouse.configureMaterial,
    setResolution(name, width) {
      if (disposed) return false;
      if (name === 'mac') return mac.setResolution(width);
      if (name === 'youtube' || name === 'windows') return false;
      return computers.setResolution(name === 'screen' ? 'research' : name, width);
    },
    setPlaying: async value => mouse.setPlaying(value),
    refreshDate(date) {
      if (disposed) return false;
      const desktopChanged = computers.refreshDate(date), macChanged = mac.refreshDate(date), clockChanged = mouse.refreshDate(date);
      return desktopChanged || macChanged || clockChanged;
    },
    setMenuProgress(value) {
      mac.setMenuProgress(value); computers.setMenuProgress(value);
    },
    dispose() {
      if (disposed) return;
      disposed = true; computers.dispose(); mac.dispose(); tabletMap.dispose(); mouse.dispose();
      wallpaper.removeAttribute('src');
      macDesktop.removeAttribute('src');
      companion.removeAttribute('src');
      for (const image of [...Object.values(icons), ...Object.values(rdpImages)]) image.removeAttribute('src');
    },
  };
}
