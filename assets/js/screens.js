import { createComputerScreens } from './computer-screens.js';
import { CanvasTexture, SRGBColorSpace } from 'three';
import { createMacDesktop } from './mac-desktop.js';
import { createMouseVideo } from './mouse-video.js';
import { MAC_DOCK_ICON_KEYS } from './mac-dock.js';

// Carry the build version into image URLs so replaced screenshots cannot reuse an older build's cache.
const screenAsset = file => new URL(`../../scene/${file}`, import.meta.url).href + new URL(import.meta.url).search;

export async function createScreens() {
  const wallpaper = new Image(), macDesktop = new Image(), companion = new Image();
  wallpaper.src = screenAsset('app-reference/dell-desktop.png');
  macDesktop.src = screenAsset('app-reference/mac-desktop.png');
  companion.src = screenAsset('codex-spritesheet-v4.webp');
  const rdpImages = {};
  for (const [name, file] of [['desktop', 'rdp-desktop.webp'], ['calculator', 'rdp-calculator.png']]) {
    const image = new Image(); image.src = screenAsset(file);
    rdpImages[name] = image;
  }
  const references = Promise.all(['codex-empty', 'codex-working', 'codex-completed', 'codex-computer', 'edge', 'ghidra', 'ghidra-function', 'ghidra-variable', 'ghidra-references',
    'caido-history', 'caido-replay', 'caido-history-menu', 'caido-history-dialog', 'caido-replay-menu', 'caido-replay-dialog',
  ].map(async name => {
    const image = new Image(); image.src = screenAsset(`app-reference/${name}.png`);
    await image.decode(); return [`ref-${name}`, image];
  }));
  const [entries, mouse, referenceEntries] = await Promise.all([
    Promise.all(MAC_DOCK_ICON_KEYS.map(async name => {
      const image = new Image(); image.src = screenAsset(`macos-icons/${name}.png`);
      await image.decode(); return [name, image];
    })),
    createMouseVideo(),
    references,
    wallpaper.decode(),
    macDesktop.decode(),
    companion.decode(),
    ...Object.values(rdpImages).map(image => image.decode()),
  ]);
  const icons = Object.fromEntries([...entries, ...referenceEntries]);
  const computers = createComputerScreens(wallpaper, icons, rdpImages);
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
