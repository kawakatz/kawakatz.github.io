export const MAC_DOCK_ORDER = [
  'finder', 'settings', 'calendar', 'mail', 'safari', 'chrome', 'edge', 'firefox',
  'vscode', 'sublime', 'ghostty', 'terminal', 'termius', 'discord', 'slack', 'github',
  'vmware', 'utm', 'windows', 'docker', 'activity', 'separator',
  'caido', 'drawio', 'codex', 'claude', 'separator',
  'minimized-chrome', 'minimized-codex', 'minimized-slack', 'minimized-discord', 'trash',
];
export const MAC_DOCK_ICON_KEYS = [...new Set(MAC_DOCK_ORDER.filter(key => key !== 'separator').map(key => key.replace('minimized-', '')))];

const FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
const month = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Tokyo', month: 'short' });
const day = new Intl.DateTimeFormat('en-US', { timeZone: 'Asia/Tokyo', day: 'numeric' });
const units = key => key === 'separator' ? .5 : key.startsWith('minimized-') ? 1.04 : 1;
function dockLayout({ x, y, w, h }) {
  const total = MAC_DOCK_ORDER.reduce((sum, key) => sum + units(key), 0);
  const size = Math.min(h * 1.02, (w - h * .32) / total);
  return { size, cursor: x + (w - total * size) / 2, top: y + (h - size) * .37 };
}

// Minimized items return the window body, excluding the small application badge.
export function getMacDockItemRect(item, bounds) {
  const { size, top, cursor: start } = dockLayout(bounds); let cursor = start;
  for (const key of MAC_DOCK_ORDER) {
    const span = size * units(key);
    if (key === item && key !== 'separator') return key.startsWith('minimized-')
      ? { x: cursor + span * .04, y: top + size * .16, w: size * 1.08 * .84, h: size * .68 }
      : { x: cursor + (span - size) / 2, y: top, w: size, h: size };
    cursor += span;
  }
  return null;
}
function round(ctx, x, y, w, h, r, color) {
  ctx.beginPath(); ctx.roundRect(x, y, w, h, r);
  if (color) { ctx.fillStyle = color; ctx.fill(); }
}
function text(ctx, value, x, y, size, color, weight = 500) {
  ctx.fillStyle = color; ctx.font = `${weight} ${size}px ${FONT}`; ctx.fillText(value, x, y);
}
function calendar(ctx, image, x, y, size, date) {
  ctx.drawImage(image, x, y, size, size);
  ctx.save(); ctx.translate(x, y); ctx.scale(size / 256, size / 256);
  round(ctx, 27, 26, 203, 204, 49); ctx.clip();
  const paper = ctx.createLinearGradient(0, 77, 0, 230);
  paper.addColorStop(0, '#fcfcfc'); paper.addColorStop(1, '#eeeeee');
  ctx.fillStyle = paper; ctx.fillRect(26, 77, 205, 154);
  ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
  text(ctx, month.format(date).toUpperCase(), 128, 62, 27, '#fff', 650);
  text(ctx, day.format(date), 128, 209, 118, '#191919', 400); ctx.restore();
}
function activity(ctx, image, x, y, size, time) {
  ctx.drawImage(image, x, y, size, size);
  ctx.save(); ctx.translate(x, y); ctx.scale(size / 256, size / 256);
  round(ctx, 29, 29, 198, 198, 46); ctx.clip();
  const glass = ctx.createLinearGradient(0, 28, 0, 229);
  glass.addColorStop(0, '#293332'); glass.addColorStop(1, '#111a18');
  ctx.fillStyle = glass; ctx.fillRect(27, 27, 203, 203);
  ctx.strokeStyle = '#3d59504f'; ctx.lineWidth = 1.8;
  ctx.beginPath();
  for (let p = 40; p < 229; p += 32) { ctx.moveTo(p, 27); ctx.lineTo(p, 230); ctx.moveTo(27, p); ctx.lineTo(230, p); }
  ctx.stroke();
  const second = ((time % 30) + 30) % 30, p = Math.max(0, Math.min(1, (second - .75) / 28.45));
  const phase = p === 1 ? 0 : p * p * (3 - 2 * p) * Math.PI * 2;
  ctx.beginPath();
  for (let i = 0; i <= 48; i++) {
    const p = i / 48, a = phase - p * Math.PI * 2;
    const value = .3 + .16 * Math.sin(a * 3) + .10 * Math.sin(a * 7) + .045 * Math.sin(a * 13);
    const px = 27 + p * 203, py = 207 - value * 152;
    if (i) ctx.lineTo(px, py); else ctx.moveTo(px, py);
  }
  ctx.strokeStyle = '#78e8b4'; ctx.lineWidth = 3.7; ctx.lineJoin = 'round'; ctx.stroke();
  ctx.lineTo(230, 230); ctx.lineTo(27, 230); ctx.closePath(); ctx.fillStyle = '#60dba51a'; ctx.fill(); ctx.restore();
}
function minimized(ctx, image, kind, x, y, size) {
  const w = size * 1.08, h = size * .68, widthScale = .84;
  ctx.save(); ctx.translate(x, y + size * .16);
  ctx.save(); ctx.scale(widthScale, 1);
  round(ctx, 0, 0, w, h, size * .06, kind === 'chrome' ? '#faf9f7' : kind === 'slack' ? '#f8f8f8' : '#303135');
  round(ctx, 0, 0, w, h, size * .06); ctx.strokeStyle = 'rgba(245,248,255,.65)'; ctx.lineWidth = size * .018; ctx.stroke();
  round(ctx, 0, 0, w, size * .12, size * .06, kind === 'chrome' ? '#dfdfdf' : kind === 'slack' ? '#dedce2' : '#46464b');
  for (let i = 0; i < 3; i++) {
    ctx.beginPath(); ctx.arc(size * (.065 + i * .058), size * .057, size * .022, 0, Math.PI * 2);
    ctx.fillStyle = ['#ef766b', '#e7c369', '#75c481'][i]; ctx.fill();
  }
  if (kind === 'chrome') {
    round(ctx, size * .18, size * .018, size * .58, size * .075, size * .03, '#f8f8f8');
    ctx.fillStyle = '#737a82'; ctx.fillRect(size * .085, size * .24, size * .42, size * .055);
    ctx.fillStyle = '#a0a5ab'; ctx.fillRect(size * .085, size * .395, size * .32, size * .019);
    for (let i = 0; i < 3; i++) { ctx.fillStyle = '#b4b7bb'; ctx.fillRect(size * .085, size * (.49 + i * .055), size * (.72 - i * .1), size * .015); }
  } else {
    ctx.fillStyle = kind === 'slack' ? '#482a4a' : kind === 'discord' ? '#22232b' : '#242426';
    ctx.fillRect(size * .025, size * .135, size * .25, h - size * .16);
    for (let i = 0; i < 5; i++) { ctx.fillStyle = '#a49cac'; ctx.fillRect(size * .06, size * (.2 + i * .085), size * (.10 + i % 2 * .055), size * .019); }
    ctx.fillStyle = kind === 'slack' ? '#78717e' : '#bcc0c8';
    ctx.fillRect(size * .32, size * .19, size * .31, size * .027);
    for (let i = 0; i < 3; i++) {
      if (kind !== 'codex') round(ctx, size * .32, size * (.30 + i * .105), size * .075, size * .075, size * .012, ['#baa0ca', '#95b9aa', '#b4a38b'][i]);
      ctx.fillStyle = kind === 'slack' ? '#aaa6af' : '#a7a8af';
      ctx.fillRect(size * (kind === 'codex' ? .34 : .43), size * (.31 + i * .105), size * (.41 - i % 2 * .065), size * .02);
      ctx.fillStyle = kind === 'slack' ? '#ccc9cf' : '#666971';
      ctx.fillRect(size * (kind === 'codex' ? .34 : .43), size * (.35 + i * .105), size * (.51 - i % 2 * .11), size * .017);
    }
  }
  ctx.restore();
  ctx.drawImage(image, w * widthScale - size * .43, h - size * .36, size * .52, size * .52); ctx.restore();
}

// Coordinates are logical; the caller's final canvas transform supplies raster density.
// time is seconds; the supplied wall date is shown in Japan time.
export function drawMacDock(ctx, icons, { x, y, w, h }, time = 0, date = new Date(), { chromeProgress = 0 } = {}) {
  ctx.save(); ctx.imageSmoothingEnabled = true; ctx.imageSmoothingQuality = 'high';
  round(ctx, x, y, w, h, h * .28, 'rgba(130,148,163,.30)');
  round(ctx, x + .25, y + .25, w - .5, h - .5, h * .28); ctx.strokeStyle = 'rgba(255,255,255,.44)'; ctx.lineWidth = .5; ctx.stroke();
  const { size, top, cursor: start } = dockLayout({ x, y, w, h });
  let cursor = start;
  for (const item of MAC_DOCK_ORDER) {
    const span = size * units(item);
    if (item === 'separator') {
      ctx.strokeStyle = 'rgba(255,255,255,.82)'; ctx.lineWidth = Math.max(.6, size * .021);
      ctx.beginPath(); ctx.moveTo(cursor + span / 2, y + h * .22); ctx.lineTo(cursor + span / 2, y + h * .78); ctx.stroke();
    } else {
      const key = item.replace('minimized-', ''), left = cursor + (span - size) / 2;
      if (item.startsWith('minimized-')) { if (item !== 'minimized-chrome' || chromeProgress <= 0) minimized(ctx, icons[key], key, cursor + span * .04, top, size); }
      else if (key === 'calendar') calendar(ctx, icons[key], left, top, size, date);
      else if (key === 'activity') activity(ctx, icons[key], left, top, size, time);
      else ctx.drawImage(icons[key], left, top, size, size);
      if (['finder', 'codex', 'slack', 'discord', 'activity'].includes(item)) {
        ctx.fillStyle = 'rgba(245,249,255,.86)'; ctx.beginPath(); ctx.arc(cursor + span / 2, y + h * .943, Math.max(.38, size * .021), 0, Math.PI * 2); ctx.fill();
      }
    }
    cursor += span;
  }
  ctx.restore();
}
