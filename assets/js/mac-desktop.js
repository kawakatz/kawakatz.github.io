import { CanvasTexture, SRGBColorSpace } from 'three';

const WIDTH = 3600, HEIGHT = 2338, MENU_HEIGHT = 76;
const FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';
const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = value => String(value).padStart(2, '0');
const IDLE = [1680, 660, 660, 840, 840, 1920], WAVE = [140, 140, 140, 280];

function companionFrame(elapsed) {
  let time = elapsed % 21900;
  const waving = time >= 19800, durations = waving ? WAVE : IDLE;
  time = waving ? (time - 19800) % 700 : time % 6600;
  let frame = 0;
  while (frame < durations.length - 1 && time >= durations[frame]) time -= durations[frame++];
  return (waving ? 24 : 0) + frame;
}

// Preserve the supplied desktop; only its date labels and small usage readouts are redrawn.
export function createMacDesktop(screenshot, sprites) {
  const canvases = Array.from({ length: 2 }, () => document.createElement('canvas'));
  const [image, desktop] = canvases, ctx = image.getContext('2d'), art = desktop.getContext('2d');
  const map = new CanvasTexture(image); map.colorSpace = SRGBColorSpace; map.anisotropy = 8;
  let disposed = false, progress = 0, bucket = 0, petFrame = 0, previousElapsed = 0, date = new Date(), second = Math.floor(date.getTime() / 1000);

  function text(value, x, y, size, color, weight = 500, align = 'left') {
    art.fillStyle = color; art.font = `${weight} ${size}px ${FONT}`; art.textAlign = align;
    art.fillText(value, x, y);
  }
  function clearLabel(x, y, w, h, cleanX, cleanY = y) {
    // Copy a clean neighbouring strip at the original screenshot resolution.
    art.drawImage(screenshot, cleanX, cleanY, 2, h, x, y, w, h);
  }
  function renderDesktop() {
    art.setTransform(desktop.width / WIDTH, 0, 0, desktop.height / HEIGHT, 0, 0);
    art.drawImage(screenshot, 0, 0, WIDTH, HEIGHT);
    // UTC accessors on this shifted date keep every widget in Japan time on any host.
    const japan = new Date(date.getTime() + 9 * 60 * 60 * 1000);
    const day = japan.getUTCDay(), month = japan.getUTCMonth(), number = japan.getUTCDate(), hour = japan.getUTCHours();
    const time = `${pad(hour)}:${pad(japan.getUTCMinutes())}:${pad(japan.getUTCSeconds())}`;
    clearLabel(3284, 16, 298, 44, 3296);
    text(`${DAYS[day].slice(0, 3)} ${MONTHS[month]} ${number}  ${time}`, 3574, 48, 28, '#d3e5ef', 500, 'right');

    if (progress > .12) {
      clearLabel(103, 17, 114, 44, 209);
      text('Chrome', 107, 49, 30, '#fff', 650);
    }
    clearLabel(63, 141, 490, 36, 574);
    text(`${DAYS[day].toUpperCase()}, ${MONTHS[month].toUpperCase()} ${number}`, 68, 166, 22, '#d4d4d4', 700);
    for (let i = 0; i < 6; i++) {
      const x = 89 + i * 115;
      clearLabel(x - 38, 1008, 76, 39, x + 42);
      text(String((hour + i) % 24), x, 1038, 22, '#d4d9e0', 600, 'center');
    }
    for (let i = 0; i < 5; i++) {
      const y = 1220 + i * 61;
      clearLabel(63, y - 31, 95, 40, 160);
      text(DAYS[(day + i + 1) % 7].slice(0, 3), 68, y, 26, '#f4f5f7', 650);
    }

    // Decorative local readouts; no account usage or network access is involved.
    const remaining = 769 - bucket % 770;
    const quota = 75 - Math.floor(bucket / 30) % 4, weekly = 29 + Math.floor(bucket / 120) % 3;
    clearLabel(2228, 16, 285, 46, 2484);
    text(`5h ${quota}% W ${weekly}% · ${pad(Math.floor(remaining / 60))}:${pad(remaining % 60)}`, 2236, 49, 27, '#d3e5ef');
    const resetDate = new Date(japan);
    resetDate.setUTCDate(number + ((4 - day + 7) % 7 || 7));
    clearLabel(2508, 16, 326, 46, 2840);
    text(`W ${3 + Math.floor(bucket / 180) % 2}% · ${MONTHS[resetDate.getUTCMonth()]} ${resetDate.getUTCDate()} at 0:00`, 2516, 49, 27, '#d3e5ef');
    draw();
  }
  function draw() {
    ctx.clearRect(0, 0, image.width, image.height);
    const t = Math.max(0, Math.min(1, (progress - .35) / .4)), slide = t * t * (3 - 2 * t);
    const bar = Math.round(image.height * MENU_HEIGHT / HEIGHT);
    ctx.fillStyle = '#171717'; ctx.fillRect(0, 0, image.width, image.height);
    if (!slide) ctx.drawImage(desktop, 0, 0);
    else {
      ctx.drawImage(desktop, 0, bar, image.width, image.height - bar, -slide * image.width, bar, image.width, image.height - bar);
      ctx.drawImage(desktop, 0, 0, image.width, bar, 0, 0, image.width, bar);
    }
    ctx.save(); ctx.scale(image.width/WIDTH,image.height/HEIGHT);
    ctx.fillStyle = 'rgba(0,0,0,.15)'; ctx.beginPath(); ctx.ellipse(3349-slide*WIDTH,2262,23,4,0,0,Math.PI*2); ctx.fill();
    ctx.drawImage(sprites,(petFrame%8)*192,Math.floor(petFrame/8)*208,192,208,3236-slide*WIDTH,2013,225.6,244.4);
    ctx.restore();
    map.needsUpdate = true;
  }
  function setResolution(width) {
    if (disposed || !Number.isFinite(width) || width <= 0) return false;
    width = Math.max(768, Math.ceil(width / 256) * 256);
    if (image.width === width) return false;
    if (image.width) map.dispose();
    for (const canvas of [image,desktop]) { canvas.width = width; canvas.height = Math.round(width * HEIGHT / WIDTH); }
    renderDesktop(); return true;
  }
  setResolution(3840);
  return {
    map, setResolution,
    refreshDate(value = new Date()) {
      if (disposed || !(value instanceof Date) || !Number.isFinite(value.getTime())) return false;
      const next = Math.floor(value.getTime() / 1000);
      if (next === second) return false;
      date = new Date(value); second = next; renderDesktop(); return true;
    },
    update(elapsedMs) {
      if (disposed || !Number.isFinite(elapsedMs) || elapsedMs <= previousElapsed) return false;
      previousElapsed = elapsedMs;
      const next = Math.floor(elapsedMs / 1000), frame = companionFrame(elapsedMs), newSecond = next !== bucket;
      if (!newSecond && frame === petFrame) return false;
      bucket = next; petFrame = frame;
      if (newSecond) renderDesktop(); else draw();
      return true;
    },
    setMenuProgress(value) {
      if (disposed || !Number.isFinite(value)) return false;
      value = Math.max(0, Math.min(1, value)); if (value === progress) return false;
      const chromeChanged = (value > .12) !== (progress > .12);
      progress = value;
      if (chromeChanged) renderDesktop(); else draw();
      return true;
    },
    dispose() {
      if (disposed) return; disposed = true; map.dispose();
      for (const canvas of canvases) canvas.width = canvas.height = 1;
    },
  };
}
