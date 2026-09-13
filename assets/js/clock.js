import { CanvasTexture, SRGBColorSpace } from 'three';

const segments = ['abcdef', 'bc', 'abged', 'abgcd', 'fgbc', 'afgcd', 'afgecd', 'abc', 'abcdefg', 'abfgcd'];
const weekdays = ['日', '月', '火', '水', '木', '金', '土'];

// Seiko BC402 / FSQ-147W: time and calendar are live; 24.8°C / 48% are specimen readings.
export function drawClock(ctx, width, height, now = new Date()) {
  const tokyo = new Date(now.getTime() + 9 * 60 * 60 * 1000);
  const hh = String(tokyo.getUTCHours()).padStart(2, '0');
  const mm = String(tokyo.getUTCMinutes()).padStart(2, '0');
  const ss = String(tokyo.getUTCSeconds()).padStart(2, '0');
  ctx.save(); ctx.scale(width / 1280, height / 650);
  const paper = ctx.createLinearGradient(0, 0, 0, 650);
  paper.addColorStop(0, '#bac0ad'); paper.addColorStop(1, '#aab39f');
  ctx.fillStyle = paper; ctx.fillRect(0, 0, 1280, 650);
  const ink = '#202a25';
  const shapes = {
    a: [[9,0],[43,0],[47,6],[41,12],[11,12],[5,6]],
    b: [[49,5],[52,8],[52,43],[47,48],[40,41],[40,17]],
    c: [[47,52],[52,57],[52,92],[49,95],[40,83],[40,59]],
    d: [[11,88],[41,88],[47,94],[42,100],[10,100],[5,94]],
    e: [[5,52],[12,59],[12,83],[3,95],[0,92],[0,57]],
    f: [[3,5],[12,17],[12,41],[5,48],[0,43],[0,8]],
    g: [[10,44],[42,44],[46,50],[42,56],[10,56],[6,50]],
  };
  function digit(value, x, y, size) {
    ctx.save(); ctx.translate(x, y); ctx.scale(size / 100, size / 100);
    ctx.transform(1, 0, -.065, 1, 6.5, 0);
    for (const [name, points] of Object.entries(shapes)) {
      ctx.fillStyle = segments[Number(value)]?.includes(name) ? ink : 'rgba(32,42,37,.035)';
      ctx.beginPath(); ctx.moveTo(...points[0]);
      for (const point of points.slice(1)) ctx.lineTo(...point);
      ctx.closePath(); ctx.fill();
    }
    ctx.restore();
  }
  function number(value, x, y, size, slots = 2) {
    for (const [index, character] of Array.from(String(value).padStart(slots, ' ')).entries()) {
      if (character !== ' ') digit(character, x + index * size * .61, y, size);
    }
  }
  function text(value, x, y, size = 24, align = 'left') {
    ctx.fillStyle = ink; ctx.textAlign = align; ctx.textBaseline = 'alphabetic';
    ctx.font = `${size}px -apple-system, "Hiragino Kaku Gothic ProN", sans-serif`;
    ctx.fillText(value, x, y);
  }
  function dot(x, y, size) { ctx.fillStyle = ink; ctx.fillRect(x, y, size, size); }

  number(hh, 126, 40, 320); number(mm, 554, 40, 320);
  dot(522, 124, 18); dot(512, 267, 18);
  number(ss, 989, 219, 141);

  // The small stacked-wave mark occupies the upper-right corner on the real LCD.
  ctx.strokeStyle = ink; ctx.lineWidth = 4;
  for (let line = 0; line < 3; line++) {
    const y = 39 + line * 10;
    ctx.beginPath(); ctx.moveTo(1150, y); ctx.quadraticCurveTo(1180, y + 16, 1209, y);
    ctx.quadraticCurveTo(1229, y + 9, 1243, y - 4); ctx.stroke();
  }
  text('E', 1229, 96, 20, 'center');
  ctx.beginPath(); ctx.arc(1229, 89, 14, 0, Math.PI * 2); ctx.stroke();

  ctx.strokeStyle = 'rgba(32,42,37,.68)'; ctx.lineWidth = 2;
  ctx.beginPath(); ctx.moveTo(27, 390); ctx.lineTo(1248, 390);
  ctx.moveTo(590, 414); ctx.lineTo(590, 587); ctx.stroke();
  number(tokyo.getUTCMonth() + 1, 28, 433, 137);
  ctx.lineWidth = 6; ctx.strokeStyle = ink;
  ctx.beginPath(); ctx.moveTo(239, 440); ctx.lineTo(216, 566); ctx.stroke();
  number(tokyo.getUTCDate(), 272, 433, 137);
  text(weekdays[tokyo.getUTCDay()], 527, 558, 74, 'center');

  number('24', 636, 433, 137); dot(805, 562, 9);
  number('8', 822, 507, 63, 1); text('°C', 825, 464, 33);
  number('48', 994, 433, 137); text('%', 1173, 566, 45);
  text('快適', 959, 607, 21, 'center');
  for (let step = 0; step < 6; step++) {
    ctx.fillStyle = step === 3 ? ink : 'rgba(32,42,37,.23)';
    ctx.fillRect(839 + step * 60, 626, 47, 3);
  }
  ctx.fillStyle = ink; ctx.beginPath(); ctx.moveTo(1042, 614); ctx.lineTo(1031, 603); ctx.lineTo(1053, 603); ctx.closePath(); ctx.fill();
  ctx.strokeStyle = 'rgba(21,29,24,.4)'; ctx.lineWidth = 3; ctx.strokeRect(1.5, 1.5, 1277, 647);
  ctx.restore();
}

export function createClockTexture() {
  const canvas = document.createElement('canvas'); canvas.width = 1280; canvas.height = 650;
  drawClock(canvas.getContext('2d'), canvas.width, canvas.height);
  const texture = new CanvasTexture(canvas);
  texture.colorSpace = SRGBColorSpace; texture.anisotropy = 8;
  return texture;
}
