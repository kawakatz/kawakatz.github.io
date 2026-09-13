import { CanvasTexture, SRGBColorSpace } from 'three';

// US MacBook and JIS Mouse layouts; geometry and printed legends share deck coordinates.
export function keyLayout(kind) {
  if (kind !== 'macbook' && kind !== 'mouse-laptop') throw new Error(`Unknown keyboard: ${kind}`);
  const mac = kind === 'macbook', pitch = mac ? .272 / 14.5 : .018;
  const rowPitch = mac ? .0175 : .018, top = mac ? -.074 : -.098;
  const left = mac ? -.136 : -.171, gap = .0013, keys = [];
  const letters = (latin, kana) => Array.from(latin, (label, i) => [label, 1, kana[i]]);
  function key(unit, row, units, label, secondary, rows = 1) {
    const result = { x: left + (unit + units / 2) * pitch, z: top + row * rowPitch, w: units * pitch - gap, d: rows * rowPitch - gap, label };
    if (secondary) result.secondary = secondary;
    keys.push(result);
    return result;
  }
  function row(index, specs, start = 0) {
    let unit = start;
    for (const spec of specs) {
      const [label, units = 1, secondary] = typeof spec === 'string' ? [spec] : spec;
      key(unit, index, units, label, secondary); unit += units;
    }
  }
  const numbers = letters('1234567890-^¥', 'ぬふあうえおやゆよわほへー');
  const upper = letters('QWERTYUIOP@[', 'たていすかんなにらせ゛゜');
  const middle = letters('ASDFGHJKL;:', 'ちとしはきくまのりれけ');
  const lower = letters('ZXCVBNM,./\\', 'つさそひこみもねるめろ');
  if (mac) {
    row(0, [['esc', 1.5], ...Array.from({ length: 12 }, (_, i) => `F${i + 1}`)]);
    const icons = ['sun-low', 'sun', 'windows', 'search', 'mic', 'moon', 'previous', 'play', 'next', 'mute', 'volume-low', 'volume'];
    keys.slice(1).forEach((cap, i) => { cap.icon = icons[i]; });
    key(13.5, 0, 1, '').touchId = true;
    row(1, [...letters('`1234567890-=', '~!@#$%^&*()_+'), ['delete', 1.5]]);
    row(2, [['tab', 1.5], ...'QWERTYUIOP', ['[', 1, '{'], [']', 1, '}'], ['\\', 1, '|']]);
    row(3, [['caps lock', 1.75], ...'ASDFGHJKL', [';', 1, ':'], ["'", 1, '"'], ['return', 1.75]]);
    row(4, [['shift', 2.25], ...'ZXCVBNM', [',', 1, '<'], ['.', 1, '>'], ['/', 1, '?'], ['shift', 2.25]]);
    row(5, ['fn', ['control', 1, '⌃'], ['option', 1, '⌥'], ['command', 1.25, '⌘'], ['', 5], ['command', 1.25, '⌘'], ['option', 1, '⌥']]);
  } else {
    row(0, ['Esc', ...Array.from({ length: 12 }, (_, i) => `F${i + 1}`), 'Insert', 'Delete', 'PrtSc', 'ScrLk', 'Pause', 'End']);
    const icons = ['touchpad', 'screen', 'mute', 'volume-low', 'volume', 'sun-low', 'sun', 'screen', 'wireless', 'camera', 'airplane', 'moon'];
    keys.forEach((cap, i) => { cap.d = .0118; if (i > 0 && i <= 12) cap.icon = icons[i - 1]; });
    row(1, [['半角', 1, '全角'], ...numbers, 'Backspace']);
    row(2, [['Tab', 1.5], ...upper]);
    row(3, [['Caps', 1.75], ...middle, [']', .75, 'む']]);
    key(13.5, 2.5, 1.5, 'Enter', undefined, 2);
    row(4, [['Shift', 2.25], ...lower, ['Shift', 1.75]]);
    row(5, [['Ctrl', 1.25], 'Fn', '⊞', 'Alt', ['無変換', 1.25], ['', 2.25], ['変換', 1.25], 'かな', 'Alt', 'Ctrl']);
    row(1, ['Num', '/', '*', '−'], 15);
    row(2, [['7', 1, 'Home'], '8', ['9', 1, 'PgUp']], 15);
    key(18, 2.5, 1, '+', undefined, 2);
    row(3, ['4', '5', '6'], 15);
    row(4, [['1', 1, 'End'], '2', ['3', 1, 'PgDn']], 15);
    key(18, 4.5, 1, 'Enter', undefined, 2);
    row(5, [['0', 2, 'Ins'], ['.', 1, 'Del']], 15);
  }
  const arrows = mac ? 11.5 : 12;
  for (const [unit, rowIndex, label] of [[arrows, 5.25, '←'], [arrows + 1, 4.75, '↑'], [arrows + 1, 5.25, '↓'], [arrows + 2, 5.25, '→']]) {
    const cap = key(unit, rowIndex, 1, mac ? ({ '←': '◀', '↑': '▲', '↓': '▼', '→': '▶' })[label] : label); cap.d = rowPitch / 2 - gap;
  }
  return keys;
}

function drawIcon(ctx, name, x, y, size) {
  ctx.save(); ctx.translate(x, y); ctx.scale(size, size);
  ctx.lineWidth = .065; ctx.lineCap = 'round'; ctx.lineJoin = 'round';
  ctx.beginPath();
  if (name.startsWith('sun')) {
    const radius = name === 'sun-low' ? .16 : .23;
    ctx.arc(0, 0, radius, 0, Math.PI * 2);
    for (let i = 0; i < 8; i++) {
      const a = i * Math.PI / 4;
      ctx.moveTo(Math.cos(a) * .32, Math.sin(a) * .32); ctx.lineTo(Math.cos(a) * .45, Math.sin(a) * .45);
    }
  } else if (name === 'search') {
    ctx.arc(-.08, -.08, .27, 0, Math.PI * 2); ctx.moveTo(.13, .13); ctx.lineTo(.41, .41);
  } else if (name === 'globe') {
    ctx.arc(0, 0, .42, 0, Math.PI * 2); ctx.moveTo(-.42, 0); ctx.lineTo(.42, 0);
    ctx.moveTo(0, -.42); ctx.bezierCurveTo(-.29, -.20, -.29, .20, 0, .42); ctx.bezierCurveTo(.29, .20, .29, -.20, 0, -.42);
  } else if (name === 'windows') {
    ctx.rect(-.43, -.32, .37, .28); ctx.rect(.06, -.32, .37, .28); ctx.rect(-.43, .08, .86, .28);
  } else if (name === 'mic') {
    ctx.roundRect(-.13, -.42, .26, .56, .13); ctx.moveTo(-.26, -.05); ctx.bezierCurveTo(-.26, .39, .26, .39, .26, -.05); ctx.moveTo(0, .27); ctx.lineTo(0, .45);
  } else if (name === 'moon') {
    ctx.arc(0, 0, .4, -.5 * Math.PI, .5 * Math.PI, true); ctx.bezierCurveTo(-.32, .22, -.32, -.22, 0, -.4);
  } else if (['previous', 'next', 'play'].includes(name)) {
    if (name === 'previous') ctx.scale(-1, 1);
    for (const offset of name === 'play' ? [-.22] : [-.37, -.04]) {
      ctx.moveTo(offset, -.28); ctx.lineTo(offset + .30, 0); ctx.lineTo(offset, .28); ctx.closePath();
    }
    if (name === 'play') { ctx.moveTo(.21, -.28); ctx.lineTo(.21, .28); ctx.moveTo(.38, -.28); ctx.lineTo(.38, .28); }
  } else if (name.startsWith('volume') || name === 'mute') {
    ctx.moveTo(-.40, -.15); ctx.lineTo(-.22, -.15); ctx.lineTo(.02, -.36); ctx.lineTo(.02, .36); ctx.lineTo(-.22, .15); ctx.lineTo(-.4, .15); ctx.closePath();
    if (name === 'mute') { ctx.moveTo(.16, -.15); ctx.lineTo(.4, .15); ctx.moveTo(.16, .15); ctx.lineTo(.4, -.15); }
    else for (const radius of name === 'volume' ? [.24, .41] : [.25]) { ctx.moveTo(Math.cos(-.65) * radius, Math.sin(-.65) * radius); ctx.arc(0, 0, radius, -.65, .65); }
  } else if (name === 'wireless') {
    for (const radius of [.15, .30, .45]) { ctx.moveTo(Math.cos(-2.5) * radius, Math.sin(-2.5) * radius + .25); ctx.arc(0, .25, radius, -2.5, -.64); }
  } else if (name === 'airplane') {
    ctx.moveTo(0, -.4); ctx.lineTo(0, .4); ctx.moveTo(-.4, .1); ctx.lineTo(0, -.15); ctx.lineTo(.4, .1); ctx.moveTo(-.17, .36); ctx.lineTo(0, .25); ctx.lineTo(.17, .36);
  } else {
    ctx.roundRect(-.43, -.30, .86, .58, .06);
    if (name === 'camera') ctx.arc(0, 0, .16, 0, Math.PI * 2);
    else if (name === 'touchpad') { ctx.moveTo(-.43, .1); ctx.lineTo(.43, .1); ctx.moveTo(0, .1); ctx.lineTo(0, .28); }
    else { ctx.moveTo(0, .28); ctx.lineTo(0, .42); ctx.moveTo(-.2, .42); ctx.lineTo(.2, .42); }
  }
  ctx.stroke(); ctx.restore();
}

export function createKeyboardTextures() {
  const maps = {};
  for (const kind of ['macbook', 'mouse-laptop']) {
    const mac = kind === 'macbook', width = mac ? .3126 : .378, depth = mac ? .2212 : .267;
    const canvas = document.createElement('canvas');
    canvas.width = 2048; canvas.height = Math.round(canvas.width * depth / width);
    const ctx = canvas.getContext('2d'), scale = canvas.width / width;
    ctx.translate(canvas.width / 2, canvas.height / 2);
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    const print = (text, x, z, size, maximum) => {
      ctx.font = `500 ${size * scale}px -apple-system, Arial, sans-serif`;
      ctx.fillText(text, x * scale, z * scale, maximum * scale);
    };
    for (const cap of keyLayout(kind)) {
      if (cap.touchId || !cap.label) continue;
      ctx.fillStyle = ctx.strokeStyle = mac ? '#f7f7f5' : '#eef0f1';
      const word = cap.label.length > 1, maximum = cap.w - .0035;
      if (cap.icon) {
        print(cap.label, cap.x, cap.z + (mac ? .0040 : -.0023), mac ? .0019 : .0018, maximum);
        if (!mac) ctx.strokeStyle = '#72a6d6';
        drawIcon(ctx, cap.icon, cap.x * scale, (cap.z + (mac ? -.0016 : .0026)) * scale, (mac ? .0045 : .0033) * scale);
      } else if (mac) {
        if (cap.label === 'fn') {
          print('fn', cap.x + .0037, cap.z - .004, .00225, maximum);
          drawIcon(ctx, 'globe', (cap.x - .0037) * scale, (cap.z + .0035) * scale, .0037 * scale);
        } else if (word) {
          const right = ['delete', 'return'].includes(cap.label) || (cap.label === 'shift' && cap.x > 0);
          ctx.textAlign = right ? 'right' : 'left';
          print(cap.label, cap.x + (right ? 1 : -1) * (cap.w / 2 - .0023), cap.z + .0040, .00225, maximum);
          ctx.textAlign = 'center';
          if (cap.secondary) print(cap.secondary, cap.x + cap.w * .25, cap.z - .0036, .0032, maximum);
          if (cap.label === 'caps lock') { ctx.beginPath(); ctx.arc((cap.x - cap.w / 2 + .0027) * scale, (cap.z - .0035) * scale, .0006 * scale, 0, Math.PI * 2); ctx.fill(); }
        } else if (cap.secondary) {
          print(cap.secondary, cap.x, cap.z - .0040, .0032, maximum);
          print(cap.label, cap.x, cap.z + .0035, .0037, maximum);
        } else print(cap.label, cap.x, cap.z, cap.d < .01 ? .0030 : .0041, maximum);
      } else {
        if (cap.label === 'Fn') ctx.fillStyle = '#72a6d6';
        print(cap.label, cap.x - (cap.secondary ? cap.w * .15 : 0), cap.z - (cap.secondary ? .0030 : 0), word ? .00215 : .0036, maximum);
        if (cap.secondary) print(cap.secondary, cap.x + cap.w * .18, cap.z + .0036, .00205, maximum);
      }
    }
    if (mac) {
      ctx.fillStyle = '#171c21';
      for (const side of [-1, 1]) {
        for (let col = 0; col < 8; col++) for (let line = 0; line < 89; line++) {
          ctx.beginPath(); ctx.arc((side * .144 + (col - 3.5) * .0011) * scale, (-.0819 + line * .0011) * scale, .00023 * scale, 0, Math.PI * 2); ctx.fill();
        }
      }
    }
    const map = new CanvasTexture(canvas);
    map.colorSpace = SRGBColorSpace; map.anisotropy = 8;
    maps[kind] = map;
  }
  return maps;
}
