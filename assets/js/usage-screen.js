import { CanvasTexture, SRGBColorSpace } from 'three';

// Authored display artwork from the supplied split Usage screenshot.
// Values are fixed to that reference. The caller owns the paused animation clock.
const WIDTH = 1536, HEIGHT = 998;
const FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif';
const fill = (ctx, x, y, w, h, color) => { ctx.fillStyle = color; ctx.fillRect(x, y, w, h); };
function text(ctx, label, x, y, size = 16, color = '#292929', weight = 400, font = FONT) {
  ctx.fillStyle = color; ctx.font = `${weight} ${size}px ${font}`;
  ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic'; ctx.fillText(label, x, y);
}
function round(ctx, x, y, w, h, radius, color, border) {
  ctx.beginPath(); ctx.roundRect(x, y, w, h, radius);
  if (color) { ctx.fillStyle = color; ctx.fill(); }
  if (border) { ctx.strokeStyle = border; ctx.lineWidth = 1; ctx.stroke(); }
}
function line(ctx, points, color, width = 1.5) {
  ctx.beginPath(); points.forEach(([x, y], i) => i ? ctx.lineTo(x, y) : ctx.moveTo(x, y));
  ctx.strokeStyle = color; ctx.lineWidth = width; ctx.lineCap = 'round'; ctx.lineJoin = 'round'; ctx.stroke();
}
function circle(ctx, x, y, radius, color, border) {
  ctx.beginPath(); ctx.arc(x, y, radius, 0, Math.PI * 2);
  if (color) { ctx.fillStyle = color; ctx.fill(); }
  if (border) { ctx.strokeStyle = border; ctx.lineWidth = 1.4; ctx.stroke(); }
}
function icon(ctx, kind, x, y, color, size = 18) {
  ctx.save(); ctx.translate(x, y); ctx.scale(size / 20, size / 20);
  const paths = {
    close: [[[5,5],[15,15]], [[15,5],[5,15]]],
    account: [[[3,18],[4,14],[7,12],[13,12],[16,14],[17,18]]],
    billing: [[[2,4],[18,4],[18,16],[2,16],[2,4]], [[2,8],[18,8]], [[5,12],[8,12]]],
    usage: [[[3,3],[15,3],[18,5],[15,8],[3,8],[1,6],[3,3]], [[3,12],[11,12],[14,15],[11,18],[3,18],[1,15],[3,12]]],
    bars: [[[2,16],[2,9],[5,9],[5,16],[2,16]], [[8,16],[8,3],[11,3],[11,16],[8,16]], [[14,16],[14,6],[17,6],[17,16],[14,16]], [[1,19],[19,19]]],
    notification: [[[4,14],[6,11],[6,6],[8,3],[12,3],[14,6],[14,11],[16,14],[4,14]], [[8,17],[12,17]]],
    voice: [[[2,8],[2,12]], [[6,4],[6,16]], [[10,1],[10,19]], [[14,5],[14,15]], [[18,8],[18,12]]],
    analytics: [[[2,3],[18,3],[18,17],[2,17],[2,3]], [[4,13],[8,8],[11,11],[16,6]]],
    lock: [[[4,9],[16,9],[16,18],[4,18],[4,9]], [[6,9],[6,5],[8,2],[12,2],[14,5],[14,9]], [[10,12],[10,15]]],
    safety: [[[10,1],[18,5],[17,13],[14,17],[10,19],[6,17],[3,13],[2,5],[10,1]], [[6,10],[9,13],[14,7]]],
    storage: [[[4,3],[16,3],[19,10],[18,17],[2,17],[1,10],[4,3]], [[2,10],[18,10]], [[5,14],[8,14]]],
    code: [[[6,5],[2,10],[6,15]], [[14,5],[18,10],[14,15]], [[12,2],[8,18]]],
    briefcase: [[[2,6],[18,6],[18,18],[2,18],[2,6]], [[6,6],[6,2],[14,2],[14,6]], [[2,11],[18,11]], [[9,10],[11,10],[11,13],[9,13],[9,10]]],
    list: [[[7,4],[18,4]], [[7,10],[18,10]], [[7,16],[18,16]], [[2,3],[4,3],[4,5],[2,5],[2,3]], [[2,9],[4,9],[4,11],[2,11],[2,9]], [[2,15],[4,15],[4,17],[2,17],[2,15]]],
    browser: [[[2,2],[18,2],[18,16],[2,16],[2,2]], [[2,7],[18,7]], [[6,4],[7,4]], [[10,10],[10,18],[13,15],[15,19]]],
    external: [[[10,3],[17,3],[17,10]], [[17,3],[6,14]]],
    data: [[[3,2],[9,1],[15,4],[15,10],[9,13],[3,10],[3,2]], [[3,4],[9,7],[15,4]], [[9,7],[9,13]], [[11,13],[16,11],[19,14],[18,18],[14,19],[11,16],[11,13]]],
  };
  if (kind === 'search') { circle(ctx, 8, 8, 5.5, null, color); line(ctx, [[12,12],[17,17]], color); }
  else if (kind === 'general') {
    for (let i = 0; i < 8; i++) {
      const angle = i * Math.PI / 4;
      line(ctx, [[10 + Math.cos(angle) * 6,10 + Math.sin(angle) * 6],[10 + Math.cos(angle) * 8.5,10 + Math.sin(angle) * 8.5]], color, 2);
    }
    circle(ctx, 10, 10, 6, null, color); circle(ctx, 10, 10, 2.2, null, color);
  } else if (kind === 'personalization' || kind === 'memory') {
    circle(ctx, 10, 10, 8, null, color); line(ctx, [[10,5],[10,10],[14,10]], color);
    if (kind === 'personalization') line(ctx, [[6,5],[5,8],[8,9]], color);
  } else if (kind === 'globe') {
    circle(ctx, 10, 10, 8, null, color);
    ctx.beginPath(); ctx.ellipse(10,10,3.5,8,0,0,Math.PI*2); ctx.stroke(); line(ctx, [[2,10],[18,10]], color);
  } else if (kind === 'plugins') {
    circle(ctx, 10, 10, 8, null, color);
    for (let i=0;i<5;i++) { const a=i*Math.PI*2/5;line(ctx,[[10+Math.cos(a)*3,10+Math.sin(a)*3],[10+Math.cos(a+.7)*6,10+Math.sin(a+.7)*6]],color); }
  } else if (kind === 'key') {
    circle(ctx, 13, 6, 5, null, color); circle(ctx, 14, 5, 1.2, color);
    line(ctx, [[9,10],[2,17],[5,19],[7,17],[6,16],[8,14],[9,15],[11,13]], color);
  } else if (kind === 'refresh') {
    ctx.strokeStyle=color;ctx.lineWidth=1.5;ctx.beginPath();ctx.arc(10,10,7,.3,5.5);ctx.stroke();line(ctx,[[16,3],[16,8],[11,8]],color);
  } else {
    if (kind === 'account') circle(ctx, 10, 6, 3.5, null, color);
    for (const path of paths[kind] || paths.briefcase) line(ctx, path, color);
  }
  ctx.restore();
}
function sidebarRow(ctx, x, y, width, label, kind, selected, dark) {
  if (selected) round(ctx, x, y - 25, width, 38, 9, dark ? '#303030' : '#e5e5e3');
  icon(ctx, kind, x + 12, y - 15, dark ? '#d7d7d7' : '#747572', 17);
  text(ctx, label, x + 40, y, 14.5, dark ? '#e2e2e2' : '#686965', selected ? 600 : 400);
}
function bar(ctx, x, y, w, fraction, dark = false) {
  round(ctx, x, y, w, dark ? 5 : 7, 3.5, dark ? '#414141' : fraction ? '#cce1fb' : '#f1f1ef', dark ? null : '#e8e9e7');
  if (fraction) round(ctx, x, y, w * fraction, dark ? 5 : 7, 3.5, dark ? '#fafafa' : '#307fd7');
}
function paintChatGPT(ctx) {
  round(ctx, 4, 4, 758, 990, 12, '#090909', '#646464');
  text(ctx, 'ChatGPT', 27, 48, 26, '#dddddd', 650);
  icon(ctx, 'search', 183, 29, '#727272', 20);
  icon(ctx, 'browser', 218, 30, '#727272', 20);
  round(ctx, 379, 21, 242, 38, 22, '#141414');
  round(ctx, 380, 22, 120, 36, 20, '#202020');
  text(ctx, 'Chat', 421, 46, 16, '#d0d0d0', 550); text(ctx, 'Work', 542, 46, 16, '#818181', 550);
  icon(ctx, 'refresh', 714, 30, '#777', 22);

  round(ctx, 22, 86, 721, 886, 17, '#222222');
  fill(ctx, 201, 87, 1, 884, '#363636');
  round(ctx, 35, 102, 31, 32, 7, '#303030'); icon(ctx, 'close', 40, 107, '#e0e0e0', 21);
  round(ctx, 35, 153, 153, 37, 20, null, '#454545'); icon(ctx, 'search', 46, 163, '#a1a1a1', 16);
  text(ctx, 'Search settings', 70, 177, 13, '#acacac');
  const rows = [
    ['General','general'],['Notifications','notification'],['Personalization','personalization'],['Plugins','plugins'],
    ['Voice','voice'],['Billing','billing'],['Usage','usage'],['Analytics','analytics'],['Data controls','data'],
    ['Cloud browser','browser'],['Storage','storage'],['Safety','safety'],['Security and login','key'],['Parental controls','account'],
  ];
  rows.forEach(([label,kind], index) => sidebarRow(ctx, 29, 224 + index * 46, 165, label, kind, label === 'Usage', true));

  text(ctx, 'Usage', 226, 135, 25, '#f0f0f0', 500); fill(ctx, 226, 161, 492, 1, '#454545');
  text(ctx, 'Plan limits', 226, 211, 22, '#f0f0f0', 500);
  text(ctx, 'Shared across Codex, Work, Workspace Agents,', 226, 243, 14, '#a5a5a5');
  text(ctx, 'and ChatGPT for Excel. Chat conversations', 226, 264, 14, '#a5a5a5');
  text(ctx, 'are not included.', 226, 285, 14, '#a5a5a5');
  fill(ctx, 226, 305, 492, 1, '#444444');
  round(ctx, 226, 327, 492, 125, 18, '#1c1c1c', '#2d2d2d');
  text(ctx, 'Weekly limit', 245, 363, 19, '#f0f0f0', 550);
  text(ctx, 'Resets in 6d 10h', 245, 396, 16, '#bcbcbc');
  text(ctx, '76% left', 635, 396, 16, '#bcbcbc'); bar(ctx, 245, 419, 453, .76, true);

  text(ctx, 'Usage limit resets', 226, 509, 22, '#f0f0f0', 500);
  text(ctx, 'Use a reset to restore your 5-hour limit,', 226, 539, 14, '#a5a5a5');
  text(ctx, 'weekly limit, or both.', 226, 560, 14, '#a5a5a5');
  fill(ctx, 226, 580, 492, 1, '#444444');
  round(ctx, 226, 601, 492, 114, 17, '#1c1c1c', '#2d2d2d');
  text(ctx, 'Full reset', 245, 638, 17, '#eaeaea', 500);
  text(ctx, 'Expires Oct 5, 1:19 PM', 245, 674, 15, '#b6b6b6');
  round(ctx, 597, 643, 102, 35, 19, null, '#494949'); text(ctx, 'Use reset', 613, 666, 14.5, '#eeeeee');

  text(ctx, 'Credits', 226, 772, 22, '#f0f0f0', 500);
  text(ctx, 'Buy credits or turn on automatic reload to', 226, 803, 14, '#a5a5a5');
  text(ctx, 'continue using Work when you reach usage limits.', 226, 824, 14, '#a5a5a5');
  text(ctx, 'Learn more', 226, 847, 14, '#579ddb');
  fill(ctx, 226, 866, 492, 1, '#444444');
  round(ctx, 226, 887, 492, 63, 16, '#1c1c1c', '#2d2d2d');
  text(ctx, 'Credits', 245, 925, 16, '#dedede');
  round(ctx, 592, 901, 106, 34, 18, null, '#494949'); text(ctx, 'Add credits', 606, 923, 14, '#ededed');
}
function paintClaude(ctx) {
  round(ctx, 773, 4, 759, 990, 12, '#babbb8', '#c5c5c3');
  text(ctx, 'Claude', 795, 48, 29, '#454742', 600, 'Georgia, serif');
  icon(ctx, 'browser', 946, 28, '#737570', 22); icon(ctx, 'notification', 1490, 29, '#777a74', 22);
  round(ctx, 791, 86, 722, 886, 16, '#fff', '#d2d2ce');
  ctx.save(); ctx.beginPath(); ctx.roundRect(791, 86, 722, 886, 16); ctx.clip();
  fill(ctx, 791, 86, 177, 886, '#fcfcfa'); ctx.restore();
  fill(ctx, 967, 87, 1, 884, '#e3e3df');
  round(ctx, 803, 103, 153, 37, 10, '#fff', '#e1e1dd'); icon(ctx, 'search', 814, 113, '#91958f', 16);
  text(ctx, 'Search', 839, 128, 14, '#8f928c'); text(ctx, 'Settings', 808, 182, 13, '#92958e');
  const rows = [
    ['General','general'],['Account','account'],['Privacy','lock'],['Billing','billing'],['Usage','bars'],
    ['Capabilities','briefcase'],['Memory','memory'],['Claude Code','code'],['Cowork','list'],['Claude in Chrome','globe'],
  ];
  rows.forEach(([label,kind], index) => sidebarRow(ctx, 799, 220 + index * 43, 159, label, kind, label === 'Usage', false));
  text(ctx, 'Platform', 808, 686, 13, '#92958e'); sidebarRow(ctx, 799, 724, 159, 'API keys', 'key', false, false);
  icon(ctx, 'external', 935, 708, '#91958f', 17);
  sidebarRow(ctx, 799, 946, 159, 'Customize', 'briefcase', false, false);
  icon(ctx, 'close', 1473, 108, '#4a4d47', 21);

  const x = 990;
  text(ctx, 'Plan usage limits', x, 157, 20, '#262925', 650); text(ctx, 'Max (20x)', 1173, 157, 17, '#686b64', 500);
  text(ctx, 'Current session', x, 214, 17, '#343731', 500);
  text(ctx, 'Resets in 3 hr 32 min', x, 242, 14, '#787c74');
  bar(ctx, 1210, 215, 191, .30); text(ctx, '30% used', 1420, 224, 14, '#747970');

  text(ctx, 'Weekly limits', x, 307, 21, '#292d26', 650);
  round(ctx, x, 337, 499, 119, 15, '#fcfcfb', '#e7e7e2'); circle(ctx, 1010, 362, 7, null, '#7d8278');
  text(ctx, 'i', 1008, 367, 13, '#72786d', 600);
  text(ctx, 'Your limits are temporarily boosted.', 1028, 366, 15, '#383d33', 650);
  text(ctx, 'Your weekly Claude Code limit is 50% higher', 1028, 393, 14, '#377db4');
  text(ctx, 'through September 13.', 1028, 421, 14, '#626a5b');
  text(ctx, 'Learn more about usage limits', x, 490, 14, '#3278b7');
  line(ctx, [[x,493],[1186,493]], '#b0c8de', .8);

  text(ctx, 'All models', x, 540, 17, '#343a2f', 500);
  text(ctx, 'Resets Wed 4:00 PM', x, 568, 14, '#757c6e');
  bar(ctx, 1210, 539, 191, .32); text(ctx, '32% used', 1420, 548, 14, '#747970');
  text(ctx, 'Fable', x, 620, 17, '#343a2f', 500);
  text(ctx, 'Resets Wed 4:00 PM', x, 648, 14, '#757c6e');
  bar(ctx, 1210, 619, 191, 0); text(ctx, '0% used', 1427, 628, 14, '#747970');
  text(ctx, 'Last updated: 1 minute ago', x, 719, 14, '#72796a'); icon(ctx, 'refresh', 1176, 704, '#656e5d', 18);

  text(ctx, 'Usage credits', x, 782, 20, '#303829', 650);
  text(ctx, 'Turn on usage credits to keep using Claude', x, 819, 14, '#4c5544');
  text(ctx, 'if you hit a plan limit.', x, 841, 14, '#4c5544');
  const creditLinkX = x + ctx.measureText('if you hit a plan limit.').width + 6;
  text(ctx, 'Learn more', creditLinkX, 841, 14, '#367cad');
  round(ctx, 1440, 816, 40, 22, 12, '#d5d7d2'); circle(ctx, 1451, 827, 8.5, '#fff');
  fill(ctx, x, 867, 498, 1, '#edeee9');
  text(ctx, '$0.00 spent', x, 898, 15, '#3d4733');
  bar(ctx, 1127, 905, 274, 0); text(ctx, '0% used', 1427, 914, 14, '#747970');
  text(ctx, 'Resets Oct 1', x, 929, 14, '#747d6b');
}
function cursor(ctx, x, y) {
  ctx.save(); ctx.translate(x, y); ctx.shadowColor = '#00000033'; ctx.shadowBlur = 3; ctx.shadowOffsetY = 1;
  ctx.beginPath(); ctx.moveTo(0,0); ctx.lineTo(0,23); ctx.lineTo(6,17); ctx.lineTo(11,28);
  ctx.lineTo(16,25); ctx.lineTo(11,15); ctx.lineTo(20,14); ctx.closePath();
  ctx.fillStyle = '#242424'; ctx.fill(); ctx.strokeStyle = '#f6f6f6'; ctx.lineWidth = 1.4; ctx.stroke(); ctx.restore();
}
const smooth = value => { const t = Math.max(0, Math.min(1, value)); return t * t * (3 - 2 * t); };
function cursorPosition(seconds) {
  const time = seconds % 38;
  const points = [[0,576,432],[4,576,432],[9,682,378],[13,682,378],[20,1312,558],[26,1312,558],[33,576,432],[38,576,432]];
  for (let i=1;i<points.length;i++) {
    if (time <= points[i][0]) {
      const a=points[i-1], b=points[i], t=smooth((time-a[0])/(b[0]-a[0]));
      return [a[1]+(b[1]-a[1])*t, a[2]+(b[2]-a[2])*t];
    }
  }
  return points[0].slice(1);
}

export function createUsageScreen() {
  const surface = document.createElement('canvas'), background = document.createElement('canvas');
  for (const canvas of [surface, background]) { canvas.width = WIDTH; canvas.height = HEIGHT; }
  const base = background.getContext('2d'), ctx = surface.getContext('2d');
  fill(base, 0, 0, WIDTH, HEIGHT, '#eaeae8'); paintChatGPT(base); paintClaude(base);
  const map = new CanvasTexture(surface); map.colorSpace = SRGBColorSpace; map.anisotropy = 8;
  let previous = -1, disposed = false;
  function update(elapsedMs) {
    if (disposed || !Number.isFinite(elapsedMs) || elapsedMs < 0) return false;
    const bucket = Math.floor(elapsedMs * 30 / 1000 + 1e-7);
    if (bucket <= previous) return false;
    previous = bucket; ctx.drawImage(background, 0, 0); cursor(ctx, ...cursorPosition(elapsedMs / 1000));
    map.needsUpdate = true; return true;
  }
  update(0);
  return { map, update, dispose() {
    if (disposed) return;
    disposed = true; map.dispose();
    surface.width = surface.height = background.width = background.height = 1;
  } };
}
