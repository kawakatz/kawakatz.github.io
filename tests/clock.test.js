import test from 'node:test';
import assert from 'node:assert/strict';
import { drawClock } from '../assets/js/clock.js';

function read(date) {
    const digits = [], labels = [], stack = [];
    let current, path = [];
    const ctx = {
      save() { stack.push(current); }, restore() { current = stack.pop(); },
      translate(x, y) { current = { x, y, segments: 0, paths: [], top: Infinity, bottom: -Infinity }; digits.push(current); },
      fill() {
        if (current && this.fillStyle === '#202a25') {
          current.segments++;
          current.paths.push(path);
          current.top = Math.min(current.top, ...path.map(point => point[1]));
          current.bottom = Math.max(current.bottom, ...path.map(point => point[1]));
        }
      },
      fillText(value) { labels.push(value); },
      createLinearGradient() { return { addColorStop() {} }; },
      scale() {}, transform() {}, fillRect() {}, strokeRect() {}, beginPath() { path = []; },
      moveTo(x, y) { path.push([x, y]); }, lineTo(x, y) { path.push([x, y]); }, closePath() {}, stroke() {}, arc() {}, quadraticCurveTo() {},
    };
    drawClock(ctx, 1280, 650, new Date(date));
    return { time: digits.slice(0, 6).map(digit => digit.segments), labels, digits };
}

test('the seven-segment clock changes seconds and crosses midnight in Japan', () => {
  const before = read('2026-09-09T14:59:59Z');
  assert.deepEqual(before.time, [5, 5, 5, 6, 5, 6]); // 23:59:59
  assert.ok(before.labels.includes('水'));
  const midnight = read('2026-09-09T15:00:00Z');
  assert.deepEqual(midnight.time, [6, 6, 6, 6, 6, 6]); // 00:00:00
  assert.ok(midnight.labels.includes('木'));
  assert.deepEqual(read('2026-09-09T15:00:01Z').time, [6, 6, 6, 6, 6, 2]);
});

test('LCD ones are optically inset, with shared balanced segments at every size', () => {
  const full = read('2026-11-11T02:08:08Z').digits[3];
  const ones = read('2026-11-11T02:01:01Z').digits.filter(digit => digit.segments === 2);
  for (const one of ones) {
    const ratio = (one.bottom - one.top) / (full.bottom - full.top);
    assert.ok(ratio >= .88 && ratio <= .94, `Unbalanced one height: ${ratio}`);
    assert.equal(one.top + one.bottom, full.top + full.bottom);
    assert.deepEqual(one.paths, ones[0].paths);
  }
  for (let value = 0; value <= 9; value++) {
    const { digits } = read(`2026-11-11T02:0${value}:0${value}Z`);
    for (const digit of digits) assert.ok(digit.top >= 0 && digit.bottom <= 100 && digit.bottom - digit.top >= 88);
  }
  for (const points of full.paths) {
    for (let i = 0; i < points.length; i++) {
      const [x, y] = points[i], prev = points[(i + points.length - 1) % points.length], next = points[(i + 1) % points.length];
      const a = [prev[0] - x, prev[1] - y], b = [next[0] - x, next[1] - y];
      const cosine = (a[0] * b[0] + a[1] * b[1]) / (Math.hypot(...a) * Math.hypot(...b));
      assert.ok(cosine < .5, `Acute segment tip at ${x},${y}`);
    }
  }
});
