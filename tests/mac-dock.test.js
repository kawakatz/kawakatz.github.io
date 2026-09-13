import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { drawMacDock, getMacDockItemRect, MAC_DOCK_ORDER, MAC_DOCK_ICON_KEYS } from '../assets/js/mac-dock.js';

test('native Dock preserves the requested order, live date, miniature badges, and graph loop', () => {
  assert.equal(MAC_DOCK_ORDER.join(','), 'finder,settings,calendar,mail,safari,chrome,edge,firefox,vscode,sublime,ghostty,terminal,termius,discord,slack,github,vmware,utm,windows,docker,activity,separator,caido,drawio,codex,claude,separator,minimized-chrome,minimized-codex,minimized-slack,minimized-discord,trash');
  assert.equal(MAC_DOCK_ICON_KEYS.length, 26);
  const icons = Object.fromEntries(MAC_DOCK_ICON_KEYS.map(key => {
    const data = readFileSync(new URL(`../assets/scene/macos-icons/${key}.png`, import.meta.url));
    assert.equal(data.toString('ascii', 1, 4), 'PNG');
    assert.equal(data.readUInt32BE(16), data.readUInt32BE(20), `${key} must retain its square native aspect`);
    assert.ok(data.readUInt32BE(16) >= 256, `${key} must retain native icon detail`);
    return [key, { key }];
  }));
  const commands = [], images = [], labels = [];
  const ctx = new Proxy({
    createLinearGradient: () => ({ addColorStop() {} }),
    drawImage(image, ...args) { images.push(image.key); commands.push(['drawImage', image.key, ...args]); },
    fillText(value, ...args) { labels.push(value); commands.push(['fillText', value, ...args]); },
  }, { get: (target, key) => key in target ? target[key] : (...args) => commands.push([key, ...args]) });
  const bounds = { x: 610, y: 566, w: 910, h: 32 };
  function render(time, date = new Date('2026-09-10T03:00:00Z'), chromeProgress = 0) {
    commands.length = images.length = labels.length = 0;
    drawMacDock(ctx, icons, bounds, time, date, { chromeProgress });
    return commands.map(command => [...command]);
  }
  const five = render(5);
  assert.deepEqual(images, MAC_DOCK_ORDER.filter(key => key !== 'separator').map(key => key.replace('minimized-', '')));
  assert.deepEqual(labels, ['SEP', '10'], 'Only Calendar draws text; minimized windows use colors and bars');
  const app = getMacDockItemRect('chrome', bounds);
  for (const item of MAC_DOCK_ORDER.filter(key => key.startsWith('minimized-'))) {
    const rect = getMacDockItemRect(item, bounds);
    assert.ok(Math.abs(rect.y + rect.h / 2 - app.y - app.h / 2) < 1e-9, `${item} is vertically centered with the app icons`);
    const start = commands.findIndex(command => command[0] === 'translate' && command[1] === rect.x && command[2] === rect.y);
    assert.ok(start >= 0, `${item} is drawn at the same origin returned for window restoration`);
    const body = commands.slice(start).find(command => command[0] === 'roundRect');
    const scale = commands.slice(start).find(command => command[0] === 'scale');
    assert.ok(Math.abs(body[3] * scale[1] - rect.w) < 1e-9 && Math.abs(body[4] * scale[2] - rect.h) < 1e-9, 'The restoration rectangle matches the drawn window body');
  }
  const origin = getMacDockItemRect('minimized-chrome', bounds);
  assert.ok(origin.x >= bounds.x && origin.y >= bounds.y && origin.x + origin.w <= bounds.x + bounds.w && origin.y + origin.h <= bounds.y + bounds.h);
  assert.equal(getMacDockItemRect('missing', bounds), null);
  const originalImages = commands.filter(command => command[0] === 'drawImage');
  render(5, undefined, .01);
  assert.equal(images.filter(key => key === 'chrome').length, 1, 'Opening Notes removes the thumbnail and its badge, keeping the Chrome app icon');
  assert.deepEqual(commands.filter(command => command[0] === 'drawImage'), originalImages.filter((command, index) => command[1] !== 'chrome' || originalImages.findIndex(image => image[1] === 'chrome') === index), 'Every other Dock item keeps its position during restoration');
  assert.deepEqual(getMacDockItemRect('minimized-chrome', bounds), origin);
  assert.deepEqual(render(5), five, 'Returning Notes restores the same miniature');
  assert.deepEqual(render(35), five);
  assert.deepEqual(render(29.966667), render(30));
  assert.deepEqual(render(0), render(30.033333));
  render(5, new Date('2028-02-29T03:00:00Z'));
  assert.ok(labels.includes('FEB') && labels.includes('29'), 'Calendar must use the supplied wall date, including leap days');
  render(5, new Date('2032-12-31T15:00:00Z'));
  assert.ok(labels.includes('JAN') && labels.includes('1'), 'Calendar follows the same Japan-time midnight as the menubar');
});
