import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

test('only small touch screens redirect from the homepage before scheduling the desk', async () => {
  const home = await readFile(new URL('../_site/index.html', import.meta.url), 'utf8');
  const entry = home.match(/<script id="desk-entry">([\s\S]*?)<\/script>/);
  assert.ok(entry, 'The built homepage contains its early entry script');
  assert.ok(home.indexOf(entry[0]) < home.indexOf('<link'), 'Redirect before loading other page assets');
  assert.doesNotMatch(home, /<script\b[^>]*\bsrc=["'][^"']*\/desk\.js/,
    'No unconditional desk module fetch while redirecting');
  for (const [width, height, touch, redirect] of [
    [390, 844, true, true], [844, 390, true, true], [600, 960, true, true],
    [601, 960, true, false], [768, 1024, true, false], [1440, 900, false, false],
    [390, 844, false, false], [1920, 1080, true, false],
  ]) {
    const routes = [], listeners = [];
    runInNewContext(entry[1], {
      screen: { width, height },
      matchMedia(query) { assert.equal(query, '(any-pointer: coarse)'); return { matches: touch }; },
      location: { replace(url) { routes.push(url); } },
      document: { addEventListener(...args) { listeners.push(args); } },
    });
    assert.deepEqual(routes, redirect ? ['/notes/'] : [], `${width}×${height}, touch=${touch}`);
    assert.equal(listeners.length, redirect ? 0 : 1, 'Phones must not schedule the desk import');
    if (!redirect) {
      assert.equal(listeners[0][0], 'DOMContentLoaded');
      assert.equal(listeners[0][2].once, true);
    }
  }
  for (const path of ['notes/index.html', 'others/index.html', 'about/index.html', 'notes/okta-terrify-vs-macos/index.html']) {
    const html = await readFile(new URL(`../_site/${path}`, import.meta.url), 'utf8');
    assert.ok(!html.includes('id="desk-entry"'), `${path} must not redirect or load the desk`);
  }
});
