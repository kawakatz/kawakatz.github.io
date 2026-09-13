import test from 'node:test';
import assert from 'node:assert/strict';

test('article lightbox zooms from the image and closes safely across keyboard, motion and loading states', async t => {
  const element = () => ({
    handlers: {}, attributes: {}, classList: Object.assign(new Set(), { remove(name) { this.delete(name); } }),
    addEventListener(event, handler) { this.handlers[event] = handler; },
    setAttribute(name, value) { this.attributes[name] = value; }
  });
  const focused = [], decodes = [], animations = [];
  const tick = () => new Promise(resolve => setImmediate(resolve));
  const animate = (frames, timing) => {
    const completion = Promise.withResolvers();
    const animation = {
      frames, timing, finished: completion.promise, resolve: completion.resolve, reject: completion.reject,
      reversed: 0, cancelled: 0,
      reverse() { this.reversed++; }, cancel() { this.cancelled++; }
    };
    animations.push(animation);
    return animation;
  };
  const image = (src, currentSrc, alt, linked = false) => ({
    ...element(), src, currentSrc, alt, tabIndex: -1,
    closest: () => linked ? {} : null,
    getBoundingClientRect: () => ({ x: 90, y: 120, width: 200, height: 100 }),
    focus(options) { focused.push([this, options]); }
  });
  const first = image('/fallback.png', '/selected.png', '  Lab diagram  ');
  const second = image('/second.png', '', '');
  const linked = image('/linked.png', '', 'Linked image', true);
  const linkedClick = linked.handlers.click = () => {};
  const enlarged = {
    animate, getBoundingClientRect: () => ({ x: 20, y: 30, width: 800, height: 400 }),
    decode() { const pending = Promise.withResolvers(); decodes.push(pending); return pending.promise; }
  };
  const closeButton = { ...element(), append(child) { assert.equal(child, enlarged); } };
  let opened = 0, closed = 0, reducedMotion = false;
  const dialog = {
    ...element(), animate, open: false,
    querySelector: selector => selector === '.lightbox-close' ? closeButton : null,
    showModal() { this.open = true; opened++; },
    close() { this.open = false; closed++; this.handlers.close(); }
  };
  const previous = ['document', 'matchMedia'].map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]);
  t.after(() => {
    for (const [name, descriptor] of previous) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  });
  Object.defineProperty(globalThis, 'matchMedia', { configurable: true, value: query => {
    assert.equal(query, '(prefers-reduced-motion: reduce)');
    return { matches: reducedMotion };
  } });
  Object.defineProperty(globalThis, 'document', { configurable: true, value: {
    createElement(tag) { assert.equal(tag, 'img'); return enlarged; },
    querySelector: selector => selector === '.image-lightbox' ? dialog : null,
    querySelectorAll(selector) {
      if (selector === '.work-entry a[data-preview]') return [];
      assert.equal(selector, '#article-content img'); return [first, second, linked];
    }
  } });
  await import('../assets/js/site.js');

  assert.equal(first.tabIndex, 0);
  assert.deepEqual(first.attributes, { role: 'button', 'aria-label': 'Enlarge Lab diagram', 'aria-haspopup': 'dialog' });
  assert.ok(first.classList.has('image-zoom'));
  assert.equal(linked.tabIndex, -1);
  assert.deepEqual(linked.attributes, {});
  assert.equal(linked.classList.size, 0);
  assert.deepEqual(linked.handlers, { click: linkedClick });

  let prevented = 0;
  const key = value => ({ key: value, preventDefault() { prevented++; } });
  first.handlers.keydown(key('ArrowRight'));
  assert.deepEqual([opened, prevented], [0, 0]);

  const opening = first.handlers.click();
  assert.equal(dialog.open, false, 'Wait for decoding before showing the dialog');
  await second.handlers.click();
  assert.deepEqual([decodes.length, enlarged.src], [1, '/selected.png'], 'Ignore another open while decoding');
  decodes[0].resolve();
  await opening;
  assert.deepEqual([enlarged.src, enlarged.alt, dialog.open], ['/selected.png', 'Lab diagram', true]);
  assert.ok(first.classList.has('is-zoomed'));
  assert.deepEqual(animations[0].frames, [{ transform: 'translate(70px, 90px) scale(0.25, 0.25)' }, { transform: 'none' }]);
  assert.deepEqual(animations[0].timing, { duration: 300, easing: 'cubic-bezier(.2, 0, .2, 1)', fill: 'both' });
  assert.deepEqual(animations[1].frames, { backgroundColor: ['#ffffff00', '#fff'] });
  await second.handlers.click();
  assert.equal(decodes.length, 1, 'Ignore another open while the dialog is visible');

  const closing = closeButton.handlers.click({ target: enlarged });
  assert.deepEqual([dialog.open, closed], [true, 0], 'Keep the dialog open until reverse zoom finishes');
  dialog.handlers.click({ target: dialog });
  await closeButton.handlers.click();
  assert.deepEqual(animations.map(animation => animation.reversed), [1, 1], 'Repeated close must not reverse again');
  animations[0].resolve();
  await closing;
  assert.deepEqual([dialog.open, closed], [false, 1]);
  assert.deepEqual(animations.map(animation => animation.cancelled), [1, 1]);
  assert.equal(first.classList.has('is-zoomed'), false);
  assert.deepEqual(focused, [[first, { preventScroll: true }]]);

  second.handlers.keydown(key('Enter'));
  decodes.at(-1).resolve();
  await tick();
  assert.deepEqual([enlarged.src, enlarged.alt, opened], ['/second.png', 'Image 2', 2]);
  let cancelPrevented = false;
  dialog.handlers.cancel({ preventDefault() { cancelPrevented = true; } });
  assert.equal(cancelPrevented, true);
  assert.deepEqual([dialog.open, animations[2].reversed, animations[3].reversed], [true, 1, 1]);
  animations[2].reject(new Error('Animation cancelled'));
  await tick();
  assert.deepEqual([dialog.open, closed], [false, 2]);
  assert.deepEqual(focused.at(-1), [second, { preventScroll: true }]);

  reducedMotion = true;
  const beforeSpace = prevented;
  first.handlers.keydown(key(' '));
  assert.equal(prevented, beforeSpace + 1, 'Space must prevent the page from scrolling');
  decodes.at(-1).resolve();
  await tick();
  assert.deepEqual([enlarged.src, enlarged.alt, opened], ['/selected.png', 'Lab diagram', 3]);
  assert.equal(animations.length, 4, 'Reduced motion must skip both animations');
  await closeButton.handlers.click();
  assert.deepEqual(animations.map(animation => animation.reversed), [1, 1, 1, 1]);
  assert.deepEqual(focused.at(-1), [first, { preventScroll: true }]);
  assert.deepEqual([dialog.open, closed, focused.length], [false, 3, 3]);

  const failed = first.handlers.click();
  decodes.at(-1).reject(new Error('Image decode failed'));
  await failed;
  assert.deepEqual([dialog.open, opened, focused.length], [false, 3, 3]);
  const retry = first.handlers.click();
  decodes.at(-1).resolve();
  await retry;
  assert.equal(opened, 4, 'A decode failure must allow another open');
  dialog.handlers.click({ target: dialog });
  await tick();
  assert.deepEqual([dialog.open, closed, first.classList.has('is-zoomed')], [false, 4, false]);
});
