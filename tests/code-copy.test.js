import test from 'node:test';
import assert from 'node:assert/strict';

test('code copy preserves content and reports pending, success, failure and retry states', async t => {
  const code = { textContent: 'const answer = 42;\n  answer;\n' };
  let toolbar, resolveWrite, rejectWrite;
  const writes = [], timers = new Map();
  const block = {
    classList: ['language-javascript', 'highlighter-rouge'],
    querySelector: selector => selector === '.rouge-code pre' ? code : { textContent: '1\n2\n' },
    prepend: element => { toolbar = element; }
  };
  const globals = {
    document: {
      querySelectorAll: () => [],
      querySelector: selector => selector === '.prose' ? {
        querySelectorAll: selector => selector.includes('highlighter-rouge') ? [block] : []
      } : null,
      createElement: tag => ({
        tagName: tag.toUpperCase(), dataset: {}, attributes: {}, children: [],
        setAttribute(name, value) { this.attributes[name] = value; },
        append(...children) { this.children.push(...children); },
        addEventListener(event, handler) { this[event] = handler; }
      })
    },
    navigator: { clipboard: { writeText(text) {
      writes.push(text);
      return new Promise((resolve, reject) => { resolveWrite = resolve; rejectWrite = reject; });
    } } },
    setTimeout(callback, delay) { const timer = { callback, delay }; timers.set(timer, timer); return timer; },
    clearTimeout: timer => timers.delete(timer)
  };
  const originals = Object.keys(globals).map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]);
  t.after(() => {
    for (const [name, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  });
  for (const [name, value] of Object.entries(globals)) Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  await import('../assets/js/site.js');

  const copy = toolbar.children.find(element => element.tagName === 'BUTTON');
  const status = toolbar.children.find(element => element.className === 'code-copy-status');
  assert.equal(copy.attributes['aria-label'], 'Copy javascript code');
  assert.equal(copy.title, 'Copy code');
  assert.match(copy.innerHTML, /aria-hidden="true"/);
  assert.equal(status.attributes.role, 'status');

  let pending = copy.click();
  assert.equal(copy.disabled, true);
  assert.equal(status.textContent, '');
  assert.deepEqual(writes, [code.textContent]);
  resolveWrite();
  await pending;
  assert.equal(copy.disabled, false);
  assert.equal(copy.dataset.state, 'copied');
  assert.equal(status.textContent, 'Copied');
  const successTimer = [...timers.keys()][0];
  assert.equal(successTimer.delay, 2200);

  pending = copy.click();
  assert.equal(timers.has(successTimer), false, 'Retry cancels the previous reset');
  assert.equal(copy.disabled, true);
  assert.equal(status.textContent, '');
  rejectWrite(new Error('Clipboard denied'));
  await pending;
  assert.equal(copy.disabled, false);
  assert.equal(copy.dataset.state, 'error');
  assert.equal(status.textContent, 'Select and copy manually');
  const errorTimer = [...timers.keys()][0];
  assert.equal(errorTimer.delay, 4000);
  timers.delete(errorTimer);
  errorTimer.callback();
  assert.equal(copy.dataset.state, undefined);
  assert.equal(status.textContent, '');

  pending = copy.click();
  resolveWrite();
  await pending;
  [...timers.keys()][0].callback();
  assert.equal(copy.dataset.state, undefined);
  assert.equal(status.textContent, '');
  assert.deepEqual(writes, Array(3).fill(code.textContent));
});
