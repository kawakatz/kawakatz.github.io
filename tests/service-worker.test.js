import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

test('the replacement worker retires Chirpy without deleting unrelated caches', async () => {
  const handlers = {}, calls = [];
  runInNewContext(await readFile(new URL('../sw.min.js', import.meta.url), 'utf8'), {
    self: {
      addEventListener(name, handler) { handlers[name] = handler; },
      skipWaiting() { calls.push('skipWaiting'); },
      clients: { async claim() { calls.push('claim'); } },
      registration: { async unregister() { calls.push('unregister'); } },
    },
    caches: {
      async keys() { return ['chirpy-123', 'unrelated-cache', 'chirpy-456']; },
      async delete(name) { calls.push(name); },
    },
  });
  assert.equal(handlers.fetch, undefined, 'The retired worker must not intercept requests');
  handlers.install();
  let activation;
  handlers.activate({ waitUntil(promise) { activation = promise; } });
  await activation;
  assert.deepEqual(calls, ['skipWaiting', 'chirpy-123', 'chirpy-456', 'claim', 'unregister']);
});
