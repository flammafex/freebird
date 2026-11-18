// Proof-of-work admission and transport guards with a mocked fetch. No peer dependency.
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomBytes } from 'node:crypto';
import { admissionFromPow } from '../src/admission.mjs';
import { FreebirdError } from '../src/errors.mjs';
import { configure, send } from '../src/transport.mjs';

const ISSUER = 'https://issuer.example:8443';
const code = randomBytes(32).toString('base64url');
assert.equal(code.length, 43);

function recorder(reply) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return typeof reply === 'function' ? reply(url, init) : reply;
  };
  return { calls, fetch };
}

test('admissionFromPow: posts the payload once with safe fetch options and returns the code', async () => {
  const { calls, fetch } = recorder(Response.json({ admission: code }));
  assert.equal(await admissionFromPow(ISSUER, 'solved-payload', { fetch }), code);
  assert.equal(calls.length, 1);
  const { url, init } = calls[0];
  assert.equal(url, `${ISSUER}/freebird/pow/admission`);
  assert.equal(init.method, 'POST');
  assert.equal(init.body, JSON.stringify({ payload: 'solved-payload' }));
  assert.equal(init.headers['Content-Type'], 'application/json');
  assert.equal(init.credentials, 'omit');
  assert.equal(init.cache, 'no-store');
  assert.equal(init.redirect, 'error');
  assert.equal(init.referrerPolicy, 'no-referrer');
  assert.ok(init.signal instanceof AbortSignal);
});

test('admissionFromPow: refusal statuses are typed and never echo the response body', async () => {
  const leaked = `secret-${code}`;
  for (const [status, headers] of [
    [403, {}], [422, {}], [429, { 'Retry-After': '42' }], [503, { 'Retry-After': '42' }],
  ]) {
    const { fetch } = recorder(new Response(leaked, { status, headers }));
    await assert.rejects(admissionFromPow(ISSUER, 'p', { fetch }), error => {
      assert.ok(error instanceof FreebirdError);
      assert.equal(error.stage, 'admission');
      assert.equal(error.status, status);
      assert.equal(error.reason, 'http');
      assert.equal(error.message.includes(code), false);
      assert.equal(error.message.includes('secret'), false);
      assert.equal(error.retryAfter, status === 429 || status === 503 ? 42 : undefined);
      return true;
    });
  }
});

test('admissionFromPow: malformed success bodies are protocol errors and echo nothing', async () => {
  for (const body of ['not json', '{}', JSON.stringify({ admission: 'short' }),
    JSON.stringify({ admission: `${code.slice(0, 42)}B` }), 'x'.repeat(2000)]) {
    const { fetch } = recorder(new Response(body, { status: 200 }));
    await assert.rejects(admissionFromPow(ISSUER, 'p', { fetch }), error => {
      assert.ok(error instanceof FreebirdError);
      assert.equal(error.reason, 'protocol');
      assert.equal(error.message.includes(body.slice(0, 20)), false);
      return true;
    });
  }
});

test('admissionFromPow: network failure and timeout are typed without upstream text', async () => {
  const network = recorder(async () => { throw new TypeError('connect ECONNREFUSED 10.0.0.1 secret'); });
  await assert.rejects(admissionFromPow(ISSUER, 'p', { fetch: network.fetch }), error => {
    assert.equal(error.reason, 'network');
    assert.equal(error.message.includes('secret'), false);
    return true;
  });
  const slow = (url, init) => new Promise((_, reject) => {
    init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
  });
  await assert.rejects(admissionFromPow(ISSUER, 'p', { fetch: slow, timeout: 20 }), error => {
    assert.equal(error.reason, 'timeout');
    assert.equal(error.stage, 'admission');
    return true;
  });
});

test('admissionFromPow: rejects a missing payload before any request', async () => {
  const { calls, fetch } = recorder(Response.json({ admission: code }));
  for (const payload of ['', undefined, 7]) {
    await assert.rejects(admissionFromPow(ISSUER, payload, { fetch }), TypeError);
  }
  assert.equal(calls.length, 0);
});

test('configuration: refuses non-HTTPS issuers, bad timeouts and missing fetch before any request', async () => {
  const { calls, fetch } = recorder(Response.json({ admission: code }));
  for (const options of [
    { issuer: 'http://issuer.example:8443', fetch },
    { issuer: 'https://issuer.example/path', fetch },
    { issuer: ISSUER, fetch, timeout: 0 },
    { issuer: ISSUER, fetch, timeout: 1.5 },
    { issuer: ISSUER, fetch, timeout: 999_999 },
    { issuer: ISSUER, fetch, onStage: 'nope' },
    { issuer: ISSUER, fetch: 'nope' },
  ]) {
    await assert.rejects(admissionFromPow(options.issuer, 'p', options), TypeError);
  }
  assert.equal(calls.length, 0);
});

test('configuration: plain HTTP is accepted only for 127.0.0.1 with allowInsecureLoopback', () => {
  assert.equal(configure({ issuer: 'http://127.0.0.1:8081', allowInsecureLoopback: true }).origin,
    'http://127.0.0.1:8081');
  assert.throws(() => configure({ issuer: 'http://127.0.0.1:8081' }), TypeError);
  assert.throws(() => configure({ issuer: 'http://localhost:8081', allowInsecureLoopback: true }), TypeError);
});

test('send: a caller abort surfaces as aborted, not as a timeout', async () => {
  const controller = new AbortController();
  const fetch = (url, init) => new Promise((_, reject) => {
    init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    controller.abort();
  });
  const config = configure({ issuer: ISSUER, fetch });
  await assert.rejects(send('access', new URL(`${ISSUER}/x`), { signal: controller.signal }, config),
    error => error.reason === 'aborted');
});
