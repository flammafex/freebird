// A mock `fetch` lets these tests check `requestAdmission` without opening a network connection
// or installing dependencies.
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomBytes } from 'node:crypto';
import { FreebirdError, requestAdmission } from '../src/index.mjs';

const ISSUER = 'https://issuer.example:8443';
const KEY = `fba_${randomBytes(32).toString('base64url')}`;
const CODE = randomBytes(32).toString('base64url');
assert.equal(KEY.length, 47);
assert.equal(CODE.length, 43);

function recorder(reply) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return typeof reply === 'function' ? reply(url, init) : reply;
  };
  return { calls, fetch };
}

test('posts once to the app admission path with Bearer auth, no body and safe fetch options', async () => {
  const { calls, fetch } = recorder(Response.json({ admission: CODE }));
  assert.equal(await requestAdmission({ issuer: ISSUER, key: KEY, fetch }), CODE);
  assert.equal(calls.length, 1);
  const { url, init } = calls[0];
  assert.equal(url, `${ISSUER}/freebird/app/admission`);
  assert.equal(init.method, 'POST');
  assert.equal(init.body, undefined);
  assert.equal(init.headers.Authorization, `Bearer ${KEY}`);
  assert.equal(init.redirect, 'error');
  assert.ok(init.signal instanceof AbortSignal);
});

test('an issuer with a trailing slash is the same origin; a path is refused', async () => {
  const { calls, fetch } = recorder(Response.json({ admission: CODE }));
  await requestAdmission({ issuer: `${ISSUER}/`, key: KEY, fetch });
  assert.equal(calls[0].url, `${ISSUER}/freebird/app/admission`);
  for (const issuer of [
    `${ISSUER}/api`, `${ISSUER}/?x=1`, `${ISSUER}/#frag`, 'https://u:p@issuer.example',
    'http://issuer.example', 'http://127.0.0.1:8081', 'https://', 'issuer.example', undefined, 42,
  ]) {
    await assert.rejects(requestAdmission({ issuer, key: KEY, fetch }), TypeError);
  }
  assert.equal(calls.length, 1);
});

test('plain HTTP is accepted only for 127.0.0.1 and only with allowInsecureLoopback', async () => {
  const { calls, fetch } = recorder(Response.json({ admission: CODE }));
  await requestAdmission({
    issuer: 'http://127.0.0.1:8081', key: KEY, fetch, allowInsecureLoopback: true,
  });
  assert.equal(calls[0].url, 'http://127.0.0.1:8081/freebird/app/admission');
  await assert.rejects(requestAdmission({ issuer: 'http://127.0.0.1:8081', key: KEY, fetch }), TypeError);
  await assert.rejects(requestAdmission({
    issuer: 'http://localhost:8081', key: KEY, fetch, allowInsecureLoopback: true,
  }), TypeError);
  await assert.rejects(requestAdmission({
    issuer: 'http://issuer.example', key: KEY, fetch, allowInsecureLoopback: true,
  }), TypeError);
  assert.equal(calls.length, 1);
});

test('malformed keys are refused before any request, and the error never contains the key', async () => {
  const { calls, fetch } = recorder(Response.json({ admission: CODE }));
  for (const key of [
    undefined, '', 'fba_', KEY.slice(4), `fbb_${KEY.slice(4)}`, `${KEY} `, `Bearer ${KEY}`,
    `fba_${'A'.repeat(42)}+`, `fba_${'A'.repeat(42)}B`, KEY + 'A', 42,
  ]) {
    await assert.rejects(requestAdmission({ issuer: ISSUER, key, fetch }), error => {
      assert.ok(error instanceof TypeError);
      if (typeof key === 'string' && key.length >= 8) {
        assert.equal(error.message.includes(key), false);
      }
      return true;
    });
  }
  assert.equal(calls.length, 0);
});

test('429 carries the daily-cap Retry-After in seconds; the error text has no key or code', async () => {
  const { fetch } = recorder(new Response(`leaked ${KEY}`, {
    status: 429, headers: { 'Retry-After': '3600' },
  }));
  await assert.rejects(requestAdmission({ issuer: ISSUER, key: KEY, fetch }), error => {
    assert.ok(error instanceof FreebirdError);
    assert.equal(error.stage, 'admission');
    assert.equal(error.status, 429);
    assert.equal(error.retryAfter, 3600);
    assert.equal(error.reason, 'http');
    assert.equal(error.message.includes(KEY), false);
    assert.equal(error.message.includes('leaked'), false);
    return true;
  });
});

test('429 without Retry-After (busy) has no retryAfter; Retry-After dates are converted', async () => {
  const busy = recorder(new Response(null, { status: 429 }));
  await assert.rejects(requestAdmission({ issuer: ISSUER, key: KEY, fetch: busy.fetch }), error => {
    assert.equal(error.status, 429);
    assert.equal(error.retryAfter, undefined);
    return true;
  });
  const future = new Date(Date.now() + 120_000).toUTCString();
  const dated = recorder(new Response(null, { status: 429, headers: { 'Retry-After': future } }));
  await assert.rejects(requestAdmission({ issuer: ISSUER, key: KEY, fetch: dated.fetch }), error => {
    assert.ok(error.retryAfter >= 118 && error.retryAfter <= 120, String(error.retryAfter));
    return true;
  });
});

test('401 is a rejected key; other refusals keep their status', async () => {
  for (const status of [401, 400, 403, 503]) {
    const { fetch } = recorder(new Response(null, { status }));
    await assert.rejects(requestAdmission({ issuer: ISSUER, key: KEY, fetch }), error => {
      assert.equal(error.status, status);
      assert.equal(error.stage, 'admission');
      assert.equal(error.reason, 'http');
      return true;
    });
  }
});

test('malformed success bodies are protocol errors and never echo the body', async () => {
  for (const body of [
    'not json', '{}', JSON.stringify({ admission: 'short' }),
    JSON.stringify({ admission: `${CODE.slice(0, 42)}B` }), // `B` sets a padding bit, so encoding fails validation.
    JSON.stringify({ admission: CODE, extra: 'x'.repeat(2000) }),
  ]) {
    const { fetch } = recorder(new Response(body, { status: 200 }));
    await assert.rejects(requestAdmission({ issuer: ISSUER, key: KEY, fetch }), error => {
      assert.equal(error.reason, 'protocol');
      assert.equal(error.message.includes(CODE), false);
      return true;
    });
  }
});

test('network failures and timeouts are typed; upstream messages are dropped', async () => {
  const network = recorder(async () => { throw new TypeError(`socket hang up ${KEY}`); });
  await assert.rejects(requestAdmission({ issuer: ISSUER, key: KEY, fetch: network.fetch }), error => {
    assert.equal(error.reason, 'network');
    assert.equal(error.message.includes(KEY), false);
    return true;
  });
  const timeout = recorder(async () => { throw new DOMException('timed out', 'TimeoutError'); });
  await assert.rejects(requestAdmission({ issuer: ISSUER, key: KEY, fetch: timeout.fetch }), error => {
    assert.equal(error.reason, 'timeout');
    return true;
  });
});
