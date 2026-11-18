// A local HTTP listener lets this test check that `requestAdmission` reaches `127.0.0.1` when
// `allowInsecureLoopback` is enabled.
// The listener uses only Node.js built-ins.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { FreebirdError, requestAdmission } from '../src/index.mjs';

const KEY = `fba_${randomBytes(32).toString('base64url')}`;
const CODE = randomBytes(32).toString('base64url');

function listen(handler) {
  return new Promise((resolve, reject) => {
    const server = createServer(handler);
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve({
        origin: `http://127.0.0.1:${server.address().port}`,
        close: () => new Promise(done => server.close(done)),
      });
    });
  });
}

test('round trip over loopback: Bearer key on the wire, one code returned', async () => {
  const seen = [];
  const server = await listen((request, response) => {
    let body = '';
    request.on('data', chunk => { body += chunk; });
    request.on('end', () => {
      seen.push({
        method: request.method, url: request.url, auth: request.headers.authorization, body,
      });
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify({ admission: CODE }));
    });
  });
  try {
    const code = await requestAdmission({
      issuer: server.origin, key: KEY, allowInsecureLoopback: true,
    });
    assert.equal(code, CODE);
    assert.deepEqual(seen, [{
      method: 'POST', url: '/freebird/app/admission', auth: `Bearer ${KEY}`, body: '',
    }]);
  } finally {
    await server.close();
  }
});

test('429 Retry-After over loopback is surfaced as retryAfter', async () => {
  const server = await listen((request, response) => {
    response.writeHead(429, { 'Retry-After': '86399' });
    response.end();
  });
  try {
    await assert.rejects(requestAdmission({
      issuer: server.origin, key: KEY, allowInsecureLoopback: true,
    }), error => {
      assert.ok(error instanceof FreebirdError);
      assert.equal(error.status, 429);
      assert.equal(error.retryAfter, 86399);
      return true;
    });
  } finally {
    await server.close();
  }
});

test('redirects are errors, not followed (the key is never forwarded elsewhere)', async () => {
  let targetHits = 0;
  const target = await listen((request, response) => {
    targetHits++;
    response.end(JSON.stringify({ admission: CODE }));
  });
  const server = await listen((request, response) => {
    response.writeHead(302, { Location: `${target.origin}/elsewhere` });
    response.end();
  });
  try {
    await assert.rejects(requestAdmission({
      issuer: server.origin, key: KEY, allowInsecureLoopback: true,
    }), error => error.reason === 'network');
    assert.equal(targetHits, 0);
  } finally {
    await server.close();
    await target.close();
  }
});

test('plain HTTP without the explicit option is refused before any socket is opened', async () => {
  let hits = 0;
  const server = await listen((request, response) => {
    hits++;
    response.end();
  });
  try {
    await assert.rejects(requestAdmission({ issuer: server.origin, key: KEY }), TypeError);
    assert.equal(hits, 0);
  } finally {
    await server.close();
  }
});
