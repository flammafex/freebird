// These tests use `@cloudflare/privacypass-ts` at version `0.9.0` to exercise blind-RSA signing
// and verification.
// The Issuer and Origin run in memory so that the tests do not need a server.
// If the peer dependency cannot be loaded, the test runner reports why the tests were skipped.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { installPeer } from '../test-support/peer.mjs';

const peer = await installPeer();
const skip = peer.available ? false
  : 'privacypass-ts 0.9.0 not installed; run `npm ci --ignore-scripts` in demo/web';

const pp = peer.available ? await import('@cloudflare/privacypass-ts') : undefined;
const freebird = peer.available ? await import('../src/index.mjs') : undefined;
const { FreebirdError } = freebird ?? {};

const ISSUER_ORIGIN = 'https://issuer.example:8443';
const ISSUER_NAME = 'issuer.example:8443';
const ORIGIN_URL = 'https://origin.example/private-token/protected';
const DIRECTORY_URL = `${ISSUER_ORIGIN}/.well-known/private-token-issuer-directory`;
const ISSUE_URL = `${ISSUER_ORIGIN}/private-token/issue`;
const PSS = pp?.publicVerif.BlindRSAMode.PSS;

const b64url = bytes => Buffer.from(bytes).toString('base64')
  .replaceAll('+', '-').replaceAll('/', '_');
const newCode = () => randomBytes(32).toString('base64url');

const keys = peer.available ? await pp.publicVerif.Issuer.generateKey(PSS, {
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
}) : undefined;
const issuer = peer.available
  ? new pp.publicVerif.Issuer(PSS, ISSUER_NAME, keys.privateKey, keys.publicKey) : undefined;
const origin = peer.available ? new pp.publicVerif.Origin(PSS) : undefined;
const spki = peer.available ? await pp.publicVerif.getPublicKeyBytes(keys.publicKey) : undefined;

// Set options to vary Issuer or Origin responses and check how the client handles each failure.
function world(options = {}) {
  const log = {
    requests: [], issuances: 0, redemptions: 0, verified: 0, badOptions: [],
    admissionsSpent: new Set(),
  };
  const valid = new Set(options.admissions ?? []);
  const challengeBytes = (options.tokenType === 1
    ? new pp.TokenChallenge(1, options.challengeIssuer ?? ISSUER_NAME, new Uint8Array(32))
    : origin.createTokenChallenge(options.challengeIssuer ?? ISSUER_NAME, new Uint8Array(32)))
    .serialize();
  const challengeHeader = `PrivateToken challenge="${b64url(challengeBytes)}", `
    + `token-key="${b64url(options.tokenKey ?? spki)}"`;
  const directory = {
    'issuer-request-uri': options.requestUri ?? ISSUE_URL,
    'token-keys': [{ 'token-type': 2, 'token-key': b64url(spki) }],
  };

  const fetch = async (input, init = {}) => {
    const url = new URL(input);
    const headers = new Headers(init.headers);
    log.requests.push({ method: init.method ?? 'GET', url: url.href, headers, body: init.body });
    if (init.redirect !== 'error' || init.credentials !== 'omit' || init.cache !== 'no-store'
        || init.referrerPolicy !== 'no-referrer' || !init.signal) {
      log.badOptions.push(url.href);
    }

    if (url.href === DIRECTORY_URL) {
      if (options.directoryStatus) {
        return new Response(null, {
          status: options.directoryStatus,
          headers: { 'Retry-After': '7' },
        });
      }
      return Response.json(directory);
    }
    if (url.href === ORIGIN_URL) {
      const authorization = headers.get('authorization');
      if (!authorization) {
        if (options.noChallenge) return new Response('public', { status: 200 });
        return new Response(null, { status: 401, headers: { 'WWW-Authenticate': challengeHeader } });
      }
      log.redemptions++;
      if (options.alwaysRefuse) return new Response('no', { status: 401 });
      const match = /^PrivateToken token="([A-Za-z0-9_=-]+)"$/.exec(authorization);
      if (!match) return new Response(null, { status: 401 });
      // Copy the `Buffer` bytes because `Token.deserialize` starts at offset zero in the backing buffer.
      const token = pp.Token.deserialize(pp.TOKEN_TYPES.BLIND_RSA, Uint8Array.from(Buffer.from(match[1]
        .replaceAll('-', '+').replaceAll('_', '/'), 'base64')));
      const ok = await origin.verify(token, keys.publicKey);
      if (ok) log.verified++;
      return ok ? new Response('protected', { status: 200 }) : new Response(null, { status: 401 });
    }
    if (url.href === ISSUE_URL) {
      log.issuances++;
      const code = headers.get('freebird-admission');
      if (options.issuanceStatus) {
        return new Response(null, {
          status: options.issuanceStatus,
          headers: options.issuanceRetryAfter ? { 'Retry-After': options.issuanceRetryAfter } : {},
        });
      }
      if (!code || !valid.has(code) || log.admissionsSpent.has(code)) {
        return new Response(null, { status: 403 });
      }
      log.admissionsSpent.add(code);
      const tokenRequest = pp.publicVerif.TokenRequest.deserialize(pp.TOKEN_TYPES.BLIND_RSA,
        Uint8Array.from(init.body));
      const tokenResponse = await issuer.issue(tokenRequest);
      return new Response(tokenResponse.serialize(), {
        status: 200,
        headers: { 'Content-Type': 'application/private-token-response' },
      });
    }
    throw new Error(`unexpected request in fake Issuer/Origin: ${url.origin}`);
  };
  return { log, fetch, challengeHeader };
}

test('fetchWithToken: one directory, one admission, one issuance, one redemption; the token verifies', { skip }, async () => {
  const code = newCode();
  const w = world({ admissions: [code] });
  let admissionCalls = 0;
  const stages = [];
  const response = await freebird.fetchWithToken(ORIGIN_URL, {
    issuer: ISSUER_ORIGIN,
    admission: () => { admissionCalls++; return code; },
    fetch: w.fetch,
    onStage: stage => stages.push(stage),
  });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'protected');
  assert.deepEqual(stages, ['challenged', 'admitted', 'issued']);
  assert.equal(admissionCalls, 1);
  assert.equal(w.log.issuances, 1);
  assert.equal(w.log.verified, 1);
  assert.deepEqual(w.log.badOptions, []);
  assert.deepEqual(w.log.requests.map(r => `${r.method} ${r.url}`), [
    `GET ${ORIGIN_URL}`, `GET ${DIRECTORY_URL}`, `POST ${ISSUE_URL}`, `GET ${ORIGIN_URL}`,
  ]);
  const [, , issuance] = w.log.requests;
  assert.equal(issuance.headers.get('freebird-admission'), code);
  assert.equal(issuance.headers.get('content-type'), 'application/private-token-request');
  assert.equal(issuance.body.length, 259);
  assert.equal(w.log.requests[3].headers.get('authorization').startsWith('PrivateToken token="'), true);
});

test('fetchWithToken: a 401 after the token is a typed access error, with exactly one retry', { skip }, async () => {
  const code = newCode();
  const w = world({ admissions: [code], alwaysRefuse: true });
  await assert.rejects(freebird.fetchWithToken(ORIGIN_URL, {
    issuer: ISSUER_ORIGIN, admission: code, fetch: w.fetch,
  }), error => {
    assert.ok(error instanceof FreebirdError);
    assert.equal(error.stage, 'access');
    assert.equal(error.status, 401);
    return true;
  });
  assert.equal(w.log.issuances, 1);
  assert.equal(w.log.redemptions, 1);
  assert.equal(w.log.requests.filter(r => r.url === ORIGIN_URL).length, 2);
});

test('fetchWithToken: a reused admission is refused by the Issuer (403) and never retried', { skip }, async () => {
  const code = newCode();
  const w = world({ admissions: [code] });
  const first = await freebird.fetchWithToken(ORIGIN_URL, {
    issuer: ISSUER_ORIGIN, admission: code, fetch: w.fetch,
  });
  assert.equal(first.status, 200);
  await assert.rejects(freebird.fetchWithToken(ORIGIN_URL, {
    issuer: ISSUER_ORIGIN, admission: code, fetch: w.fetch,
  }), error => {
    assert.equal(error.stage, 'issuance');
    assert.equal(error.status, 403);
    assert.equal(error.reason, 'http');
    return true;
  });
  assert.equal(w.log.issuances, 2);
  assert.equal(w.log.redemptions, 1);
});

test('fetchWithToken: no challenge means no admission is requested and the response is returned', { skip }, async () => {
  const w = world({ noChallenge: true });
  let admissionCalls = 0;
  const response = await freebird.fetchWithToken(ORIGIN_URL, {
    issuer: ISSUER_ORIGIN,
    admission: () => { admissionCalls++; return newCode(); },
    fetch: w.fetch,
  });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'public');
  assert.equal(admissionCalls, 0);
  assert.equal(w.log.requests.length, 1);
});

test('obtainToken: a key missing from the directory stops before admission or issuance', { skip }, async () => {
  const w = world({ tokenKey: new Uint8Array(spki.length).fill(7) });
  let admissionCalls = 0;
  await assert.rejects(freebird.obtainToken(w.challengeHeader, {
    issuer: ISSUER_ORIGIN,
    admission: () => { admissionCalls++; return newCode(); },
    fetch: w.fetch,
  }), error => {
    assert.equal(error.stage, 'challenge');
    assert.equal(error.reason, 'protocol');
    return true;
  });
  assert.equal(admissionCalls, 0);
  assert.equal(w.log.issuances, 0);
});

test('obtainToken: a challenge naming another Issuer stops before admission', { skip }, async () => {
  const w = world({ challengeIssuer: 'other.example:8443' });
  let admissionCalls = 0;
  await assert.rejects(freebird.obtainToken(w.challengeHeader, {
    issuer: ISSUER_ORIGIN,
    admission: () => { admissionCalls++; return newCode(); },
    fetch: w.fetch,
  }), error => error.stage === 'challenge');
  assert.equal(admissionCalls, 0);
  assert.equal(w.log.issuances, 0);
});

test('obtainToken: a non-type-2 challenge is rejected before the directory is even fetched', { skip }, async () => {
  const w = world({ tokenType: 1 });
  await assert.rejects(freebird.obtainToken(w.challengeHeader, {
    issuer: ISSUER_ORIGIN, admission: newCode(), fetch: w.fetch,
  }), error => error.stage === 'challenge');
  assert.equal(w.log.requests.length, 0);
});

test('obtainToken: an issuance URI on another host is refused before the admission is sent', { skip }, async () => {
  const w = world({ requestUri: 'https://evil.example/private-token/issue' });
  await assert.rejects(freebird.obtainToken(w.challengeHeader, {
    issuer: ISSUER_ORIGIN, admission: newCode(), fetch: w.fetch,
  }), error => error.stage === 'directory');
  assert.equal(w.log.issuances, 0);
});

test('obtainToken: directory 503 keeps Retry-After; no admission is requested', { skip }, async () => {
  const w = world({ directoryStatus: 503 });
  let admissionCalls = 0;
  await assert.rejects(freebird.obtainToken(w.challengeHeader, {
    issuer: ISSUER_ORIGIN,
    admission: () => { admissionCalls++; return newCode(); },
    fetch: w.fetch,
  }), error => {
    assert.equal(error.stage, 'directory');
    assert.equal(error.status, 503);
    assert.equal(error.retryAfter, 7);
    return true;
  });
  assert.equal(admissionCalls, 0);
});

test('obtainToken: 429 at issuance is typed with retryAfter and is not retried', { skip }, async () => {
  const w = world({ issuanceStatus: 429, issuanceRetryAfter: '30' });
  let admissionCalls = 0;
  await assert.rejects(freebird.obtainToken(w.challengeHeader, {
    issuer: ISSUER_ORIGIN,
    admission: () => { admissionCalls++; return newCode(); },
    fetch: w.fetch,
  }), error => {
    assert.equal(error.stage, 'issuance');
    assert.equal(error.status, 429);
    assert.equal(error.retryAfter, 30);
    return true;
  });
  assert.equal(admissionCalls, 1);
  assert.equal(w.log.issuances, 1);
});

test('obtainToken: 422 at issuance is typed as a key mismatch refusal', { skip }, async () => {
  const w = world({ issuanceStatus: 422 });
  await assert.rejects(freebird.obtainToken(w.challengeHeader, {
    issuer: ISSUER_ORIGIN, admission: newCode(), fetch: w.fetch,
  }), error => error.status === 422 && error.stage === 'issuance');
});

test('obtainToken: an admission callback error propagates and no issuance is sent', { skip }, async () => {
  const w = world();
  await assert.rejects(freebird.obtainToken(w.challengeHeader, {
    issuer: ISSUER_ORIGIN,
    admission: () => { throw new Error('user closed the proof widget'); },
    fetch: w.fetch,
  }), /user closed/);
  assert.equal(w.log.issuances, 0);
});

test('fetchWithToken: refuses Authorization in init and non-replayable bodies before any request', { skip }, async () => {
  const w = world();
  await assert.rejects(freebird.fetchWithToken(ORIGIN_URL, {
    issuer: ISSUER_ORIGIN, admission: newCode(), fetch: w.fetch,
    init: { headers: { Authorization: 'PrivateToken token="x"' } },
  }), TypeError);
  await assert.rejects(freebird.fetchWithToken(ORIGIN_URL, {
    issuer: ISSUER_ORIGIN, admission: newCode(), fetch: w.fetch,
    init: { method: 'POST', body: new ReadableStream() },
  }), TypeError);
  assert.equal(w.log.requests.length, 0);
});

test('fetchWithToken: a stalled Origin times out with a typed error', { skip }, async () => {
  const stalled = (url, init) => new Promise((_, reject) => {
    init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'TimeoutError')));
  });
  await assert.rejects(freebird.fetchWithToken(ORIGIN_URL, {
    issuer: ISSUER_ORIGIN, admission: newCode(), fetch: stalled, timeout: 20,
  }), error => error.stage === 'access' && error.reason === 'timeout');
});
