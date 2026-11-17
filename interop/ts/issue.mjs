import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { open, stat, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';

export function loopbackBase(value) {
  // Validate the spelling too: URL normalization must not admit integer,
  // hexadecimal, shortened IPv4, credentials, or alternate hosts.
  assert.match(value, /^http:\/\/(127(?:\.(?:0|[1-9]\d{0,2})){3}|\[::1\])(?::[1-9]\d{0,4})?\/?$/);
  const url = new URL(value);
  assert.ok(url.hostname === '[::1]' || url.hostname.split('.').every(x => Number(x) <= 255));
  return url;
}

export function decode(value) {
  assert.equal(typeof value, 'string');
  assert.match(value, /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?$/);
  assert.ok(value.length > 0);
  const bytes = Buffer.from(value, 'base64url');
  assert.equal(bytes.toString('base64').replaceAll('+', '-').replaceAll('/', '_'), value);
  return bytes;
}

export function parseChallenge(header) {
  assert.equal(typeof header, 'string');
  const match = /^PrivateToken\s+challenge="([A-Za-z0-9_=-]+)",\s*token-key="([A-Za-z0-9_=-]+)"(?:,\s*max-age=[0-9]+)?$/i.exec(header);
  assert.ok(match);
  return { bytes: decode(match[1]), spki: decode(match[2]) };
}

const hash = bytes => createHash('sha256').update(bytes).digest();
const equal = (a, b) => assert.deepEqual(Buffer.from(a), Buffer.from(b));

// Core http, agent:false and numeric addresses deliberately bypass proxy
// environment variables. Redirects are returned, never followed.
async function request(base, path, limit, headers = {}, payload) {
  return new Promise((resolvePromise, reject) => {
    const req = http.request(new URL(path, base), {
      method: payload ? 'POST' : 'GET', agent: false, headers,
    }, res => {
      const chunks = [];
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > limit) req.destroy(new Error('response limit'));
        else chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        clearTimeout(timer);
        resolvePromise({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
      });
    });
    const timer = setTimeout(() => req.destroy(new Error('timeout')), 10000);
    req.on('error', error => { clearTimeout(timer); reject(error); });
    req.end(payload);
  });
}

export async function main(args) {
  assert.ok(Number(process.versions.node.split('.')[0]) >= 20);
  assert.equal(args.length, 4);
  const [issuerArg, originArg, invitationFile, outputDir] = args;
  const issuer = loopbackBase(issuerArg);
  const origin = loopbackBase(originArg);
  const out = await stat(outputDir);
  assert.ok(out.isDirectory() && (out.mode & 0o077) === 0);
  const file = await open(invitationFile, 'r');
  let invitation;
  try {
    const info = await file.stat();
    assert.ok(info.isFile() && (info.mode & 0o077) === 0 && info.size <= 4096);
    invitation = (await file.readFile('utf8')).trim();
    assert.match(invitation, /^[\x21-\x7e]{1,4096}$/);
  } finally { await file.close(); }
  const pkg = JSON.parse(await readFile(new URL('./node_modules/@cloudflare/privacypass-ts/package.json', import.meta.url)));
  assert.equal(pkg.version, '0.9.0');
  console.log(`@cloudflare/privacypass-ts ${pkg.version}`);
  const directoryResponse = await request(issuer, '/.well-known/private-token-issuer-directory', 16384,
    { Accept: 'application/private-token-issuer-directory' });
  assert.equal(directoryResponse.status, 200);
  assert.equal(directoryResponse.headers['content-type'], 'application/private-token-issuer-directory');
  console.log('directory: 200');
  const directory = JSON.parse(directoryResponse.body);
  const advertised = new URL(directory['issuer-request-uri']);
  assert.equal(advertised.protocol, 'https:');
  assert.ok(!advertised.username && !advertised.password && !advertised.search && !advertised.hash);
  assert.equal(advertised.pathname, '/private-token/issue');
  const keys = directory['token-keys'];
  assert.ok(Array.isArray(keys) && keys.length === 1 && keys[0]['token-type'] === 2);
  const spki = decode(keys[0]['token-key']);
  const response = await request(origin, '/private-token/protected', 4096, { 'Cache-Control': 'no-store' });
  assert.equal(response.status, 401);
  console.log('challenge: 401');
  const { bytes, spki: challengeKey } = parseChallenge(response.headers['www-authenticate']);
  equal(spki, challengeKey);
  // The upstream deserializer reads the backing ArrayBuffer from offset zero.
  const challenge = TokenChallenge.deserialize(Uint8Array.from(bytes));
  equal(challenge.serialize(), bytes);
  assert.equal(challenge.tokenType, 2);
  assert.equal(challenge.issuerName, advertised.host);
  assert.deepEqual(challenge.originInfo, ['origin.test']);
  const keyId = hash(spki);
  const digest = hash(bytes);
  console.log(`key ID: ${keyId.toString('hex')}`);
  const client = new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
  const tokenRequest = await client.createTokenRequest(challenge, spki);
  const serialized = tokenRequest.serialize();
  assert.equal(serialized.length, 259);
  assert.equal(tokenRequest.truncatedTokenKeyId, keyId[31]);
  const issued = await request(issuer, '/private-token/issue', 256, {
    'Content-Type': 'application/private-token-request',
    Accept: 'application/private-token-response',
    'Cache-Control': 'no-store',
    'Freebird-Admission': invitation,
  }, serialized);
  invitation = undefined;
  assert.equal(issued.status, 200);
  assert.equal(issued.body.length, 256);
  assert.equal(issued.headers['cache-control'], 'no-store');
  assert.equal(issued.headers['content-type'], 'application/private-token-response');
  console.log('issuance: 200');
  const token = await client.finalize(publicVerif.TokenResponse.deserialize(issued.body));
  equal(token.authInput.tokenKeyId, keyId);
  equal(token.authInput.challengeDigest, digest);
  const raw = token.serialize();
  assert.equal(raw.length, 354);
  for (const [name, data] of [['spki.der', spki], ['challenge.bin', bytes],
    ['request.bin', serialized], ['token.bin', raw]]) {
    const destination = await open(join(outputDir, name), 'wx', 0o600);
    try { await destination.writeFile(data); } finally { await destination.close(); }
  }
  console.log('serialization: OK; finalization: OK; private artifacts: OK');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(() => {
    console.error('interop issuance failed');
    process.exitCode = 1;
  });
}
