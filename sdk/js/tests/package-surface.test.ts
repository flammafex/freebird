// SPDX-License-Identifier: Apache-2.0 OR MIT

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const packageRoot = fileURLToPath(new URL('..', import.meta.url));
const runtimeExports = [
  'BatchIssuanceError', 'BatchIssuanceInterruptedError', 'DiscoveryError', 'FreebirdClient',
  'FreebirdError', 'InvalidTokenError', 'MemoryTokenStore', 'RateLimitedError',
  'ReplayedTokenError', 'StorageTokenStore', 'StalePublicKeyError', 'VerificationError',
  'VerifierNotConfiguredError', 'VerifierUnavailableError', 'buildBatchBinding',
  'buildIssueBinding', 'buildNativeBearerV7BatchBinding', 'buildNativeBearerV7IssueBinding',
  'buildRenewBinding', 'crypto', 'generateProofOfWork', 'tokenId', 'verifyPow',
].sort();
const cryptoExports = [
  'blind', 'buildPrivateTokenInput', 'buildRedemptionToken', 'buildScopeDigest', 'finalize',
  'nativeBearerV7', 'parseRedemptionToken',
].sort();
const nativeV7Exports = [
  'bindingFromV7Discovery', 'blindV7', 'buildV7Body', 'deriveV7Nullifier',
  'directBindingFromDiscovery', 'finalizeV7', 'parseV7Body', 'parseV7Token',
  'serializeV7Token', 'v7ApplicationDigest', 'v7ArtifactDigest', 'v7BodyTranscript',
  'verifyV7Token',
].sort();

function assertRuntimeSurface(source: Record<string, unknown>): void {
  expect(Object.keys(source).sort()).toEqual(runtimeExports);
  expect(Object.keys(source.crypto as object).sort()).toEqual(cryptoExports);
  expect(Object.keys((source.crypto as { nativeBearerV7: object }).nativeBearerV7).sort())
    .toEqual(nativeV7Exports);
  const client = source.FreebirdClient as typeof import('../src/client.js').FreebirdClient;
  expect(typeof client.prototype.issueToken).toBe('function');
  expect(typeof client.prototype.issueTokens).toBe('function');
  expect(typeof client.prototype.issueNativeBearerV7).toBe('function');
  expect(typeof client.prototype.issueNativeBearerV7Batch).toBe('function');
  expect(typeof client.prototype.verifyNativeBearerV7Locally).toBe('function');
  for (const removed of [
    'issuePublicToken', 'issuePublicTokens', 'issuePublicBlindSignature',
    'issuePublicTokenForCurrentKey', 'issuePublicTokensForCurrentKey',
    'verifyPublicBearerPassLocally', 'exchange', 'exchangePasses', 'issueGraphBlindSignature',
    'pollExchangeStatus', 'pollGraphIssuanceStatus',
  ]) expect(removed in client.prototype).toBe(false);
  for (const removed of [
    'buildPublicIssueBinding', 'buildPublicBearerMessage', 'buildPublicBearerPass',
    'parsePublicBearerPass', 'exchangePasses', 'pollExchangeStatus',
  ]) expect(removed in source).toBe(false);
}

describe('SDK package surface', () => {
  it('publishes condition-specific declaration and runtime targets', () => {
    const manifest = JSON.parse(readFileSync(`${packageRoot}/package.json`, 'utf8')) as {
      exports: { '.': { import: Record<string, string>; require: Record<string, string> } };
    };
    expect(manifest.exports['.'].import).toEqual({ types: './dist/index.d.ts', default: './dist/index.js' });
    expect(manifest.exports['.'].require).toEqual({ types: './dist/index.d.cts', default: './dist/index.cjs' });
  });

  it('declares the Node.js engine required by the V7 crypto dependency', () => {
    const manifest = JSON.parse(readFileSync(`${packageRoot}/package.json`, 'utf8')) as {
      engines?: { node?: string };
    };
    const lockfile = JSON.parse(readFileSync(`${packageRoot}/package-lock.json`, 'utf8')) as {
      packages?: { '': { engines?: { node?: string } } };
    };
    expect(manifest.engines?.node).toBe('>=24');
    expect(lockfile.packages?.['']?.engines?.node).toBe('>=24');
  });

  it('keeps the source index runtime facade V4/V7-only', async () => {
    assertRuntimeSurface(await import('../src/index.js') as unknown as Record<string, unknown>);
  });

  it('builds and supports both package self-reference entry points', async () => {
    execFileSync('npm', ['run', 'build'], { cwd: packageRoot, stdio: 'pipe' });
    const tsc = `${packageRoot}/node_modules/typescript/bin/tsc`;
    execFileSync(process.execPath, [tsc, '--project', 'tests/package-consumers/tsconfig.esm.json'], { cwd: packageRoot, stdio: 'pipe' });
    execFileSync(process.execPath, [tsc, '--project', 'tests/package-consumers/tsconfig.cjs.json'], { cwd: packageRoot, stdio: 'pipe' });
    const expected = JSON.stringify(runtimeExports);
    const cjsScript = `const sdk=require('@flammafex/freebird'); if(JSON.stringify(Object.keys(sdk).sort())!==${JSON.stringify(expected)})process.exit(1);`;
    const esmScript = `const sdk=await import('@flammafex/freebird'); if(JSON.stringify(Object.keys(sdk).sort())!==${JSON.stringify(expected)})process.exit(1);`;
    execFileSync(process.execPath, ['--eval', cjsScript], { cwd: packageRoot, stdio: 'pipe' });
    execFileSync(process.execPath, ['--input-type=module', '--eval', esmScript], { cwd: packageRoot, stdio: 'pipe' });
  });
});
