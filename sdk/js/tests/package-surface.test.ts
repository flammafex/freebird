// SPDX-License-Identifier: Apache-2.0 OR MIT

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const packageRoot = fileURLToPath(new URL('..', import.meta.url));
const runtimeExports = [
  'BatchIssuanceError',
  'DiscoveryError',
  'ExchangeError',
  'FreebirdClient',
  'FreebirdError',
  'GraphIssuanceError',
  'InvalidTokenError',
  'MemoryTokenStore',
  'PollAbortedError',
  'PollError',
  'PollTimeoutError',
  'RateLimitedError',
  'ReplayedTokenError',
  'StorageTokenStore',
  'VerificationError',
  'VerifierNotConfiguredError',
  'VerifierUnavailableError',
  'buildBatchBinding',
  'buildGraphIssuanceHmacAuthorizationV2',
  'buildHmacAuthorizationV2',
  'buildIssueBinding',
  'buildPublicIssueBinding',
  'buildRenewBinding',
  'crypto',
  'deserializeGraphIssuanceRecoveryContext',
  'exchangePasses',
  'generateOperationId',
  'generateProofOfWork',
  'generateStatusCapability',
  'graphIssuanceHmacAuthorizationTagV2',
  'graphIssuanceHmacAuthorizationTranscriptV2',
  'hmacAuthorizationTagV2',
  'hmacAuthorizationTranscriptV2',
  'parseGraphIssuanceHmacAuthorizationV2',
  'parseHmacAuthorizationV2',
  'pollExchangeStatus',
  'pollGraphIssuanceStatus',
  'pollUntilTerminal',
  'serializeGraphIssuanceRecoveryContext',
  'tokenId',
  'verifyGraphIssuanceHmacAuthorizationV2',
  'verifyHmacAuthorizationV2',
  'verifyPow',
].sort();
const cryptoExports = [
  'blind',
  'buildGraphIssuanceHmacAuthorizationV2',
  'buildHmacAuthorizationV2',
  'buildPrivateTokenInput',
  'buildPublicBearerMessage',
  'buildPublicBearerPass',
  'buildRedemptionToken',
  'buildScopeDigest',
  'finalize',
  'graphIssuanceHmacAuthorizationTagV2',
  'graphIssuanceHmacAuthorizationTranscriptV2',
  'hmacAuthorizationTagV2',
  'hmacAuthorizationTranscriptV2',
  'parseGraphIssuanceHmacAuthorizationV2',
  'parseHmacAuthorizationV2',
  'parsePublicBearerPass',
  'parseRedemptionToken',
  'rsaBlind',
  'rsaUnblind',
  'rsaVerify',
  'tokenKeyIdFromHex',
  'tokenKeyIdFromSpki',
  'tokenKeyIdToHex',
  'verifyGraphIssuanceHmacAuthorizationV2',
  'verifyHmacAuthorizationV2',
].sort();

function assertRuntimeSurface(source: Record<string, unknown>): void {
  if (JSON.stringify(Object.keys(source).sort()) !== JSON.stringify(runtimeExports)) {
    throw new Error(`unexpected runtime exports: ${Object.keys(source).sort().join(',')}`);
  }
  const crypto = source.crypto as Record<string, unknown>;
  if (JSON.stringify(Object.keys(crypto).sort()) !== JSON.stringify(cryptoExports)) {
    throw new Error(`unexpected crypto exports: ${Object.keys(crypto).sort().join(',')}`);
  }
  if (source.FreebirdClient === undefined || typeof crypto.blind !== 'function') {
    throw new Error('required SDK runtime export is missing');
  }
}

describe('SDK index and package surface', () => {
  it('publishes condition-specific declaration and runtime targets', () => {
    const manifest = JSON.parse(readFileSync(`${packageRoot}/package.json`, 'utf8')) as {
      exports: { '.': { import: Record<string, string>; require: Record<string, string> } };
    };
    expect(manifest.exports['.'].import).toEqual({
      types: './dist/index.d.ts',
      default: './dist/index.js',
    });
    expect(manifest.exports['.'].require).toEqual({
      types: './dist/index.d.cts',
      default: './dist/index.cjs',
    });
  });

  it('keeps the source index runtime facade explicit', async () => {
    const source = await import('../src/index.js');
    assertRuntimeSurface(source as unknown as Record<string, unknown>);
  });

  it('builds and supports both package self-reference entry points', async () => {
    execFileSync('npm', ['run', 'build'], { cwd: packageRoot, stdio: 'pipe' });

    const tsc = `${packageRoot}/node_modules/typescript/bin/tsc`;
    execFileSync(process.execPath, [tsc, '--project', 'tests/package-consumers/tsconfig.esm.json'], {
      cwd: packageRoot,
      stdio: 'pipe',
    });
    execFileSync(process.execPath, [tsc, '--project', 'tests/package-consumers/tsconfig.cjs.json'], {
      cwd: packageRoot,
      stdio: 'pipe',
    });

    const expected = JSON.stringify(runtimeExports);
    const cjsScript = `
      const sdk = require('@freebird/sdk');
      const expected = ${JSON.stringify(expected)};
      if (JSON.stringify(Object.keys(sdk).sort()) !== expected) process.exit(1);
      if (typeof sdk.FreebirdClient !== 'function' || typeof sdk.crypto.blind !== 'function') process.exit(2);
    `;
    execFileSync(process.execPath, ['--eval', cjsScript], { cwd: packageRoot, stdio: 'pipe' });

    const esmScript = `
      const sdk = await import('@freebird/sdk');
      const expected = ${JSON.stringify(expected)};
      if (JSON.stringify(Object.keys(sdk).sort()) !== expected) process.exit(1);
      if (typeof sdk.FreebirdClient !== 'function' || typeof sdk.crypto.blind !== 'function') process.exit(2);
    `;
    execFileSync(process.execPath, ['--input-type=module', '--eval', esmScript], {
      cwd: packageRoot,
      stdio: 'pipe',
    });

    expect(expected).toBe(JSON.stringify(runtimeExports));
  });
});
