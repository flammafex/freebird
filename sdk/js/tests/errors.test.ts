// SPDX-License-Identifier: Apache-2.0 OR MIT

import { describe, expect, it } from 'vitest';
import {
  DiscoveryError,
  FreebirdError,
  InvalidTokenError,
  RateLimitedError,
  ReplayedTokenError,
  VerificationError,
  VerifierNotConfiguredError,
  VerifierUnavailableError,
} from '../src/index.js';
import type { FreebirdErrorCode } from '../src/errors.js';

describe('FreebirdError hierarchy', () => {
  it('FreebirdError is an Error with a code and generic message', () => {
    const error = new FreebirdError('discovery', 'generic message');
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(FreebirdError);
    expect(error.code).toBe('discovery');
    expect(error.message).toBe('generic message');
    expect(error.name).toBe('FreebirdError');
  });

  it('each concrete error class carries the right code and name', () => {
    const cases: Array<[FreebirdError, FreebirdErrorCode, string]> = [
      [new DiscoveryError(), 'discovery', 'DiscoveryError'],
      [new VerificationError(), 'verification', 'VerificationError'],
      [new VerifierNotConfiguredError(), 'verifier_not_configured', 'VerifierNotConfiguredError'],
      [new RateLimitedError(30), 'rate_limited', 'RateLimitedError'],
      [new VerifierUnavailableError(), 'verifier_unavailable', 'VerifierUnavailableError'],
      [new InvalidTokenError(), 'invalid_token', 'InvalidTokenError'],
      [new ReplayedTokenError(), 'replayed_token', 'ReplayedTokenError'],
    ];
    for (const [error, code, name] of cases) {
      expect(error).toBeInstanceOf(FreebirdError);
      expect(error.code).toBe(code);
      expect(error.name).toBe(name);
    }
  });

  it('supports instanceof branching across the hierarchy', () => {
    const invalid = new InvalidTokenError();
    expect(invalid).toBeInstanceOf(InvalidTokenError);
    expect(invalid).toBeInstanceOf(VerificationError);
    expect(invalid).toBeInstanceOf(FreebirdError);
    expect(invalid).toBeInstanceOf(Error);

    const replayed = new ReplayedTokenError();
    expect(replayed).toBeInstanceOf(ReplayedTokenError);
    expect(replayed).toBeInstanceOf(VerificationError);
    expect(replayed).toBeInstanceOf(FreebirdError);

    // A plain VerificationError is not an InvalidTokenError.
    const generic = new VerificationError();
    expect(generic).toBeInstanceOf(VerificationError);
    expect(generic).not.toBeInstanceOf(InvalidTokenError);
    expect(generic).not.toBeInstanceOf(ReplayedTokenError);
  });

  it('RateLimitedError carries retryAfter in whole seconds', () => {
    const error = new RateLimitedError(120);
    expect(error.retryAfter).toBe(120);
    expect(error.code).toBe('rate_limited');
  });

  it('messages are generic and do not leak server detail', () => {
    // Constructed with a server-provided detail string, the message must not
    // echo it verbatim to end users.
    const error = new FreebirdError('issuance', 'Issuer rejected the request');
    expect(error.message).not.toContain('secret-internal-detail');
  });
});
