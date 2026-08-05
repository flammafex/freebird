// SPDX-License-Identifier: Apache-2.0 OR MIT

import type { ExchangeOutcome, FreebirdToken, GraphIssuanceOutcome, TokenResult } from './types.js';

/**
 * Stable machine-readable failure codes carried by every {@link FreebirdError}.
 *
 * These are intentionally coarse and stable so consumers can branch on them
 * without depending on human-readable messages. Messages stay generic; detail
 * belongs in the `code` and server-side logs (never echoed to end users).
 */
export type FreebirdErrorCode =
  | 'discovery'
  | 'verification'
  | 'verifier_not_configured'
  | 'exchange'
  | 'graph_issuance'
  | 'issuance'
  | 'rate_limited'
  | 'verifier_unavailable'
  | 'invalid_token'
  | 'replayed_token'
  | 'poll';

/**
 * Base class for every typed error thrown by the SDK.
 *
 * Carries a stable {@link FreebirdErrorCode} and a generic, non-leaky message.
 */
export class FreebirdError extends Error {
  readonly code: FreebirdErrorCode;

  constructor(code: FreebirdErrorCode, message: string) {
    super(message);
    this.name = 'FreebirdError';
    this.code = code;
  }
}

/** Discovery metadata could not be fetched or failed validation. */
export class DiscoveryError extends FreebirdError {
  constructor(message = 'Failed to load issuer or verifier discovery metadata') {
    super('discovery', message);
    this.name = 'DiscoveryError';
  }
}

/** A token could not be verified. */
export class VerificationError extends FreebirdError {
  constructor(message = 'Token verification failed', code: FreebirdErrorCode = 'verification') {
    super(code, message);
    this.name = 'VerificationError';
  }
}

/** The client is not configured with a verifier endpoint. */
export class VerifierNotConfiguredError extends FreebirdError {
  constructor(message = 'Verifier is not configured') {
    super('verifier_not_configured', message);
    this.name = 'VerifierNotConfiguredError';
  }
}

/** A V2 public bearer exchange operation failed. */
export class ExchangeError extends FreebirdError {
  readonly outcome?: ExchangeOutcome;

  constructor(message = 'Exchange operation failed', outcome?: ExchangeOutcome) {
    super('exchange', message);
    this.name = 'ExchangeError';
    this.outcome = outcome;
  }
}

/** A graph issuance operation failed. */
export class GraphIssuanceError extends FreebirdError {
  readonly outcome?: GraphIssuanceOutcome;

  constructor(message = 'Graph issuance failed', outcome?: GraphIssuanceOutcome) {
    super('graph_issuance', message);
    this.name = 'GraphIssuanceError';
    this.outcome = outcome;
  }
}

/** The server rate-limited the request; `retryAfter` is in whole seconds. */
export class RateLimitedError extends FreebirdError {
  readonly retryAfter: number;

  constructor(retryAfter: number, message = 'Rate limited') {
    super('rate_limited', message);
    this.name = 'RateLimitedError';
    this.retryAfter = retryAfter;
  }
}

/** The verifier is temporarily unavailable (retryable). */
export class VerifierUnavailableError extends FreebirdError {
  constructor(message = 'Verifier is unavailable') {
    super('verifier_unavailable', message);
    this.name = 'VerifierUnavailableError';
  }
}

/** The presented token is invalid (malformed or failed verification). */
export class InvalidTokenError extends VerificationError {
  constructor(message = 'Token is invalid') {
    super(message, 'invalid_token');
    this.name = 'InvalidTokenError';
  }
}

/** The presented token has already been used (replay detected). */
export class ReplayedTokenError extends VerificationError {
  constructor(message = 'Token has already been used') {
    super(message, 'replayed_token');
    this.name = 'ReplayedTokenError';
  }
}

/** A polling operation failed (base class for poll-specific errors). */
export class PollError extends FreebirdError {
  constructor(message = 'Polling operation failed') {
    super('poll', message);
    this.name = 'PollError';
  }
}

/** A polling operation exceeded its `timeoutMs` cap. */
export class PollTimeoutError extends PollError {
  constructor(message = 'Polling timed out') {
    super(message);
    this.name = 'PollTimeoutError';
  }
}

/** A polling operation was cancelled via its `AbortSignal`. */
export class PollAbortedError extends PollError {
  constructor(message = 'Polling was aborted') {
    super(message);
    this.name = 'PollAbortedError';
  }
}

/**
 * One or more tokens in a batch issuance failed.
 *
 * The successfully finalized tokens are carried on `tokens` (in input order,
 * with failures omitted) and the raw per-token outcomes on `results`, so
 * callers can see exactly which tokens failed and why without the failure
 * details being silently dropped.
 */
export class BatchIssuanceError extends FreebirdError {
  readonly results: TokenResult[];
  readonly tokens: FreebirdToken[];
  readonly failed: number;

  constructor(results: TokenResult[], tokens: FreebirdToken[]) {
    super('issuance', 'One or more tokens in the batch failed to issue');
    this.name = 'BatchIssuanceError';
    this.results = results;
    this.tokens = tokens;
    this.failed = results.filter((result) => result.status === 'error').length;
  }
}
