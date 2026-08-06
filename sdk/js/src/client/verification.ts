// SPDX-License-Identifier: Apache-2.0 OR MIT

import type {
  BatchVerifyResp,
  FreebirdToken,
  TokenToVerify,
  VerifyResp,
} from '../types.js';
import type { ClientState } from './state.js';
import {
  InvalidTokenError,
  RateLimitedError,
  ReplayedTokenError,
  VerificationError,
  VerifierNotConfiguredError,
  VerifierUnavailableError,
} from '../errors.js';

/**
 * All verification methods require an explicit `verifierUrl`. The verifier
 * endpoints are never published by issuer discovery, so there is nothing to
 * resolve from — a missing URL is a hard configuration error.
 */
function requireVerifierUrl(state: ClientState): string {
  if (!state.config.verifierUrl) throw new VerifierNotConfiguredError();
  return state.config.verifierUrl;
}

/** Parses the `Retry-After` header into whole seconds (0 when absent/invalid). */
function parseRetryAfter(res: Response): number {
  const header = res.headers.get('Retry-After');
  if (!header) return 0;
  const seconds = Number.parseInt(header, 10);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : 0;
}

/**
 * Maps a non-2xx verifier response to the matching typed error. Server error
 * bodies are never echoed to end users — the message stays generic and the
 * detail lives in the stable `code`.
 */
function throwForStatus(res: Response): never {
  switch (res.status) {
    case 400:
      // Malformed or failed verification (see public.rs: verify returns 400
      // for decode/verify failures).
      throw new InvalidTokenError();
    case 401:
      // On /v1/verify a 401 means the token was already used (replay), per
      // public.rs:149-152.
      throw new ReplayedTokenError();
    case 429:
      throw new RateLimitedError(parseRetryAfter(res));
    case 503:
      throw new VerifierUnavailableError();
    default:
      throw new VerificationError();
  }
}

/**
 * Verifies a token against the configured verifier, consuming it (recording
 * the nullifier as spent). Throws typed errors on failure; resolves to the
 * full {@link VerifyResp} on success.
 */
export async function verifyToken(
  state: ClientState,
  token: FreebirdToken,
): Promise<VerifyResp> {
  const verifierUrl = requireVerifierUrl(state);
  const res = await (state.config.fetch ?? fetch)(`${verifierUrl}/v1/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token_b64: token.tokenValue }),
  });
  if (!res.ok) return throwForStatus(res);
  return (await res.json()) as VerifyResp;
}

/**
 * Checks token validity WITHOUT consuming it. Hits the distinct `/v1/check`
 * endpoint (public.rs::check), which validates format and authenticator but
 * does not record the nullifier as spent — the token can still be used with
 * `/v1/verify` afterwards.
 */
export async function checkToken(
  state: ClientState,
  token: FreebirdToken,
): Promise<VerifyResp> {
  const verifierUrl = requireVerifierUrl(state);
  const res = await (state.config.fetch ?? fetch)(`${verifierUrl}/v1/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token_b64: token.tokenValue }),
  });
  if (!res.ok) return throwForStatus(res);
  return (await res.json()) as VerifyResp;
}

/**
 * Verifies a batch of tokens in one request against `/v1/verify/batch`.
 * Each token is consumed. Per-token outcomes are surfaced in
 * {@link BatchVerifyResp.results} (including `code: "replay_detected"`).
 */
export async function verifyBatch(
  state: ClientState,
  tokens: FreebirdToken[],
): Promise<BatchVerifyResp> {
  const verifierUrl = requireVerifierUrl(state);
  const body: { tokens: TokenToVerify[] } = {
    tokens: tokens.map((token) => ({ token_b64: token.tokenValue })),
  };
  const res = await (state.config.fetch ?? fetch)(`${verifierUrl}/v1/verify/batch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) return throwForStatus(res);
  return (await res.json()) as BatchVerifyResp;
}

/**
 * Boolean convenience over {@link verifyToken} for callers that only need a
 * yes/no answer. Returns `false` for invalid or replayed tokens, but rethrows
 * infrastructure errors (`VerifierNotConfiguredError`, `VerifierUnavailableError`,
 * `RateLimitedError`) so callers can distinguish "token is bad" from "verifier
 * is unavailable".
 */
export async function verifyTokenValid(
  state: ClientState,
  token: FreebirdToken,
): Promise<boolean> {
  try {
    const resp = await verifyToken(state, token);
    return resp.ok === true;
  } catch (err) {
    if (err instanceof InvalidTokenError || err instanceof ReplayedTokenError) {
      return false;
    }
    throw err;
  }
}
