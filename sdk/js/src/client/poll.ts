// SPDX-License-Identifier: Apache-2.0 OR MIT

import type { ExchangeOutcome, GraphIssuanceOutcome } from '../types.js';
import { PollAbortedError, PollTimeoutError } from '../errors.js';

/** Options controlling a polling loop. */
export interface PollOptions {
  /**
   * Minimum delay (ms) between status polls. Defaults to 1000ms. The server's
   * `retryAfter` (when present) is honored as a floor, so the actual delay is
   * `max(intervalMs, retryAfter * 1000)`.
   */
  intervalMs?: number;
  /** Overall cap (ms) for the polling loop. Defaults to 60000ms. */
  timeoutMs?: number;
  /** Cancels the polling loop. */
  signal?: AbortSignal;
}

const DEFAULT_INTERVAL_MS = 1000;
const DEFAULT_TIMEOUT_MS = 60_000;

/**
 * Polls a status fetcher until a terminal outcome is reached.
 *
 * `shouldRetry` decides whether an outcome is retryable (e.g. a pending
 * exchange or a retryable 503); `retryAfterOf` extracts the server-provided
 * retry delay (in whole seconds) from a retryable outcome, used as the floor
 * for the next poll. Throws {@link PollTimeoutError} if `timeoutMs` elapses
 * and {@link PollAbortedError} if `signal` is aborted.
 */
export async function pollUntilTerminal<T extends { kind: string }>(
  fetchStatus: () => Promise<T>,
  options: PollOptions,
  shouldRetry: (outcome: T) => boolean,
  retryAfterOf: (outcome: T) => number | undefined,
): Promise<T> {
  const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const signal = options.signal;
  const deadline = Date.now() + timeoutMs;

  if (signal?.aborted) throw new PollAbortedError();

  for (;;) {
    const outcome = await fetchStatus();
    if (!shouldRetry(outcome)) return outcome;

    const retryAfter = retryAfterOf(outcome);
    const floorMs = retryAfter !== undefined ? retryAfter * 1000 : 0;
    const delay = Math.max(intervalMs, floorMs);

    if (Date.now() + delay > deadline) throw new PollTimeoutError();
    await sleep(delay, signal);
  }
}

/**
 * Polls an exchange status until it is committed or fails terminally.
 *
 * Retries while the outcome is `pending`, honoring the server's `retryAfter`
 * (in whole seconds) as the floor for the next poll.
 */
export function pollExchangeStatus(
  fetchStatus: () => Promise<ExchangeOutcome>,
  options: PollOptions = {},
): Promise<ExchangeOutcome> {
  return pollUntilTerminal(
    fetchStatus,
    options,
    (outcome) => outcome.kind === 'pending',
    (outcome) => (outcome.kind === 'pending' ? outcome.retryAfter : undefined),
  );
}

/**
 * Polls a graph issuance status until it is committed or fails terminally.
 *
 * Graph issuance has no `pending` state; the only retryable outcome is a 503
 * (`graph_issuance_unavailable`), which is retried on the configured interval.
 */
export function pollGraphIssuanceStatus(
  fetchStatus: () => Promise<GraphIssuanceOutcome>,
  options: PollOptions = {},
): Promise<GraphIssuanceOutcome> {
  return pollUntilTerminal(
    fetchStatus,
    options,
    (outcome) => outcome.kind === 'error' && outcome.httpStatus === 503,
    () => undefined,
  );
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new PollAbortedError());
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(new PollAbortedError());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
