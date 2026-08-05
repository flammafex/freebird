// SPDX-License-Identifier: Apache-2.0 OR MIT

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  PollAbortedError,
  PollTimeoutError,
  pollExchangeStatus,
  pollGraphIssuanceStatus,
} from '../src/index.js';
import type { ExchangeOutcome, GraphIssuanceOutcome } from '../src/index.js';

const pending = (retryAfter: number): ExchangeOutcome => ({
  kind: 'pending',
  httpStatus: 202,
  response: { error: 'exchange_retryable' },
  retryAfter,
  rawResponseBody: '',
  cacheControl: 'no-store',
});
const committed = (): ExchangeOutcome => ({
  kind: 'committed',
  httpStatus: 200,
  response: {} as never,
  rawResponseBody: '',
  cacheControl: 'no-store',
});
const exchangeError = (): ExchangeOutcome => ({
  kind: 'error',
  httpStatus: 400,
  response: { error: 'invalid_exchange' },
  rawResponseBody: '',
  cacheControl: 'no-store',
});
const graphCommitted = (): GraphIssuanceOutcome => ({
  kind: 'committed',
  httpStatus: 200,
  response: {} as never,
  rawResponseBody: '',
  cacheControl: 'no-store',
});
const graph503 = (): GraphIssuanceOutcome => ({
  kind: 'error',
  httpStatus: 503,
  response: { error: 'graph_issuance_unavailable' },
  rawResponseBody: '',
  cacheControl: 'no-store',
});
const graphError = (): GraphIssuanceOutcome => ({
  kind: 'error',
  httpStatus: 400,
  response: { error: 'invalid_graph_issuance' },
  rawResponseBody: '',
  cacheControl: 'no-store',
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('pollExchangeStatus', () => {
  it('returns immediately on a committed outcome', async () => {
    const fetchStatus = vi.fn().mockResolvedValue(committed());
    await expect(pollExchangeStatus(fetchStatus)).resolves.toEqual(committed());
    expect(fetchStatus).toHaveBeenCalledTimes(1);
  });

  it('returns immediately on a terminal error outcome', async () => {
    const fetchStatus = vi.fn().mockResolvedValue(exchangeError());
    await expect(pollExchangeStatus(fetchStatus)).resolves.toEqual(exchangeError());
    expect(fetchStatus).toHaveBeenCalledTimes(1);
  });

  it('retries while pending and honors retryAfter as the floor', async () => {
    vi.useFakeTimers();
    const fetchStatus = vi.fn()
      .mockResolvedValueOnce(pending(2))
      .mockResolvedValueOnce(committed());

    const promise = pollExchangeStatus(fetchStatus, { intervalMs: 100 });
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchStatus).toHaveBeenCalledTimes(1);

    // retryAfter=2s is the floor; 1999ms is not enough to trigger the retry.
    await vi.advanceTimersByTimeAsync(1999);
    expect(fetchStatus).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1);
    await expect(promise).resolves.toEqual(committed());
    expect(fetchStatus).toHaveBeenCalledTimes(2);
  });

  it('uses intervalMs when it exceeds retryAfter', async () => {
    vi.useFakeTimers();
    const fetchStatus = vi.fn()
      .mockResolvedValueOnce(pending(0))
      .mockResolvedValueOnce(committed());

    const promise = pollExchangeStatus(fetchStatus, { intervalMs: 500 });
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(499);
    expect(fetchStatus).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    await expect(promise).resolves.toEqual(committed());
    expect(fetchStatus).toHaveBeenCalledTimes(2);
  });

  it('throws PollTimeoutError when the timeout cap is exceeded', async () => {
    vi.useFakeTimers();
    const fetchStatus = vi.fn().mockResolvedValue(pending(0));
    const promise = pollExchangeStatus(fetchStatus, { intervalMs: 100, timeoutMs: 250 });
    const assertion = expect(promise).rejects.toBeInstanceOf(PollTimeoutError);
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(300);
    await assertion;
  });

  it('throws PollAbortedError when the signal is aborted during a wait', async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const fetchStatus = vi.fn().mockResolvedValue(pending(0));
    const promise = pollExchangeStatus(fetchStatus, { intervalMs: 1000, signal: controller.signal });
    await vi.advanceTimersByTimeAsync(0);
    controller.abort();
    await expect(promise).rejects.toBeInstanceOf(PollAbortedError);
  });

  it('throws PollAbortedError immediately for a pre-aborted signal', async () => {
    const controller = new AbortController();
    controller.abort();
    const fetchStatus = vi.fn().mockResolvedValue(committed());
    await expect(pollExchangeStatus(fetchStatus, { signal: controller.signal }))
      .rejects.toBeInstanceOf(PollAbortedError);
    expect(fetchStatus).not.toHaveBeenCalled();
  });
});

describe('pollGraphIssuanceStatus', () => {
  it('returns immediately on a committed outcome', async () => {
    const fetchStatus = vi.fn().mockResolvedValue(graphCommitted());
    await expect(pollGraphIssuanceStatus(fetchStatus)).resolves.toEqual(graphCommitted());
    expect(fetchStatus).toHaveBeenCalledTimes(1);
  });

  it('returns immediately on a terminal (non-503) error outcome', async () => {
    const fetchStatus = vi.fn().mockResolvedValue(graphError());
    await expect(pollGraphIssuanceStatus(fetchStatus)).resolves.toEqual(graphError());
    expect(fetchStatus).toHaveBeenCalledTimes(1);
  });

  it('retries on retryable 503 outcomes', async () => {
    vi.useFakeTimers();
    const fetchStatus = vi.fn()
      .mockResolvedValueOnce(graph503())
      .mockResolvedValueOnce(graphCommitted());

    const promise = pollGraphIssuanceStatus(fetchStatus, { intervalMs: 100 });
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchStatus).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(100);
    await expect(promise).resolves.toEqual(graphCommitted());
    expect(fetchStatus).toHaveBeenCalledTimes(2);
  });

  it('throws PollTimeoutError when the timeout cap is exceeded', async () => {
    vi.useFakeTimers();
    const fetchStatus = vi.fn().mockResolvedValue(graph503());
    const promise = pollGraphIssuanceStatus(fetchStatus, { intervalMs: 100, timeoutMs: 250 });
    const assertion = expect(promise).rejects.toBeInstanceOf(PollTimeoutError);
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(300);
    await assertion;
  });
});
