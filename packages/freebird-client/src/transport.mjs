// HTTP plumbing shared by the protocol steps. Every request is made with
// credentials omitted, redirects rejected, caches bypassed and a timeout.
import { FreebirdError, protocolError } from './errors.mjs';
import { issuerBaseURL, parseRetryAfter } from './protocol.mjs';

export const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 120_000;

/** Validates the caller's options once and returns the internal settings. */
export function configure(options = {}) {
  if (options === null || typeof options !== 'object') {
    throw new TypeError('Options must be an object.');
  }
  const allowInsecureLoopback = options.allowInsecureLoopback === true;
  const issuer = issuerBaseURL(options.issuer, { allowInsecureLoopback });
  const timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > MAX_TIMEOUT_MS) {
    throw new TypeError(`timeout must be an integer from 1 to ${MAX_TIMEOUT_MS} milliseconds.`);
  }
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new TypeError('No fetch implementation is available.');
  if (options.onStage !== undefined && typeof options.onStage !== 'function') {
    throw new TypeError('onStage must be a function.');
  }
  return {
    origin: issuer.origin,
    allowInsecureLoopback,
    timeout,
    fetch: fetchImpl,
    onStage: options.onStage,
  };
}

export async function send(stage, url, init, config) {
  // Native browser fetch must not receive the config object as its receiver.
  const { fetch } = config;
  const timer = AbortSignal.timeout(config.timeout);
  const signal = init.signal ? AbortSignal.any([init.signal, timer]) : timer;
  try {
    return await fetch(url, {
      ...init,
      signal,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
  } catch {
    // The underlying error can carry URLs or upstream text; drop it.
    const reason = timer.aborted ? 'timeout' : init.signal?.aborted ? 'aborted' : 'network';
    throw new FreebirdError(`The ${stage} request failed (${reason}).`, { stage, reason });
  }
}

export async function discard(response) {
  try {
    await response.body?.cancel();
  } catch {
    // Already consumed or locked: nothing left to release.
  }
}

/** A non-success answer. The body is discarded; only the status and Retry-After survive. */
export async function refusal(stage, response) {
  const { status } = response;
  const retryAfter = status === 429 || status === 503
    ? parseRetryAfter(response.headers.get('retry-after'))
    : undefined;
  await discard(response);
  return new FreebirdError(`The ${stage} request was refused (HTTP ${status}).`, {
    stage, status, retryAfter, reason: 'http',
  });
}

export async function readText(stage, response, limit) {
  let text;
  try {
    text = await response.text();
  } catch {
    throw new FreebirdError(`The ${stage} response could not be read.`, { stage, reason: 'network' });
  }
  if (text.length > limit) throw protocolError(stage, `The ${stage} response is too large.`);
  return text;
}

export async function readBytes(stage, response, limit) {
  let buffer;
  try {
    buffer = await response.arrayBuffer();
  } catch {
    throw new FreebirdError(`The ${stage} response could not be read.`, { stage, reason: 'network' });
  }
  if (buffer.byteLength > limit) throw protocolError(stage, `The ${stage} response is too large.`);
  return new Uint8Array(buffer);
}
