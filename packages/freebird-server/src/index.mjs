// Exchange an application key for one admission code per `POST` on Node.js 20 or later.
// The application server can import this module without installing any dependencies.
// Keep the application key on the server and out of logs to prevent others from using it to request codes.

const KEY = /^fba_([A-Za-z0-9_-]{43})$/;
const CODE = /^[A-Za-z0-9_-]{43}$/;
const TIMEOUT_MS = 10_000;
const MAX_RESPONSE_CHARS = 1024;

export class FreebirdError extends Error {
  /**
   * Keep the stage and other failure details separate from the error message.
   *
   * @param {string} message Supply fixed text that contains no sensitive data.
   * @param {{
   *   stage?: 'admission',
   *   status?: number,
   *   retryAfter?: number,
   *   reason?: 'network' | 'timeout' | 'protocol' | 'http',
   * }} [details]
   */
  constructor(message, { stage, status, retryAfter, reason } = {}) {
    super(message);
    this.name = 'FreebirdError';
    this.stage = stage;
    this.status = status;
    /** If a `429` or `503` response had a valid `Retry-After` header, store the delay in seconds. */
    this.retryAfter = retryAfter;
    this.reason = reason;
  }
}

/**
 * Send an application key to the Issuer to obtain one single-use admission code.
 *
 * @param {{
 *   issuer: string,
 *   key: string,
 *   fetch?: typeof fetch,
 *   allowInsecureLoopback?: boolean,
 * }} options
 *   Set `issuer` to an HTTPS origin with no path, query, or credentials.
 *   Set `allowInsecureLoopback` to permit `http://127.0.0.1` in tests.
 * @returns {Promise<string>} The promise resolves to a 43-character code.
 *   Give it to one user because the code can be used once and expires after 24 hours.
 */
export async function requestAdmission({
  issuer,
  key,
  fetch: fetchImpl = globalThis.fetch,
  allowInsecureLoopback = false,
} = {}) {
  const origin = issuerOrigin(issuer, allowInsecureLoopback === true);
  const match = typeof key === 'string' ? KEY.exec(key) : null;
  if (!match || !canonical(match[1])) throw new TypeError('The application key is malformed.');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch must be a function.');

  let response;
  try {
    response = await fetchImpl(new URL('/freebird/app/admission', origin), {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    // Keep only the failure category so that sensitive request details stay out of the error message.
    const timedOut = error?.name === 'TimeoutError';
    throw new FreebirdError(`The admission request failed (${timedOut ? 'timeout' : 'network'}).`, {
      stage: 'admission', reason: timedOut ? 'timeout' : 'network',
    });
  }

  if (response.status !== 200) {
    const { status } = response;
    const retryAfter = status === 429 || status === 503
      ? parseRetryAfter(response.headers.get('retry-after')) : undefined;
    await discard(response);
    throw new FreebirdError(refusalMessage(status), {
      stage: 'admission', status, retryAfter, reason: 'http',
    });
  }

  let text;
  try {
    text = await response.text();
  } catch {
    throw new FreebirdError('The admission response could not be read.', {
      stage: 'admission', reason: 'network',
    });
  }
  const json = parseJSON(text);
  if (!json || typeof json !== 'object' || text.length > MAX_RESPONSE_CHARS
      || typeof json.admission !== 'string' || !CODE.test(json.admission)
      || !canonical(json.admission)) {
    throw new FreebirdError('Invalid admission response.', {
      stage: 'admission', status: 200, reason: 'protocol',
    });
  }
  return json.admission;
}

function refusalMessage(status) {
  if (status === 401) return 'The application key was rejected (HTTP 401).';
  if (status === 429) return 'The Issuer is busy or the daily cap was reached (HTTP 429).';
  return `The admission request was refused (HTTP ${status}).`;
}

function issuerOrigin(value, allowInsecureLoopback) {
  let url;
  try {
    url = typeof value === 'string' ? new URL(value) : undefined;
  } catch {
    url = undefined;
  }
  const secure = url?.protocol === 'https:'
    || (allowInsecureLoopback && url?.protocol === 'http:' && url.hostname === '127.0.0.1');
  if (!url || !secure || url.username || url.password || url.search || url.hash
      || url.pathname !== '/') {
    throw new TypeError('The Issuer must be an HTTPS origin without a path or credentials.');
  }
  return url.origin;
}

// Require the low two bits of the final base64url character to be zero so that each 32-byte value
// has only one encoding.
function canonical(code43) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return alphabet.indexOf(code43[42]) % 4 === 0;
}

function parseJSON(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

async function discard(response) {
  try {
    await response.body?.cancel();
  } catch {
    // Ignore cancellation failures because the body may already be consumed or locked.
  }
}

// Parse `Retry-After` as seconds or an IMF-fixdate and return `undefined` for other formats.
function parseRetryAfter(value, now = Date.now()) {
  if (typeof value !== 'string') return undefined;
  const text = value.trim();
  if (/^[0-9]{1,9}$/.test(text)) return Number(text);
  if (!/^[A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$/.test(text)) {
    return undefined;
  }
  const when = Date.parse(text);
  return Number.isNaN(when) ? undefined : Math.max(0, Math.ceil((when - now) / 1000));
}
