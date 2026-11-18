// Application-server side of Freebird app admission: one POST per admission code.
// Node >= 20, ESM, zero dependencies. The application key is a secret: keep it
// on the server and never send it to a browser or log it.

const KEY = /^fba_([A-Za-z0-9_-]{43})$/;
const CODE = /^[A-Za-z0-9_-]{43}$/;
const TIMEOUT_MS = 10_000;
const MAX_RESPONSE_CHARS = 1024;

export class FreebirdError extends Error {
  /**
   * @param {string} message fixed, non-sensitive text
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
    /** Seconds from Retry-After on 429 (the daily cap), when the Issuer sent it. */
    this.retryAfter = retryAfter;
    this.reason = reason;
  }
}

/**
 * Asks the Issuer for one single-use admission code for an application.
 *
 * @param {{
 *   issuer: string,
 *   key: string,
 *   fetch?: typeof fetch,
 *   allowInsecureLoopback?: boolean,
 * }} options
 *   `issuer` is the Issuer HTTPS origin (no path, query or credentials).
 *   `allowInsecureLoopback` permits `http://127.0.0.1` only, for tests.
 * @returns {Promise<string>} the 43-character admission code. Hand it to exactly
 *   one user; it is valid for 24 hours and usable once.
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
    // The underlying error may echo request details; keep only the category.
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

// Exactly one textual spelling per 32-byte value: the final character carries
// only two significant bits, so its low two bits must be zero.
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
    // Already consumed or locked.
  }
}

// Delta seconds or an IMF-fixdate; anything else is ignored.
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
