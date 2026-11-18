// Typed errors for the Freebird client. Messages are fixed, package-authored
// text. They never include admission codes, tokens, keys, URLs with secrets or
// response bodies, so they are safe to show to users.

export class FreebirdError extends Error {
  /**
   * @param {string} message fixed, non-sensitive text
   * @param {{
   *   stage?: 'directory' | 'challenge' | 'admission' | 'issuance' | 'access',
   *   status?: number,
   *   retryAfter?: number,
   *   reason?: 'network' | 'timeout' | 'aborted' | 'protocol' | 'http',
   * }} [details]
   */
  constructor(message, { stage, status, retryAfter, reason } = {}) {
    super(message);
    this.name = 'FreebirdError';
    this.stage = stage;
    /** HTTP status when the Issuer or Origin answered; absent otherwise. */
    this.status = status;
    /** Seconds from a Retry-After header on 429/503, when present. */
    this.retryAfter = retryAfter;
    this.reason = reason;
  }
}

export function protocolError(stage, message) {
  return new FreebirdError(message, { stage, reason: 'protocol' });
}
