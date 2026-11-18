// Use fixed error messages so that credentials, sensitive URLs, and response bodies do not appear
// in user-facing text.

export class FreebirdError extends Error {
  /**
   * Keep the stage and other failure details separate from the error message.
   *
   * @param {string} message Supply fixed text that contains no sensitive data.
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
    /** The HTTP status is set if a response came from the Issuer or Origin. */
    this.status = status;
    /** If a `429` or `503` response had a valid `Retry-After` header, store the delay in seconds. */
    this.retryAfter = retryAfter;
    this.reason = reason;
  }
}

export function protocolError(stage, message) {
  return new FreebirdError(message, { stage, reason: 'protocol' });
}
