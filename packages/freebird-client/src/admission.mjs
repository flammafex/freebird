// Posting `{ payload }` to `/freebird/pow/admission` exchanges a proof for an admission code
// without loading the Privacy Pass library.
import { protocolError } from './errors.mjs';
import { isAdmissionCode, parseJSON } from './protocol.mjs';
import { configure, readText, refusal, send } from './transport.mjs';

/**
 * Send one solved ALTCHA payload to obtain a 43-character admission code that can be used once.
 * The request is sent once, and the payload is kept out of error messages.
 */
export async function admissionFromPow(issuer, payload, options = {}) {
  if (typeof payload !== 'string' || payload.length === 0) {
    throw new TypeError('payload must be the non-empty proof-of-work result.');
  }
  const config = configure({ ...options, issuer });
  const response = await send('admission', new URL('/freebird/pow/admission', config.origin), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ payload }),
  }, config);
  if (response.status !== 200) throw await refusal('admission', response);
  return parseAdmission('admission', await readText('admission', response, 1024));
}

export function parseAdmission(stage, text) {
  const json = parseJSON(text);
  if (!json || typeof json !== 'object' || !isAdmissionCode(json.admission)) {
    throw protocolError(stage, 'Invalid admission response.');
  }
  return json.admission;
}
