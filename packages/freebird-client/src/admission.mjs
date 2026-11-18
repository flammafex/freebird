// Proof-of-work admission: POST {payload} to /freebird/pow/admission.
// No peer dependency.
import { protocolError } from './errors.mjs';
import { isAdmissionCode, parseJSON } from './protocol.mjs';
import { configure, readText, refusal, send } from './transport.mjs';

/**
 * Exchanges one solved ALTCHA payload for one single-use admission code.
 * The payload is sent once and never logged. Resolves to the 43-character code.
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
