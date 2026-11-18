// Privacy Pass type-2 issuance and redemption. Depends on the peer dependency
// through ./privacypass.mjs only.
import { FreebirdError, protocolError } from './errors.mjs';
import { encodePaddedBase64url, equalBytes } from './encoding.mjs';
import { publicVerif, TokenChallenge } from './privacypass.mjs';
import {
  DIRECTORY_PATH, authorizationHeader, checkChallenge, checkDirectory, isAdmissionCode,
  parseJSON, parsePrivateTokenChallenge, transportAllowed,
} from './protocol.mjs';
import { configure, discard, readBytes, readText, refusal, send } from './transport.mjs';

const DIRECTORY_ACCEPT = 'application/private-token-issuer-directory, application/json';
const DIRECTORY_LIMIT = 65536;
const TOKEN_REQUEST_LENGTH = 259;
const TOKEN_RESPONSE_LENGTH = 256;
const TOKEN_LENGTH = 354;
const FORBIDDEN_METHODS = ['CONNECT', 'TRACE', 'TRACK'];

export { authorizationHeader };

/**
 * Obtains one Privacy Pass token for the Origin challenge in `challengeHeader`.
 *
 * Order matters: the directory and challenge are checked before `admission` is
 * called, so a proof-of-work or admission is never spent on a challenge the
 * Issuer does not vouch for. `admission` may be a string or a function returning
 * the code (called at most once). Resolves to the padded base64url token.
 */
export async function obtainToken(challengeHeader, options = {}) {
  const config = configure(options);
  const { admission } = options;
  if (typeof admission !== 'string' && typeof admission !== 'function') {
    throw new TypeError('admission must be an admission code string or a function that returns one.');
  }
  const { bytes, spki } = parsePrivateTokenChallenge(challengeHeader);
  const challenge = parseChallenge(bytes);

  const directoryURL = new URL(DIRECTORY_PATH, config.origin);
  const directoryResponse = await send('directory', directoryURL, {
    headers: { Accept: DIRECTORY_ACCEPT },
  }, config);
  if (directoryResponse.status !== 200) throw await refusal('directory', directoryResponse);
  const directory = checkDirectory(parseJSON(await readText('directory', directoryResponse, DIRECTORY_LIMIT)),
    directoryURL.href, { allowInsecureLoopback: config.allowInsecureLoopback });
  checkChallenge(challenge, spki, directory);
  notify(config, 'challenged');

  let code = typeof admission === 'function' ? await admission() : admission;
  if (!isAdmissionCode(code)) throw protocolError('admission', 'The admission code is malformed.');
  notify(config, 'admitted');

  const client = new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
  let issued;
  try {
    const body = await tokenRequestBytes(client, challenge, spki);
    issued = await send('issuance', directory.requestURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/private-token-request',
        Accept: 'application/private-token-response',
        'Freebird-Admission': code,
      },
      body,
    }, config);
  } finally {
    // One admission buys one issuance request. Never retry with it.
    code = undefined;
  }
  if (issued.status !== 200) throw await refusal('issuance', issued);

  const responseBytes = await readBytes('issuance', issued, TOKEN_RESPONSE_LENGTH);
  if (responseBytes.length !== TOKEN_RESPONSE_LENGTH) {
    throw protocolError('issuance', 'Invalid type-2 token response length.');
  }
  let token;
  try {
    token = await client.finalize(publicVerif.TokenResponse.deserialize(Uint8Array.from(responseBytes)));
  } catch {
    throw protocolError('issuance', 'The token response could not be verified.');
  }
  const serialized = token.serialize();
  if (serialized.length !== TOKEN_LENGTH) throw protocolError('issuance', 'Invalid type-2 token length.');
  notify(config, 'issued');
  return encodePaddedBase64url(serialized);
}

/**
 * Requests a protected URL. On 401 with a PrivateToken challenge it obtains one
 * token (one admission) and retries the same request exactly once with
 * `Authorization: PrivateToken`. Resolves to the Response; a 401 after the token
 * is thrown as a FreebirdError with stage 'access'.
 */
export async function fetchWithToken(url, options = {}) {
  const config = configure(options);
  const target = protectedURL(url, config.allowInsecureLoopback);
  const init = requestInit(options.init);
  const first = await send('access', target, init, config);
  if (first.status !== 401) return first;
  const challenge = first.headers.get('WWW-Authenticate');
  await discard(first);

  const token = await obtainToken(challenge, options);
  const headers = new Headers(init.headers);
  headers.set('Authorization', authorizationHeader(token));
  const response = await send('access', target, { ...init, headers }, config);
  if (response.status === 401) {
    await discard(response);
    throw new FreebirdError('The Origin refused the token (HTTP 401).', {
      stage: 'access', status: 401, reason: 'http',
    });
  }
  return response;
}

function notify(config, stage) {
  config.onStage?.(stage);
}

function parseChallenge(bytes) {
  let challenge;
  try {
    // Upstream ignores byteOffset. Always give it a standalone backing buffer.
    challenge = TokenChallenge.deserialize(Uint8Array.from(bytes));
  } catch {
    throw protocolError('challenge', 'The Origin sent a malformed token challenge.');
  }
  if (!equalBytes(challenge.serialize(), bytes)) {
    throw protocolError('challenge', 'The Origin sent a non-canonical token challenge.');
  }
  // Rejected before any network request: the directory is not even fetched.
  if (challenge.tokenType !== 2) {
    throw protocolError('challenge', 'Expected an RFC 9578 type-2 challenge.');
  }
  return challenge;
}

async function tokenRequestBytes(client, challenge, spki) {
  let request;
  try {
    request = await client.createTokenRequest(challenge, spki);
  } catch {
    throw protocolError('issuance', 'The token request could not be created.');
  }
  const body = request.serialize();
  if (body.length !== TOKEN_REQUEST_LENGTH) throw protocolError('issuance', 'Invalid type-2 request length.');
  return body;
}

function protectedURL(value, allowInsecureLoopback) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError('The protected URL must be absolute.');
  }
  if (!transportAllowed(url, allowInsecureLoopback) || url.username || url.password) {
    throw new TypeError('The protected URL must use HTTPS without credentials.');
  }
  return url;
}

// Only body types that can be resent unchanged are accepted, because the single
// retry repeats the request.
function requestInit(init = {}) {
  if (init === null || typeof init !== 'object') throw new TypeError('init must be an object.');
  const headers = new Headers(init.headers);
  if (headers.has('authorization') || headers.has('freebird-admission')) {
    throw new TypeError('init.headers must not set Authorization or Freebird-Admission.');
  }
  const body = init.body ?? undefined;
  if (body !== undefined && typeof body !== 'string' && !(body instanceof Uint8Array)) {
    throw new TypeError('init.body must be a string or Uint8Array.');
  }
  const method = (init.method ?? 'GET').toUpperCase();
  if (typeof method !== 'string' || !/^[A-Z]+$/.test(method) || FORBIDDEN_METHODS.includes(method)) {
    throw new TypeError('init.method is not allowed.');
  }
  return { method, headers, body, signal: init.signal };
}
