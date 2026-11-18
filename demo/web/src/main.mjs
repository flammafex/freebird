import 'altcha/external';
import { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';
import {
  checkChallenge, checkDirectory, decodePaddedBase64url, encodePaddedBase64url,
  equalBytes, issuerBaseURL, parsePrivateTokenChallenge, statusMessage,
} from './helpers.mjs';

const startButton = document.querySelector('#start-button');
const replayButton = document.querySelector('#replay-button');
const status = document.querySelector('#flow-status');
const errorBox = document.querySelector('#flow-error');
const proofContainer = document.querySelector('#proof-container');
const protectedURL = new URL('/private-token/protected', location.origin);
let issuer;
let widget;
let replayToken; // Memory only; retained solely for the explicit replay demonstration.
let busy = false;

class DemoError extends Error {}

function setStep(step, state) {
  document.querySelector(`#step-${step}`).dataset.state = state;
}

function progress(step, message, next) {
  setStep(step, 'complete');
  if (next) setStep(next, 'active');
  status.textContent = message;
}

function removeWidget() {
  widget?.reset();
  proofContainer.replaceChildren();
  widget = undefined;
}

function fail(error) {
  replayToken = undefined;
  replayButton.disabled = true;
  removeWidget();
  busy = false;
  startButton.disabled = false;
  startButton.textContent = 'Start again';
  for (const step of document.querySelectorAll('#flow-steps li[data-state="active"]')) {
    step.dataset.state = 'failed';
  }
  status.textContent = 'Stopped.';
  // Never print an upstream error/body: it might contain a credential.
  errorBox.textContent = error instanceof DemoError
    ? error.message : 'Invalid server data or a cryptographic operation failed. Start again.';
  errorBox.hidden = false;
}

async function request(url, options = {}) {
  try {
    return await fetch(url, {
      ...options,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new DemoError('Network request failed or timed out. Check HTTPS, Issuer CORS and CSP, then start again.');
  }
}

function expectStatus(response, expected, stage) {
  if (response.status !== expected) throw new DemoError(statusMessage(stage, response.status));
}

// Static, same-origin classic workers: no inline worker, blob URL, CDN or WASM.
for (const digest of ['SHA-256', 'SHA-384', 'SHA-512']) {
  globalThis.$altcha.algorithms.set(`PBKDF2/${digest}`,
    () => new Worker(new URL('./workers/pbkdf2.js', import.meta.url)));
  globalThis.$altcha.algorithms.set(digest,
    () => new Worker(new URL('./workers/sha.js', import.meta.url)));
}

function mountProof(directory, challenge, spki) {
  const challengeURL = new URL('/freebird/pow/challenge', issuer);
  let proofUsed = false;
  let proofError = 'Proof-of-work failed or expired. Start again.';
  globalThis.$altcha.defaults.set({
    // ALTCHA 3 calls the former challengeurl setting "challenge".
    challenge: challengeURL.href,
    auto: 'onload',
    type: 'native',
    workers: Math.min(4, navigator.hardwareConcurrency || 2),
    debug: false,
    hideFooter: true,
    hideLogo: true,
    humanInteractionSignature: false,
    serverVerificationFields: false,
    serverVerificationTimeZone: false,
    setCookie: null,
    credentials: 'omit',
    formatError: () => 'Proof-of-work failed. Start again.',
    fetch: async (url, options) => {
      try {
        if (new URL(url).href !== challengeURL.href
            || (options?.method && options.method !== 'GET')) {
          throw new DemoError('Unexpected proof-of-work endpoint.');
        }
        const response = await request(url, options);
        expectStatus(response, 200, 'Proof-of-work');
        return response;
      } catch (error) {
        proofError = error instanceof DemoError ? error.message : proofError;
        throw new Error(proofError); // A fixed status only; safe for widget diagnostics.
      }
    },
  });
  widget = document.createElement('altcha-widget');
  widget.id = 'pow-widget';
  widget.addEventListener('statechange', event => {
    if (proofUsed) return;
    if (event.detail.state === 'verifying') {
      status.textContent = 'Solving proof-of-work in your browser…';
      document.querySelector('#step-solving').dataset.state = 'active';
    } else if (['error', 'expired'].includes(event.detail.state)) {
      proofUsed = true;
      fail(new DemoError(proofError));
    }
  });
  widget.addEventListener('verified', event => {
    if (proofUsed) return;
    proofUsed = true;
    const payload = event.detail.payload;
    removeWidget();
    finishFlow(payload, directory, challenge, spki).catch(fail);
  });
  proofContainer.append(widget);
}

async function finishFlow(payload, directory, challenge, spki) {
  if (typeof payload !== 'string' || !payload) throw new DemoError('Missing proof-of-work result. Start again.');
  progress('solving', 'Proof solved. Requesting admission…', 'admitted');
  const admissionResponse = await request(new URL('/freebird/pow/admission', issuer), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ payload }),
  });
  payload = undefined;
  expectStatus(admissionResponse, 200, 'Admission');
  let { admission } = await admissionResponse.json();
  if (typeof admission !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(admission)
      || decodePaddedBase64url(`${admission}=`).length !== 32) {
    throw new DemoError('Invalid admission response. Start again.');
  }
  progress('admitted', 'Admitted. Obtaining a Privacy Pass token…', 'token');

  // Re-check the issuer and the advertised directory key before any issuance.
  checkChallenge(challenge, spki, directory);
  const client = new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
  let issued;
  try {
    const tokenRequest = await client.createTokenRequest(challenge, spki);
    const body = tokenRequest.serialize();
    if (body.length !== 259) throw new DemoError('Invalid type-2 request length.');
    issued = await request(directory.requestURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/private-token-request',
        Accept: 'application/private-token-response',
        'Freebird-Admission': admission,
      },
      body,
    });
  } finally {
    admission = undefined; // One use; never retry issuance with this admission.
  }
  expectStatus(issued, 200, 'Issuance');
  const responseBytes = new Uint8Array(await issued.arrayBuffer());
  if (responseBytes.length !== 256) throw new DemoError('Invalid type-2 token response length.');
  const token = await client.finalize(publicVerif.TokenResponse.deserialize(Uint8Array.from(responseBytes)));
  const serialized = token.serialize();
  if (serialized.length !== 354) throw new DemoError('Invalid type-2 token length.');
  const encoded = encodePaddedBase64url(serialized);
  progress('token', 'Token obtained. Requesting the protected page…', 'access');
  const redemption = await request(protectedURL, {
    headers: { Authorization: `PrivateToken token="${encoded}"` },
  });
  expectStatus(redemption, 200, 'Access');
  // Treat the protected resource as data, never inject its HTML into this page.
  await redemption.body?.cancel();
  replayToken = encoded;
  progress('access', 'Access granted (200).');
  busy = false;
  replayButton.disabled = false;
  startButton.disabled = false;
  startButton.textContent = 'Start again';
}

async function start() {
  if (busy) return;
  busy = true;
  replayToken = undefined;
  startButton.disabled = true;
  replayButton.disabled = true;
  errorBox.hidden = true;
  removeWidget();
  for (const step of document.querySelectorAll('#flow-steps li')) step.dataset.state = 'waiting';
  setStep('solving', 'active');
  status.textContent = 'Loading the Issuer directory and Origin challenge…';

  const directoryURL = new URL('/.well-known/private-token-issuer-directory', issuer);
  const directoryResponse = await request(directoryURL, {
    headers: { Accept: 'application/private-token-issuer-directory, application/json' },
  });
  expectStatus(directoryResponse, 200, 'Directory');
  const directory = checkDirectory(await directoryResponse.json(), directoryURL);
  const originResponse = await request(protectedURL);
  expectStatus(originResponse, 401, 'Origin challenge');
  const { bytes, spki } = parsePrivateTokenChallenge(originResponse.headers.get('WWW-Authenticate'));
  await originResponse.body?.cancel();
  // Upstream ignores byteOffset. Always give it a standalone backing buffer.
  const challenge = TokenChallenge.deserialize(Uint8Array.from(bytes));
  if (!equalBytes(challenge.serialize(), bytes)) {
    throw new DemoError('The Origin sent a malformed or non-canonical token challenge.');
  }
  checkChallenge(challenge, spki, directory);
  status.textContent = 'Solving proof-of-work in your browser…';
  mountProof(directory, challenge, spki);
}

async function tryReplay() {
  if (busy || !replayToken) return;
  busy = true;
  startButton.disabled = true;
  replayButton.disabled = true;
  setStep('replay', 'active');
  status.textContent = 'Trying the spent token once more…';
  let response;
  try {
    response = await request(protectedURL, {
      headers: { Authorization: `PrivateToken token="${replayToken}"` },
    });
  } finally {
    replayToken = undefined;
  }
  await response.body?.cancel();
  if (response.status !== 401) {
    throw new DemoError(response.status === 200
      ? 'Replay unexpectedly accepted (200). Check the Origin replay protection.'
      : statusMessage('Replay', response.status));
  }
  progress('replay', 'Replay refused (401). The token was one-use.');
  busy = false;
  startButton.disabled = false;
}

startButton.addEventListener('click', () => start().catch(fail));
replayButton.addEventListener('click', () => tryReplay().catch(fail));
// Do not leave the replay credential alive in a back/forward cache.
window.addEventListener('pagehide', () => {
  replayToken = undefined;
  replayButton.disabled = true;
});

try {
  issuer = issuerBaseURL(document.querySelector('meta[name="freebird-issuer"]')?.content);
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    throw new Error('This demo requires HTTPS and browser Web Crypto.');
  }
  status.textContent = 'Ready. Solve a proof to enter.';
  startButton.disabled = false;
} catch (error) {
  errorBox.textContent = error.message;
  errorBox.hidden = false;
  status.textContent = 'Configuration required.';
}
