import 'altcha/external';
import {
  admissionFromPow, authorizationHeader, FreebirdError, obtainToken,
} from '../../../packages/freebird-client/src/index.mjs';
import { issuerBaseURL, statusMessage } from './helpers.mjs';

const networkError = 'Network request failed or timed out. Check HTTPS, Issuer CORS and CSP, then start again.';
const stageLabels = { directory: 'Directory', admission: 'Admission', issuance: 'Issuance' };

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
  let message = 'Invalid server data or a cryptographic operation failed. Start again.';
  if (error instanceof DemoError) {
    message = error.message;
  } else if (error instanceof FreebirdError) {
    if (error.status !== undefined && stageLabels[error.stage]) {
      message = statusMessage(stageLabels[error.stage], error.status);
    } else if (error.reason === 'network' || error.reason === 'timeout') {
      message = networkError;
    } else if (error.stage === 'admission') {
      message = 'Invalid admission response. Start again.';
    }
  }
  errorBox.textContent = message;
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
    throw new DemoError(networkError);
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

function mountProof(resolve, reject) {
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
      reject(new DemoError(proofError));
    }
  });
  widget.addEventListener('verified', event => {
    if (proofUsed) return;
    proofUsed = true;
    const payload = event.detail.payload;
    removeWidget();
    resolve(payload);
  });
  proofContainer.append(widget);
}

async function solveForAdmission() {
  status.textContent = 'Solving proof-of-work in your browser…';
  const payload = await new Promise(mountProof);
  if (typeof payload !== 'string' || !payload) throw new DemoError('Missing proof-of-work result. Start again.');
  progress('solving', 'Proof solved. Requesting admission…', 'admitted');
  const admission = await admissionFromPow(issuer.origin, payload);
  progress('admitted', 'Admitted. Obtaining a Privacy Pass token…', 'token');
  return admission;
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

  const originResponse = await request(protectedURL);
  expectStatus(originResponse, 401, 'Origin challenge');
  const challengeHeader = originResponse.headers.get('WWW-Authenticate');
  await originResponse.body?.cancel();
  // The client validates the challenge and directory before asking for a proof.
  const token = await obtainToken(challengeHeader, {
    issuer: issuer.origin,
    admission: solveForAdmission,
  });
  progress('token', 'Token obtained. Requesting the protected page…', 'access');
  const redemption = await request(protectedURL, {
    headers: { Authorization: authorizationHeader(token) },
  });
  expectStatus(redemption, 200, 'Access');
  // Treat the protected resource as data, never inject its HTML into this page.
  await redemption.body?.cancel();
  replayToken = token;
  progress('access', 'Access granted (200).');
  busy = false;
  replayButton.disabled = false;
  startButton.disabled = false;
  startButton.textContent = 'Start again';
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
      headers: { Authorization: authorizationHeader(replayToken) },
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
