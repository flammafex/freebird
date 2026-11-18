// Invoked by scripts/test-browser-demo.py with real services and Chrome.
// Intentionally inert under `node --test`, which has no live TLS fixture.
import { setTimeout as delay } from 'node:timers/promises';

class CheckFailure extends Error {}
function check(condition, status) {
  if (!condition) throw new CheckFailure(status);
}

async function main(debuggingPort, origin, issuer) {
  check(Number.parseInt(process.versions.node, 10) >= 26, 'Node 26+ required');
  const allowedOrigins = new Set([origin, issuer]);
  const protectedURL = `${origin}/private-token/protected`;
  const targets = await (await fetch(`http://127.0.0.1:${debuggingPort}/json/list`,
    { signal: AbortSignal.timeout(10_000) })).json();
  const target = targets.find(entry => entry.type === 'page' && entry.url === 'about:blank');
  check(target?.webSocketDebuggerUrl, 'Chrome page target unavailable');
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  const pending = new Map();
  const requests = new Map();
  const responses = [];
  const networkErrors = [];
  const setups = new Set();
  let nextID = 0;
  let consoleErrors = 0;
  let cspErrors = 0;
  let outsideRequests = 0;
  let powWorkerCount = 0;
  let setupFailed = false;

  function send(method, params = {}, sessionId, timeout = 15_000) {
    return new Promise((resolve, reject) => {
      const id = ++nextID;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new CheckFailure('CDP command timed out'));
      }, timeout);
      pending.set(id, { resolve, reject, timer });
      socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }

  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const command = pending.get(message.id);
      if (!command) return;
      pending.delete(message.id);
      clearTimeout(command.timer);
      if (message.error) command.reject(new CheckFailure('CDP command rejected'));
      else command.resolve(message.result);
      return;
    }
    const { method, params, sessionId } = message;
    const requestKey = id => `${sessionId ?? 'page'}:${id}`;
    if (method === 'Target.attachedToTarget') {
      // Observe dedicated workers as well as the document; run no injected solver.
      const setup = (async () => {
        const workerSession = params.sessionId;
        if (params.targetInfo.type === 'worker') {
          // Chrome can omit the worker bootstrap from Network events. Its target
          // URL still identifies the actual loaded script; audit that URL too.
          const url = new URL(params.targetInfo.url);
          if (!allowedOrigins.has(url.origin) || url.username || url.password || url.search) {
            outsideRequests++;
          }
          if (url.href === `${origin}/assets/workers/pbkdf2.js`) powWorkerCount++;
        }
        await send('Runtime.enable', {}, workerSession);
        await send('Network.enable', {}, workerSession);
        await send('Runtime.runIfWaitingForDebugger', {}, workerSession);
      })().catch(() => { setupFailed = true; });
      setups.add(setup);
      setup.finally(() => setups.delete(setup));
    } else if (method === 'Network.requestWillBeSent') {
      try {
        const url = new URL(params.request.url);
        if (!allowedOrigins.has(url.origin) || url.username || url.password || url.search) {
          outsideRequests++;
        }
        // Never retain headers, POST bodies, or other credential-bearing CDP data.
        requests.set(requestKey(params.requestId),
          { url: `${url.origin}${url.pathname}`, method: params.request.method });
      } catch {
        outsideRequests++;
      }
    } else if (method === 'Network.responseReceived') {
      const request = requests.get(requestKey(params.requestId));
      if (request) {
        const headers = Object.fromEntries(Object.entries(params.response.headers)
          .map(([key, value]) => [key.toLowerCase(), value]));
        responses.push({ ...request, status: params.response.status, headers,
          tls: Boolean(params.response.securityDetails) });
      }
    } else if (method === 'Runtime.exceptionThrown'
        || (method === 'Runtime.consoleAPICalled' && ['error', 'assert'].includes(params.type))) {
      consoleErrors++;
    } else if (method === 'Log.entryAdded') {
      const entry = params.entry;
      if (entry.source === 'security') cspErrors++;
      if (entry.level === 'error') {
        // Chrome logs the two expected HTTP 401s as resource errors, not JS errors.
        if (entry.source === 'network') {
          networkErrors.push({ url: entry.url, expected401: /\b401\b/.test(entry.text) });
        } else {
          consoleErrors++;
        }
      }
    }
  });

  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new CheckFailure('CDP connection timed out')), 10_000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => {
        clearTimeout(timer);
        reject(new CheckFailure('CDP connection failed'));
      }, { once: true });
    });
    await send('Page.enable');
    await send('Runtime.enable');
    await send('Log.enable');
    await send('Network.enable');
    await send('Network.setCacheDisabled', { cacheDisabled: true });
    await send('Target.setAutoAttach',
      { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
    await send('Page.addScriptToEvaluateOnNewDocument', { source: `
      globalThis.__freebirdE2E = { cspViolations: 0 };
      document.addEventListener('securitypolicyviolation', () => {
        globalThis.__freebirdE2E.cspViolations++;
      });
    ` });

    async function evaluate(expression) {
      const result = await send('Runtime.evaluate',
        { expression, returnByValue: true, awaitPromise: true });
      check(!result.exceptionDetails, 'page evaluation failed');
      return result.result.value;
    }

    async function waitFor(expression, label, timeout = 120_000) {
      const deadline = Date.now() + timeout;
      while (Date.now() < deadline) {
        check(!setupFailed, 'worker instrumentation failed');
        const state = await evaluate(`({
          done: Boolean(${expression}),
          failed: Boolean(document.querySelector('#flow-error:not([hidden])'))
        })`);
        check(!state.failed, `${label}: page reported failure`);
        if (state.done) return;
        await delay(100);
      }
      throw new CheckFailure(`${label}: timed out`);
    }

    const navigation = await send('Page.navigate', { url: `${origin}/` });
    check(!navigation.errorText, 'HTTPS navigation failed');
    await waitFor(`document.querySelector('#flow-status')?.textContent
      === 'Ready. Solve a proof to enter.'
      && document.querySelector('#start-button')?.disabled === false`, 'page ready', 15_000);
    check(await evaluate('isSecureContext && Boolean(crypto.subtle)'), 'not a secure context');
    await evaluate("document.querySelector('#start-button').click()");
    await waitFor(`document.querySelector('#flow-status')?.textContent === 'Access granted (200).'
      && document.querySelector('#step-access')?.dataset.state === 'complete'
      && document.querySelector('#replay-button')?.disabled === false`, 'access');
    for (const step of ['solving', 'admitted', 'token', 'access']) {
      check(await evaluate(`document.querySelector('#step-${step}').dataset.state === 'complete'`),
        'incomplete browser flow');
    }
    console.log('browser demo access: 200');
    await evaluate("document.querySelector('#replay-button').click()");
    await waitFor(`document.querySelector('#flow-status')?.textContent
      === 'Replay refused (401). The token was one-use.'
      && document.querySelector('#step-replay')?.dataset.state === 'complete'
      && document.querySelector('#replay-button')?.disabled === true`, 'replay', 15_000);
    console.log('browser demo replay: 401');
    await Promise.all([...setups]);
    // Allow asynchronous CSP/Log events triggered by the last response to arrive.
    await delay(250);
    check(!setupFailed && powWorkerCount > 0, 'real PoW worker not observed');
    check(consoleErrors === 0, 'browser console/exception errors observed');
    check(cspErrors === 0 && await evaluate('__freebirdE2E.cspViolations === 0'),
      'browser CSP/security violations observed');
    check(networkErrors.every(entry => entry.url === protectedURL && entry.expected401),
      'unexpected browser resource errors');

    const documentResponse = responses.find(response => response.url === `${origin}/`);
    check(documentResponse?.status === 200 && documentResponse.tls, 'TLS document not observed');
    const headers = documentResponse.headers;
    const csp = headers['content-security-policy'] ?? '';
    check(csp.includes("default-src 'none'") && csp.includes("script-src 'self'")
      && csp.includes("style-src 'self'") && csp.includes("worker-src 'self'")
      && csp.includes(`connect-src 'self' ${issuer};`)
      && !/unsafe-inline|unsafe-eval|wasm-unsafe-eval|blob:|data:/.test(csp),
    'strict document CSP missing');
    check(headers['x-content-type-options'] === 'nosniff'
      && headers['referrer-policy'] === 'no-referrer', 'document security headers missing');
    console.log('browser demo console/CSP: passed');

    check(outsideRequests === 0, 'request outside Issuer/Origin boundary observed');
    for (const [url, method, stage] of [
      [`${issuer}/.well-known/private-token-issuer-directory`, 'GET', 'directory'],
      [`${issuer}/freebird/pow/challenge`, 'GET', 'challenge'],
      [`${issuer}/freebird/pow/admission`, 'POST', 'admission'],
      [`${issuer}/private-token/issue`, 'POST', 'issuance'],
    ]) {
      check(responses.some(response => response.url === url && response.method === method
        && response.status === 200), `required browser protocol request missing: ${stage}`);
    }
    const redemptions = responses.filter(response => response.url === protectedURL
      && response.method === 'GET').map(response => response.status);
    check(JSON.stringify(redemptions) === '[401,200,401]', 'redemption/replay statuses differ');
    console.log('browser demo network boundary: passed');
  } finally {
    for (const command of pending.values()) clearTimeout(command.timer);
    socket.close();
  }
}

if (!process.env.NODE_TEST_CONTEXT) {
  main(...process.argv.slice(2)).catch(error => {
    // Never dump upstream exception messages, URLs, console arguments, or CDP data.
    console.error(`browser demo CDP: failed; ${error instanceof CheckFailure
      ? error.message : 'browser/driver operation failed (diagnostics suppressed)'}`);
    process.exitCode = 1;
  });
}
