// Use these helpers to check demo settings and format status messages.
// `main.mjs` imports the protocol steps from `packages/freebird-client` so that the demo uses
// the same checks as other clients.

export function issuerBaseURL(value) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('Set the freebird-issuer meta tag to the Issuer HTTPS origin.');
  }
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search
      || url.hash || url.pathname !== '/') {
    throw new Error('The Issuer must be an HTTPS origin without a path or credentials.');
  }
  return url;
}

export function statusMessage(stage, status) {
  if (status === 403 && stage === 'Admission') {
    return 'Admission refused (403): the proof is invalid, expired or already used. Start again.';
  }
  if (status === 403) return `${stage} refused (403): the admission is invalid, expired or used. Start again.`;
  if (status === 422) return `${stage} refused (422): the Issuer key changed or does not match. Start again.`;
  if (status === 429) return `${stage} busy (429). Wait a moment, then start again.`;
  if (status === 401) return `${stage} refused (401): the token is invalid, expired or already spent. Start again.`;
  return `${stage} failed (HTTP ${status}). Start again.`;
}
