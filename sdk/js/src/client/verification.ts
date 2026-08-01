// SPDX-License-Identifier: Apache-2.0 OR MIT

import type { FreebirdToken } from '../types.js';
import type { ClientState } from './state.js';

export async function verifyToken(state: ClientState, token: FreebirdToken): Promise<boolean> {
  if (!state.config.verifierUrl) throw new Error('Verifier URL not configured');
  const res = await fetch(`${state.config.verifierUrl}/v1/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token_b64: token.tokenValue }),
  });
  if (!res.ok) return false;
  const body = await res.json();
  return body.ok === true;
}
