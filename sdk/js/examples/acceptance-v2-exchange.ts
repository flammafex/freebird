// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Acceptance example — V2 exchange → status.
//
// This demonstrates the "zero bespoke protocol code" bar for the V2 flow: a
// consumer assembles a valid exchange request, submits it, and polls to a
// terminal outcome using ONLY the SDK's high-level methods. No hand-rolled
// request assembly, blinding, digest, or retry/poll logic.
//
// PREREQUISITES: a running issuer (127.0.0.1:8081) and verifier
// (127.0.0.1:8082) that publish V2 exchange discovery, plus a source artifact
// (a V5 public bearer pass) to exchange. This example is intentionally NOT a
// unit test: it requires live services.
//
// Run:  npx tsx examples/acceptance-v2-exchange.ts
//   or:  npm run build && node dist/examples/acceptance-v2-exchange.js

import { FreebirdClient } from '../src/index.js';
import type { ExchangeRequestSource } from '../src/index.js';

const ISSUER_URL = 'http://127.0.0.1:8081';
const VERIFIER_URL = 'http://127.0.0.1:8082';

async function main(): Promise<void> {
  const client = new FreebirdClient({ issuerUrl: ISSUER_URL, verifierUrl: VERIFIER_URL });

  // 1. Resolve the active exchange graph/transition from discovery.
  const metadata = await client.getKeyDiscoveryMetadata();
  const exchange = metadata.exchange;
  if (!exchange) throw new Error('issuer publishes no V2 exchange discovery');
  const graph = exchange.active_graph;
  const transition = graph.transitions[0];
  const sourceSlot = transition.source_slots[0];

  // 2. Provide one source artifact per source slot. In a real consumer this is
  //    a previously-issued V5 public bearer pass (base64url) matching the
  //    source descriptor.
  const sources: ExchangeRequestSource[] = transition.source_slots.map((slot) => ({
    slot: {
      descriptor_id: slot.descriptor_id,
      keyset_id: transition.source_keyset_id,
      slot_id: slot.slot_id,
      quantity: slot.quantity,
    },
    artifact: 'BASE64URL_OF_A_V5_PUBLIC_BEARER_PASS',
  }));

  // 3. Assemble a valid ExchangeRequest. `exchangePasses` fills the operation
  //    id, graph/transition ids, keyset ids, sources, and blinded outputs.
  const request = await client.exchangePasses(sources, {
    graphId: graph.graph_id,
    transitionId: transition.transition_id,
  });
  console.log('assembled exchange request for graph', request.graph_id);

  // 4. Generate a status capability and submit the exchange.
  const statusCapability = client.generateStatusCapability();
  const outcome = await client.exchange(request, statusCapability);
  console.log('exchange outcome:', outcome.kind);

  // 5. Poll until the operation reaches a terminal outcome. `pollExchangeStatus`
  //    retries with backoff, honoring the server's retryAfter as the floor.
  const finalOutcome = await client.pollExchangeStatus(request, statusCapability, {
    intervalMs: 500,
    timeoutMs: 30_000,
  });
  console.log('final exchange outcome:', finalOutcome.kind);
}

main().catch((err) => {
  console.error('V2 exchange acceptance flow failed:', err);
  process.exitCode = 1;
});
