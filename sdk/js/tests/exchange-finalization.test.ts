// SPDX-License-Identifier: Apache-2.0 OR MIT

import { RSABSSA } from '@cloudflare/blindrsa-ts';
import { sha256 } from '@noble/hashes/sha256';
import { describe, expect, it } from 'vitest';
import { crypto as sdkCrypto } from '../src/index.js';
import { finalizeExchange, prepareExchange } from '../src/client/protocol.js';
import type {
  ExchangeOutcome,
  ExchangeRequestSource,
  ExchangeResultOutput,
} from '../src/index.js';
import type {
  ExchangeDescriptorInfo,
  ExchangeGraphInfo,
  ExchangeTransitionInfo,
} from '../src/types.js';

const b64 = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ascii = (value: string): Uint8Array => new TextEncoder().encode(value);
const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
const fromB64 = (value: string): Uint8Array => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')),
    (character) => character.charCodeAt(0));
};

interface SigningKey {
  pair: CryptoKeyPair;
  descriptor: ExchangeDescriptorInfo;
}

interface Fixture {
  graph: ExchangeGraphInfo;
  transition: ExchangeTransitionInfo;
  source: ExchangeRequestSource;
  keys: SigningKey[];
}

async function signingKey(descriptorId: string, issuerId: string): Promise<SigningKey> {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384' },
    true,
    ['sign', 'verify'],
  );
  const standard = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const raw = standard.slice(24);
  const spki = new Uint8Array([
    0x30, 0x82, 0, 0, 0x30, 61, 0x06, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    1, 1, 0x0a, 0x30, 48, 0xa0, 13, 0x30, 11, 0x06, 9, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0xa1, 26, 0x30, 24, 0x06, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1,
    8, 0x30, 11, 0x06, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa2, 3, 0x02, 1, 0,
    0x03, 0x82, 0, 0, 0,
  ]);
  const writeU16 = (offset: number, value: number): void => {
    spki[offset] = value >>> 8;
    spki[offset + 1] = value & 255;
  };
  writeU16(2, spki.length - 4 + raw.length);
  writeU16(69, 1 + raw.length);
  spki[66] = 48;
  const sha384Oid = [0x30, 11, 0x06, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2];
  spki.set(sha384Oid, 21);
  spki.set(sha384Oid, 49);
  const fullSpki = new Uint8Array(spki.length + raw.length);
  fullSpki.set(spki);
  fullSpki.set(raw, spki.length);

  return {
    pair,
    descriptor: {
      descriptor_id: descriptorId,
      profile_id: 'freebird/public-bearer-exchange/v2',
      issuer_id: issuerId,
      token_key_id: hex(sha256(fullSpki)),
      pubkey_spki_b64: b64(fullSpki),
      suite: 'RSABSSA-SHA384-PSS-Deterministic',
      valid_from: 1,
      valid_until: 4_000_000_000,
    },
  };
}

async function fixture(): Promise<Fixture> {
  const issuerId = 'issuer:exchange:test';
  const keys = await Promise.all([
    signingKey('1'.repeat(64), issuerId),
    signingKey('2'.repeat(64), issuerId),
  ]);
  const sourceDescriptor: ExchangeDescriptorInfo = {
    ...keys[0].descriptor,
    descriptor_id: 'a'.repeat(64),
  };
  const sourceKeysetId = 'b'.repeat(64);
  const targetKeysetId = 'c'.repeat(64);
  const graphId = 'd'.repeat(64);
  const transitionId = 'e'.repeat(64);
  const transition: ExchangeTransitionInfo = {
    transition_id: transitionId,
    source_keyset_id: sourceKeysetId,
    target_keyset_id: targetKeysetId,
    source_slots: [{ descriptor_id: sourceDescriptor.descriptor_id, slot_id: 'source', class: 'source', quantity: 1 }],
    output_slots: keys.map((key, index) => ({
      descriptor_id: key.descriptor.descriptor_id,
      slot_id: `output-${index}`,
      class: 'target',
      quantity: 1,
    })),
    budget_id: 'f'.repeat(64),
    budget_limit: 10,
    admission_state: 'accepting_new',
  };
  const graph: ExchangeGraphInfo = {
    profile_id: 'freebird/public-bearer-exchange/v2',
    graph_id: graphId,
    descriptors: [sourceDescriptor, ...keys.map((key) => key.descriptor)],
    keysets: [
      { keyset_id: sourceKeysetId, descriptor_ids: [sourceDescriptor.descriptor_id] },
      { keyset_id: targetKeysetId, descriptor_ids: keys.map((key) => key.descriptor.descriptor_id) },
    ],
    transitions: [transition],
  };
  return {
    graph,
    transition,
    source: {
      slot: {
        descriptor_id: sourceDescriptor.descriptor_id,
        keyset_id: sourceKeysetId,
        slot_id: 'source',
        quantity: 1,
      },
      artifact: b64(ascii('source artifact')),
    },
    keys,
  };
}

function committedOutcome(
  prepared: Awaited<ReturnType<typeof prepareExchange>>,
  outputs: ExchangeResultOutput[],
): ExchangeOutcome {
  const request = prepared.request;
  const digest = b64(new Uint8Array(32).fill(7));
  return {
    kind: 'committed',
    httpStatus: 200,
    rawResponseBody: '{}',
    cacheControl: 'no-store',
    response: {
      result: {
        version: 2,
        public_operation_id: request.public_operation_id,
        graph_id: request.graph_id,
        transition_id: request.transition_id,
        source_keyset_id: request.source_keyset_id,
        target_keyset_id: request.target_keyset_id,
        outputs,
        result_digest: digest,
      },
      receipt: {
        version: 2,
        public_operation_id: request.public_operation_id,
        graph_id: request.graph_id,
        transition_id: request.transition_id,
        source_keyset_id: request.source_keyset_id,
        target_keyset_id: request.target_keyset_id,
        result_digest: digest,
        created_at: 1,
        expires_at: 2,
        receipt_key_id: '8'.repeat(64),
        signature: b64(new Uint8Array(64)),
      },
    },
  };
}

describe('V2 exchange preparation and finalization', () => {
  it('prepares, signs, unblinds, and builds ordered public bearer passes', async () => {
    const testFixture = await fixture();
    const prepared = await prepareExchange(
      [testFixture.source],
      { graphId: testFixture.graph.graph_id, transitionId: testFixture.transition.transition_id },
      { nonces: [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)] },
      async () => ({ graph: testFixture.graph, transition: testFixture.transition }),
    );
    const suite = RSABSSA.SHA384.PSS.Deterministic();
    const outputs: ExchangeResultOutput[] = await Promise.all(prepared.outputs.map(async (output, index) => ({
      slot: output.slot,
      blinded_value: output.blindedValue,
      blind_signature: b64(await suite.blindSign(
        testFixture.keys[index].pair.privateKey,
        fromB64(output.blindedValue),
      )),
    })));

    const finalized = await finalizeExchange(prepared, committedOutcome(prepared, outputs));
    expect(finalized).toHaveLength(2);
    finalized.forEach((output, index) => {
      expect(output.slot).toEqual(prepared.request.outputs[index].slot);
      expect(output.nonce).toEqual(new Uint8Array(32).fill(index + 1));
      expect(sdkCrypto.parsePublicBearerPass(output.pass)).toMatchObject({
        nonce: new Uint8Array(32).fill(index + 1),
        issuerId: 'issuer:exchange:test',
      });
    });
  });

  it('rejects reordered, mismatched, and tampered committed outputs', async () => {
    const testFixture = await fixture();
    const prepared = await prepareExchange(
      [testFixture.source],
      { graphId: testFixture.graph.graph_id, transitionId: testFixture.transition.transition_id },
      { nonces: [new Uint8Array(32).fill(3), new Uint8Array(32).fill(4)] },
      async () => ({ graph: testFixture.graph, transition: testFixture.transition }),
    );
    const suite = RSABSSA.SHA384.PSS.Deterministic();
    const outputs: ExchangeResultOutput[] = await Promise.all(prepared.outputs.map(async (output, index) => ({
      slot: output.slot,
      blinded_value: output.blindedValue,
      blind_signature: b64(await suite.blindSign(
        testFixture.keys[index].pair.privateKey,
        fromB64(output.blindedValue),
      )),
    })));

    const reordered = committedOutcome(prepared, [outputs[1], outputs[0]]);
    await expect(finalizeExchange(prepared, reordered)).rejects.toThrow('do not match');

    const mismatched = committedOutcome(prepared, outputs.map((output) => ({ ...output })));
    (mismatched as Extract<ExchangeOutcome, { kind: 'committed' }>).response.result.outputs[0].blinded_value =
      b64(new Uint8Array(256).fill(9));
    await expect(finalizeExchange(prepared, mismatched)).rejects.toThrow('do not match');

    const tampered = committedOutcome(prepared, outputs.map((output) => ({ ...output })));
    const signature = fromB64(outputs[0].blind_signature);
    signature[signature.length - 1] ^= 1;
    (tampered as Extract<ExchangeOutcome, { kind: 'committed' }>).response.result.outputs[0].blind_signature =
      b64(signature);
    await expect(finalizeExchange(prepared, tampered)).rejects.toThrow();
  });
});
