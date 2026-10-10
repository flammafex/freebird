// SPDX-License-Identifier: Apache-2.0 OR MIT

import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { materializeV7Registry, parseV7KeyDiscovery } from '../src/client/v7_discovery.js';

const directory = process.env.FREEBIRD_GATE0_DIRECTORY;
const fixtureTest = directory === undefined ? it.skip : it;
const MAX_MANIFEST_BYTES = 4_000_000;
const GRAPH_PROFILE = 'freebird/native-graph-issuance/v7';

async function assertNoSymlinkPath(absolutePath: string): Promise<void> {
  const parsed = path.parse(absolutePath);
  let current = parsed.root;
  for (const component of absolutePath.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error('Gate 0 fixture path contains a symlink');
  }
}

function rejectDuplicateMembers(text: string): void {
  let offset = 0;
  const whitespace = (): void => { while (/\s/.test(text[offset] ?? '')) offset += 1; };
  const string = (): string => {
    const start = offset++;
    while (offset < text.length) {
      if (text[offset] === '\\') { offset += 2; continue; }
      if (text[offset++] === '"') return JSON.parse(text.slice(start, offset)) as string;
    }
    throw new Error('Gate 0 public manifest contains malformed JSON');
  };
  const value = (): void => {
    whitespace();
    if (text[offset] === '{') {
      offset += 1;
      whitespace();
      const keys = new Set<string>();
      if (text[offset] === '}') { offset += 1; return; }
      while (true) {
        whitespace();
        if (text[offset] !== '"') throw new Error('Gate 0 public manifest contains malformed JSON');
        const key = string();
        if (keys.has(key)) throw new Error('Gate 0 public manifest contains duplicate JSON members');
        keys.add(key);
        whitespace();
        if (text[offset++] !== ':') throw new Error('Gate 0 public manifest contains malformed JSON');
        value();
        whitespace();
        const separator = text[offset++];
        if (separator === '}') return;
        if (separator !== ',') throw new Error('Gate 0 public manifest contains malformed JSON');
      }
    }
    if (text[offset] === '[') {
      offset += 1;
      whitespace();
      if (text[offset] === ']') { offset += 1; return; }
      while (true) {
        value();
        whitespace();
        const separator = text[offset++];
        if (separator === ']') return;
        if (separator !== ',') throw new Error('Gate 0 public manifest contains malformed JSON');
      }
    }
    if (text[offset] === '"') { string(); return; }
    const primitive = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(offset));
    if (!primitive) throw new Error('Gate 0 public manifest contains malformed JSON');
    offset += primitive[0].length;
  };
  value();
  whitespace();
  if (offset !== text.length) throw new Error('Gate 0 public manifest contains malformed JSON');
}

async function readPublicManifest(rootValue: string): Promise<Record<string, unknown>> {
  if (!path.isAbsolute(rootValue) || rootValue.includes('\0')) {
    throw new Error('FREEBIRD_GATE0_DIRECTORY must name an absolute private fixture root');
  }
  const root = path.normalize(rootValue);
  await assertNoSymlinkPath(root);
  const rootInfo = await lstat(root);
  if (!rootInfo.isDirectory() || (rootInfo.mode & 0o777) !== 0o700 || await realpath(root) !== root) {
    throw new Error('Gate 0 fixture root must be a nonsymlink mode-0700 directory');
  }

  const manifestPath = path.join(root, 'manifest.json');
  await assertNoSymlinkPath(manifestPath);
  const file = await open(manifestPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await file.stat();
    if (!info.isFile() || (info.mode & 0o777) !== 0o600 || info.size < 1 || info.size > MAX_MANIFEST_BYTES) {
      throw new Error('Gate 0 public manifest has invalid file type, permissions, or size');
    }
    const bytes = await file.readFile();
    if (bytes.length !== info.size || bytes.length > MAX_MANIFEST_BYTES) {
      throw new Error('Gate 0 public manifest changed or exceeded its size limit');
    }
    let decoded: unknown;
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      rejectDuplicateMembers(text);
      decoded = JSON.parse(text);
    } catch {
      throw new Error('Gate 0 public manifest is not valid UTF-8 JSON');
    }
    if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
      throw new Error('Gate 0 public manifest must be a JSON object');
    }
    return decoded as Record<string, unknown>;
  } finally {
    await file.close();
  }
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Gate 0 public manifest has an invalid required projection');
  }
  return value as Record<string, unknown>;
}

function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error('Gate 0 public manifest has an invalid required list');
  return value;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || expected.some((key) => !Object.hasOwn(value, key))) {
    throw new Error('Gate 0 public manifest has an unsupported closed-object layout');
  }
}

describe('G0.2 private fixture SDK adapter', () => {
  fixtureTest('accepts the public manifest through strict V7 discovery and registry materialization', async () => {
    const manifest = await readPublicManifest(directory!);
    exactKeys(manifest, [
      'version', 'run_id', 'issuer_origin', 'verifier_origin', 'issuer_id', 'graph_issuer_id',
      'asset_id', 'graph_policy_id', 'v4', 'replay_authority', 'receipt_keyset', 'discovery_pins', 'sybil',
    ]);
    if (manifest.version !== 'scarcity/freebird-gate0/v1' || manifest.graph_issuer_id !== manifest.issuer_id) {
      throw new Error('Gate 0 public manifest version or issuer identity is invalid');
    }
    const v4 = object(manifest.v4);
    const pins = object(manifest.discovery_pins);
    exactKeys(v4, ['credential_issuer_id', 'kid', 'public_key_b64', 'verifier_id', 'audience', 'scope_digest_b64']);
    exactKeys(pins, [
      'native_bearer_v7', 'native_bearer_v7_retained', 'native_exchange_v7', 'native_graph_issuance_v7',
    ]);
    if (v4.credential_issuer_id !== manifest.issuer_id) {
      throw new Error('Gate 0 V4 issuer does not match the public issuer pin');
    }
    const graphPins = object(pins.native_graph_issuance_v7);
    const activePolicies = array(graphPins.active_policies).map(object);
    const selectedPolicyId = manifest.graph_policy_id;
    const policy = activePolicies.find((candidate) => candidate.policy_id === selectedPolicyId);
    if (!policy || policy.profile_id !== GRAPH_PROFILE || policy.issuer_id !== manifest.issuer_id ||
      policy.asset_id !== manifest.asset_id) {
      throw new Error('Pinned graph policy is absent from the active public graph policy set');
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof policy.valid_from !== 'number' || !Number.isSafeInteger(policy.valid_from) ||
      typeof policy.valid_until !== 'number' || !Number.isSafeInteger(policy.valid_until) ||
      policy.valid_from > now || policy.valid_until < now) {
      throw new Error('Pinned active graph policy is not currently fresh');
    }

    const currentEpoch = Math.max(1, Math.floor(now / 86_400));
    const discoveryEnvelope = {
      issuer_id: manifest.issuer_id,
      current_epoch: currentEpoch,
      valid_epochs: [currentEpoch],
      epoch_duration_sec: 86_400,
      voprf: {
        suite: 'VOPRF-P256-SHA256',
        kid: v4.kid,
        pubkey: v4.public_key_b64,
      },
      ...pins,
    };

    let parsed;
    try {
      parsed = await parseV7KeyDiscovery(JSON.stringify(discoveryEnvelope));
    } catch {
      throw new Error('Strict Freebird SDK rejected the public Gate 0 discovery pins');
    }
    const registry = await materializeV7Registry(parsed);
    const directPins = [pins.native_bearer_v7, ...array(pins.native_bearer_v7_retained)];
    const exchange = object(pins.native_exchange_v7);
    const activeDescriptors = array(exchange.active_descriptors);
    const retainedDescriptors = array(exchange.retained_descriptors);
    const exchangePins = [...activeDescriptors, ...retainedDescriptors].map(object);
    const graphPolicy = parsed.native_graph_issuance_v7!.active_policies.find(
      (candidate) => candidate.policy_id === selectedPolicyId,
    )!;
    const exchangeEntry = registry.by_token_key_id.get(graphPolicy.token_key_id);
    const directCount = registry.entries.filter((entry) => entry.roles.includes('direct')).length;
    const exchangeCount = registry.entries.filter((entry) => entry.roles.includes('exchange')).length;
    const graphOnlyEntries = registry.entries.filter((entry) =>
      entry.roles.includes('graph_issuance') && !entry.roles.includes('exchange'));

    expect(parsed.issuer_id).toBe(manifest.issuer_id);
    expect(directCount).toBe(directPins.length);
    expect(exchangeCount).toBe(exchangePins.length);
    expect(registry.entries).toHaveLength(directPins.length + exchangePins.length);
    expect(graphOnlyEntries).toHaveLength(0);
    expect(exchangeEntry?.roles).toContain('exchange');
    expect(exchangeEntry?.roles).toContain('graph_issuance');
    expect(exchangeEntry?.references.some((reference) =>
      reference.role === 'graph_issuance' && reference.policy_id === selectedPolicyId)).toBe(true);
  });
});
