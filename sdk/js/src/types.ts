/**
 * Configuration for the Freebird client
 */
export interface ClientConfig {
  /** The base URL of the issuer (e.g. "https://issuer.example.com") */
  issuerUrl: string;
  /** The base URL of the verifier (e.g. "https://verifier.example.com") */
  verifierUrl?: string;
  /** Optional verifier scope override when verifierUrl is unavailable. */
  verifierId?: string;
  /** Optional audience override when verifierUrl is unavailable. */
  audience?: string;
  /**
   * Optional TTL (ms) for the cached `/.well-known/keys` discovery metadata.
   *
   * When unset, the TTL is derived from the metadata's `epoch_duration_sec`
   * (i.e. the cache expires when the current epoch advances). Set this to
    * override the epoch-derived TTL, e.g. to observe key rotation more
   * aggressively than once per epoch.
   */
  keyCacheTtlMs?: number;
  /**
   * Optional persistent store for issued tokens.
   *
   * When provided, consumers can persist and reload tokens across sessions
   * without hand-rolling storage. See {@link TokenStore} and the
   * `MemoryTokenStore`/`StorageTokenStore` implementations.
   */
  tokenStore?: TokenStore;
  /**
   * Optional Proof-of-Work difficulty (leading zero bits) to mine when the
   * issuer requires PoW Sybil resistance.
   *
   * When unset, PoW is disabled unless the issuer publishes a PoW requirement
   * in `/.well-known/issuer` (the `sybil` field), which takes precedence over
   * this config. The issuance methods mine a request-bound `proof_of_work`
   * proof automatically when PoW is required.
   */
  powDifficulty?: number;
  /**
   * Optional custom `fetch` implementation used for all outbound HTTP.
   *
   * When provided, every request the client makes (discovery, issuance,
    * verification) is routed through this function
   * instead of the global `fetch`. This lets consumers route traffic through a
   * proxy (e.g. Tor/SOCKS5) for network-level privacy. Defaults to the global
   * `fetch` when unset.
   */
  fetch?: typeof fetch;
  /**
   * Maximum UTF-8 JSON body size for V4 batch issuance requests.
   *
   * The default is 60 KiB. The value may be lowered but not raised above the
   * SDK ceiling. Requests are greedily split before the existing 10,000-item
   * protocol ceiling is reached when necessary.
   */
  batchBodyLimitBytes?: number;
}

/**
 * Represents the .well-known/issuer metadata
 */
export interface IssuerMetadata {
  issuer_id: string;
  voprf: {
    suite: string;
    kid: string;
    pubkey: string; // Base64url encoded SEC1 compressed point
  };
  /**
   * Issuer-published Sybil resistance requirements. Absent on issuers that do
   * not publish them. Mirrors `SybilConfigSummary` in
   * `issuer/src/routes/admin/types.rs`.
   */
  sybil?: SybilConfigSummary;
}

/**
 * Issuer-published Sybil resistance requirements (sanitized — no secrets).
 * Mirrors `SybilConfigSummary` in `issuer/src/routes/admin/types.rs`.
 */
export interface SybilConfigSummary {
  /** Current Sybil resistance mode (e.g. `"pow"`, `"proof_of_work"`, `"none"`). */
  mode: string;
  /** Human-readable description of the mode. */
  mode_description: string;
  /** Mode-specific settings (untagged; shape depends on `mode`). */
  settings: SybilModeSettings;
  /** Combined-mode mechanisms (only when `mode` is `"combined"`). */
  combined_mechanisms?: string[] | null;
  /** Combined-mode type (only when `mode` is `"combined"`). */
  combined_mode_type?: string | null;
  /** Combined threshold (only for `"combined"` + `"threshold"`). */
  combined_threshold?: number | null;
}

/**
 * Mode-specific Sybil settings. The wire shape is untagged and depends on
 * `SybilConfigSummary.mode`; the SDK only reads `difficulty` for PoW.
 */
export type SybilModeSettings =
  | { difficulty: number }
  | { interval: string; interval_secs: number }
  | {
      invites_per_user: number;
      cooldown: string;
      cooldown_secs: number;
      expires: string;
      expires_secs: number;
      new_user_wait: string;
      new_user_wait_secs: number;
      persistence_path: string;
      bootstrap_users_configured: boolean;
    }
  | { levels: TrustLevelSummary[]; persistence_path: string }
  | { min_score: number; persistence_path: string }
  | {
      required_vouchers: number;
      cooldown: string;
      cooldown_secs: number;
      expires: string;
      expires_secs: number;
      new_user_wait: string;
      new_user_wait_secs: number;
      persistence_path: string;
    }
  | { max_proof_age?: string | null; max_proof_age_secs?: number | null }
  | Record<string, never>;

/** Summary of a progressive-trust level. Mirrors `TrustLevelSummary`. */
export interface TrustLevelSummary {
  min_age: string;
  min_age_secs: number;
  max_tokens: number;
  cooldown: string;
  cooldown_secs: number;
}

export interface KeyDiscoveryMetadata {
  issuer_id: string;
  current_epoch: number;
  valid_epochs: number[];
  epoch_duration_sec: number;
  voprf: {
    suite: string;
    kid: string;
    pubkey: string;
  };
}

/**
 * Represents the .well-known/verifier metadata
 */
export interface VerifierMetadata {
  verifier_id: string;
  audience: string;
  scope_digest_b64: string;
}

/**
 * A single vouch proof for Multi-Party Vouching
 */
export interface VouchProof {
  voucher_id: string;
  vouchee_id: string;
  timestamp: number;
  signature: string;
  voucher_pubkey_b64: string;
}

/**
 * Supported Sybil resistance proof types.
 * Mirrors the enum in `common/src/api.rs`
 */
export type SybilProof =
  | {
      type: 'proof_of_work';
      nonce: number;
      input: string;
      timestamp: number;
    }
  | {
      type: 'rate_limit';
      client_id: string;
      timestamp: number;
    }
  | {
      type: 'invitation';
      code: string;
      signature: string;
    }
  | {
      type: 'registered_user';
      user_id: string;
    }
  | {
      type: 'web_authn';
      subject_hash: string;
      auth_proof: string;
      timestamp: number;
    }
  | {
      type: 'progressive_trust';
      user_id_hash: string;
      first_seen: number;
      tokens_issued: number;
      last_issuance: number;
      hmac_proof: string;
    }
  | {
      type: 'proof_of_diversity';
      user_id_hash: string;
      diversity_score: number;
      unique_networks: number;
      unique_devices: number;
      first_seen: number;
      hmac_proof: string;
    }
  | {
      type: 'multi_party_vouching';
      vouchee_id_hash: string;
      vouches: VouchProof[];
      hmac_proof: string;
      timestamp: number;
    }
  | {
      type: 'social_graph';
      /** Complete cred.presentation artifact encoded as a JSON string. */
      attestation: string;
      /** The presentation_signature field encoded as a hexadecimal string. */
      presentation: string;
    }
  | {
      type: 'multi';
      proofs: SybilProof[];
    }
  | { type: 'none' };

/**
 * Exact binding for one issuance request passed to a Sybil proof factory.
 *
 * A factory is called separately for each request binding; proofs must not be
 * reused across different bindings.
 */
export interface SybilProofRequestContext {
  binding: string;
}

/** Creates one request-bound Sybil proof for an issuance request. */
export type SybilProofFactory = (
  context: SybilProofRequestContext,
) => SybilProof | Promise<SybilProof>;

/**
 * Request to issue a token (Client -> Issuer)
 */
export interface IssueRequest {
  /** Base64url encoded blinded element */
  blinded_element_b64: string;
  /** Optional context string (unused in v1) */
  ctx_b64?: string;
  /** Sybil resistance proof if required */
  sybil_proof?: SybilProof;
}

/**
 * Response from token issuance (Issuer -> Client)
 */
export interface IssueResponse {
  /** Base64url encoded VOPRF evaluation [VERSION|A|B|DLEQ_proof] (131 bytes) */
  token: string;
  /** Key ID used for issuance */
  kid: string;
  /** Issuer identifier */
  issuer_id: string;
  /** Sybil verification details (optional) */
  sybil_info?: {
    required: boolean;
    passed: boolean;
    cost: number;
  };
}

/**
 * Exact JSON body accepted by POST /v1/oprf/issue/batch.
 * Mirrors `BatchIssueReq` in `common/src/api/issuance.rs`.
 */
export interface BatchIssueReq {
  /** Base64url-encoded blinded VOPRF elements. */
  blinded_elements: string[];
  /** Optional context string (unused in v1). */
  ctx_b64?: string;
  /** Sybil resistance proof if required. */
  sybil_proof?: SybilProof;
}

/**
 * Per-token outcome of a V4 batch issuance. Mirrors the `TokenResult` enum in
 * `common/src/api/issuance.rs`, tagged on `status` with lowercase variant names.
 */
export type TokenResult =
  | { status: 'success'; token: string; kid: string; issuer_id: string }
  | { status: 'error'; message: string; code: string };

/**
 * Exact JSON body returned by POST /v1/oprf/issue/batch.
 * Mirrors `BatchIssueResp` in `common/src/api/issuance.rs`.
 */
export interface BatchIssueResp {
  results: TokenResult[];
  successful: number;
  failed: number;
  processing_time_ms: number;
  throughput: number;
  sybil_info?: {
    required: boolean;
    passed: boolean;
    cost: number;
  };
}

type SybilProofSelection =
  | { sybilProof?: never; proofFactory?: never }
  | { sybilProof: SybilProof; proofFactory?: never }
  | { sybilProof?: never; proofFactory: SybilProofFactory };

/** Options for {@link FreebirdClient.issueTokens}. */
export type IssueTokensOptions = SybilProofSelection & {
  /** Optional context string (unused in v1). */
  ctxB64?: string;
};

/**
 * Internal state maintained between blinding and unblinding.
 * This must be kept secure on the client.
 */
export interface BlindState {
  /** The random scalar 'r' used for blinding */
  r: bigint; // or Uint8Array depending on implementation preference
  /** The original hashed point H(input) */
  p: any; // Will be a Point from @noble/curves
}

/**
 * A complete, unblinded token ready for use.
 */
export interface FreebirdToken {
  /** Base64url-encoded redemption token */
  tokenValue: string;
  /** The Issuer ID this token belongs to (extracted for convenience) */
  issuerId: string;
  /** Token wire version */
  version?: 4 | 7;
  /** V4 key ID used for issuance */
  kid?: string;
  /** V7 native bearer token key ID */
  tokenKeyId?: string;
  /**
   * Unix timestamp (seconds) at which the token expires. Token stores use this to evict expired
   * tokens on `load`/`list`. Absent for tokens without a known expiry.
   */
  valid_until?: number;
}

/**
 * A persistent store for issued tokens.
 *
 * Implementations must evict expired tokens (those whose `valid_until` has
 * passed) on `load` and `list`. Tokens are keyed by their `tokenValue`.
 */
export interface TokenStore {
  /** Persists a token, replacing any existing token with the same id. */
  save(token: FreebirdToken): Promise<void>;
  /**
   * Loads a token by id (its `tokenValue`). When `id` is omitted, returns the
   * most recently saved token, or `null` if the store is empty.
   */
  load(id?: string): Promise<FreebirdToken | null>;
  /** Lists all non-expired tokens. */
  list(): Promise<FreebirdToken[]>;
  /** Removes all tokens from the store. */
  clear(): Promise<void>;
}

/**
 * Exact JSON body accepted by POST /v1/verify and POST /v1/check.
 * Mirrors `VerifyReq` in `common/src/api/verification.rs`.
 */
export interface VerifyReq {
  /** Base64url-encoded redemption token. */
  token_b64: string;
}

/**
 * Exact JSON body returned by POST /v1/verify and POST /v1/check.
 * Mirrors `VerifyResp` in `common/src/api/verification.rs`.
 */
export interface VerifyResp {
  ok: boolean;
  /** Present only on error responses. */
  error?: string | null;
  /** Unix timestamp (seconds) at which the token was verified. */
  verified_at: number;
}

/** One token in a batch verification request. Mirrors `TokenToVerify`. */
export interface TokenToVerify {
  token_b64: string;
}

/**
 * Exact JSON body accepted by POST /v1/verify/batch.
 * Mirrors `BatchVerifyReq` in `common/src/api/verification.rs`.
 */
export interface BatchVerifyReq {
  tokens: TokenToVerify[];
}

/**
 * Per-token outcome of a batch verification. Mirrors the `VerifyResult` enum
 * in `common/src/api/verification.rs`, which is tagged on `status` with
 * lowercase variant names. `code` is one of `verification_failed`,
 * `replay_detected`, or `store_error`.
 */
export type VerifyResult =
  | { status: 'success'; verified_at: number }
  | { status: 'error'; message: string; code: string };

/**
 * Exact JSON body returned by POST /v1/verify/batch.
 * Mirrors `BatchVerifyResp` in `common/src/api/verification.rs`.
 */
export interface BatchVerifyResp {
  results: VerifyResult[];
  successful: number;
  failed: number;
  processing_time_ms: number;
  throughput: number;
}

/** A nominal, lowercase hexadecimal V7 identifier (the encoded form of 32 bytes). */
export type V7CanonicalId = string & { readonly __freebirdV7CanonicalId: unique symbol };
export type V7TokenKeyId = V7CanonicalId & { readonly __freebirdV7TokenKeyId: unique symbol };
export type V7DescriptorId = V7CanonicalId & { readonly __freebirdV7DescriptorId: unique symbol };
export type V7SpkiFingerprint = V7CanonicalId & { readonly __freebirdV7SpkiFingerprint: unique symbol };
export type V7GraphId = V7CanonicalId & { readonly __freebirdV7GraphId: unique symbol };
export type V7KeysetId = V7CanonicalId & { readonly __freebirdV7KeysetId: unique symbol };
export type V7TransitionId = V7CanonicalId & { readonly __freebirdV7TransitionId: unique symbol };
export type V7PolicyId = V7CanonicalId & { readonly __freebirdV7PolicyId: unique symbol };

/** A nominal V7 fixed-width byte string. Values are always exactly 32 bytes. */
export type V7Bytes32 = Uint8Array & { readonly __freebirdV7Bytes32: unique symbol };
export type V7OwnerCommitment = V7Bytes32 & { readonly __freebirdV7OwnerCommitment: unique symbol };
export type V7Nonce = V7Bytes32 & { readonly __freebirdV7Nonce: unique symbol };
export type V7Nullifier = V7Bytes32 & { readonly __freebirdV7Nullifier: unique symbol };
export type V7MessageRandomizer = V7Bytes32 & { readonly __freebirdV7MessageRandomizer: unique symbol };
/** A V7 amount in minor units. It is deliberately bigint, never a JS Number. */
export type V7Amount = bigint & { readonly __freebirdV7Amount: unique symbol };
/** A raw V7 RSA-3072 blind message or signature. */
export type V7Raw384 = Uint8Array & { readonly __freebirdV7Raw384: unique symbol };

/** Nominal V7 issuer/key identity. */
export interface V7KeyIdentity {
  readonly issuer_id: string;
  readonly token_key_id: V7TokenKeyId;
  readonly __freebirdV7KeyIdentity: true;
}

/** Nominal immutable V7 public-key binding retained by a registry. */
export interface V7KeyBinding {
  readonly identity: V7KeyIdentity;
  readonly token_key_id: V7TokenKeyId;
  readonly descriptor_id: V7DescriptorId;
  readonly spki_fingerprint: V7SpkiFingerprint;
  readonly pubkey_spki_b64: string;
  readonly __freebirdV7KeyBinding: true;
}

/** Canonical V7 body fields supplied to the native bearer protocol. */
export interface V7Body {
  readonly asset_id: string;
  readonly amount_minor: V7Amount;
  readonly identity: V7KeyIdentity;
  readonly nonce: V7Nonce;
  readonly nullifier: V7Nullifier;
  /** Callers must supply this exact 32-byte commitment; it is never derived. */
  readonly owner_commitment: V7OwnerCommitment;
  readonly __freebirdV7Body: true;
}

/** A complete nominal V7 bearer artifact. */
export interface V7Token {
  readonly body: V7Body;
  readonly message_randomizer: V7MessageRandomizer;
  readonly signature: V7Raw384;
  readonly __freebirdV7Token: true;
}

/** Opaque state retained between V7 blinding and finalization. */
export interface V7BlindState {
  readonly identity: V7KeyIdentity;
  readonly spki_fingerprint: V7SpkiFingerprint;
  readonly randomizer: V7MessageRandomizer;
  readonly __freebirdV7BlindState: true;
}

/** Validated direct V7 key material and fixed-body policy used by crypto primitives. */
export interface V7DirectBinding {
  readonly identity: V7KeyIdentity;
  readonly public_key_spki: Uint8Array;
  readonly spki_fingerprint: V7SpkiFingerprint;
  readonly asset_id: string;
  readonly amount_minor: V7Amount;
  readonly valid_from: bigint;
  readonly valid_until: bigint;
  readonly __freebirdV7DirectBinding: true;
}

export type V7RegistryRole = 'direct' | 'exchange' | 'graph_issuance';

export interface V7RegistryReference {
  readonly role: V7RegistryRole;
  readonly descriptor_id: V7DescriptorId;
  readonly policy_id?: V7PolicyId;
  readonly graph_id?: V7GraphId;
  readonly keyset_id?: V7KeysetId;
}

/** One immutable issuer-local V7 registry binding with merged role references. */
export interface V7RegistryEntry extends V7KeyBinding {
  readonly profile_id: string;
  readonly issuer_id: string;
  readonly asset_id: string;
  readonly amount_minor: V7Amount;
  readonly suite: string;
  readonly modulus_bits: 3072;
  readonly exponent: 65537;
  readonly valid_from: bigint;
  readonly valid_until: bigint;
  readonly roles: readonly V7RegistryRole[];
  readonly references: readonly V7RegistryReference[];
}

/** Atomically materialized direct, exchange, and graph V7 trust state. */
export interface V7Registry {
  readonly issuer_id: string;
  readonly entries: readonly V7RegistryEntry[];
  readonly by_token_key_id: ReadonlyMap<V7TokenKeyId, V7RegistryEntry>;
  readonly __freebirdV7Registry: true;
}

/** Direct-only V7 registry entry exposed to SDK consumers. */
export interface V7DirectRegistryEntry extends V7KeyBinding {
  readonly profile_id: 'scarcity/native-bearer/v7';
  readonly issuer_id: string;
  readonly asset_id: string;
  readonly amount_minor: V7Amount;
  readonly suite: string;
  readonly modulus_bits: 3072;
  readonly exponent: 65537;
  readonly valid_from: bigint;
  readonly valid_until: bigint;
}

/** Direct-only V7 registry DTO; non-direct references remain private. */
export interface V7DirectRegistry {
  readonly issuer_id: string;
  readonly entries: readonly V7DirectRegistryEntry[];
  readonly by_token_key_id: ReadonlyMap<V7TokenKeyId, V7DirectRegistryEntry>;
  readonly __freebirdV7DirectRegistry: true;
}

export interface V7VoprfKeyInfo {
  readonly suite: string;
  readonly kid: string;
  readonly pubkey: string;
}

export interface V7NativeBearerKeyInfo {
  readonly profile_id: string;
  readonly issuer_id: string;
  readonly descriptor_id: V7DescriptorId;
  readonly token_key_id: V7TokenKeyId;
  readonly asset_id: string;
  readonly amount_minor: V7Amount;
  readonly suite: string;
  readonly modulus_bits: 3072;
  readonly exponent: 65537;
  readonly pubkey_spki_b64: string;
  readonly spki_fingerprint: V7SpkiFingerprint;
  readonly valid_from: bigint;
  readonly valid_until: bigint;
}

export interface V7ExchangeProfile {
  readonly version: 3;
  readonly profile_id: 'freebird/native-exchange/v3';
  readonly graph_id: V7GraphId;
  readonly suite: 'RSABSSA-SHA384-PSS-Randomized-V7';
  readonly modulus_bits: 3072;
  readonly exponent: 65537;
}

export interface V7ExchangeDescriptor {
  readonly descriptor_id: V7DescriptorId;
  readonly profile_id: 'freebird/native-exchange/v3';
  readonly issuer_id: string;
  readonly token_key_id: V7TokenKeyId;
  readonly asset_id: string;
  readonly amount_minor: string;
  readonly suite: 'RSABSSA-SHA384-PSS-Randomized-V7';
  readonly modulus_bits: 3072;
  readonly exponent: 65537;
  readonly pubkey_spki_b64: string;
  readonly spki_fingerprint: V7SpkiFingerprint;
  readonly valid_from: bigint;
  readonly valid_until: bigint;
}

export interface V7ExchangeKeyset {
  readonly keyset_id: V7KeysetId;
  readonly profile_id: 'freebird/native-exchange/v3';
  readonly descriptor_ids: readonly V7DescriptorId[];
}

export interface V7ExchangeSlot {
  readonly descriptor_id: V7DescriptorId;
  readonly keyset_id: V7KeysetId;
  readonly slot_id: string;
  readonly quantity: 1;
}

export interface V7ExchangeTransition {
  readonly transition_id: V7TransitionId;
  readonly profile_id: 'freebird/native-exchange/v3';
  readonly source_keyset_id: V7KeysetId;
  readonly target_keyset_id: V7KeysetId;
  readonly source_slots: readonly V7ExchangeSlot[];
  readonly output_slots: readonly V7ExchangeSlot[];
}

export interface V7ExchangeDiscovery {
  readonly version: 3;
  readonly profile: V7ExchangeProfile;
  readonly active_descriptors: readonly V7ExchangeDescriptor[];
  readonly retained_descriptors: readonly V7ExchangeDescriptor[];
  readonly active_keysets: readonly V7ExchangeKeyset[];
  readonly retained_keysets: readonly V7ExchangeKeyset[];
  readonly transitions: readonly V7ExchangeTransition[];
}

export interface V7GraphIssuancePolicy {
  readonly policy_id: V7PolicyId;
  readonly profile_id: 'freebird/native-graph-issuance/v7';
  readonly graph_id: V7GraphId;
  readonly keyset_id: V7KeysetId;
  readonly descriptor_id: V7DescriptorId;
  readonly token_key_id: V7TokenKeyId;
  readonly issuer_id: string;
  readonly asset_id: string;
  readonly amount_minor: string;
  readonly suite: 'RSABSSA-SHA384-PSS-Randomized-V7';
  readonly modulus_bits: 3072;
  readonly exponent: 65537;
  readonly quantity: 1;
  readonly pubkey_spki_b64: string;
  readonly spki_fingerprint: V7SpkiFingerprint;
  readonly valid_from: bigint;
  readonly valid_until: bigint;
}

export interface V7GraphIssuanceDiscovery {
  readonly version: 7;
  readonly profile_id: 'freebird/native-graph-issuance/v7';
  readonly active_policies: readonly V7GraphIssuancePolicy[];
  readonly retained_policies: readonly V7GraphIssuancePolicy[];
}

/** Strict V7-only response returned by `GET /.well-known/keys`. */
export interface V7KeyDiscoveryResp {
  readonly issuer_id: string;
  readonly current_epoch: number;
  readonly valid_epochs: readonly number[];
  readonly epoch_duration_sec: bigint;
  readonly voprf: V7VoprfKeyInfo;
  readonly native_bearer_v7: V7NativeBearerKeyInfo;
  readonly native_bearer_v7_retained: readonly V7NativeBearerKeyInfo[];
  readonly native_exchange_v7?: V7ExchangeDiscovery;
  readonly native_graph_issuance_v7?: V7GraphIssuanceDiscovery;
}

/** Public direct-only projection of strict V7 key discovery. */
export interface V7DirectKeyDiscovery {
  readonly issuer_id: string;
  readonly current_epoch: number;
  readonly valid_epochs: readonly number[];
  readonly epoch_duration_sec: bigint;
  readonly voprf: V7VoprfKeyInfo;
  readonly native_bearer_v7: V7NativeBearerKeyInfo;
  readonly native_bearer_v7_retained: readonly V7NativeBearerKeyInfo[];
}
