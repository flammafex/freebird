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
   * override the epoch-derived TTL, e.g. to poll for key rotation more
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
  public?: {
    token_type: string;
    token_key_id: string;
    rfc9474_variant: string;
    modulus_bits: number;
    spend_policy: string;
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

export interface PublicKeyInfo {
  token_key_id: string;
  token_type: string;
  rfc9474_variant: string;
  modulus_bits: number;
  pubkey_spki_b64: string;
  issuer_id: string;
  valid_from: number;
  valid_until: number;
  audience?: string;
  spend_policy: string;
  max_uses?: number;
}

/** A source or output position in the immutable exchange rule. */
export interface ExchangeSlot {
  descriptor_id: string;
  keyset_id: string;
  slot_id: string;
  quantity: number;
}

export interface ExchangeRequestSource {
  slot: ExchangeSlot;
  /** Base64url-encoded V5 public bearer source artifact. */
  artifact: string;
}

export interface ExchangeRequestOutput {
  slot: ExchangeSlot;
  /** Base64url-encoded RFC 9474 blinded target message. */
  blinded_value: string;
}

/** Exact JSON body accepted by POST /v2/public/exchange. */
export interface ExchangeRequest {
  version: 2;
  /** Public, non-secret 16-byte operation identifier (canonical base64url). */
  public_operation_id: string;
  graph_id: string;
  transition_id: string;
  source_keyset_id: string;
  target_keyset_id: string;
  sources: ExchangeRequestSource[];
  outputs: ExchangeRequestOutput[];
}

export interface ExchangeResultOutput {
  slot: ExchangeSlot;
  blinded_value: string;
  /** Base64url-encoded RFC 9474 blind signature. */
  blind_signature: string;
}

export interface ExchangeResult {
  version: 2;
  public_operation_id: string;
  graph_id: string;
  transition_id: string;
  source_keyset_id: string;
  target_keyset_id: string;
  outputs: ExchangeResultOutput[];
  result_digest: string;
}

export interface ExchangeReceipt {
  version: 2;
  public_operation_id: string;
  graph_id: string;
  transition_id: string;
  source_keyset_id: string;
  target_keyset_id: string;
  result_digest: string;
  created_at: number;
  expires_at: number;
  receipt_key_id: string;
  signature: string;
}

/** Exact stored success JSON returned by POST and status lookup. */
export interface ExchangeSuccessResponse {
  result: ExchangeResult;
  receipt: ExchangeReceipt;
}

export interface ExchangeReceiptKeyInfo {
  key_id: string;
  algorithm: 'Ed25519';
  purpose: 'exchange_receipt_active' | 'exchange_receipt_retained';
  public_key_b64: string;
  valid_from: number;
  valid_until: number;
}

export interface ExchangeTargetKeysetInfo {
  keyset_id: string;
  /** Canonical ordered descriptor membership. */
  descriptor_ids: string[];
}

export interface ExchangeDescriptorInfo {
  descriptor_id: string;
  profile_id: string;
  issuer_id: string;
  token_key_id: string;
  pubkey_spki_b64: string;
  suite: string;
  valid_from: number;
  valid_until: number;
  audience?: string;
}

export interface ExchangeTransitionSlotInfo {
  descriptor_id: string;
  slot_id: string;
  class: string;
  quantity: number;
}

export type ExchangeAdmissionState = 'accepting_new' | 'recovery_only' | 'disabled';

export interface ExchangeTransitionInfo {
  transition_id: string;
  source_keyset_id: string;
  target_keyset_id: string;
  source_slots: ExchangeTransitionSlotInfo[];
  output_slots: ExchangeTransitionSlotInfo[];
  budget_id: string;
  budget_limit: number;
  admission_state: ExchangeAdmissionState;
}

export interface ExchangeGraphInfo {
  profile_id: 'freebird/public-bearer-exchange/v2';
  graph_id: string;
  descriptors: ExchangeDescriptorInfo[];
  keysets: ExchangeTargetKeysetInfo[];
  transitions: ExchangeTransitionInfo[];
}

/** All-or-nothing V2 exchange trust container from /.well-known/keys. */
export interface ExchangeDiscoveryMetadata {
  active_graph: ExchangeGraphInfo;
  retained_graphs: ExchangeGraphInfo[];
  active_receipt_key: ExchangeReceiptKeyInfo;
  retained_receipt_keys: ExchangeReceiptKeyInfo[];
}

export interface GraphIssuancePolicyInfo {
  issuance_policy_id: string;
  graph_id: string;
  keyset_id: string;
  descriptor_id: string;
  budget_id: string;
  budget_limit: number;
  quantity: number;
  admission_state: ExchangeAdmissionState;
  authorization_scheme: string;
  /** Published only for v4_local policies; binds the authorization namespace. */
  authorization_scope_digest_b64?: string;
}

export interface GraphIssuanceDiscoveryMetadata {
  version: 2;
  policies: GraphIssuancePolicyInfo[];
  replay_authority: GraphIssuanceReplayAuthorityDiscovery;
}

export interface GraphIssuanceReplayAuthorityDiscovery {
  authority_id: string;
  v4_scope_digest_tombstones: string[];
}

/** Exact V2 JSON body accepted by POST /v1/public/graph/issue. */
export interface GraphIssuanceRequest {
  version: 2;
  public_operation_id: string;
  issuance_policy_id: string;
  graph_id: string;
  keyset_id: string;
  descriptor_id: string;
  blinded_message: string;
  authorization: string;
}

export interface GraphIssuanceResult {
  version: 2;
  public_operation_id: string;
  issuance_policy_id: string;
  graph_id: string;
  keyset_id: string;
  descriptor_id: string;
  token_key_id: string;
  quantity: number;
  request_digest: string;
  blind_signature: string;
  result_digest: string;
}

/**
 * Exact persisted inputs needed to retry or observe an issuance operation.
 *
 * The nested request is retained verbatim, while the duplicated selectors and
 * digests make accidental recovery-context mutation detectable without
 * consulting issuer discovery. `blindingState` is intentionally opaque to the
 * SDK and is returned to the caller for finalization.
 */
export interface GraphIssuanceRecoveryContext {
  request: GraphIssuanceRequest;
  requestDigest: string;
  publicOperationId: string;
  issuancePolicyId: string;
  graphId: string;
  keysetId: string;
  descriptorId: string;
  statusCapability: string;
  /** The token key selected by the fresh issuance operation. */
  expectedTokenKeyId: string;
  /** Caller-owned RFC 9474 blinding state; the SDK never interprets it. */
  blindingState: unknown;
}

export type GraphIssuanceOutcome =
  | { kind: 'committed'; httpStatus: 200; response: GraphIssuanceResult; rawResponseBody: string; cacheControl: 'no-store' }
  | { kind: 'error'; httpStatus: 400 | 404 | 409 | 413 | 503; response: { error: string }; rawResponseBody: string; cacheControl: 'no-store' };

export interface ExchangeTransitionSelection {
  graph: ExchangeGraphInfo;
  transition: ExchangeTransitionInfo;
}

export type ExchangeErrorCode =
  | 'invalid_status_capability'
  | 'invalid_public_operation_id'
  | 'exchange_request_too_large'
  | 'exchange_unavailable'
  | 'invalid_exchange_request'
  | 'operation_conflict'
  | 'invalid_exchange'
  | 'unknown_operation'
  | 'status_unauthorized';

export interface ExchangePendingResponse {
  error: 'exchange_retryable';
}

export interface ExchangeErrorResponse {
  error: ExchangeErrorCode;
}

interface ExchangeHttpOutcome {
  /** The exact response text returned by the durable exchange record. */
  rawResponseBody: string;
  cacheControl: 'no-store';
}

export interface ExchangeCommittedOutcome extends ExchangeHttpOutcome {
  kind: 'committed';
  httpStatus: 200;
  response: ExchangeSuccessResponse;
}

export interface ExchangePendingOutcome extends ExchangeHttpOutcome {
  kind: 'pending';
  httpStatus: 202;
  response: ExchangePendingResponse;
  /** Retry-After delay in whole seconds. */
  retryAfter: number;
}

export type ExchangeErrorOutcome = ExchangeHttpOutcome &
  (
    | {
        kind: 'error';
        httpStatus: 400;
        response: {
          error:
            | 'invalid_status_capability'
            | 'invalid_public_operation_id'
            | 'invalid_exchange_request'
            | 'invalid_exchange';
        };
      }
    | {
        kind: 'error';
        httpStatus: 413;
        response: { error: 'exchange_request_too_large' };
      }
    | {
        kind: 'error';
        httpStatus: 404;
        response: { error: 'unknown_operation' };
      }
    | {
        kind: 'error';
        httpStatus: 409;
        response: { error: 'operation_conflict' };
      }
    | {
        kind: 'error';
        httpStatus: 503;
        response: { error: 'exchange_unavailable' };
      }
  );

export type ExchangeOutcome =
  | ExchangeCommittedOutcome
  | ExchangePendingOutcome
  | ExchangeErrorOutcome;

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
  public: PublicKeyInfo[];
  /** Absent on legacy issuers that do not publish exchange metadata. */
  exchange?: ExchangeDiscoveryMetadata;
  /** Absent unless policy-authorized graph initial issuance is configured. */
  graph_issuance?: GraphIssuanceDiscoveryMetadata;
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

export interface PublicIssueRequest {
  /** Base64url encoded RFC 9474 blinded message */
  blinded_msg_b64: string;
  /** Strict lowercase hex token key ID */
  token_key_id?: string;
  /** Sybil resistance proof if required */
  sybil_proof?: SybilProof;
}

export interface PublicIssueResponse {
  /** Base64url encoded RFC 9474 blind signature */
  blind_signature_b64: string;
  /** Strict lowercase hex token key ID */
  token_key_id: string;
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

/**
 * Exact JSON body accepted by POST /v1/public/issue/batch.
 * Mirrors `PublicBatchIssueReq` in `common/src/api/issuance.rs`.
 */
export interface PublicBatchIssueReq {
  /** Base64url-encoded RFC 9474 blinded messages. */
  blinded_msgs: string[];
  /** Strict lowercase hex token key ID. */
  token_key_id?: string;
  /** Sybil resistance proof if required. */
  sybil_proof?: SybilProof;
}

/**
 * Exact JSON body returned by POST /v1/public/issue/batch.
 * Mirrors `PublicBatchIssueResp` in `common/src/api/issuance.rs`.
 */
export interface PublicBatchIssueResp {
  /** Base64url-encoded RFC 9474 blind signatures, one per blinded message. */
  blind_signatures: string[];
  token_key_id: string;
  issuer_id: string;
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

/**
 * Options for {@link FreebirdClient.issueTokens}.
 */
export interface IssueTokensOptions {
  /** Sybil resistance proof if required. */
  sybilProof?: SybilProof;
  /** Optional context string (unused in v1). */
  ctxB64?: string;
}

/**
 * Options for {@link FreebirdClient.issuePublicTokens}.
 */
export interface IssuePublicTokensOptions {
  /** Strict lowercase hex token key ID of the signing key. */
  tokenKeyId?: string;
  /** Sybil resistance proof if required. */
  sybilProof?: SybilProof;
  /** Issuer identifier embedded in each pass. */
  issuerId: string;
  /** Per-token 32-byte nonces, one per message, embedded in each pass. */
  nonces: Uint8Array[];
}

/**
 * A V5 public bearer pass: the wire format produced by
 * `voprf.buildPublicBearerPass` (and parsed by `voprf.parsePublicBearerPass`).
 */
export type PublicBearerPass = Uint8Array;

/**
 * Opaque RFC 9474 blinding state held between blinding and unblinding.
 *
 * `inv` is the secret blinding inverse factor. It must never be persisted to
 * any store; `@cloudflare/blindrsa-ts` handles zeroization of key material.
 */
export interface RsaBlindState {
  /** Secret blinding inverse factor. Never persist. */
  inv: Uint8Array;
  /** The RFC 9474 prepared message that was blinded. */
  prepared: Uint8Array;
  /** SPKI DER bytes of the RSA public key used for blinding. */
  publicKey: Uint8Array;
}

/**
 * Options for {@link FreebirdClient.issuePublicToken}.
 */
export interface IssuePublicTokenOptions {
  /** 32-byte public bearer nonce embedded in the pass. */
  nonce: Uint8Array;
  /** Strict lowercase hex token key ID of the signing key. */
  tokenKeyId: string;
  /** Issuer identifier embedded in the pass. */
  issuerId: string;
  /** Sybil resistance proof if required. */
  sybilProof?: SybilProof;
}

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
  version?: 4 | 5;
  /** V4 key ID used for issuance */
  kid?: string;
  /** V5 public bearer token key ID */
  tokenKeyId?: string;
  /**
   * Unix timestamp (seconds) at which the token expires, taken from
   * `PublicKeyInfo.valid_until`. Token stores use this to evict expired
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
