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
  /** V4 token wire version */
  version?: 4;
  /** Key ID used for issuance */
  kid?: string;
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
