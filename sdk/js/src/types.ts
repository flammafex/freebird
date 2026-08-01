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
}
