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

/** Exact JSON body accepted by POST /v1/public/exchange. */
export interface ExchangeRequest {
  profile: string;
  rule_id: string;
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
  operation_id: string;
  profile: string;
  target_keyset_id: string;
  outputs: ExchangeResultOutput[];
  result_digest: string;
}

export interface ExchangeReceipt {
  operation_id: string;
  profile: string;
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
  keyset_id: string;
  purpose: 'exchange_source' | 'exchange_target';
  profile_id: string;
  role: 'source' | 'target';
  issuer_id: string;
  class: string;
  token_key_id: string;
  pubkey_spki_b64: string;
  suite: string;
  valid_from: number;
  valid_until: number;
  max_quantity: number;
  audience?: string;
}

export interface ExchangeDiscoveryMetadata {
  profile_id: string;
  target_keysets: ExchangeTargetKeysetInfo[];
  descriptors: ExchangeDescriptorInfo[];
  receipt_keys: ExchangeReceiptKeyInfo[];
}

export type ExchangeErrorCode =
  | 'invalid_idempotency_key'
  | 'exchange_unavailable'
  | 'invalid_exchange_request'
  | 'operation_conflict'
  | 'invalid_exchange'
  | 'unknown_operation';

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
          error: 'invalid_idempotency_key' | 'invalid_exchange_request' | 'invalid_exchange';
        };
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
      type: 'webauthn';
      username: string;
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
