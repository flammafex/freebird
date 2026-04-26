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
