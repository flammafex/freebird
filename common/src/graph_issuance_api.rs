// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Canonical wire bindings for policy-authorized graph blind issuance.
//!
//! This module is deliberately independent of the issuer and verifier
//! implementations.  In particular, all values which are represented as
//! base64url on the wire are decoded before they are framed or authenticated.
//! Base64 text is never part of a digest or MAC transcript.

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const GRAPH_ISSUANCE_VERSION_V2: u8 = 2;
pub const REPLAY_AUTHORITY_VERSION_V1: u8 = 1;

pub const GRAPH_ISSUANCE_AUTHORIZATION_HMAC_SHA256: &str = "hmac_sha256";
pub const GRAPH_ISSUANCE_AUTHORIZATION_V4_LOCAL: &str = "v4_local";
pub const GRAPH_ISSUANCE_AUTHORIZATION_DEVELOPMENT_MOCK: &str = "development_mock";
pub const GRAPH_ISSUANCE_QUANTITY: u32 = 1;

pub const MAX_AUTHORIZATION: usize = 16 * 1024;
pub const MAX_BLINDED_MESSAGE: usize = 512;
pub const MAX_BLIND_SIGNATURE: usize = 512;
pub const MAX_ISSUANCE_ID: usize = 128;

const DOMAIN_REQUEST_V2: &[u8] = b"freebird graph blind issuance request v2\0";
const DOMAIN_AUTHORIZATION_BINDING_V2: &[u8] =
    b"freebird graph blind issuance authorization binding v2\0";
const DOMAIN_RESULT_V2: &[u8] = b"freebird graph blind issuance result v2\0";
pub const DOMAIN_HMAC_AUTHORIZATION_V2: &[u8] = b"freebird graph issuance hmac authorization v2\0";
pub const DOMAIN_REPLAY_AUTHORITY_PROBE_V1: &[u8] = b"freebird v4 replay authority probe v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuanceRequestV2 {
    pub version: u8,
    pub public_operation_id: String,
    pub issuance_policy_id: String,
    pub graph_id: String,
    pub keyset_id: String,
    pub descriptor_id: String,
    pub blinded_message: String,
    pub authorization: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuanceResultV2 {
    pub version: u8,
    pub public_operation_id: String,
    pub issuance_policy_id: String,
    pub graph_id: String,
    pub keyset_id: String,
    pub descriptor_id: String,
    pub token_key_id: String,
    pub quantity: u32,
    pub request_digest: String,
    pub blind_signature: String,
    pub result_digest: String,
}

pub type GraphIssuanceRequest = GraphIssuanceRequestV2;
pub type GraphIssuanceResult = GraphIssuanceResultV2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphIssuanceError(pub &'static str);

impl std::fmt::Display for GraphIssuanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for GraphIssuanceError {}

/// Append a raw byte string using the contract's u32 big-endian length
/// prefix.  Callers should validate/bound values before framing them.
pub fn put_u32be_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), GraphIssuanceError> {
    let length =
        u32::try_from(value.len()).map_err(|_| GraphIssuanceError("framed value is too large"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

/// Append a u32 in network byte order.
pub fn put_u32be(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// Alias used by callers which do not need to mention the implementation
/// detail that the length prefix is four bytes.
pub fn put_length_prefixed_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), GraphIssuanceError> {
    put_u32be_bytes(output, value)
}

fn decode_canonical(value: &str, maximum: usize) -> Result<Vec<u8>, GraphIssuanceError> {
    if value.contains('=') || value.len() > maximum.div_ceil(3) * 4 {
        return Err(GraphIssuanceError("invalid canonical base64url"));
    }
    let bytes = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| GraphIssuanceError("invalid canonical base64url"))?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || Base64UrlUnpadded::encode_string(&bytes) != value
    {
        return Err(GraphIssuanceError("invalid canonical base64url"));
    }
    Ok(bytes)
}

/// Decode exactly `N` bytes of canonical, unpadded base64url.
pub fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], GraphIssuanceError> {
    decode_canonical(value, N)?.try_into().map_err(|_| {
        GraphIssuanceError(match N {
            16 => "value must be 16 bytes",
            32 => "value must be 32 bytes",
            _ => "value has an invalid length",
        })
    })
}

pub fn decode_operation_id(value: &str) -> Result<[u8; 16], GraphIssuanceError> {
    decode_exact(value)
}

pub fn parse_operation_id(value: &str) -> Result<[u8; 16], GraphIssuanceError> {
    decode_operation_id(value)
}

pub fn decode_digest(value: &str) -> Result<[u8; 32], GraphIssuanceError> {
    decode_exact(value)
}

pub fn parse_digest(value: &str) -> Result<[u8; 32], GraphIssuanceError> {
    decode_digest(value)
}

pub fn decode_authority_id(value: &str) -> Result<[u8; 32], GraphIssuanceError> {
    decode_exact(value)
}

pub fn decode_probe_id(value: &str) -> Result<[u8; 32], GraphIssuanceError> {
    decode_exact(value)
}

pub fn decode_proof(value: &str) -> Result<[u8; 32], GraphIssuanceError> {
    decode_exact(value)
}

pub fn decode_nonce(value: &str) -> Result<[u8; 32], GraphIssuanceError> {
    decode_exact(value)
}

fn decode_bounded_nonempty(value: &str, maximum: usize) -> Result<Vec<u8>, GraphIssuanceError> {
    decode_canonical(value, maximum)
}

/// Validate an identifier whose wire representation is a SHA-256 digest.
pub fn validate_lowercase_hex_id(value: &str) -> Result<(), GraphIssuanceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(GraphIssuanceError("invalid lowercase hexadecimal id"));
    }
    Ok(())
}

pub fn validate_graph_selector_id(value: &str) -> Result<(), GraphIssuanceError> {
    validate_lowercase_hex_id(value)
}

pub fn validate_token_key_id(value: &str) -> Result<(), GraphIssuanceError> {
    validate_lowercase_hex_id(value)
}

fn validate_issuance_policy_id(value: &str) -> Result<(), GraphIssuanceError> {
    if value.is_empty() || value.len() > MAX_ISSUANCE_ID || !value.is_ascii() {
        return Err(GraphIssuanceError("invalid issuance policy id"));
    }
    Ok(())
}

fn domain_hash(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    hash.finalize().into()
}

impl GraphIssuanceRequestV2 {
    pub fn operation_id(&self) -> Result<[u8; 16], GraphIssuanceError> {
        decode_operation_id(&self.public_operation_id)
    }

    pub fn validate(&self) -> Result<(), GraphIssuanceError> {
        self.request_digest().map(|_| ())
    }

    fn selector_bytes(&self) -> Result<Vec<u8>, GraphIssuanceError> {
        if self.version != GRAPH_ISSUANCE_VERSION_V2 {
            return Err(GraphIssuanceError("unsupported graph issuance version"));
        }
        let mut bytes = vec![self.version];
        put_u32be_bytes(&mut bytes, &self.operation_id()?)?;
        validate_issuance_policy_id(&self.issuance_policy_id)?;
        for selector in [&self.graph_id, &self.keyset_id, &self.descriptor_id] {
            validate_graph_selector_id(selector)?;
        }
        for selector in [
            &self.issuance_policy_id,
            &self.graph_id,
            &self.keyset_id,
            &self.descriptor_id,
        ] {
            put_u32be_bytes(&mut bytes, selector.as_bytes())?;
        }
        put_u32be_bytes(
            &mut bytes,
            &decode_bounded_nonempty(&self.blinded_message, MAX_BLINDED_MESSAGE)?,
        )?;
        Ok(bytes)
    }

    /// Digest of the request fields which are safe for an authorization
    /// producer to know before constructing the authorization itself.
    pub fn authorization_binding_digest(&self) -> Result<[u8; 32], GraphIssuanceError> {
        Ok(domain_hash(
            DOMAIN_AUTHORIZATION_BINDING_V2,
            &self.selector_bytes()?,
        ))
    }

    /// Digest of all request fields, including the decoded opaque
    /// authorization bytes.
    pub fn request_digest(&self) -> Result<[u8; 32], GraphIssuanceError> {
        let mut bytes = self.selector_bytes()?;
        put_u32be_bytes(
            &mut bytes,
            &decode_bounded_nonempty(&self.authorization, MAX_AUTHORIZATION)?,
        )?;
        Ok(domain_hash(DOMAIN_REQUEST_V2, &bytes))
    }
}

impl GraphIssuanceResultV2 {
    fn bytes_without_digest(&self) -> Result<Vec<u8>, GraphIssuanceError> {
        if self.version != GRAPH_ISSUANCE_VERSION_V2 {
            return Err(GraphIssuanceError("unsupported graph issuance version"));
        }
        let operation = decode_operation_id(&self.public_operation_id)?;
        validate_issuance_policy_id(&self.issuance_policy_id)?;
        for selector in [&self.graph_id, &self.keyset_id, &self.descriptor_id] {
            validate_graph_selector_id(selector)?;
        }
        validate_token_key_id(&self.token_key_id)?;
        if self.quantity != GRAPH_ISSUANCE_QUANTITY {
            return Err(GraphIssuanceError("graph issuance quantity must be one"));
        }

        let mut bytes = vec![self.version];
        put_u32be_bytes(&mut bytes, &operation)?;
        for selector in [
            &self.issuance_policy_id,
            &self.graph_id,
            &self.keyset_id,
            &self.descriptor_id,
            &self.token_key_id,
        ] {
            put_u32be_bytes(&mut bytes, selector.as_bytes())?;
        }
        put_u32be(&mut bytes, self.quantity);
        put_u32be_bytes(&mut bytes, &decode_digest(&self.request_digest)?)?;
        put_u32be_bytes(
            &mut bytes,
            &decode_bounded_nonempty(&self.blind_signature, MAX_BLIND_SIGNATURE)?,
        )?;
        Ok(bytes)
    }

    pub fn calculated_result_digest(&self) -> Result<[u8; 32], GraphIssuanceError> {
        Ok(domain_hash(DOMAIN_RESULT_V2, &self.bytes_without_digest()?))
    }

    /// Validate a result without trusting any selector or digest supplied by
    /// the result itself.
    pub fn validate(&self) -> Result<(), GraphIssuanceError> {
        let expected = decode_digest(&self.result_digest)?;
        if expected
            .ct_eq(&self.calculated_result_digest()?)
            .unwrap_u8()
            != 1
        {
            return Err(GraphIssuanceError("result digest mismatch"));
        }
        Ok(())
    }

    /// Validate all request/result bindings used by recovery.  This is the
    /// only result validation entry point callers should use for a persisted
    /// response.
    pub fn validate_against(
        &self,
        request: &GraphIssuanceRequestV2,
        expected_token_key_id: &str,
    ) -> Result<(), GraphIssuanceError> {
        if request.version != GRAPH_ISSUANCE_VERSION_V2
            || self.version != GRAPH_ISSUANCE_VERSION_V2
            || self.public_operation_id != request.public_operation_id
            || self.issuance_policy_id != request.issuance_policy_id
            || self.graph_id != request.graph_id
            || self.keyset_id != request.keyset_id
            || self.descriptor_id != request.descriptor_id
        {
            return Err(GraphIssuanceError(
                "graph issuance result selector mismatch",
            ));
        }
        validate_token_key_id(expected_token_key_id)?;
        if self.token_key_id != expected_token_key_id {
            return Err(GraphIssuanceError("graph issuance token key mismatch"));
        }
        if self.quantity != GRAPH_ISSUANCE_QUANTITY {
            return Err(GraphIssuanceError("graph issuance quantity must be one"));
        }
        let expected_request_digest = request.request_digest()?;
        if decode_digest(&self.request_digest)?
            .ct_eq(&expected_request_digest)
            .unwrap_u8()
            != 1
        {
            return Err(GraphIssuanceError("request digest mismatch"));
        }
        self.validate()
    }

    pub fn validate_against_request(
        &self,
        request: &GraphIssuanceRequestV2,
        expected_token_key_id: &str,
    ) -> Result<(), GraphIssuanceError> {
        self.validate_against(request, expected_token_key_id)
    }
}

/// Return the raw HMAC-SHA256 tag for the V2 external authorization contract.
pub fn hmac_authorization_transcript_v2(
    nonce: &[u8; 32],
    policy_id: &str,
    authorization_binding_digest: &[u8; 32],
) -> Result<Vec<u8>, GraphIssuanceError> {
    validate_issuance_policy_id(policy_id)?;
    let policy_bytes = policy_id.as_bytes();
    let length = u32::try_from(policy_bytes.len())
        .map_err(|_| GraphIssuanceError("issuance policy id is too large"))?;
    let mut transcript =
        Vec::with_capacity(DOMAIN_HMAC_AUTHORIZATION_V2.len() + 32 + 4 + policy_bytes.len() + 32);
    transcript.extend_from_slice(DOMAIN_HMAC_AUTHORIZATION_V2);
    transcript.extend_from_slice(nonce);
    transcript.extend_from_slice(&length.to_be_bytes());
    transcript.extend_from_slice(policy_bytes);
    transcript.extend_from_slice(authorization_binding_digest);
    Ok(transcript)
}

pub fn hmac_authorization_tag_v2(
    secret: &[u8],
    nonce: &[u8; 32],
    policy_id: &str,
    authorization_binding_digest: &[u8; 32],
) -> Result<[u8; 32], GraphIssuanceError> {
    let transcript =
        hmac_authorization_transcript_v2(nonce, policy_id, authorization_binding_digest)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|_| GraphIssuanceError("invalid HMAC secret"))?;
    mac.update(&transcript);
    Ok(mac.finalize().into_bytes().into())
}

pub fn hmac_authorization_tag(
    secret: &[u8],
    nonce: &[u8; 32],
    policy_id: &str,
    authorization_binding_digest: &[u8; 32],
) -> Result<[u8; 32], GraphIssuanceError> {
    hmac_authorization_tag_v2(secret, nonce, policy_id, authorization_binding_digest)
}

/// Construct canonical `nonce_raw || tag_raw` HMAC authorization bytes.
pub fn build_hmac_authorization_v2(
    secret: &[u8],
    nonce: &[u8; 32],
    policy_id: &str,
    authorization_binding_digest: &[u8; 32],
) -> Result<String, GraphIssuanceError> {
    let tag = hmac_authorization_tag_v2(secret, nonce, policy_id, authorization_binding_digest)?;
    let mut authorization = Vec::with_capacity(64);
    authorization.extend_from_slice(nonce);
    authorization.extend_from_slice(&tag);
    Ok(Base64UrlUnpadded::encode_string(&authorization))
}

pub fn parse_hmac_authorization_v2(
    authorization: &str,
) -> Result<([u8; 32], [u8; 32]), GraphIssuanceError> {
    let bytes = decode_canonical(authorization, 64)?;
    if bytes.len() != 64 {
        return Err(GraphIssuanceError(
            "graph issuance HMAC authorization must be 64 bytes",
        ));
    }
    let nonce: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| GraphIssuanceError("invalid HMAC nonce"))?;
    let tag: [u8; 32] = bytes[32..]
        .try_into()
        .map_err(|_| GraphIssuanceError("invalid HMAC tag"))?;
    Ok((nonce, tag))
}

/// Verify a V2 HMAC authorization and return its raw nonce for nullifier
/// derivation.  No V1 transcript is accepted here.
pub fn verify_hmac_authorization_v2(
    secret: &[u8],
    policy_id: &str,
    authorization_binding_digest: &[u8; 32],
    authorization: &str,
) -> Result<[u8; 32], GraphIssuanceError> {
    let (nonce, supplied_tag) = parse_hmac_authorization_v2(authorization)?;
    let expected_tag =
        hmac_authorization_tag_v2(secret, &nonce, policy_id, authorization_binding_digest)?;
    if supplied_tag.ct_eq(&expected_tag).unwrap_u8() != 1 {
        return Err(GraphIssuanceError("invalid graph issuance authorization"));
    }
    Ok(nonce)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAuthorityProbeV1 {
    pub version: u8,
    pub authority_id: String,
    pub probe_id: String,
}

impl ReplayAuthorityProbeV1 {
    pub fn authority_id(&self) -> Result<[u8; 32], GraphIssuanceError> {
        decode_authority_id(&self.authority_id)
    }

    pub fn probe_id(&self) -> Result<[u8; 32], GraphIssuanceError> {
        decode_probe_id(&self.probe_id)
    }

    pub fn validate(&self) -> Result<(), GraphIssuanceError> {
        if self.version != REPLAY_AUTHORITY_VERSION_V1 {
            return Err(GraphIssuanceError("unsupported replay authority version"));
        }
        self.authority_id()?;
        self.probe_id()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAuthorityProofV1 {
    pub version: u8,
    pub authority_id: String,
    pub probe_id: String,
    pub proof: String,
}

impl ReplayAuthorityProofV1 {
    /// Validate a response against the IDs from the request which caused the
    /// probe.  The response is not allowed to select the authority or probe
    /// namespace used for proof verification (or for a subsequent Redis ACK
    /// lookup).
    pub fn validate_against(
        &self,
        challenge: &[u8; 32],
        issuer_id: &str,
        expected_authority_id: &str,
        expected_probe_id: &str,
    ) -> Result<(), GraphIssuanceError> {
        if self.version != REPLAY_AUTHORITY_VERSION_V1 {
            return Err(GraphIssuanceError("unsupported replay authority version"));
        }
        let expected_authority_id = decode_authority_id(expected_authority_id)?;
        let expected_probe_id = decode_probe_id(expected_probe_id)?;
        let response_authority_id = decode_authority_id(&self.authority_id)?;
        let response_probe_id = decode_probe_id(&self.probe_id)?;
        if response_authority_id
            .ct_eq(&expected_authority_id)
            .unwrap_u8()
            != 1
            || response_probe_id.ct_eq(&expected_probe_id).unwrap_u8() != 1
        {
            return Err(GraphIssuanceError(
                "replay authority response selector mismatch",
            ));
        }
        let proof = decode_proof(&self.proof)?;
        let expected = replay_authority_proof_v1(
            challenge,
            &expected_authority_id,
            &expected_probe_id,
            issuer_id,
        )?;
        if proof.ct_eq(&expected).unwrap_u8() != 1 {
            return Err(GraphIssuanceError("replay authority proof mismatch"));
        }
        Ok(())
    }
}

/// Construct the raw replay-authority probe proof.  `authority_id` and
/// `probe_id` are raw bytes, not their base64url encodings.
pub fn replay_authority_proof_transcript_v1(
    authority_id: &[u8; 32],
    probe_id: &[u8; 32],
    issuer_id: &str,
) -> Result<Vec<u8>, GraphIssuanceError> {
    let issuer_bytes = issuer_id.as_bytes();
    let length = u32::try_from(issuer_bytes.len())
        .map_err(|_| GraphIssuanceError("issuer id is too large"))?;
    let mut transcript = Vec::with_capacity(
        DOMAIN_REPLAY_AUTHORITY_PROBE_V1.len() + 32 + 32 + 4 + issuer_bytes.len(),
    );
    transcript.extend_from_slice(DOMAIN_REPLAY_AUTHORITY_PROBE_V1);
    transcript.extend_from_slice(authority_id);
    transcript.extend_from_slice(probe_id);
    transcript.extend_from_slice(&length.to_be_bytes());
    transcript.extend_from_slice(issuer_bytes);
    Ok(transcript)
}

pub fn replay_authority_proof_v1(
    challenge: &[u8; 32],
    authority_id: &[u8; 32],
    probe_id: &[u8; 32],
    issuer_id: &str,
) -> Result<[u8; 32], GraphIssuanceError> {
    let transcript = replay_authority_proof_transcript_v1(authority_id, probe_id, issuer_id)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(challenge)
        .map_err(|_| GraphIssuanceError("invalid replay authority challenge"))?;
    mac.update(&transcript);
    Ok(mac.finalize().into_bytes().into())
}

pub fn replay_authority_proof(
    challenge: &[u8; 32],
    authority_id: &[u8; 32],
    probe_id: &[u8; 32],
    issuer_id: &str,
) -> Result<[u8; 32], GraphIssuanceError> {
    replay_authority_proof_v1(challenge, authority_id, probe_id, issuer_id)
}

pub fn build_replay_authority_proof_v1(
    challenge: &[u8; 32],
    authority_id: &str,
    probe_id: &str,
    issuer_id: &str,
) -> Result<String, GraphIssuanceError> {
    let authority_id = decode_authority_id(authority_id)?;
    let probe_id = decode_probe_id(probe_id)?;
    let proof = replay_authority_proof_v1(challenge, &authority_id, &probe_id, issuer_id)?;
    Ok(Base64UrlUnpadded::encode_string(&proof))
}

// Names used by the authority lane are kept explicit about the protocol
// version; these aliases also make the wire model pleasant to import.
pub type ReplayAuthorityProbe = ReplayAuthorityProbeV1;
pub type ReplayAuthorityProof = ReplayAuthorityProofV1;

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> GraphIssuanceRequestV2 {
        GraphIssuanceRequestV2 {
            version: GRAPH_ISSUANCE_VERSION_V2,
            public_operation_id: Base64UrlUnpadded::encode_string(&[7; 16]),
            issuance_policy_id: "bootstrap-v2".into(),
            graph_id: "1".repeat(64),
            keyset_id: "2".repeat(64),
            descriptor_id: "3".repeat(64),
            blinded_message: Base64UrlUnpadded::encode_string(&[4; 256]),
            authorization: Base64UrlUnpadded::encode_string(&[5; 64]),
        }
    }

    #[test]
    fn fixed_decoders_reject_noncanonical_or_wrong_lengths() {
        assert_eq!(
            decode_operation_id(&Base64UrlUnpadded::encode_string(&[7; 16])).unwrap(),
            [7; 16]
        );
        assert!(decode_operation_id("").is_err());
        assert!(decode_operation_id(&Base64UrlUnpadded::encode_string(&[7; 15])).is_err());
        assert!(
            decode_digest(&format!("{}=", Base64UrlUnpadded::encode_string(&[7; 32]))).is_err()
        );
        assert!(decode_digest(&Base64UrlUnpadded::encode_string(&[7; 31])).is_err());
        assert!(decode_authority_id(&Base64UrlUnpadded::encode_string(&[7; 31])).is_err());
        assert!(decode_probe_id(&Base64UrlUnpadded::encode_string(&[7; 31])).is_err());
        assert!(decode_proof(&Base64UrlUnpadded::encode_string(&[7; 31])).is_err());
        assert!(decode_nonce(&Base64UrlUnpadded::encode_string(&[7; 31])).is_err());
    }

    #[test]
    fn lowercase_hex_ids_are_exact() {
        assert!(validate_lowercase_hex_id(&"a1".repeat(32)).is_ok());
        assert!(validate_lowercase_hex_id(&"A1".repeat(32)).is_err());
        assert!(validate_lowercase_hex_id(&"g".repeat(64)).is_err());
        assert!(validate_lowercase_hex_id(&"a".repeat(63)).is_err());
    }

    #[test]
    fn request_digest_binds_authorization_and_every_selector() {
        let request = request();
        let digest = request.request_digest().unwrap();
        let binding = request.authorization_binding_digest().unwrap();
        assert_eq!(
            Base64UrlUnpadded::encode_string(&binding),
            "XlKH0YegK8esWoKbeWQtIDCVzGwT1JLcrx0Uag_ykEw"
        );
        assert_eq!(
            Base64UrlUnpadded::encode_string(&digest),
            "GmoCf632DNZaUd1RcVagcvRaJiKMMhVJZq7MVgtZFxI"
        );
        let mut changed = request.clone();
        changed.authorization = Base64UrlUnpadded::encode_string(&[6; 64]);
        assert_ne!(digest, changed.request_digest().unwrap());
        assert_eq!(binding, changed.authorization_binding_digest().unwrap());
        changed = request.clone();
        changed.descriptor_id = "4".repeat(64);
        assert_ne!(binding, changed.authorization_binding_digest().unwrap());
    }

    #[derive(Debug, Deserialize)]
    struct HmacVector {
        version: u8,
        secret_ascii: String,
        nonce_hex: String,
        issuance_policy_id: String,
        authorization_binding_digest_hex: String,
        framing: String,
        transcript_domain_hex: String,
        authorization_base64url: String,
    }

    #[test]
    fn hmac_v2_consumes_shared_machine_readable_vector_and_rejects_mutation() {
        let vector: HmacVector = serde_json::from_str(include_str!(
            "../../docs/examples/public-bearer-graph-issuance-hmac-v2-vector.json"
        ))
        .unwrap();
        assert_eq!(vector.version, GRAPH_ISSUANCE_VERSION_V2);
        assert_eq!(vector.framing, "nonce_raw[32] || tag_raw[32]");

        let nonce: [u8; 32] = hex::decode(vector.nonce_hex).unwrap().try_into().unwrap();
        let binding: [u8; 32] = hex::decode(vector.authorization_binding_digest_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let domain = hex::decode(vector.transcript_domain_hex).unwrap();
        assert_eq!(domain, DOMAIN_HMAC_AUTHORIZATION_V2);

        let secret = vector.secret_ascii.as_bytes();
        let transcript =
            hmac_authorization_transcript_v2(&nonce, &vector.issuance_policy_id, &binding).unwrap();
        assert!(transcript.starts_with(&domain));
        let authorization =
            build_hmac_authorization_v2(secret, &nonce, &vector.issuance_policy_id, &binding)
                .unwrap();
        assert_eq!(authorization, vector.authorization_base64url);
        assert_eq!(
            verify_hmac_authorization_v2(
                secret,
                &vector.issuance_policy_id,
                &binding,
                &authorization,
            )
            .unwrap(),
            nonce
        );
        let mut changed = authorization.as_bytes().to_vec();
        changed[0] = if changed[0] == b'A' { b'B' } else { b'A' };
        let changed = String::from_utf8(changed).unwrap();
        assert!(verify_hmac_authorization_v2(
            secret,
            &vector.issuance_policy_id,
            &binding,
            &changed
        )
        .is_err());
    }

    #[test]
    fn result_binds_request_selectors_key_and_quantity() {
        let request = request();
        let request_digest = request.request_digest().unwrap();
        let mut result = GraphIssuanceResultV2 {
            version: GRAPH_ISSUANCE_VERSION_V2,
            public_operation_id: request.public_operation_id.clone(),
            issuance_policy_id: request.issuance_policy_id.clone(),
            graph_id: request.graph_id.clone(),
            keyset_id: request.keyset_id.clone(),
            descriptor_id: request.descriptor_id.clone(),
            token_key_id: "a".repeat(64),
            quantity: 1,
            request_digest: Base64UrlUnpadded::encode_string(&request_digest),
            blind_signature: Base64UrlUnpadded::encode_string(&[9; 256]),
            result_digest: String::new(),
        };
        result.result_digest =
            Base64UrlUnpadded::encode_string(&result.calculated_result_digest().unwrap());
        assert_eq!(
            result.result_digest,
            "NBV2aptoc6c0G9bkKEeNZVF4YYMtjUziOkMfw2kP1N0"
        );
        assert!(result.validate_against(&request, &"a".repeat(64)).is_ok());
        result.quantity = 2;
        assert!(result.validate_against(&request, &"a".repeat(64)).is_err());
        result.quantity = 1;
        result.result_digest = Base64UrlUnpadded::encode_string(&[8; 32]);
        assert!(result.validate_against(&request, &"a".repeat(64)).is_err());
    }

    #[test]
    fn replay_authority_proof_fixed_vector_and_tamper_rejection() {
        let challenge = [1; 32];
        let authority = [2; 32];
        let probe = [3; 32];
        let proof =
            replay_authority_proof_v1(&challenge, &authority, &probe, "issuer:test").unwrap();
        assert_eq!(
            Base64UrlUnpadded::encode_string(&proof),
            "THFSTMyc6htC_fEHvc1kgs5dgayJJuTJixk87B6yzgI"
        );
        let encoded_authority = Base64UrlUnpadded::encode_string(&authority);
        let encoded_probe = Base64UrlUnpadded::encode_string(&probe);
        let response = ReplayAuthorityProofV1 {
            version: 1,
            authority_id: encoded_authority,
            probe_id: encoded_probe,
            proof: Base64UrlUnpadded::encode_string(&proof),
        };
        let expected_authority = Base64UrlUnpadded::encode_string(&authority);
        let expected_probe = Base64UrlUnpadded::encode_string(&probe);
        assert!(response
            .validate_against(
                &challenge,
                "issuer:test",
                &expected_authority,
                &expected_probe
            )
            .is_ok());
        assert!(response
            .validate_against(
                &challenge,
                "issuer:test",
                &Base64UrlUnpadded::encode_string(&[4; 32]),
                &expected_probe
            )
            .is_err());
        let mut tampered = response.clone();
        tampered.probe_id = Base64UrlUnpadded::encode_string(&[4; 32]);
        assert!(tampered
            .validate_against(
                &challenge,
                "issuer:test",
                &expected_authority,
                &expected_probe
            )
            .is_err());
        tampered = response;
        tampered.proof = Base64UrlUnpadded::encode_string(&[4; 32]);
        assert!(tampered
            .validate_against(
                &challenge,
                "issuer:test",
                &expected_authority,
                &expected_probe
            )
            .is_err());
    }
}
