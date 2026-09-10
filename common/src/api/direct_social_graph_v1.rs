// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The closed, direct-Clout Social Graph V1 contract.
//!
//! This module is intentionally not exported from `api` yet.  In particular,
//! the types below are not compatibility shims for the older, untyped social
//! graph API.  Wire values are validated at the boundary and every digest is
//! made from a domain-separated, length-framed transcript.

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

pub const DIRECT_SOCIAL_GRAPH_V1_ATTEST_REQUEST_PROFILE: &str =
    "freebird/direct-social-graph/attest-request/v1";
pub const DIRECT_SOCIAL_GRAPH_V1_ATTESTATION_PROFILE: &str =
    "freebird/direct-social-graph/attestation/v1";
pub const DIRECT_SOCIAL_GRAPH_V1_PRESENTATION_PROFILE: &str =
    "freebird/direct-social-graph/presentation/v1";
pub const DIRECT_SOCIAL_GRAPH_V1_KEYSET_PROFILE: &str = "freebird/direct-social-graph/keyset/v1";

// The *_PROFILE_ID names match the naming convention used by the other
// nominal contracts.  They are Rust names for the same exact wire constants,
// not alternate wire spellings.
pub const DIRECT_SOCIAL_GRAPH_V1_ATTEST_REQUEST_PROFILE_ID: &str =
    DIRECT_SOCIAL_GRAPH_V1_ATTEST_REQUEST_PROFILE;
pub const DIRECT_SOCIAL_GRAPH_V1_ATTESTATION_PROFILE_ID: &str =
    DIRECT_SOCIAL_GRAPH_V1_ATTESTATION_PROFILE;
pub const DIRECT_SOCIAL_GRAPH_V1_PRESENTATION_PROFILE_ID: &str =
    DIRECT_SOCIAL_GRAPH_V1_PRESENTATION_PROFILE;
pub const DIRECT_SOCIAL_GRAPH_V1_KEYSET_PROFILE_ID: &str = DIRECT_SOCIAL_GRAPH_V1_KEYSET_PROFILE;

pub const DIRECT_SOCIAL_GRAPH_V1_VERSION: u8 = 1;
pub const DIRECT_SOCIAL_GRAPH_V1_QUOTA_PERIOD_SECS: u64 = 86_400;
pub const DIRECT_SOCIAL_GRAPH_V1_QUOTA_SECS: u64 = DIRECT_SOCIAL_GRAPH_V1_QUOTA_PERIOD_SECS;
pub const DIRECT_SOCIAL_GRAPH_V1_JWKS_MAX_STALE_SECS: u64 = 900;
pub const DIRECT_SOCIAL_GRAPH_V1_MAX_PRESENTATION_LIFETIME_SECS: u64 = 300;
pub const DIRECT_SOCIAL_GRAPH_V1_MAX_ATTESTATION_LIFETIME_SECS: u64 = 300;
pub const DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS: u64 = 30;

pub const DIRECT_SOCIAL_GRAPH_V1_DOMAIN_EVIDENCE_DIGEST: &[u8] =
    b"freebird direct social graph v1 evidence digest\0";
pub const DIRECT_SOCIAL_GRAPH_V1_DOMAIN_HOLDER_COMMITMENT: &[u8] =
    b"freebird direct social graph v1 holder commitment\0";
pub const DIRECT_SOCIAL_GRAPH_V1_DOMAIN_SUBJECT_BINDING: &[u8] =
    b"freebird direct social graph v1 subject binding\0";
pub const DIRECT_SOCIAL_GRAPH_V1_DOMAIN_ATTESTATION_DIGEST: &[u8] =
    b"freebird direct social graph v1 attestation digest\0";
pub const DIRECT_SOCIAL_GRAPH_V1_DOMAIN_REQUEST_BINDING: &[u8] =
    b"freebird direct social graph v1 request binding\0";
pub const DIRECT_SOCIAL_GRAPH_V1_DOMAIN_PRESENTATION_DIGEST: &[u8] =
    b"freebird direct social graph v1 presentation digest\0";
pub const DIRECT_SOCIAL_GRAPH_V1_DOMAIN_JWKS_KID: &[u8] =
    b"freebird direct social graph v1 jwks kid\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectSocialGraphV1Error(pub &'static str);

impl fmt::Display for DirectSocialGraphV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for DirectSocialGraphV1Error {}

/// A Clout trust signal.  The six fields are the complete Clout V1 signal;
/// do not add a second subject or key field here.  The truster is the signing
/// Ed25519 public key and trustee is the graph subject/key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSocialGraphV1CloutEdge {
    pub truster: String,
    pub trustee: String,
    /// Trust weight in millionths; 1_000_000 is full trust.
    pub weight_micros: u32,
    pub timestamp: u64,
    pub revoked: bool,
    pub signature: String,
}

impl DirectSocialGraphV1CloutEdge {
    pub fn validate(&self) -> Result<(), DirectSocialGraphV1Error> {
        hex_bytes(&self.truster, 32, "invalid Clout truster")?;
        hex_bytes(&self.trustee, 32, "invalid Clout trustee")?;
        hex_bytes(&self.signature, 64, "invalid Clout signature")?;
        if self.weight_micros > 1_000_000 || (self.revoked && self.weight_micros != 0) {
            return Err(DirectSocialGraphV1Error("invalid Clout weight/revocation"));
        }
        Ok(())
    }

    /// The exact payload signed by Clout.  In particular, `revoked` is
    /// omitted for a live, non-zero edge and is forced on for a zero edge,
    /// matching Clout's signal semantics rather than Rust's struct shape.
    pub fn canonical_signal(&self) -> Result<Vec<u8>, DirectSocialGraphV1Error> {
        self.validate()?;
        let mut signal = format!(
            "{{\"timestamp\":{},\"trustee\":\"{}\",\"truster\":\"{}\",\"weight_micros\":{}",
            self.timestamp, self.trustee, self.truster, self.weight_micros
        );
        if self.revoked || self.weight_micros == 0 {
            signal.push_str(",\"revoked\":true");
        }
        signal.push('}');
        let digest = Sha256::digest(signal.as_bytes());
        Ok(format!("CLOUT_TRUST_SIGNAL_V1:{}", lower_hex(&digest)).into_bytes())
    }

    fn canonical_order_bytes(&self) -> Result<Vec<u8>, DirectSocialGraphV1Error> {
        // Include the complete edge, not only the signed signal: two
        // differently encoded records must not occupy the same evidence slot.
        let signal = self.canonical_signal()?;
        let mut bytes = signal;
        bytes.extend_from_slice(self.signature.as_bytes());
        Ok(bytes)
    }
}

/// Direct request sent to the attester.  The two digest leaves are explicit
/// so a receiver never has to guess which projection was signed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSocialGraphV1AttestRequest {
    pub version: u8,
    pub profile_id: String,
    pub attester_id: String,
    pub policy_id: String,
    pub request_nonce: String,
    pub timestamp: u64,
    pub holder_commitment: String,
    pub subject: String,
    pub evidence: Vec<DirectSocialGraphV1CloutEdge>,
    pub evidence_digest: String,
    pub subject_binding: String,
    /// Lowercase hexadecimal Ed25519 signature over the canonical request
    /// subject-binding transcript.
    pub subject_signature: String,
}

impl DirectSocialGraphV1AttestRequest {
    pub fn validate(&self) -> Result<(), DirectSocialGraphV1Error> {
        if self.version != DIRECT_SOCIAL_GRAPH_V1_VERSION
            || self.profile_id != DIRECT_SOCIAL_GRAPH_V1_ATTEST_REQUEST_PROFILE
        {
            return Err(DirectSocialGraphV1Error(
                "wrong direct social graph request profile",
            ));
        }
        bounded_text(&self.attester_id, "invalid attester id")?;
        bounded_text(&self.policy_id, "invalid policy id")?;
        hex_bytes(&self.request_nonce, 16, "invalid request nonce")?;
        hex_bytes(&self.subject_signature, 64, "invalid subject signature")?;
        if self.timestamp == 0 {
            return Err(DirectSocialGraphV1Error("invalid request timestamp"));
        }
        hex_bytes(&self.holder_commitment, 32, "invalid holder commitment")?;
        hex_bytes(&self.subject, 32, "invalid Clout subject")?;
        let evidence_digest = direct_social_graph_v1_evidence_digest(&self.evidence)?;
        if self.evidence_digest != evidence_digest {
            return Err(DirectSocialGraphV1Error("evidence digest mismatch"));
        }
        let subject_binding =
            direct_social_graph_v1_subject_binding(&self.subject, &self.holder_commitment)?;
        if self.subject_binding != subject_binding {
            return Err(DirectSocialGraphV1Error("subject binding mismatch"));
        }
        direct_social_graph_v1_subject_binding_transcript(
            &self.attester_id,
            &self.policy_id,
            &self.request_nonce,
            self.timestamp,
            &self.subject,
            &self.holder_commitment,
        )?;
        Ok(())
    }

    pub fn validate_at(&self, now: u64) -> Result<(), DirectSocialGraphV1Error> {
        self.validate()?;
        if self.timestamp > now.saturating_add(DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS) {
            return Err(DirectSocialGraphV1Error("request is from the future"));
        }
        Ok(())
    }
}

/// Signed attestation issued by the social graph attester.  It contains no
/// raw graph evidence and no Freebird request binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSocialGraphV1Attestation {
    pub version: u8,
    pub profile_id: String,
    pub attester_id: String,
    pub kid: String,
    pub policy_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub eligibility_level: u8,
    pub quota_nullifier: String,
    pub jti: String,
    pub holder_commitment: String,
    /// Lowercase hex Ed25519 signature (64 bytes).
    pub signature: String,
}

impl DirectSocialGraphV1Attestation {
    pub fn validate(&self) -> Result<(), DirectSocialGraphV1Error> {
        if self.version != DIRECT_SOCIAL_GRAPH_V1_VERSION
            || self.profile_id != DIRECT_SOCIAL_GRAPH_V1_ATTESTATION_PROFILE
        {
            return Err(DirectSocialGraphV1Error(
                "wrong direct social graph attestation profile",
            ));
        }
        bounded_text(&self.attester_id, "invalid attester id")?;
        bounded_text(&self.kid, "invalid attester key id")?;
        bounded_text(&self.policy_id, "invalid policy id")?;
        bounded_text(&self.jti, "invalid attestation id")?;
        hex_bytes(&self.holder_commitment, 32, "invalid holder commitment")?;
        hex_bytes(&self.signature, 64, "invalid attestation signature")?;
        hex_bytes(&self.quota_nullifier, 32, "invalid quota nullifier")?;
        if self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at
                > DIRECT_SOCIAL_GRAPH_V1_MAX_ATTESTATION_LIFETIME_SECS
            || !(1..=3).contains(&self.eligibility_level)
        {
            return Err(DirectSocialGraphV1Error(
                "invalid attestation lifetime/eligibility",
            ));
        }
        Ok(())
    }

    pub fn validate_at(&self, now: u64) -> Result<(), DirectSocialGraphV1Error> {
        self.validate()?;
        if self.issued_at > now.saturating_add(DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS)
            || self
                .expires_at
                .saturating_add(DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS)
                < now
        {
            return Err(DirectSocialGraphV1Error(
                "attestation is outside clock window",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, DirectSocialGraphV1Error> {
        direct_social_graph_v1_attestation_digest(self)
    }
}

/// Request-bound presentation metadata.  The attestation is embedded rather
/// than represented by an untyped JSON string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSocialGraphV1Presentation {
    pub version: u8,
    pub profile_id: String,
    pub attestation: DirectSocialGraphV1Attestation,
    pub app_id: String,
    pub request_id: String,
    pub request_binding_hash: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl DirectSocialGraphV1Presentation {
    pub fn validate(&self) -> Result<(), DirectSocialGraphV1Error> {
        if self.version != DIRECT_SOCIAL_GRAPH_V1_VERSION
            || self.profile_id != DIRECT_SOCIAL_GRAPH_V1_PRESENTATION_PROFILE
        {
            return Err(DirectSocialGraphV1Error(
                "wrong direct social graph presentation profile",
            ));
        }
        self.attestation.validate()?;
        bounded_text(&self.app_id, "invalid presentation app id")?;
        bounded_text(&self.request_id, "invalid presentation request id")?;
        hex_bytes(
            &self.request_binding_hash,
            32,
            "invalid request binding hash",
        )?;
        if self.expires_at <= self.created_at
            || self.expires_at - self.created_at
                > DIRECT_SOCIAL_GRAPH_V1_MAX_PRESENTATION_LIFETIME_SECS
        {
            return Err(DirectSocialGraphV1Error("invalid presentation lifetime"));
        }
        Ok(())
    }

    pub fn validate_at(&self, now: u64) -> Result<(), DirectSocialGraphV1Error> {
        self.validate()?;
        if self.created_at > now.saturating_add(DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS)
            || self
                .expires_at
                .saturating_add(DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS)
                < now
        {
            return Err(DirectSocialGraphV1Error(
                "presentation is outside clock window",
            ));
        }
        Ok(())
    }
}

/// Holder proof for a presentation.  Public-key and signature bytes use
/// canonical unpadded base64url; hashes in the presentation remain hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSocialGraphV1Proof {
    pub version: u8,
    pub profile_id: String,
    pub presentation: DirectSocialGraphV1Presentation,
    pub holder_public_key: String,
    pub signature: String,
}

pub type DirectSocialGraphV1PresentationProof = DirectSocialGraphV1Proof;

impl DirectSocialGraphV1Proof {
    pub fn validate(&self) -> Result<(), DirectSocialGraphV1Error> {
        if self.version != DIRECT_SOCIAL_GRAPH_V1_VERSION
            || self.profile_id != DIRECT_SOCIAL_GRAPH_V1_PRESENTATION_PROFILE
        {
            return Err(DirectSocialGraphV1Error(
                "wrong direct social graph proof profile",
            ));
        }
        self.presentation.validate()?;
        base64_bytes(&self.holder_public_key, 32, "invalid holder public key")?;
        base64_bytes(&self.signature, 64, "invalid holder signature")?;
        let expected = direct_social_graph_v1_holder_commitment(&self.holder_public_key)?;
        if expected != self.presentation.attestation.holder_commitment {
            return Err(DirectSocialGraphV1Error("holder commitment mismatch"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, DirectSocialGraphV1Error> {
        direct_social_graph_v1_presentation_digest(&self.presentation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DirectSocialGraphV1KeyState {
    Active,
    Retained,
    Revoked,
}

/// Typed Ed25519 JWKS member.  `x` is the only key-material field and is
/// always canonical unpadded base64url for exactly 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSocialGraphV1Jwk {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub x: String,
    pub state: DirectSocialGraphV1KeyState,
    pub valid_from: u64,
    pub valid_until: u64,
    pub revoked_at: Option<u64>,
}

impl DirectSocialGraphV1Jwk {
    pub fn validate(&self) -> Result<(), DirectSocialGraphV1Error> {
        if self.kty != "OKP" || self.crv != "Ed25519" || self.use_ != "sig" || self.alg != "EdDSA" {
            return Err(DirectSocialGraphV1Error(
                "invalid direct social graph JWKS type",
            ));
        }
        bounded_text(&self.kid, "invalid JWKS kid")?;
        let public_key = base64_bytes(&self.x, 32, "invalid JWKS public key")?;
        if hex::encode(Sha256::digest(public_key)) != self.kid {
            return Err(DirectSocialGraphV1Error(
                "JWKS kid does not match public key",
            ));
        }
        if self.valid_until <= self.valid_from {
            return Err(DirectSocialGraphV1Error("invalid JWKS validity interval"));
        }
        match self.state {
            DirectSocialGraphV1KeyState::Revoked if self.revoked_at.is_none() => Err(
                DirectSocialGraphV1Error("revoked JWKS key has no revocation time"),
            ),
            DirectSocialGraphV1KeyState::Active | DirectSocialGraphV1KeyState::Retained
                if self.revoked_at.is_some() =>
            {
                Err(DirectSocialGraphV1Error("live JWKS key is revoked"))
            }
            DirectSocialGraphV1KeyState::Revoked
                if self.revoked_at.is_some_and(|at| at < self.valid_from) =>
            {
                Err(DirectSocialGraphV1Error(
                    "JWKS revocation precedes validity",
                ))
            }
            DirectSocialGraphV1KeyState::Revoked
                if self.revoked_at.is_some_and(|at| at > self.valid_until) =>
            {
                Err(DirectSocialGraphV1Error(
                    "JWKS revocation follows key validity",
                ))
            }
            _ => Ok(()),
        }
    }

    pub fn kid_digest(&self) -> Result<String, DirectSocialGraphV1Error> {
        direct_social_graph_v1_jwks_kid_digest(&self.x)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectSocialGraphV1Keyset {
    pub version: u8,
    pub profile_id: String,
    pub attester_id: String,
    pub published_at: u64,
    pub keys: Vec<DirectSocialGraphV1Jwk>,
}

impl DirectSocialGraphV1Keyset {
    pub fn validate(&self) -> Result<(), DirectSocialGraphV1Error> {
        if self.version != DIRECT_SOCIAL_GRAPH_V1_VERSION
            || self.profile_id != DIRECT_SOCIAL_GRAPH_V1_KEYSET_PROFILE
        {
            return Err(DirectSocialGraphV1Error(
                "wrong direct social graph keyset profile",
            ));
        }
        bounded_text(&self.attester_id, "invalid keyset attester id")?;
        if self.keys.is_empty() {
            return Err(DirectSocialGraphV1Error("empty direct social graph keyset"));
        }
        let mut active = 0;
        for (index, key) in self.keys.iter().enumerate() {
            key.validate()?;
            if key.state == DirectSocialGraphV1KeyState::Active {
                active += 1;
            }
            if self.keys[..index].iter().any(|prior| prior.kid == key.kid) {
                return Err(DirectSocialGraphV1Error("duplicate JWKS kid"));
            }
        }
        if active != 1 {
            return Err(DirectSocialGraphV1Error(
                "JWKS keyset must have exactly one active key",
            ));
        }
        Ok(())
    }

    pub fn validate_at(&self, now: u64) -> Result<(), DirectSocialGraphV1Error> {
        self.validate()?;
        if self.published_at > now.saturating_add(DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS)
            || now.saturating_sub(self.published_at) > DIRECT_SOCIAL_GRAPH_V1_JWKS_MAX_STALE_SECS
        {
            return Err(DirectSocialGraphV1Error("JWKS keyset is stale"));
        }
        for key in &self.keys {
            if key.valid_from > now.saturating_add(DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS)
                || key.revoked_at.is_some_and(|at| {
                    at > now.saturating_add(DIRECT_SOCIAL_GRAPH_V1_CLOCK_SKEW_SECS)
                })
            {
                return Err(DirectSocialGraphV1Error("JWKS key is from the future"));
            }
        }
        let active = self
            .keys
            .iter()
            .find(|key| key.state == DirectSocialGraphV1KeyState::Active)
            .ok_or(DirectSocialGraphV1Error("missing active JWKS key"))?;
        if now < active.valid_from || now >= active.valid_until {
            return Err(DirectSocialGraphV1Error(
                "active JWKS key is outside validity",
            ));
        }
        Ok(())
    }
}

pub fn direct_social_graph_v1_evidence_digest(
    evidence: &[DirectSocialGraphV1CloutEdge],
) -> Result<String, DirectSocialGraphV1Error> {
    let mut leaves = Vec::with_capacity(evidence.len());
    for edge in evidence {
        edge.validate()?;
        leaves.push(edge.canonical_order_bytes()?);
    }
    if leaves.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DirectSocialGraphV1Error(
            "Clout evidence is not strictly ordered",
        ));
    }
    Ok(digest_hex(
        DIRECT_SOCIAL_GRAPH_V1_DOMAIN_EVIDENCE_DIGEST,
        |fields| {
            fields.push((evidence.len() as u64).to_be_bytes().to_vec());
            fields.extend(leaves);
        },
    ))
}

pub fn direct_social_graph_v1_holder_commitment(
    holder_public_key_b64: &str,
) -> Result<String, DirectSocialGraphV1Error> {
    let key = base64_bytes(holder_public_key_b64, 32, "invalid holder public key")?;
    Ok(digest_hex(
        DIRECT_SOCIAL_GRAPH_V1_DOMAIN_HOLDER_COMMITMENT,
        |fields| {
            fields.push(key);
        },
    ))
}

pub fn direct_social_graph_v1_subject_binding(
    subject: &str,
    holder_commitment: &str,
) -> Result<String, DirectSocialGraphV1Error> {
    let subject = hex_bytes(subject, 32, "invalid Clout subject")?;
    let commitment = hex_bytes(holder_commitment, 32, "invalid holder commitment")?;
    Ok(digest_hex(
        DIRECT_SOCIAL_GRAPH_V1_DOMAIN_SUBJECT_BINDING,
        |fields| {
            fields.push(subject);
            fields.push(commitment);
        },
    ))
}

/// Canonical bytes signed by the subject's Ed25519 key for an attestation
/// request.  The nonce and timestamp make the signed binding one-use and
/// time-scoped without exposing the evidence to the attester's consumers.
pub fn direct_social_graph_v1_subject_binding_transcript(
    attester_id: &str,
    policy_id: &str,
    request_nonce: &str,
    timestamp: u64,
    subject: &str,
    holder_commitment: &str,
) -> Result<Vec<u8>, DirectSocialGraphV1Error> {
    bounded_text(attester_id, "invalid attester id")?;
    bounded_text(policy_id, "invalid policy id")?;
    let nonce = hex_bytes(request_nonce, 16, "invalid request nonce")?;
    let subject = hex_bytes(subject, 32, "invalid Clout subject")?;
    let commitment = hex_bytes(holder_commitment, 32, "invalid holder commitment")?;
    let mut transcript = Vec::new();
    put_text(&mut transcript, attester_id)?;
    put_text(&mut transcript, policy_id)?;
    put_raw(&mut transcript, &nonce);
    put_raw(&mut transcript, &timestamp.to_be_bytes());
    put_raw(&mut transcript, &subject);
    put_raw(&mut transcript, &commitment);
    let mut output = DIRECT_SOCIAL_GRAPH_V1_DOMAIN_SUBJECT_BINDING.to_vec();
    output.extend_from_slice(&transcript);
    Ok(output)
}

pub fn direct_social_graph_v1_attestation_digest(
    attestation: &DirectSocialGraphV1Attestation,
) -> Result<String, DirectSocialGraphV1Error> {
    attestation.validate()?;
    let nullifier = hex_bytes(&attestation.quota_nullifier, 32, "invalid quota nullifier")?;
    Ok(digest_hex(
        DIRECT_SOCIAL_GRAPH_V1_DOMAIN_ATTESTATION_DIGEST,
        |fields| {
            fields.push(attestation.version.to_be_bytes().to_vec());
            fields.push(attestation.profile_id.as_bytes().to_vec());
            fields.push(attestation.attester_id.as_bytes().to_vec());
            fields.push(attestation.kid.as_bytes().to_vec());
            fields.push(attestation.policy_id.as_bytes().to_vec());
            fields.push(attestation.issued_at.to_be_bytes().to_vec());
            fields.push(attestation.expires_at.to_be_bytes().to_vec());
            fields.push(vec![attestation.eligibility_level]);
            fields.push(nullifier.clone());
            fields.push(attestation.jti.as_bytes().to_vec());
            fields.push(hex_bytes_unchecked(&attestation.holder_commitment));
        },
    ))
}

pub fn direct_social_graph_v1_request_binding_digest(binding: &[u8]) -> String {
    digest_hex(DIRECT_SOCIAL_GRAPH_V1_DOMAIN_REQUEST_BINDING, |fields| {
        fields.push(binding.to_vec());
    })
}

pub fn direct_social_graph_v1_presentation_digest(
    presentation: &DirectSocialGraphV1Presentation,
) -> Result<String, DirectSocialGraphV1Error> {
    presentation.validate()?;
    let attestation_digest = direct_social_graph_v1_attestation_digest(&presentation.attestation)?;
    Ok(digest_hex(
        DIRECT_SOCIAL_GRAPH_V1_DOMAIN_PRESENTATION_DIGEST,
        |fields| {
            fields.push(presentation.version.to_be_bytes().to_vec());
            fields.push(presentation.profile_id.as_bytes().to_vec());
            fields.push(hex_bytes_unchecked(&attestation_digest));
            fields.push(presentation.app_id.as_bytes().to_vec());
            fields.push(presentation.request_id.as_bytes().to_vec());
            fields.push(hex_bytes_unchecked(&presentation.request_binding_hash));
            fields.push(presentation.created_at.to_be_bytes().to_vec());
            fields.push(presentation.expires_at.to_be_bytes().to_vec());
        },
    ))
}

pub fn direct_social_graph_v1_jwks_kid_digest(
    public_key_b64: &str,
) -> Result<String, DirectSocialGraphV1Error> {
    let public_key = base64_bytes(public_key_b64, 32, "invalid JWKS public key")?;
    Ok(lower_hex(&Sha256::digest(public_key)))
}

/// Derive an epoch-scoped, issuer-visible quota nullifier.  The caller must
/// provide the attester-held HMAC key; it is never serialized in this module.
pub fn direct_social_graph_v1_quota_nullifier(
    hmac_key: &[u8],
    attester_id: &str,
    policy_id: &str,
    subject: &str,
    now_secs: u64,
) -> Result<String, DirectSocialGraphV1Error> {
    bounded_text(attester_id, "invalid attester id")?;
    bounded_text(policy_id, "invalid policy id")?;
    let subject = hex_bytes(subject, 32, "invalid Clout subject")?;
    let epoch = now_secs / DIRECT_SOCIAL_GRAPH_V1_QUOTA_PERIOD_SECS;
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .map_err(|_| DirectSocialGraphV1Error("invalid quota HMAC key"))?;
    mac.update(b"freebird direct social graph v1 quota nullifier\0");
    put_hmac_text(&mut mac, attester_id);
    put_hmac_text(&mut mac, policy_id);
    mac.update(&epoch.to_be_bytes());
    mac.update(&subject);
    Ok(lower_hex(&mac.finalize().into_bytes()))
}

fn put_hmac_text(mac: &mut HmacSha256, value: &str) {
    mac.update(&(value.len() as u32).to_be_bytes());
    mac.update(value.as_bytes());
}

fn put_text(output: &mut Vec<u8>, value: &str) -> Result<(), DirectSocialGraphV1Error> {
    bounded_text(value, "invalid text")?;
    put_raw(output, &(value.len() as u32).to_be_bytes());
    put_raw(output, value.as_bytes());
    Ok(())
}

fn put_raw(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(value);
}

fn digest_hex<F>(domain: &[u8], append: F) -> String
where
    F: FnOnce(&mut Vec<Vec<u8>>),
{
    let mut fields = Vec::new();
    append(&mut fields);
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u32).to_be_bytes());
        hasher.update(field);
    }
    lower_hex(&hasher.finalize())
}

fn bounded_text(value: &str, error: &'static str) -> Result<(), DirectSocialGraphV1Error> {
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
        Err(DirectSocialGraphV1Error(error))
    } else {
        Ok(())
    }
}

fn hex_bytes(
    value: &str,
    expected_len: usize,
    error: &'static str,
) -> Result<Vec<u8>, DirectSocialGraphV1Error> {
    if value.len() != expected_len * 2
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(DirectSocialGraphV1Error(error));
    }
    hex::decode(value).map_err(|_| DirectSocialGraphV1Error(error))
}

fn hex_bytes_unchecked(value: &str) -> Vec<u8> {
    // Callers use this only after hex_bytes has validated the field.
    hex::decode(value).expect("validated lowercase hex")
}

fn base64_bytes(
    value: &str,
    expected_len: usize,
    error: &'static str,
) -> Result<Vec<u8>, DirectSocialGraphV1Error> {
    let bytes =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| DirectSocialGraphV1Error(error))?;
    if bytes.len() != expected_len || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(DirectSocialGraphV1Error(error));
    }
    Ok(bytes)
}

fn lower_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(truster: &str, trustee: &str, timestamp: u64) -> DirectSocialGraphV1CloutEdge {
        DirectSocialGraphV1CloutEdge {
            truster: truster.into(),
            trustee: trustee.into(),
            weight_micros: 500_000,
            timestamp,
            revoked: false,
            signature: "11".repeat(64),
        }
    }

    #[test]
    fn clout_zero_weight_preserves_revocation_signal() {
        let edge = DirectSocialGraphV1CloutEdge {
            truster: "11".repeat(32),
            trustee: "22".repeat(32),
            weight_micros: 0,
            timestamp: 7,
            revoked: false,
            signature: "33".repeat(64),
        };
        let signal = String::from_utf8(edge.canonical_signal().unwrap()).unwrap();
        assert!(signal.starts_with("CLOUT_TRUST_SIGNAL_V1:"));
        assert!(edge.validate().is_ok());
        assert_eq!(
            String::from_utf8(edge.canonical_signal().unwrap()).unwrap(),
            "CLOUT_TRUST_SIGNAL_V1:a80f597391fd29c99ca4ed5f7bb05c80f3352512ee4fa87716a43a572f6de72a"
        );
    }

    #[test]
    fn evidence_order_and_encodings_are_strict() {
        let a = edge(&"11".repeat(32), &"22".repeat(32), 1);
        let b = edge(&"22".repeat(32), &"33".repeat(32), 2);
        let (first, second) =
            if a.canonical_order_bytes().unwrap() < b.canonical_order_bytes().unwrap() {
                (a.clone(), b.clone())
            } else {
                (b.clone(), a.clone())
            };
        assert!(direct_social_graph_v1_evidence_digest(&[first.clone(), second.clone()]).is_ok());
        assert!(direct_social_graph_v1_evidence_digest(&[second, first]).is_err());
        assert!(hex_bytes("AA", 1, "bad").is_err());
        assert!(base64_bytes("AQ==", 1, "bad").is_err());
    }

    #[test]
    fn holder_commitment_is_canonical_base64url_bound() {
        let key = Base64UrlUnpadded::encode_string(&[7_u8; 32]);
        let commitment = direct_social_graph_v1_holder_commitment(&key).unwrap();
        assert_eq!(commitment.len(), 64);
        assert!(direct_social_graph_v1_holder_commitment(&(key + "=")).is_err());
    }

    #[test]
    fn request_binding_fixed_vector() {
        assert_eq!(
            direct_social_graph_v1_request_binding_digest(b"request"),
            "56d7f38fc97b70ec2c876d1dab827e56aec0aa33b1ebae7fb2345a6ba18ceded"
        );
    }

    #[test]
    fn keyset_requires_one_active_unique_valid_key() {
        let key = DirectSocialGraphV1Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            kid: hex::encode(Sha256::digest([9_u8; 32])),
            use_: "sig".into(),
            alg: "EdDSA".into(),
            x: Base64UrlUnpadded::encode_string(&[9_u8; 32]),
            state: DirectSocialGraphV1KeyState::Active,
            valid_from: 10,
            valid_until: 20,
            revoked_at: None,
        };
        let keyset = DirectSocialGraphV1Keyset {
            version: 1,
            profile_id: DIRECT_SOCIAL_GRAPH_V1_KEYSET_PROFILE.into(),
            attester_id: "attester".into(),
            published_at: 10,
            keys: vec![key],
        };
        assert!(keyset.validate_at(11).is_ok());
        assert!(keyset.validate_at(911).is_err());
    }

    #[test]
    fn quota_and_jwks_vectors_are_literal() {
        assert_eq!(
            direct_social_graph_v1_quota_nullifier(
                &(0..32).collect::<Vec<_>>(),
                "attester",
                "policy",
                &"22".repeat(32),
                172_800,
            )
            .unwrap(),
            "a82a793a1a20c3c379b078c1909786f5b4bfb8edfc125ec10c9b1a5a38d7f473"
        );
        let public_key = Base64UrlUnpadded::encode_string(&[9_u8; 32]);
        assert_eq!(
            direct_social_graph_v1_jwks_kid_digest(&public_key).unwrap(),
            "8c0cc17a04942cc4f8e0fe0b302606d3108860c126428ba2ceeb5f9ed41c2b05"
        );
    }

    #[test]
    fn attestation_and_presentation_vectors_are_literal() {
        let attestation = DirectSocialGraphV1Attestation {
            version: 1,
            profile_id: DIRECT_SOCIAL_GRAPH_V1_ATTESTATION_PROFILE.into(),
            attester_id: "attester".into(),
            kid: "kid".into(),
            policy_id: "policy".into(),
            issued_at: 1,
            expires_at: 2,
            eligibility_level: 1,
            quota_nullifier: "11".repeat(32),
            jti: "jti".into(),
            holder_commitment: "22".repeat(32),
            signature: "33".repeat(64),
        };
        assert_eq!(
            attestation.digest().unwrap(),
            "544b752e029d52bec06e0621b6ff3cbe4a55ebab36ce0c9958f584f781e74b98"
        );
        let presentation = DirectSocialGraphV1Presentation {
            version: 1,
            profile_id: DIRECT_SOCIAL_GRAPH_V1_PRESENTATION_PROFILE.into(),
            attestation,
            app_id: "app".into(),
            request_id: "req".into(),
            request_binding_hash: "44".repeat(32),
            created_at: 1,
            expires_at: 2,
        };
        assert_eq!(
            direct_social_graph_v1_presentation_digest(&presentation).unwrap(),
            "f3454876fe36dd3d06d5c1e5188d2ca1773933c8125cd176a70cbe7e6f8d4fac"
        );
    }

    #[test]
    fn subject_binding_transcript_vector_is_literal() {
        let transcript = direct_social_graph_v1_subject_binding_transcript(
            "attester",
            "policy",
            &"33".repeat(16),
            7,
            &"22".repeat(32),
            &"11".repeat(32),
        )
        .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(transcript)),
            "409aea183faff432334e66660c45a95d329747bce310914cd216a0f832b8aa31"
        );
    }
}
