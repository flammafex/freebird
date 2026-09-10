// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Closed native V8 graph-issuance contract.
//!
//! All fixed-width values are decoded before entering a digest transcript.
//! JSON is transport only: validation rejects padded, non-canonical, or
//! incorrectly sized encodings before any value is authenticated.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const NATIVE_GRAPH_ISSUANCE_V8_VERSION: u8 = 8;
pub const NATIVE_GRAPH_ISSUANCE_V8_PROFILE_ID: &str = "freebird/native-graph-issuance/v8";
pub const NATIVE_GRAPH_ISSUANCE_V8_SUITE: &str = "RSABSSA-SHA384-PSS-Randomized-V7";
pub const NATIVE_GRAPH_ISSUANCE_V8_MODULUS_BITS: u16 = 3072;
pub const NATIVE_GRAPH_ISSUANCE_V8_EXPONENT: u32 = 65_537;
pub const NATIVE_GRAPH_ISSUANCE_V8_QUANTITY: u32 = 1;
pub const NATIVE_GRAPH_ISSUANCE_V8_RECOVERY_LIFETIME_SECS: u64 = 2_592_000;
pub const NATIVE_GRAPH_ISSUANCE_V8_RECOVERY_LIFETIME: u64 =
    NATIVE_GRAPH_ISSUANCE_V8_RECOVERY_LIFETIME_SECS;
pub const NATIVE_GRAPH_ISSUANCE_V8_ADMISSION_PROFILE_ID: &str = "scarcity/native-bearer/v7";
pub const NATIVE_GRAPH_ISSUANCE_V8_RAW384_BYTES: usize = 384;
pub const NATIVE_GRAPH_ISSUANCE_V8_MAX_ARTIFACT_BYTES: usize = 16 * 1024;

pub const NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_POLICY: &[u8] =
    b"freebird native graph issuance policy v8\0";
pub const NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_OWNER_COMMITMENT: &[u8] =
    b"freebird native graph issuance owner commitment v8\0";
pub const NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_OWNER_PROOF: &[u8] =
    b"freebird native graph issuance owner proof v8\0";
pub const NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_REQUEST: &[u8] =
    b"freebird native graph issuance request v8\0";
pub const NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_REPLAY: &[u8] =
    b"freebird native graph issuance replay v8\0";
pub const NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_REPLAY_IDENTITY: &[u8] =
    NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_REPLAY;
pub const NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_RESULT: &[u8] =
    b"freebird native graph issuance result v8\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionState {
    AcceptingNew,
    RecoveryOnly,
    Disabled,
}

pub type NativeGraphIssuanceV8AdmissionState = AdmissionState;
pub type GraphIssuanceAdmissionStateV8 = AdmissionState;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGraphIssuanceV8Policy {
    pub policy_id: String,
    pub profile_id: String,
    pub graph_id: String,
    pub keyset_id: String,
    pub descriptor_id: String,
    pub token_key_id: String,
    pub issuer_id: String,
    pub asset_id: String,
    pub amount_minor: String,
    pub suite: String,
    pub modulus_bits: u16,
    pub exponent: u32,
    pub quantity: u32,
    pub pubkey_spki_b64: String,
    pub spki_fingerprint: String,
    pub valid_from: i64,
    pub valid_until: i64,
    pub admission_profile_id: String,
    pub admission_issuer_id: String,
    pub admission_token_key_id: String,
    pub admission_asset_id: String,
    pub admission_amount_minor: String,
    pub admission_state: AdmissionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGraphIssuanceV8Discovery {
    pub version: u8,
    pub profile_id: String,
    pub policies: Vec<NativeGraphIssuanceV8Policy>,
    pub recovery_lifetime_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGraphIssuanceV8Request {
    pub version: u8,
    pub profile_id: String,
    pub issuer_id: String,
    pub public_operation_id: String,
    pub status_capability_digest: String,
    pub graph_id: String,
    pub policy_id: String,
    pub keyset_id: String,
    pub descriptor_id: String,
    pub token_key_id: String,
    pub asset_id: String,
    pub amount_minor: String,
    pub quantity: u32,
    pub blinded_message: String,
    pub owner_commitment: String,
    pub admission_artifact: String,
    pub holder_public_key: String,
    pub binding_secret: String,
    pub owner_proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGraphIssuanceV8Result {
    pub version: u8,
    pub profile_id: String,
    pub issuer_id: String,
    pub public_operation_id: String,
    pub graph_id: String,
    pub policy_id: String,
    pub keyset_id: String,
    pub descriptor_id: String,
    pub token_key_id: String,
    pub asset_id: String,
    pub amount_minor: String,
    pub quantity: u32,
    pub blinded_message: String,
    pub owner_commitment: String,
    pub replay_digest: String,
    pub request_digest: String,
    pub blind_signature: String,
    pub result_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeGraphIssuanceV8Error(pub &'static str);

impl std::fmt::Display for NativeGraphIssuanceV8Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for NativeGraphIssuanceV8Error {}

impl NativeGraphIssuanceV8Policy {
    pub fn validate(&self) -> Result<(), NativeGraphIssuanceV8Error> {
        policy_transcript(self)?;
        let spki = canonical_b64(&self.pubkey_spki_b64, 4096, "invalid V8 policy SPKI")?;
        let fingerprint = raw_hex32(&self.spki_fingerprint, "invalid V8 policy SPKI fingerprint")?;
        if Sha256::digest(&spki)[..] != fingerprint[..] {
            return Err(NativeGraphIssuanceV8Error(
                "V8 policy SPKI fingerprint mismatch",
            ));
        }
        for value in [
            &self.graph_id,
            &self.keyset_id,
            &self.descriptor_id,
            &self.token_key_id,
            &self.admission_token_key_id,
        ] {
            raw_hex32(value, "invalid V8 policy selector")?;
        }
        let expected = derive_native_graph_issuance_v8_policy_id(self)?;
        if self.policy_id != expected {
            return Err(NativeGraphIssuanceV8Error("V8 policy id mismatch"));
        }
        Ok(())
    }

    pub fn policy_id_bytes(&self) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
        raw_hex32(&self.policy_id, "invalid V8 policy id")
    }
}

impl NativeGraphIssuanceV8Discovery {
    pub fn validate(&self) -> Result<(), NativeGraphIssuanceV8Error> {
        if self.version != NATIVE_GRAPH_ISSUANCE_V8_VERSION
            || self.profile_id != NATIVE_GRAPH_ISSUANCE_V8_PROFILE_ID
            || self.recovery_lifetime_secs != NATIVE_GRAPH_ISSUANCE_V8_RECOVERY_LIFETIME_SECS
        {
            return Err(NativeGraphIssuanceV8Error("invalid V8 graph discovery"));
        }
        let mut ids = std::collections::HashSet::new();
        for policy in &self.policies {
            policy.validate()?;
            if !ids.insert(policy.policy_id.as_str()) {
                return Err(NativeGraphIssuanceV8Error("duplicate V8 policy id"));
            }
        }
        Ok(())
    }
}

impl NativeGraphIssuanceV8Request {
    pub fn validate(&self) -> Result<(), NativeGraphIssuanceV8Error> {
        self.canonical_bytes().map(|_| ())
    }

    pub fn owner_commitment_digest(&self) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
        native_graph_issuance_v8_owner_commitment_digest(
            &self.issuer_id,
            &self.graph_id,
            &self.policy_id,
            &self.holder_public_key,
            &self.binding_secret,
        )
    }

    pub fn owner_proof_digest(&self) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
        let transcript = self.canonical_bytes_without_owner_proof()?;
        Ok(hash(
            NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_OWNER_PROOF,
            &transcript,
        ))
    }

    pub fn request_digest(&self) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
        Ok(hash(
            NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_REQUEST,
            &self.canonical_bytes()?,
        ))
    }

    pub fn replay_digest(
        &self,
        admission_issuer_id: &str,
        nullifier: &[u8; 32],
    ) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
        native_graph_issuance_v8_replay_digest(admission_issuer_id, nullifier)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeGraphIssuanceV8Error> {
        let mut out = self.canonical_bytes_without_owner_proof()?;
        out.extend_from_slice(&exact_b64::<64>(
            &self.owner_proof,
            "V8 owner proof must be raw64",
        )?);
        Ok(out)
    }

    fn canonical_bytes_without_owner_proof(&self) -> Result<Vec<u8>, NativeGraphIssuanceV8Error> {
        let mut out = request_prefix(self)?;
        let owner_commitment = raw_hex32(&self.owner_commitment, "invalid V8 owner commitment")?;
        if owner_commitment
            .ct_eq(&self.owner_commitment_digest()?)
            .unwrap_u8()
            != 1
        {
            return Err(NativeGraphIssuanceV8Error("V8 owner commitment mismatch"));
        }
        out.extend_from_slice(&owner_commitment);
        let artifact = canonical_b64(
            &self.admission_artifact,
            NATIVE_GRAPH_ISSUANCE_V8_MAX_ARTIFACT_BYTES,
            "V8 admission artifact must be canonical base64url",
        )?;
        put_lp32(&mut out, &artifact)?;
        out.extend_from_slice(&exact_b64::<32>(
            &self.holder_public_key,
            "V8 holder public key must be raw32",
        )?);
        out.extend_from_slice(&exact_b64::<32>(
            &self.binding_secret,
            "V8 binding secret must be raw32",
        )?);
        Ok(out)
    }
}

impl NativeGraphIssuanceV8Result {
    pub fn validate(&self) -> Result<(), NativeGraphIssuanceV8Error> {
        let expected = self.result_digest()?;
        if raw_hex32(&self.result_digest, "invalid V8 result digest")?
            .ct_eq(&expected)
            .unwrap_u8()
            != 1
        {
            return Err(NativeGraphIssuanceV8Error("V8 result digest mismatch"));
        }
        Ok(())
    }

    pub fn result_digest(&self) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
        Ok(hash(
            NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_RESULT,
            &self.canonical_bytes()?,
        ))
    }

    pub fn result_digest_bytes(&self) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
        self.result_digest()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeGraphIssuanceV8Error> {
        let mut out = result_prefix(self)?;
        put_raw32(
            &mut out,
            &self.owner_commitment,
            "invalid V8 owner commitment",
        )?;
        put_raw32(&mut out, &self.replay_digest, "invalid V8 replay digest")?;
        put_raw32(&mut out, &self.request_digest, "invalid V8 request digest")?;
        out.extend_from_slice(&exact_b64::<NATIVE_GRAPH_ISSUANCE_V8_RAW384_BYTES>(
            &self.blind_signature,
            "V8 signature must be raw384",
        )?);
        Ok(out)
    }
}

/// Derive the policy identity.  Every policy member is included except the
/// self-referential `policy_id` and lifecycle-only `admission_state`.
pub fn derive_native_graph_issuance_v8_policy_id(
    policy: &NativeGraphIssuanceV8Policy,
) -> Result<String, NativeGraphIssuanceV8Error> {
    Ok(hex::encode(hash(
        NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_POLICY,
        &policy_transcript(policy)?,
    )))
}

pub fn native_graph_issuance_v8_owner_commitment_digest(
    issuer_id: &str,
    graph_id: &str,
    policy_id: &str,
    holder_public_key: &str,
    binding_secret: &str,
) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
    let graph_id = raw_hex32(graph_id, "invalid V8 graph id")?;
    let policy_id = raw_hex32(policy_id, "invalid V8 policy id")?;
    if issuer_id.is_empty() || issuer_id.len() > 128 || !issuer_id.is_ascii() {
        return Err(NativeGraphIssuanceV8Error("invalid V8 issuer id"));
    }
    let public_key = exact_b64::<32>(holder_public_key, "V8 holder public key must be raw32")?;
    let secret = exact_b64::<32>(binding_secret, "V8 binding secret must be raw32")?;
    let mut transcript = Vec::with_capacity(4 + issuer_id.len() + 96);
    put_text(&mut transcript, issuer_id, "invalid V8 issuer id")?;
    transcript.extend_from_slice(&graph_id);
    transcript.extend_from_slice(&policy_id);
    transcript.extend_from_slice(&public_key);
    transcript.extend_from_slice(&secret);
    Ok(hash(
        NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_OWNER_COMMITMENT,
        &transcript,
    ))
}

pub fn native_graph_issuance_v8_owner_proof_digest(
    request: &NativeGraphIssuanceV8Request,
) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
    request.owner_proof_digest()
}

pub fn native_graph_issuance_v8_request_digest(
    request: &NativeGraphIssuanceV8Request,
) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
    request.request_digest()
}

pub fn native_graph_issuance_v8_replay_digest(
    admission_issuer_id: &str,
    nullifier: &[u8; 32],
) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
    let mut transcript = Vec::new();
    put_text(
        &mut transcript,
        admission_issuer_id,
        "invalid V8 admission issuer id",
    )?;
    transcript.extend_from_slice(nullifier);
    Ok(hash(NATIVE_GRAPH_ISSUANCE_V8_DOMAIN_REPLAY, &transcript))
}

pub fn native_graph_issuance_v8_result_digest(
    result: &NativeGraphIssuanceV8Result,
) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
    result.result_digest()
}

pub fn native_graph_issuance_v8_policy_id(
    policy: &NativeGraphIssuanceV8Policy,
) -> Result<String, NativeGraphIssuanceV8Error> {
    derive_native_graph_issuance_v8_policy_id(policy)
}

fn policy_transcript(
    policy: &NativeGraphIssuanceV8Policy,
) -> Result<Vec<u8>, NativeGraphIssuanceV8Error> {
    if policy.profile_id != NATIVE_GRAPH_ISSUANCE_V8_PROFILE_ID
        || policy.suite != NATIVE_GRAPH_ISSUANCE_V8_SUITE
        || policy.modulus_bits != NATIVE_GRAPH_ISSUANCE_V8_MODULUS_BITS
        || policy.exponent != NATIVE_GRAPH_ISSUANCE_V8_EXPONENT
        || policy.quantity != NATIVE_GRAPH_ISSUANCE_V8_QUANTITY
        || policy.valid_from < 0
        || policy.valid_from >= policy.valid_until
        || policy.valid_until > 9_007_199_254_740_991
        || policy.admission_profile_id != NATIVE_GRAPH_ISSUANCE_V8_ADMISSION_PROFILE_ID
    {
        return Err(NativeGraphIssuanceV8Error(
            "invalid V8 graph policy constants",
        ));
    }
    let mut out = vec![NATIVE_GRAPH_ISSUANCE_V8_VERSION];
    put_text(&mut out, &policy.profile_id, "invalid V8 profile")?;
    for value in [
        &policy.graph_id,
        &policy.keyset_id,
        &policy.descriptor_id,
        &policy.token_key_id,
    ] {
        put_raw32(&mut out, value, "invalid V8 output selector")?;
    }
    for value in [&policy.issuer_id, &policy.asset_id] {
        put_text(&mut out, value, "invalid V8 output metadata")?;
    }
    out.extend_from_slice(&amount(&policy.amount_minor)?.to_be_bytes());
    out.extend_from_slice(&policy.modulus_bits.to_be_bytes());
    out.extend_from_slice(&policy.exponent.to_be_bytes());
    out.extend_from_slice(&policy.quantity.to_be_bytes());
    put_lp32(
        &mut out,
        &canonical_b64(&policy.pubkey_spki_b64, 4096, "invalid V8 policy SPKI")?,
    )?;
    put_raw32(
        &mut out,
        &policy.spki_fingerprint,
        "invalid V8 policy SPKI fingerprint",
    )?;
    out.extend_from_slice(&(policy.valid_from as u64).to_be_bytes());
    out.extend_from_slice(&(policy.valid_until as u64).to_be_bytes());
    put_text(
        &mut out,
        &policy.admission_profile_id,
        "invalid V8 admission profile",
    )?;
    put_text(
        &mut out,
        &policy.admission_issuer_id,
        "invalid V8 admission issuer",
    )?;
    put_raw32(
        &mut out,
        &policy.admission_token_key_id,
        "invalid V8 admission token key id",
    )?;
    put_text(
        &mut out,
        &policy.admission_asset_id,
        "invalid V8 admission asset",
    )?;
    out.extend_from_slice(&amount(&policy.admission_amount_minor)?.to_be_bytes());
    Ok(out)
}

fn request_prefix(
    request: &NativeGraphIssuanceV8Request,
) -> Result<Vec<u8>, NativeGraphIssuanceV8Error> {
    if request.version != NATIVE_GRAPH_ISSUANCE_V8_VERSION
        || request.profile_id != NATIVE_GRAPH_ISSUANCE_V8_PROFILE_ID
        || request.quantity != NATIVE_GRAPH_ISSUANCE_V8_QUANTITY
    {
        return Err(NativeGraphIssuanceV8Error(
            "invalid V8 graph request constants",
        ));
    }
    let mut out = vec![request.version];
    put_text(&mut out, &request.profile_id, "invalid V8 profile")?;
    put_text(&mut out, &request.issuer_id, "invalid V8 issuer id")?;
    out.extend_from_slice(&exact_b64::<16>(
        &request.public_operation_id,
        "V8 operation id must be raw16",
    )?);
    put_raw32(
        &mut out,
        &request.status_capability_digest,
        "invalid V8 status capability digest",
    )?;
    append_request_output_fields(
        &mut out,
        &request.graph_id,
        &request.policy_id,
        &request.keyset_id,
        &request.descriptor_id,
        &request.token_key_id,
        &request.asset_id,
        &request.amount_minor,
        request.quantity,
        &request.blinded_message,
    )?;
    Ok(out)
}

fn result_prefix(
    result: &NativeGraphIssuanceV8Result,
) -> Result<Vec<u8>, NativeGraphIssuanceV8Error> {
    if result.version != NATIVE_GRAPH_ISSUANCE_V8_VERSION
        || result.profile_id != NATIVE_GRAPH_ISSUANCE_V8_PROFILE_ID
        || result.quantity != NATIVE_GRAPH_ISSUANCE_V8_QUANTITY
    {
        return Err(NativeGraphIssuanceV8Error(
            "invalid V8 graph result constants",
        ));
    }
    let mut out = vec![result.version];
    put_text(&mut out, &result.profile_id, "invalid V8 profile")?;
    put_text(&mut out, &result.issuer_id, "invalid V8 issuer id")?;
    out.extend_from_slice(&exact_b64::<16>(
        &result.public_operation_id,
        "V8 operation id must be raw16",
    )?);
    append_request_output_fields(
        &mut out,
        &result.graph_id,
        &result.policy_id,
        &result.keyset_id,
        &result.descriptor_id,
        &result.token_key_id,
        &result.asset_id,
        &result.amount_minor,
        result.quantity,
        &result.blinded_message,
    )?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn append_request_output_fields(
    out: &mut Vec<u8>,
    graph_id: &str,
    policy_id: &str,
    keyset_id: &str,
    descriptor_id: &str,
    token_key_id: &str,
    asset_id: &str,
    amount_minor: &str,
    quantity: u32,
    blinded_message: &str,
) -> Result<(), NativeGraphIssuanceV8Error> {
    for value in [graph_id, policy_id, keyset_id, descriptor_id, token_key_id] {
        put_raw32(out, value, "invalid V8 request selector")?;
    }
    put_text(out, asset_id, "invalid V8 asset id")?;
    out.extend_from_slice(&amount(amount_minor)?.to_be_bytes());
    out.extend_from_slice(&quantity.to_be_bytes());
    out.extend_from_slice(&exact_b64::<NATIVE_GRAPH_ISSUANCE_V8_RAW384_BYTES>(
        blinded_message,
        "V8 blind must be raw384",
    )?);
    Ok(())
}

fn raw_hex32(value: &str, error: &'static str) -> Result<[u8; 32], NativeGraphIssuanceV8Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(NativeGraphIssuanceV8Error(error));
    }
    hex::decode(value)
        .map_err(|_| NativeGraphIssuanceV8Error(error))?
        .try_into()
        .map_err(|_| NativeGraphIssuanceV8Error(error))
}

fn exact_b64<const N: usize>(
    value: &str,
    error: &'static str,
) -> Result<[u8; N], NativeGraphIssuanceV8Error> {
    if value.contains('=') {
        return Err(NativeGraphIssuanceV8Error(error));
    }
    let bytes =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| NativeGraphIssuanceV8Error(error))?;
    if bytes.len() != N || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(NativeGraphIssuanceV8Error(error));
    }
    bytes
        .try_into()
        .map_err(|_| NativeGraphIssuanceV8Error(error))
}

fn canonical_b64(
    value: &str,
    maximum: usize,
    error: &'static str,
) -> Result<Vec<u8>, NativeGraphIssuanceV8Error> {
    if value.contains('=') {
        return Err(NativeGraphIssuanceV8Error(error));
    }
    let bytes =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| NativeGraphIssuanceV8Error(error))?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || Base64UrlUnpadded::encode_string(&bytes) != value
    {
        return Err(NativeGraphIssuanceV8Error(error));
    }
    Ok(bytes)
}

fn put_text(
    output: &mut Vec<u8>,
    value: &str,
    error: &'static str,
) -> Result<(), NativeGraphIssuanceV8Error> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(NativeGraphIssuanceV8Error(error));
    }
    put_lp32(output, value.as_bytes())
}

fn put_raw32(
    output: &mut Vec<u8>,
    value: &str,
    error: &'static str,
) -> Result<(), NativeGraphIssuanceV8Error> {
    output.extend_from_slice(&raw_hex32(value, error)?);
    Ok(())
}

fn put_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), NativeGraphIssuanceV8Error> {
    let length = u32::try_from(value.len())
        .map_err(|_| NativeGraphIssuanceV8Error("V8 transcript value too long"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn amount(value: &str) -> Result<u64, NativeGraphIssuanceV8Error> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(NativeGraphIssuanceV8Error("invalid V8 amount"));
    }
    let amount = value
        .parse::<u64>()
        .map_err(|_| NativeGraphIssuanceV8Error("invalid V8 amount"))?;
    if amount == 0 {
        return Err(NativeGraphIssuanceV8Error("V8 amount must be nonzero"));
    }
    Ok(amount)
}

fn hash(domain: &[u8], transcript: &[u8]) -> [u8; 32] {
    Sha256::digest([domain, transcript].concat()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> NativeGraphIssuanceV8Policy {
        let spki = Base64UrlUnpadded::encode_string(&[1, 2, 3]);
        let fingerprint = hex::encode(Sha256::digest([1, 2, 3]));
        let mut policy = NativeGraphIssuanceV8Policy {
            policy_id: String::new(),
            profile_id: NATIVE_GRAPH_ISSUANCE_V8_PROFILE_ID.into(),
            graph_id: "11".repeat(32),
            keyset_id: "22".repeat(32),
            descriptor_id: "33".repeat(32),
            token_key_id: "44".repeat(32),
            issuer_id: "issuer:test".into(),
            asset_id: "USD".into(),
            amount_minor: "42".into(),
            suite: "RSABSSA-SHA384-PSS-Randomized-V7".into(),
            modulus_bits: 3072,
            exponent: 65_537,
            quantity: 1,
            pubkey_spki_b64: spki,
            spki_fingerprint: fingerprint,
            valid_from: 1,
            valid_until: 2,
            admission_profile_id: NATIVE_GRAPH_ISSUANCE_V8_ADMISSION_PROFILE_ID.into(),
            admission_issuer_id: "admission:test".into(),
            admission_token_key_id: "55".repeat(32),
            admission_asset_id: "USD".into(),
            admission_amount_minor: "1".into(),
            admission_state: AdmissionState::AcceptingNew,
        };
        policy.policy_id = derive_native_graph_issuance_v8_policy_id(&policy).unwrap();
        policy
    }

    fn request() -> NativeGraphIssuanceV8Request {
        let mut request = NativeGraphIssuanceV8Request {
            version: NATIVE_GRAPH_ISSUANCE_V8_VERSION,
            profile_id: NATIVE_GRAPH_ISSUANCE_V8_PROFILE_ID.into(),
            issuer_id: "issuer:test".into(),
            public_operation_id: Base64UrlUnpadded::encode_string(&[1; 16]),
            status_capability_digest: "66".repeat(32),
            graph_id: "11".repeat(32),
            policy_id: "22".repeat(32),
            keyset_id: "33".repeat(32),
            descriptor_id: "44".repeat(32),
            token_key_id: "55".repeat(32),
            asset_id: "USD".into(),
            amount_minor: "42".into(),
            quantity: 1,
            blinded_message: Base64UrlUnpadded::encode_string(&[7; 384]),
            owner_commitment: String::new(),
            admission_artifact: Base64UrlUnpadded::encode_string(&[8; 64]),
            holder_public_key: Base64UrlUnpadded::encode_string(&[9; 32]),
            binding_secret: Base64UrlUnpadded::encode_string(&[10; 32]),
            owner_proof: Base64UrlUnpadded::encode_string(&[11; 64]),
        };
        request.owner_commitment = hex::encode(request.owner_commitment_digest().unwrap());
        request
    }

    #[test]
    fn policy_id_excludes_only_policy_id_and_admission_state() {
        let policy = policy();
        assert!(policy.validate().is_ok());
        let id = derive_native_graph_issuance_v8_policy_id(&policy).unwrap();

        let mut state = policy.clone();
        state.admission_state = AdmissionState::RecoveryOnly;
        assert_eq!(
            id,
            derive_native_graph_issuance_v8_policy_id(&state).unwrap()
        );
        state.admission_state = AdmissionState::Disabled;
        assert_eq!(
            id,
            derive_native_graph_issuance_v8_policy_id(&state).unwrap()
        );

        let mut admission = policy.clone();
        admission.admission_amount_minor = "2".into();
        assert_ne!(
            id,
            derive_native_graph_issuance_v8_policy_id(&admission).unwrap()
        );
        let mut output = policy;
        output.asset_id = "EUR".into();
        assert_ne!(
            id,
            derive_native_graph_issuance_v8_policy_id(&output).unwrap()
        );
    }

    #[test]
    fn request_digests_bind_raw_values_and_reject_noncanonical_forms() {
        let request = request();
        assert!(request.validate().is_ok());
        assert!(request.owner_proof_digest().is_ok());
        assert!(request.replay_digest("admission:test", &[12; 32]).is_ok());

        let mut changed = request.clone();
        changed.binding_secret = Base64UrlUnpadded::encode_string(&[12; 32]);
        assert_ne!(
            request.owner_commitment_digest().unwrap(),
            changed.owner_commitment_digest().unwrap()
        );
        assert!(changed.validate().is_err());

        let mut malformed = request.clone();
        malformed.holder_public_key.push('=');
        assert!(malformed.validate().is_err());
        malformed = request;
        malformed.owner_proof = Base64UrlUnpadded::encode_string(&[1; 63]);
        assert!(malformed.validate().is_err());
    }

    #[test]
    fn v8_digest_vectors_are_literal() {
        let request = request();
        assert_eq!(
            hex::encode(request.owner_commitment_digest().unwrap()),
            "27fa9040d6aef04711080e3aa0ba367634aa14a1513e245c5d351dbffa17c4e9"
        );
        assert_eq!(
            hex::encode(request.owner_proof_digest().unwrap()),
            "4ec290e5a278fd9599c94ace4d0fa9d24b015c361fe834efa24c540209a37bec"
        );
        assert_eq!(
            hex::encode(request.request_digest().unwrap()),
            "8707b043452c82d1030e1d56ac79186c63a97452bab9cf9b0b6635bdbee153ab"
        );
        assert_eq!(
            hex::encode(request.replay_digest("admission:test", &[12; 32]).unwrap()),
            "07d36b9b620d036a05a1e313ce3df5503b918629c673a58a5e800c11398b50bb"
        );
    }

    #[test]
    fn admission_state_serializes_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&AdmissionState::AcceptingNew).unwrap(),
            "\"accepting_new\""
        );
        assert_eq!(
            serde_json::to_string(&AdmissionState::RecoveryOnly).unwrap(),
            "\"recovery_only\""
        );
        assert_eq!(
            serde_json::to_string(&AdmissionState::Disabled).unwrap(),
            "\"disabled\""
        );
        assert!(serde_json::from_str::<AdmissionState>("\"acceptingNew\"").is_err());
    }

    #[test]
    fn result_digest_validation_rejects_tampering() {
        let request = request();
        let mut result = NativeGraphIssuanceV8Result {
            version: request.version,
            profile_id: request.profile_id,
            issuer_id: request.issuer_id,
            public_operation_id: request.public_operation_id,
            graph_id: request.graph_id,
            policy_id: request.policy_id,
            keyset_id: request.keyset_id,
            descriptor_id: request.descriptor_id,
            token_key_id: request.token_key_id,
            asset_id: request.asset_id,
            amount_minor: request.amount_minor,
            quantity: request.quantity,
            blinded_message: request.blinded_message,
            owner_commitment: request.owner_commitment,
            replay_digest: "77".repeat(32),
            request_digest: "88".repeat(32),
            blind_signature: Base64UrlUnpadded::encode_string(&[12; 384]),
            result_digest: String::new(),
        };
        result.result_digest = hex::encode(result.result_digest().unwrap());
        assert_eq!(
            result.result_digest,
            "8fa68d5fcc91a5cea89d12b0c10bab67ef0d4485bd46474c9ba437933c2577f2"
        );
        assert!(result.validate().is_ok());
        result.blind_signature = Base64UrlUnpadded::encode_string(&[13; 384]);
        assert!(result.validate().is_err());
    }
}
