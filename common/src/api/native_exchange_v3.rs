// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Closed native V7 batch-exchange contract (V3).
//!
//! These types are intentionally not aliases of the legacy V2 exchange model.
//! JSON is only a transport representation; validation below normalizes every
//! fixed-width value before it can participate in a digest.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::native_bearer_v7::validate_v7_identifier_namespace;

pub const NATIVE_EXCHANGE_V3_VERSION: u8 = 3;
pub const NATIVE_EXCHANGE_V3_PROFILE_ID: &str = "freebird/native-exchange/v3";
pub const NATIVE_EXCHANGE_V3_SUITE: &str = "RSABSSA-SHA384-PSS-Randomized-V7";
pub const NATIVE_EXCHANGE_V3_MAX_ITEMS: usize = 64;
pub const NATIVE_EXCHANGE_V3_QUANTITY: u32 = 1;
pub const NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS: u64 = 2_592_000;
pub const EXCHANGE_LUA_MAX_EXACT_INTEGER: u64 = (1u64 << 53) - 1;
pub const EXCHANGE_MAX_VALID_UNTIL: i64 = EXCHANGE_LUA_MAX_EXACT_INTEGER as i64;
pub const EXCHANGE_MAX_BUDGET_LIMIT: u64 = EXCHANGE_LUA_MAX_EXACT_INTEGER;
pub(crate) const NATIVE_EXCHANGE_V3_RAW384_BYTES: usize = 384;

pub const NATIVE_EXCHANGE_V3_DOMAIN_SOURCE_LEAF: &[u8] =
    b"freebird native exchange source leaf v3\0";
pub const NATIVE_EXCHANGE_V3_DOMAIN_REQUEST_OUTPUT_LEAF: &[u8] =
    b"freebird native exchange request-output leaf v3\0";
pub const NATIVE_EXCHANGE_V3_DOMAIN_RESULT_OUTPUT_LEAF: &[u8] =
    b"freebird native exchange result-output leaf v3\0";
pub const NATIVE_EXCHANGE_V3_DOMAIN_EMPTY_LEAF: &[u8] = b"freebird native exchange empty leaf v3\0";
pub const NATIVE_EXCHANGE_V3_DOMAIN_MERKLE_NODE: &[u8] =
    b"freebird native exchange merkle node v3\0";
pub const NATIVE_EXCHANGE_V3_DOMAIN_REQUEST: &[u8] = b"freebird native exchange request v3\0";
pub const NATIVE_EXCHANGE_V3_DOMAIN_RESULT: &[u8] = b"freebird native exchange result v3\0";
pub const NATIVE_EXCHANGE_V3_DOMAIN_RECEIPT: &[u8] = b"freebird native exchange receipt v3\0";
pub const NATIVE_EXCHANGE_V3_DOMAIN_DESCRIPTOR: &[u8] = b"freebird native exchange descriptor v3\0";

/// Hash one ordered source leaf using the closed V3 transcript.
pub fn native_exchange_v3_source_leaf(
    index: u32,
    artifact: &[u8],
    source_artifact_digest: &[u8; 32],
    descriptor_id: &[u8; 32],
    keyset_id: &[u8; 32],
    slot_id: &str,
) -> Result<[u8; 32], NativeExchangeV3Error> {
    if slot_id.is_empty() || slot_id.len() > 128 || !slot_id.is_ascii() {
        return Err(NativeExchangeV3Error("invalid V7 source slot"));
    }
    let mut transcript = index.to_be_bytes().to_vec();
    let length = u32::try_from(artifact.len())
        .map_err(|_| NativeExchangeV3Error("V7 artifact is too large"))?;
    transcript.extend_from_slice(&length.to_be_bytes());
    transcript.extend_from_slice(artifact);
    transcript.extend_from_slice(source_artifact_digest);
    transcript.extend_from_slice(descriptor_id);
    transcript.extend_from_slice(keyset_id);
    transcript.extend_from_slice(&(slot_id.len() as u32).to_be_bytes());
    transcript.extend_from_slice(slot_id.as_bytes());
    Ok(hash(NATIVE_EXCHANGE_V3_DOMAIN_SOURCE_LEAF, &transcript))
}

/// Hash one request-output or result-output Merkle leaf.
pub fn native_exchange_v3_output_leaf(
    result: bool,
    index: u32,
    output_id: &[u8; 16],
    commitment: &[u8; 32],
) -> [u8; 32] {
    let mut transcript = index.to_be_bytes().to_vec();
    transcript.extend_from_slice(output_id);
    transcript.extend_from_slice(commitment);
    hash(
        if result {
            NATIVE_EXCHANGE_V3_DOMAIN_RESULT_OUTPUT_LEAF
        } else {
            NATIVE_EXCHANGE_V3_DOMAIN_REQUEST_OUTPUT_LEAF
        },
        &transcript,
    )
}

/// Compute the fixed 64-leaf ordered Merkle root used by V7 exchange.
pub fn native_exchange_v3_ordered_root(
    leaves: &[[u8; 32]],
) -> Result<[u8; 32], NativeExchangeV3Error> {
    if leaves.len() > NATIVE_EXCHANGE_V3_MAX_ITEMS {
        return Err(NativeExchangeV3Error("too many V7 Merkle leaves"));
    }
    let empty = hash(NATIVE_EXCHANGE_V3_DOMAIN_EMPTY_LEAF, &[]);
    let mut level = vec![empty; NATIVE_EXCHANGE_V3_MAX_ITEMS];
    level[..leaves.len()].copy_from_slice(leaves);
    let mut width = level.len();
    while width > 1 {
        let mut next = Vec::with_capacity(width / 2);
        for pair in level[..width].as_chunks::<2>().0 {
            let mut transcript = Vec::with_capacity(64);
            transcript.extend_from_slice(&pair[0]);
            transcript.extend_from_slice(&pair[1]);
            next.push(hash(NATIVE_EXCHANGE_V3_DOMAIN_MERKLE_NODE, &transcript));
        }
        level = next;
        width /= 2;
    }
    Ok(level[0])
}

/// Generate the canonical six-sibling proof for a leaf in a fixed 64-leaf V7 tree.
pub fn native_exchange_v3_output_proof(
    leaves: &[[u8; 32]],
    index: usize,
) -> Result<String, NativeExchangeV3Error> {
    if leaves.is_empty() || leaves.len() > NATIVE_EXCHANGE_V3_MAX_ITEMS || index >= leaves.len() {
        return Err(NativeExchangeV3Error("invalid V7 Merkle proof index"));
    }
    let empty = hash(NATIVE_EXCHANGE_V3_DOMAIN_EMPTY_LEAF, &[]);
    let mut level = vec![empty; NATIVE_EXCHANGE_V3_MAX_ITEMS];
    level[..leaves.len()].copy_from_slice(leaves);
    let mut position = index;
    let mut proof = Vec::with_capacity(6 * 32);
    while level.len() > 1 {
        proof.extend_from_slice(&level[position ^ 1]);
        level = level
            .chunks_exact(2)
            .map(|pair| {
                let mut transcript = Vec::with_capacity(64);
                transcript.extend_from_slice(&pair[0]);
                transcript.extend_from_slice(&pair[1]);
                hash(NATIVE_EXCHANGE_V3_DOMAIN_MERKLE_NODE, &transcript)
            })
            .collect();
        position >>= 1;
    }
    Ok(Base64UrlUnpadded::encode_string(&proof))
}

/// Verify a canonical proof against the request-output or result-output leaf domain.
pub fn native_exchange_v3_verify_output_proof(
    result: bool,
    index: u32,
    output_id: &[u8; 16],
    commitment: &[u8; 32],
    proof: &str,
    root: &[u8; 32],
) -> Result<(), NativeExchangeV3Error> {
    if index as usize >= NATIVE_EXCHANGE_V3_MAX_ITEMS {
        return Err(NativeExchangeV3Error("invalid V7 Merkle proof index"));
    }
    let siblings = exact_b64::<192>(proof, "V7 proof must be canonical raw192")?;
    let mut node = native_exchange_v3_output_leaf(result, index, output_id, commitment);
    let mut position = index as usize;
    for sibling in siblings.chunks_exact(32) {
        let sibling: [u8; 32] = sibling
            .try_into()
            .map_err(|_| NativeExchangeV3Error("invalid V7 Merkle sibling"))?;
        let mut transcript = Vec::with_capacity(64);
        if position & 1 == 0 {
            transcript.extend_from_slice(&node);
            transcript.extend_from_slice(&sibling);
        } else {
            transcript.extend_from_slice(&sibling);
            transcript.extend_from_slice(&node);
        }
        node = hash(NATIVE_EXCHANGE_V3_DOMAIN_MERKLE_NODE, &transcript);
        position >>= 1;
    }
    if &node != root {
        return Err(NativeExchangeV3Error("V7 Merkle proof root mismatch"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Profile {
    pub version: u8,
    pub profile_id: String,
    /// Immutable graph identity bound to this V7 exchange profile.
    pub graph_id: String,
    pub suite: String,
    pub modulus_bits: u16,
    pub exponent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Descriptor {
    pub descriptor_id: String,
    pub profile_id: String,
    pub issuer_id: String,
    pub token_key_id: String,
    pub asset_id: String,
    pub amount_minor: String,
    pub suite: String,
    pub modulus_bits: u16,
    pub exponent: u32,
    pub pubkey_spki_b64: String,
    pub spki_fingerprint: String,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Keyset {
    pub keyset_id: String,
    pub profile_id: String,
    pub descriptor_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Slot {
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
    pub quantity: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Transition {
    pub transition_id: String,
    pub profile_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub source_slots: Vec<NativeExchangeV3Slot>,
    pub output_slots: Vec<NativeExchangeV3Slot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Discovery {
    pub version: u8,
    pub profile: NativeExchangeV3Profile,
    pub active_descriptors: Vec<NativeExchangeV3Descriptor>,
    pub retained_descriptors: Vec<NativeExchangeV3Descriptor>,
    pub active_keysets: Vec<NativeExchangeV3Keyset>,
    pub retained_keysets: Vec<NativeExchangeV3Keyset>,
    pub transitions: Vec<NativeExchangeV3Transition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Source {
    pub artifact: String,
    pub source_artifact_digest: String,
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Output {
    pub output_id: String,
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
    pub asset_id: String,
    pub amount_minor: String,
    pub blinded_message: String,
    pub handoff_commitment: String,
    pub request_output_commitment: String,
    pub request_output_proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3ResultOutput {
    pub output_id: String,
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
    pub asset_id: String,
    pub amount_minor: String,
    pub blinded_message: String,
    pub handoff_commitment: String,
    pub request_output_commitment: String,
    pub request_output_proof: String,
    pub result_output_commitment: String,
    pub result_output_proof: String,
    pub blind_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Request {
    pub version: u8,
    pub profile_id: String,
    pub issuer_or_federation_id: String,
    pub public_operation_id: String,
    pub graph_id: String,
    pub transition_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub asset_id: String,
    pub source_count: u32,
    pub output_count: u32,
    pub source_total_minor: String,
    pub output_total_minor: String,
    pub source_root: String,
    pub request_output_root: String,
    pub sources: Vec<NativeExchangeV3Source>,
    pub outputs: Vec<NativeExchangeV3Output>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Result {
    pub version: u8,
    pub profile_id: String,
    pub issuer_or_federation_id: String,
    pub public_operation_id: String,
    pub graph_id: String,
    pub transition_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub asset_id: String,
    pub source_count: u32,
    pub output_count: u32,
    pub source_total_minor: String,
    pub output_total_minor: String,
    pub source_root: String,
    pub request_output_root: String,
    pub result_output_root: String,
    pub request_digest: String,
    pub outputs: Vec<NativeExchangeV3ResultOutput>,
    pub result_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV3Receipt {
    pub version: u8,
    pub profile_id: String,
    pub issuer_or_federation_id: String,
    pub public_operation_id: String,
    pub graph_id: String,
    pub transition_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub asset_id: String,
    pub source_count: u32,
    pub output_count: u32,
    pub source_total_minor: String,
    pub output_total_minor: String,
    pub source_root: String,
    pub request_output_root: String,
    pub result_output_root: String,
    pub request_digest: String,
    pub result_digest: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub output_recovery_until: u64,
    pub receipt_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExchangeV3Error(pub &'static str);

impl std::fmt::Display for NativeExchangeV3Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for NativeExchangeV3Error {}

fn hex32(value: &str, error: &'static str) -> Result<[u8; 32], NativeExchangeV3Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(NativeExchangeV3Error(error));
    }
    hex::decode(value)
        .map_err(|_| NativeExchangeV3Error(error))?
        .try_into()
        .map_err(|_| NativeExchangeV3Error(error))
}

fn exact_b64<const N: usize>(
    value: &str,
    error: &'static str,
) -> Result<[u8; N], NativeExchangeV3Error> {
    if value.contains('=') {
        return Err(NativeExchangeV3Error(error));
    }
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| NativeExchangeV3Error(error))?;
    if bytes.len() != N || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(NativeExchangeV3Error(error));
    }
    bytes.try_into().map_err(|_| NativeExchangeV3Error(error))
}

fn canonical_b64(
    value: &str,
    max_bytes: usize,
    error: &'static str,
) -> Result<Vec<u8>, NativeExchangeV3Error> {
    if value.contains('=') {
        return Err(NativeExchangeV3Error(error));
    }
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| NativeExchangeV3Error(error))?;
    if bytes.is_empty()
        || bytes.len() > max_bytes
        || Base64UrlUnpadded::encode_string(&bytes) != value
    {
        return Err(NativeExchangeV3Error(error));
    }
    Ok(bytes)
}

fn text(value: &str, error: &'static str) -> Result<(), NativeExchangeV3Error> {
    if value.is_empty() || value.len() > 128 || std::str::from_utf8(value.as_bytes()).is_err() {
        Err(NativeExchangeV3Error(error))
    } else {
        Ok(())
    }
}

fn ascii_text(value: &str, error: &'static str) -> Result<(), NativeExchangeV3Error> {
    text(value, error)?;
    if !value.is_ascii() {
        return Err(NativeExchangeV3Error(error));
    }
    Ok(())
}

fn amount(value: &str) -> Result<u64, NativeExchangeV3Error> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(NativeExchangeV3Error("invalid amount"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| NativeExchangeV3Error("invalid amount"))?;
    if parsed == 0 {
        return Err(NativeExchangeV3Error("amount must be nonzero"));
    }
    Ok(parsed)
}

fn profile_fields(
    version: u8,
    profile_id: &str,
    suite: &str,
    modulus_bits: u16,
    exponent: u32,
) -> Result<(), NativeExchangeV3Error> {
    if version != NATIVE_EXCHANGE_V3_VERSION
        || profile_id != NATIVE_EXCHANGE_V3_PROFILE_ID
        || suite != NATIVE_EXCHANGE_V3_SUITE
        || modulus_bits != 3072
        || exponent != 65_537
    {
        return Err(NativeExchangeV3Error("invalid V7 exchange profile"));
    }
    Ok(())
}

impl NativeExchangeV3Profile {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        profile_fields(
            self.version,
            &self.profile_id,
            &self.suite,
            self.modulus_bits,
            self.exponent,
        )?;
        hex32(&self.graph_id, "invalid V7 exchange graph id").map(|_| ())
    }
}

impl NativeExchangeV3Descriptor {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        hex32(&self.descriptor_id, "invalid descriptor id")?;
        ascii_text(&self.profile_id, "invalid profile id")?;
        ascii_text(&self.issuer_id, "invalid issuer id")?;
        hex32(&self.token_key_id, "invalid V7 token key id")?;
        let amount_minor = amount(&self.amount_minor)?;
        ascii_text(&self.asset_id, "invalid asset id")?;
        profile_fields(
            3,
            &self.profile_id,
            &self.suite,
            self.modulus_bits,
            self.exponent,
        )?;
        let spki = canonical_b64(&self.pubkey_spki_b64, 4096, "invalid SPKI")?;
        let fingerprint = hex32(&self.spki_fingerprint, "invalid SPKI fingerprint")?;
        validate_v7_identifier_namespace(
            &self.token_key_id,
            &self.descriptor_id,
            &self.spki_fingerprint,
        )
        .map_err(|_| NativeExchangeV3Error("V7 descriptor/key identifiers must be distinct"))?;
        let computed_fingerprint: [u8; 32] = Sha256::digest(&spki).into();
        if computed_fingerprint != fingerprint {
            return Err(NativeExchangeV3Error("SPKI fingerprint mismatch"));
        }
        if self.valid_until > EXCHANGE_MAX_VALID_UNTIL as u64 {
            return Err(NativeExchangeV3Error("invalid descriptor validity"));
        }
        let expected_descriptor_id = derive_native_exchange_v3_descriptor_id(
            &self.profile_id,
            &self.issuer_id,
            &self.token_key_id,
            &self.asset_id,
            amount_minor,
            &self.suite,
            self.modulus_bits,
            self.exponent,
            &spki,
            &self.spki_fingerprint,
            self.valid_from,
            self.valid_until,
        )?;
        if self.descriptor_id != expected_descriptor_id {
            return Err(NativeExchangeV3Error(
                "non-canonical V7 exchange descriptor id",
            ));
        }
        let identity = freebird_crypto::V7KeyIdentity::new(
            self.issuer_id.clone(),
            freebird_crypto::V7TokenKeyId::new(hex32(
                &self.token_key_id,
                "invalid V7 token key id",
            )?),
        )
        .map_err(|_| NativeExchangeV3Error("invalid V7 key identity"))?;
        freebird_crypto::V7PublicKeyBinding::new(identity, &spki)
            .map_err(|_| NativeExchangeV3Error("invalid V7 SPKI"))?;
        if self.valid_from >= self.valid_until {
            return Err(NativeExchangeV3Error("invalid descriptor validity"));
        }
        Ok(())
    }
}

/// Derive the canonical V7 exchange descriptor ID.
///
/// This framing is also implemented by the SDK's strict discovery parser. In
/// particular, amount is a fixed-width unsigned integer, not its JSON string
/// representation, and the suite follows the amount in the transcript.
#[allow(clippy::too_many_arguments)]
pub fn derive_native_exchange_v3_descriptor_id(
    profile_id: &str,
    issuer_id: &str,
    token_key_id: &str,
    asset_id: &str,
    amount_minor: u64,
    suite: &str,
    modulus_bits: u16,
    exponent: u32,
    canonical_spki: &[u8],
    spki_fingerprint: &str,
    valid_from: u64,
    valid_until: u64,
) -> Result<String, NativeExchangeV3Error> {
    let mut transcript = Vec::new();
    put_ascii_text(&mut transcript, profile_id, "invalid profile id")?;
    put_ascii_text(&mut transcript, issuer_id, "invalid issuer id")?;
    put_ascii_text(&mut transcript, token_key_id, "invalid V7 token key id")?;
    put_ascii_text(&mut transcript, asset_id, "invalid asset id")?;
    transcript.extend_from_slice(&amount_minor.to_be_bytes());
    put_ascii_text(&mut transcript, suite, "invalid suite")?;
    transcript.extend_from_slice(&modulus_bits.to_be_bytes());
    transcript.extend_from_slice(&exponent.to_be_bytes());
    put_lp32(&mut transcript, canonical_spki)?;
    put_ascii_text(
        &mut transcript,
        spki_fingerprint,
        "invalid SPKI fingerprint",
    )?;
    transcript.extend_from_slice(&valid_from.to_be_bytes());
    transcript.extend_from_slice(&valid_until.to_be_bytes());
    Ok(hex::encode(hash(
        NATIVE_EXCHANGE_V3_DOMAIN_DESCRIPTOR,
        &transcript,
    )))
}

impl NativeExchangeV3Slot {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        hex32(&self.descriptor_id, "invalid slot descriptor id")?;
        hex32(&self.keyset_id, "invalid slot keyset id")?;
        ascii_text(&self.slot_id, "invalid slot id")?;
        if self.quantity != NATIVE_EXCHANGE_V3_QUANTITY {
            return Err(NativeExchangeV3Error("V7 slot quantity must be one"));
        }
        Ok(())
    }
}

impl NativeExchangeV3Keyset {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        hex32(&self.keyset_id, "invalid keyset id")?;
        if self.profile_id != NATIVE_EXCHANGE_V3_PROFILE_ID
            || self.descriptor_ids.is_empty()
            || self.descriptor_ids.len() > NATIVE_EXCHANGE_V3_MAX_ITEMS
        {
            return Err(NativeExchangeV3Error("invalid V7 keyset"));
        }
        for id in &self.descriptor_ids {
            hex32(id, "invalid keyset descriptor id")?;
        }
        Ok(())
    }
}

impl NativeExchangeV3Transition {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        hex32(&self.transition_id, "invalid transition id")?;
        if self.profile_id != NATIVE_EXCHANGE_V3_PROFILE_ID
            || self.source_keyset_id == self.target_keyset_id
            || self.source_slots.is_empty()
            || self.output_slots.is_empty()
        {
            return Err(NativeExchangeV3Error("invalid V7 transition"));
        }
        hex32(&self.source_keyset_id, "invalid source keyset id")?;
        hex32(&self.target_keyset_id, "invalid target keyset id")?;
        for slot in self.source_slots.iter().chain(self.output_slots.iter()) {
            slot.validate()?;
        }
        Ok(())
    }
}

impl NativeExchangeV3Discovery {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        if self.version != NATIVE_EXCHANGE_V3_VERSION {
            return Err(NativeExchangeV3Error("unsupported V7 exchange version"));
        }
        self.profile.validate()?;
        let mut descriptor_ids = std::collections::BTreeSet::new();
        let mut token_key_ids = std::collections::BTreeSet::new();
        for descriptor in self
            .active_descriptors
            .iter()
            .chain(self.retained_descriptors.iter())
        {
            descriptor.validate()?;
            if !descriptor_ids.insert(&descriptor.descriptor_id)
                || !token_key_ids.insert(&descriptor.token_key_id)
            {
                return Err(NativeExchangeV3Error(
                    "duplicate V7 exchange descriptor identity",
                ));
            }
        }
        let mut keyset_ids = std::collections::BTreeSet::new();
        for keyset in self
            .active_keysets
            .iter()
            .chain(self.retained_keysets.iter())
        {
            keyset.validate()?;
            if !keyset_ids.insert(&keyset.keyset_id) {
                return Err(NativeExchangeV3Error("duplicate V7 exchange keyset"));
            }
        }
        let mut transition_ids = std::collections::BTreeSet::new();
        for transition in &self.transitions {
            transition.validate()?;
            if !transition_ids.insert(&transition.transition_id) {
                return Err(NativeExchangeV3Error("duplicate V7 exchange transition"));
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_output_common(
    output_id: &str,
    descriptor_id: &str,
    keyset_id: &str,
    slot_id: &str,
    asset_id: &str,
    amount_minor: &str,
    blinded_message: &str,
    handoff_commitment: &str,
    request_output_commitment: &str,
    request_output_proof: &str,
) -> Result<(), NativeExchangeV3Error> {
    exact_b64::<16>(output_id, "invalid output id")?;
    hex32(descriptor_id, "invalid output descriptor id")?;
    hex32(keyset_id, "invalid output keyset id")?;
    ascii_text(slot_id, "invalid output slot id")?;
    text(asset_id, "invalid output asset id")?;
    amount(amount_minor)?;
    exact_b64::<384>(blinded_message, "V7 blinded message must be raw384")?;
    hex32(handoff_commitment, "invalid handoff commitment")?;
    hex32(request_output_commitment, "invalid request commitment")?;
    exact_b64::<192>(request_output_proof, "V7 request proof must be raw192")?;
    Ok(())
}

impl NativeExchangeV3Output {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        validate_output_common(
            &self.output_id,
            &self.descriptor_id,
            &self.keyset_id,
            &self.slot_id,
            &self.asset_id,
            &self.amount_minor,
            &self.blinded_message,
            &self.handoff_commitment,
            &self.request_output_commitment,
            &self.request_output_proof,
        )
    }
}

impl NativeExchangeV3ResultOutput {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        validate_output_common(
            &self.output_id,
            &self.descriptor_id,
            &self.keyset_id,
            &self.slot_id,
            &self.asset_id,
            &self.amount_minor,
            &self.blinded_message,
            &self.handoff_commitment,
            &self.request_output_commitment,
            &self.request_output_proof,
        )?;
        hex32(&self.result_output_commitment, "invalid result commitment")?;
        exact_b64::<192>(&self.result_output_proof, "V7 result proof must be raw192")?;
        exact_b64::<384>(&self.blind_signature, "V7 blind signature must be raw384")?;
        Ok(())
    }
}

impl NativeExchangeV3Source {
    fn artifact_bytes(&self) -> Result<Vec<u8>, NativeExchangeV3Error> {
        if self.artifact.contains('=') {
            return Err(NativeExchangeV3Error("invalid V7 artifact"));
        }
        let artifact = Base64UrlUnpadded::decode_vec(&self.artifact)
            .map_err(|_| NativeExchangeV3Error("invalid V7 artifact"))?;
        if artifact.is_empty() || Base64UrlUnpadded::encode_string(&artifact) != self.artifact {
            return Err(NativeExchangeV3Error("invalid V7 artifact"));
        }
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        let artifact = self.artifact_bytes()?;
        let token = freebird_crypto::parse_native_bearer_v7_token(&artifact)
            .map_err(|_| NativeExchangeV3Error("invalid V7 source artifact"))?;
        let digest = hex32(&self.source_artifact_digest, "invalid source digest")?;
        if token
            .artifact_digest()
            .map_err(|_| NativeExchangeV3Error("invalid source digest"))?
            != digest
        {
            return Err(NativeExchangeV3Error("source artifact digest mismatch"));
        }
        hex32(&self.descriptor_id, "invalid source descriptor id")?;
        hex32(&self.keyset_id, "invalid source keyset id")?;
        ascii_text(&self.slot_id, "invalid source slot id")?;
        Ok(())
    }

    fn transcript(&self) -> Result<Vec<u8>, NativeExchangeV3Error> {
        self.validate()?;
        let artifact = self.artifact_bytes()?;
        let mut out = Vec::new();
        put_lp32(&mut out, &artifact)?;
        put_raw32(
            &mut out,
            &self.source_artifact_digest,
            "invalid source digest",
        )?;
        put_raw32(
            &mut out,
            &self.descriptor_id,
            "invalid source descriptor id",
        )?;
        put_raw32(&mut out, &self.keyset_id, "invalid source keyset id")?;
        ascii_text(&self.slot_id, "invalid source slot id")?;
        put_text(&mut out, &self.slot_id, "invalid source slot id")?;
        Ok(out)
    }

    fn policy(&self) -> Result<(String, u64), NativeExchangeV3Error> {
        let token = freebird_crypto::parse_native_bearer_v7_token(&self.artifact_bytes()?)
            .map_err(|_| NativeExchangeV3Error("invalid V7 source artifact"))?;
        Ok((
            token.body().asset_id().to_owned(),
            token.body().amount_minor(),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn prefix(
    version: u8,
    profile_id: &str,
    issuer_or_federation_id: &str,
    public_operation_id: &str,
    graph_id: &str,
    transition_id: &str,
    source_keyset_id: &str,
    target_keyset_id: &str,
    asset_id: &str,
) -> Result<Vec<u8>, NativeExchangeV3Error> {
    if version != 3 || profile_id != NATIVE_EXCHANGE_V3_PROFILE_ID {
        return Err(NativeExchangeV3Error(
            "unsupported V7 exchange version/profile",
        ));
    }
    text(issuer_or_federation_id, "invalid issuer or federation id")?;
    text(asset_id, "invalid exchange asset id")?;
    let mut out = Vec::new();
    out.extend_from_slice(&(version as u32).to_be_bytes());
    put_text(&mut out, profile_id, "invalid profile id")?;
    put_text(
        &mut out,
        issuer_or_federation_id,
        "invalid issuer or federation id",
    )?;
    out.extend_from_slice(&exact_b64::<16>(
        public_operation_id,
        "invalid operation id",
    )?);
    for value in [graph_id, transition_id, source_keyset_id, target_keyset_id] {
        out.extend_from_slice(&hex32(value, "invalid exchange selector")?);
    }
    put_text(&mut out, asset_id, "invalid exchange asset id")?;
    Ok(out)
}

fn put_text(
    out: &mut Vec<u8>,
    value: &str,
    error: &'static str,
) -> Result<(), NativeExchangeV3Error> {
    text(value, error)?;
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_ascii_text(
    out: &mut Vec<u8>,
    value: &str,
    error: &'static str,
) -> Result<(), NativeExchangeV3Error> {
    ascii_text(value, error)?;
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_raw32(
    out: &mut Vec<u8>,
    value: &str,
    error: &'static str,
) -> Result<(), NativeExchangeV3Error> {
    out.extend_from_slice(&hex32(value, error)?);
    Ok(())
}

fn put_lp32(out: &mut Vec<u8>, value: &[u8]) -> Result<(), NativeExchangeV3Error> {
    let length = u32::try_from(value.len())
        .map_err(|_| NativeExchangeV3Error("V7 transcript is too large"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn put_output_request_transcript(
    out: &mut Vec<u8>,
    output: &NativeExchangeV3Output,
) -> Result<(), NativeExchangeV3Error> {
    output.validate()?;
    out.extend_from_slice(&exact_b64::<16>(&output.output_id, "invalid output id")?);
    put_raw32(out, &output.descriptor_id, "invalid output descriptor id")?;
    put_raw32(out, &output.keyset_id, "invalid output keyset id")?;
    put_text(out, &output.slot_id, "invalid output slot id")?;
    put_text(out, &output.asset_id, "invalid output asset id")?;
    out.extend_from_slice(&amount(&output.amount_minor)?.to_be_bytes());
    out.extend_from_slice(&exact_b64::<384>(
        &output.blinded_message,
        "invalid V7 blind",
    )?);
    put_raw32(
        out,
        &output.handoff_commitment,
        "invalid handoff commitment",
    )?;
    put_raw32(
        out,
        &output.request_output_commitment,
        "invalid request commitment",
    )?;
    out.extend_from_slice(&exact_b64::<192>(
        &output.request_output_proof,
        "invalid request proof",
    )?);
    Ok(())
}

fn put_output_result_transcript(
    out: &mut Vec<u8>,
    output: &NativeExchangeV3ResultOutput,
) -> Result<(), NativeExchangeV3Error> {
    output.validate()?;
    out.extend_from_slice(&exact_b64::<16>(&output.output_id, "invalid output id")?);
    put_raw32(out, &output.descriptor_id, "invalid output descriptor id")?;
    put_raw32(out, &output.keyset_id, "invalid output keyset id")?;
    put_text(out, &output.slot_id, "invalid output slot id")?;
    put_text(out, &output.asset_id, "invalid output asset id")?;
    out.extend_from_slice(&amount(&output.amount_minor)?.to_be_bytes());
    out.extend_from_slice(&exact_b64::<384>(
        &output.blinded_message,
        "invalid V7 blind",
    )?);
    put_raw32(
        out,
        &output.handoff_commitment,
        "invalid handoff commitment",
    )?;
    put_raw32(
        out,
        &output.request_output_commitment,
        "invalid request commitment",
    )?;
    out.extend_from_slice(&exact_b64::<192>(
        &output.request_output_proof,
        "invalid request proof",
    )?);
    put_raw32(
        out,
        &output.result_output_commitment,
        "invalid result commitment",
    )?;
    out.extend_from_slice(&exact_b64::<192>(
        &output.result_output_proof,
        "invalid result proof",
    )?);
    out.extend_from_slice(&exact_b64::<384>(
        &output.blind_signature,
        "invalid V7 signature",
    )?);
    Ok(())
}

impl NativeExchangeV3Request {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        self.canonical_bytes().map(|_| ())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeExchangeV3Error> {
        let mut out = prefix(
            self.version,
            &self.profile_id,
            &self.issuer_or_federation_id,
            &self.public_operation_id,
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
            &self.asset_id,
        )?;
        if self.sources.is_empty()
            || self.sources.len() > NATIVE_EXCHANGE_V3_MAX_ITEMS
            || self.outputs.is_empty()
            || self.outputs.len() > NATIVE_EXCHANGE_V3_MAX_ITEMS
            || self.source_count as usize != self.sources.len()
            || self.output_count as usize != self.outputs.len()
        {
            return Err(NativeExchangeV3Error("invalid V7 exchange counts"));
        }
        let source_total = amount(&self.source_total_minor)?;
        let output_total = amount(&self.output_total_minor)?;
        if source_total != output_total || self.asset_id.is_empty() {
            return Err(NativeExchangeV3Error("V7 exchange conservation mismatch"));
        }
        out.extend_from_slice(&self.source_count.to_be_bytes());
        out.extend_from_slice(&self.output_count.to_be_bytes());
        out.extend_from_slice(&source_total.to_be_bytes());
        out.extend_from_slice(&output_total.to_be_bytes());
        out.extend_from_slice(&hex32(&self.source_root, "invalid source root")?);
        out.extend_from_slice(&hex32(&self.request_output_root, "invalid request root")?);
        for source in &self.sources {
            out.extend_from_slice(&source.transcript()?);
            let (asset, value) = source.policy()?;
            if asset != self.asset_id {
                return Err(NativeExchangeV3Error("mixed V7 source assets"));
            }
            let _ = value;
        }
        let source_sum = self
            .sources
            .iter()
            .map(|source| source.policy().map(|(_, value)| value))
            .try_fold(0u64, |sum, value| {
                sum.checked_add(value?)
                    .ok_or(NativeExchangeV3Error("V7 source total overflow"))
            })?;
        let output_sum = self
            .outputs
            .iter()
            .map(|output| amount(&output.amount_minor))
            .try_fold(0u64, |sum, value| {
                sum.checked_add(value?)
                    .ok_or(NativeExchangeV3Error("V7 output total overflow"))
            })?;
        if source_sum != source_total || output_sum != output_total {
            return Err(NativeExchangeV3Error(
                "V7 declared totals do not match entries",
            ));
        }
        for output in &self.outputs {
            if output.asset_id != self.asset_id {
                return Err(NativeExchangeV3Error("mixed V7 exchange assets"));
            }
            put_output_request_transcript(&mut out, output)?;
        }
        let request_leaves = self
            .outputs
            .iter()
            .enumerate()
            .map(|(index, output)| {
                Ok(native_exchange_v3_output_leaf(
                    false,
                    index as u32,
                    &exact_b64::<16>(&output.output_id, "invalid output id")?,
                    &hex32(
                        &output.request_output_commitment,
                        "invalid request commitment",
                    )?,
                ))
            })
            .collect::<Result<Vec<_>, NativeExchangeV3Error>>()?;
        let request_root = hex32(&self.request_output_root, "invalid request root")?;
        if native_exchange_v3_ordered_root(&request_leaves)? != request_root {
            return Err(NativeExchangeV3Error("V7 request-output root mismatch"));
        }
        for (index, output) in self.outputs.iter().enumerate() {
            let output_id = exact_b64::<16>(&output.output_id, "invalid output id")?;
            let commitment = hex32(
                &output.request_output_commitment,
                "invalid request commitment",
            )?;
            native_exchange_v3_verify_output_proof(
                false,
                index as u32,
                &output_id,
                &commitment,
                &output.request_output_proof,
                &request_root,
            )?;
        }
        Ok(out)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], NativeExchangeV3Error> {
        Ok(hash(
            NATIVE_EXCHANGE_V3_DOMAIN_REQUEST,
            &self.canonical_bytes()?,
        ))
    }
}

impl NativeExchangeV3Result {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        let expected = hex32(&self.result_digest, "invalid result digest")?;
        if expected != self.result_digest()? {
            return Err(NativeExchangeV3Error("result digest mismatch"));
        }
        Ok(())
    }

    pub fn result_digest(&self) -> Result<[u8; 32], NativeExchangeV3Error> {
        let mut out = prefix(
            self.version,
            &self.profile_id,
            &self.issuer_or_federation_id,
            &self.public_operation_id,
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
            &self.asset_id,
        )?;
        out.extend_from_slice(&self.source_count.to_be_bytes());
        out.extend_from_slice(&self.output_count.to_be_bytes());
        out.extend_from_slice(&amount(&self.source_total_minor)?.to_be_bytes());
        out.extend_from_slice(&amount(&self.output_total_minor)?.to_be_bytes());
        out.extend_from_slice(&hex32(&self.source_root, "invalid source root")?);
        out.extend_from_slice(&hex32(&self.request_output_root, "invalid request root")?);
        out.extend_from_slice(&hex32(&self.result_output_root, "invalid result root")?);
        out.extend_from_slice(&hex32(&self.request_digest, "invalid request digest")?);
        if self.outputs.len() != self.output_count as usize || self.outputs.is_empty() {
            return Err(NativeExchangeV3Error("invalid V7 result count"));
        }
        for output in &self.outputs {
            put_output_result_transcript(&mut out, output)?;
        }
        let request_leaves = self
            .outputs
            .iter()
            .enumerate()
            .map(|(index, output)| {
                Ok(native_exchange_v3_output_leaf(
                    false,
                    index as u32,
                    &exact_b64::<16>(&output.output_id, "invalid output id")?,
                    &hex32(
                        &output.request_output_commitment,
                        "invalid request commitment",
                    )?,
                ))
            })
            .collect::<Result<Vec<_>, NativeExchangeV3Error>>()?;
        let result_leaves = self
            .outputs
            .iter()
            .enumerate()
            .map(|(index, output)| {
                Ok(native_exchange_v3_output_leaf(
                    true,
                    index as u32,
                    &exact_b64::<16>(&output.output_id, "invalid output id")?,
                    &hex32(
                        &output.result_output_commitment,
                        "invalid result commitment",
                    )?,
                ))
            })
            .collect::<Result<Vec<_>, NativeExchangeV3Error>>()?;
        let request_root = hex32(&self.request_output_root, "invalid request root")?;
        let result_root = hex32(&self.result_output_root, "invalid result root")?;
        if native_exchange_v3_ordered_root(&request_leaves)? != request_root {
            return Err(NativeExchangeV3Error("V7 request-output root mismatch"));
        }
        if native_exchange_v3_ordered_root(&result_leaves)? != result_root {
            return Err(NativeExchangeV3Error("V7 result-output root mismatch"));
        }
        for (index, output) in self.outputs.iter().enumerate() {
            let output_id = exact_b64::<16>(&output.output_id, "invalid output id")?;
            let request_commitment = hex32(
                &output.request_output_commitment,
                "invalid request commitment",
            )?;
            let result_commitment = hex32(
                &output.result_output_commitment,
                "invalid result commitment",
            )?;
            native_exchange_v3_verify_output_proof(
                false,
                index as u32,
                &output_id,
                &request_commitment,
                &output.request_output_proof,
                &request_root,
            )?;
            native_exchange_v3_verify_output_proof(
                true,
                index as u32,
                &output_id,
                &result_commitment,
                &output.result_output_proof,
                &result_root,
            )?;
        }
        Ok(hash(NATIVE_EXCHANGE_V3_DOMAIN_RESULT, &out))
    }
}

impl NativeExchangeV3Receipt {
    pub fn validate(&self) -> Result<(), NativeExchangeV3Error> {
        prefix(
            self.version,
            &self.profile_id,
            &self.issuer_or_federation_id,
            &self.public_operation_id,
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
            &self.asset_id,
        )?;
        amount(&self.source_total_minor)?;
        amount(&self.output_total_minor)?;
        if self.expires_at < self.created_at
            || self.output_recovery_until < self.created_at
            || self.expires_at - self.created_at != NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS
            || self.output_recovery_until - self.created_at
                != NATIVE_EXCHANGE_V3_RECEIPT_LIFETIME_SECS
            || self.output_count == 0
        {
            return Err(NativeExchangeV3Error("invalid V7 receipt validity"));
        }
        hex32(&self.source_root, "invalid source root")?;
        hex32(&self.request_output_root, "invalid request root")?;
        hex32(&self.result_output_root, "invalid result root")?;
        hex32(&self.request_digest, "invalid request digest")?;
        hex32(&self.result_digest, "invalid result digest")?;
        hex32(&self.receipt_key_id, "invalid receipt key id")?;
        exact_b64::<64>(&self.signature, "invalid receipt signature")?;
        Ok(())
    }

    pub fn receipt_digest(&self) -> Result<[u8; 32], NativeExchangeV3Error> {
        self.validate()?;
        let mut out = prefix(
            self.version,
            &self.profile_id,
            &self.issuer_or_federation_id,
            &self.public_operation_id,
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
            &self.asset_id,
        )?;
        out.extend_from_slice(&self.source_count.to_be_bytes());
        out.extend_from_slice(&self.output_count.to_be_bytes());
        out.extend_from_slice(&amount(&self.source_total_minor)?.to_be_bytes());
        out.extend_from_slice(&amount(&self.output_total_minor)?.to_be_bytes());
        for value in [
            &self.source_root,
            &self.request_output_root,
            &self.result_output_root,
            &self.request_digest,
            &self.result_digest,
            &self.receipt_key_id,
        ] {
            put_raw32(&mut out, value, "invalid V7 receipt digest field")?;
        }
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.output_recovery_until.to_be_bytes());
        Ok(hash(NATIVE_EXCHANGE_V3_DOMAIN_RECEIPT, &out))
    }
}

fn hash(domain: &[u8], transcript: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(transcript);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw<const N: usize>() -> String {
        Base64UrlUnpadded::encode_string(&[7; N])
    }

    fn test_source(amount_minor: u64) -> NativeExchangeV3Source {
        let nonce = [1; 32];
        let owner_commitment = [2; 32];
        let nullifier = freebird_crypto::PublicBearerV7Body::derive_nullifier(
            "issuer:test",
            &nonce,
            &owner_commitment,
        )
        .unwrap();
        let body = freebird_crypto::PublicBearerV7Body::new(
            "USD",
            amount_minor,
            "issuer:test",
            freebird_crypto::V7TokenKeyId::new([3; 32]),
            nonce,
            nullifier,
            owner_commitment,
        )
        .unwrap();
        let artifact = freebird_crypto::NativeBearerV7Token::new(
            body,
            freebird_crypto::V7MessageRandomizer::new([4; 32]),
            freebird_crypto::V7Signature::new([5; 384]),
        )
        .serialize()
        .unwrap();
        let token = freebird_crypto::parse_native_bearer_v7_token(&artifact).unwrap();
        NativeExchangeV3Source {
            artifact: Base64UrlUnpadded::encode_string(&artifact),
            source_artifact_digest: hex::encode(token.artifact_digest().unwrap()),
            descriptor_id: "11".repeat(32),
            keyset_id: "22".repeat(32),
            slot_id: "source".into(),
        }
    }

    fn test_request(output_count: usize) -> NativeExchangeV3Request {
        let mut outputs = (0..output_count)
            .map(|index| NativeExchangeV3Output {
                output_id: Base64UrlUnpadded::encode_string(&[index as u8 + 1; 16]),
                descriptor_id: "33".repeat(32),
                keyset_id: "44".repeat(32),
                slot_id: format!("output-{index}"),
                asset_id: "USD".into(),
                amount_minor: "1".into(),
                blinded_message: raw::<384>(),
                handoff_commitment: "55".repeat(32),
                request_output_commitment: format!("{:02x}", index + 1).repeat(32),
                request_output_proof: String::new(),
            })
            .collect::<Vec<_>>();
        let request_leaves = outputs
            .iter()
            .enumerate()
            .map(|(index, output)| {
                native_exchange_v3_output_leaf(
                    false,
                    index as u32,
                    &exact_b64::<16>(&output.output_id, "id").unwrap(),
                    &hex32(&output.request_output_commitment, "commitment").unwrap(),
                )
            })
            .collect::<Vec<_>>();
        for (index, output) in outputs.iter_mut().enumerate() {
            output.request_output_proof =
                native_exchange_v3_output_proof(&request_leaves, index).unwrap();
        }
        NativeExchangeV3Request {
            version: 3,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            issuer_or_federation_id: "federation:test".into(),
            public_operation_id: raw::<16>(),
            graph_id: "66".repeat(32),
            transition_id: "77".repeat(32),
            source_keyset_id: "22".repeat(32),
            target_keyset_id: "44".repeat(32),
            asset_id: "USD".into(),
            source_count: 1,
            output_count: output_count as u32,
            source_total_minor: output_count.to_string(),
            output_total_minor: output_count.to_string(),
            source_root: "88".repeat(32),
            request_output_root: hex::encode(
                native_exchange_v3_ordered_root(&request_leaves).unwrap(),
            ),
            sources: vec![test_source(output_count as u64)],
            outputs,
        }
    }

    #[test]
    fn v7_exchange_identifier_namespaces_are_canonical_and_distinct() {
        let token = "11".repeat(32);
        let descriptor = "22".repeat(32);
        let fingerprint = "33".repeat(32);
        assert!(validate_v7_identifier_namespace(&token, &descriptor, &fingerprint).is_ok());
        assert!(validate_v7_identifier_namespace(&token, &token, &fingerprint).is_err());
        assert!(validate_v7_identifier_namespace(&token, &descriptor, &token).is_err());
        assert!(validate_v7_identifier_namespace("AA", &descriptor, &fingerprint).is_err());
    }

    #[test]
    fn v7_ordered_roots_bind_entry_order() {
        let first = native_exchange_v3_output_leaf(false, 0, &[1; 16], &[2; 32]);
        let second = native_exchange_v3_output_leaf(false, 1, &[3; 16], &[4; 32]);
        let ordered = native_exchange_v3_ordered_root(&[first, second]).unwrap();
        let reordered = native_exchange_v3_ordered_root(&[second, first]).unwrap();
        assert_ne!(ordered, reordered);
        assert_eq!(
            ordered,
            native_exchange_v3_ordered_root(&[first, second]).unwrap()
        );
    }

    #[test]
    fn v7_output_proofs_bind_domains_indices_order_and_fixed_tree_root() {
        fn independent_root(leaves: &[[u8; 32]]) -> [u8; 32] {
            let mut nodes = vec![hash(NATIVE_EXCHANGE_V3_DOMAIN_EMPTY_LEAF, &[]); 64];
            nodes[..leaves.len()].copy_from_slice(leaves);
            for _ in 0..6 {
                nodes = nodes
                    .chunks_exact(2)
                    .map(|pair| {
                        let mut bytes = Vec::from(pair[0]);
                        bytes.extend_from_slice(&pair[1]);
                        hash(NATIVE_EXCHANGE_V3_DOMAIN_MERKLE_NODE, &bytes)
                    })
                    .collect();
            }
            nodes[0]
        }

        let ids = [[1; 16], [2; 16]];
        let commitments = [[3; 32], [4; 32]];
        let request_leaves = [
            native_exchange_v3_output_leaf(false, 0, &ids[0], &commitments[0]),
            native_exchange_v3_output_leaf(false, 1, &ids[1], &commitments[1]),
        ];
        let result_leaves = [
            native_exchange_v3_output_leaf(true, 0, &ids[0], &commitments[0]),
            native_exchange_v3_output_leaf(true, 1, &ids[1], &commitments[1]),
        ];
        let request_root = independent_root(&request_leaves);
        let result_root = independent_root(&result_leaves);
        assert_eq!(
            native_exchange_v3_ordered_root(&request_leaves).unwrap(),
            request_root
        );
        assert_eq!(
            native_exchange_v3_ordered_root(&result_leaves).unwrap(),
            result_root
        );
        assert_ne!(request_root, result_root);

        for index in 0..2 {
            let request_proof = native_exchange_v3_output_proof(&request_leaves, index).unwrap();
            let result_proof = native_exchange_v3_output_proof(&result_leaves, index).unwrap();
            assert_ne!(request_proof, result_proof);
            native_exchange_v3_verify_output_proof(
                false,
                index as u32,
                &ids[index],
                &commitments[index],
                &request_proof,
                &request_root,
            )
            .unwrap();
            native_exchange_v3_verify_output_proof(
                true,
                index as u32,
                &ids[index],
                &commitments[index],
                &result_proof,
                &result_root,
            )
            .unwrap();

            let mut wrong_sibling = Base64UrlUnpadded::decode_vec(&result_proof).unwrap();
            wrong_sibling[0] ^= 1;
            assert!(native_exchange_v3_verify_output_proof(
                true,
                index as u32,
                &ids[index],
                &commitments[index],
                &Base64UrlUnpadded::encode_string(&wrong_sibling),
                &result_root,
            )
            .is_err());
            assert!(native_exchange_v3_verify_output_proof(
                true,
                index as u32,
                &ids[index],
                &commitments[index],
                &result_proof[..result_proof.len() - 1],
                &result_root,
            )
            .is_err());
        }

        let proof = native_exchange_v3_output_proof(&result_leaves, 0).unwrap();
        assert!(native_exchange_v3_verify_output_proof(
            false,
            0,
            &ids[0],
            &commitments[0],
            &proof,
            &request_root,
        )
        .is_err());
        assert!(native_exchange_v3_verify_output_proof(
            true,
            1,
            &ids[0],
            &commitments[0],
            &proof,
            &result_root,
        )
        .is_err());
        let reordered = [result_leaves[1], result_leaves[0]];
        assert_ne!(independent_root(&reordered), result_root);
        assert!(native_exchange_v3_output_proof(&result_leaves, 2).is_err());
    }

    #[test]
    fn v7_full_request_and_result_validation_bind_exact_ordered_leaf_sets() {
        fn independent_root(leaves: &[[u8; 32]]) -> [u8; 32] {
            let mut nodes = vec![hash(NATIVE_EXCHANGE_V3_DOMAIN_EMPTY_LEAF, &[]); 64];
            nodes[..leaves.len()].copy_from_slice(leaves);
            for _ in 0..6 {
                nodes = nodes
                    .chunks_exact(2)
                    .map(|pair| {
                        let mut bytes = Vec::from(pair[0]);
                        bytes.extend_from_slice(&pair[1]);
                        hash(NATIVE_EXCHANGE_V3_DOMAIN_MERKLE_NODE, &bytes)
                    })
                    .collect();
            }
            nodes[0]
        }

        fn independent_proof(leaves: &[[u8; 32]], index: usize) -> Vec<u8> {
            let mut nodes = vec![hash(NATIVE_EXCHANGE_V3_DOMAIN_EMPTY_LEAF, &[]); 64];
            nodes[..leaves.len()].copy_from_slice(leaves);
            let mut position = index;
            let mut proof = Vec::new();
            while nodes.len() > 1 {
                proof.extend_from_slice(&nodes[position ^ 1]);
                nodes = nodes
                    .chunks_exact(2)
                    .map(|pair| {
                        let mut bytes = Vec::from(pair[0]);
                        bytes.extend_from_slice(&pair[1]);
                        hash(NATIVE_EXCHANGE_V3_DOMAIN_MERKLE_NODE, &bytes)
                    })
                    .collect();
                position >>= 1;
            }
            proof
        }

        fn unchecked_result_digest(result: &NativeExchangeV3Result) -> [u8; 32] {
            let mut bytes = prefix(
                result.version,
                &result.profile_id,
                &result.issuer_or_federation_id,
                &result.public_operation_id,
                &result.graph_id,
                &result.transition_id,
                &result.source_keyset_id,
                &result.target_keyset_id,
                &result.asset_id,
            )
            .unwrap();
            bytes.extend_from_slice(&result.source_count.to_be_bytes());
            bytes.extend_from_slice(&result.output_count.to_be_bytes());
            bytes.extend_from_slice(&amount(&result.source_total_minor).unwrap().to_be_bytes());
            bytes.extend_from_slice(&amount(&result.output_total_minor).unwrap().to_be_bytes());
            bytes.extend_from_slice(&hex32(&result.source_root, "source").unwrap());
            bytes.extend_from_slice(&hex32(&result.request_output_root, "request").unwrap());
            bytes.extend_from_slice(&hex32(&result.result_output_root, "result").unwrap());
            bytes.extend_from_slice(&hex32(&result.request_digest, "request digest").unwrap());
            for output in &result.outputs {
                put_output_result_transcript(&mut bytes, output).unwrap();
            }
            hash(NATIVE_EXCHANGE_V3_DOMAIN_RESULT, &bytes)
        }

        for count in [1, 2, 64] {
            let request = test_request(count);
            request.validate().unwrap();
            let mut padded = request.clone();
            padded.outputs[0].request_output_proof.push('=');
            assert!(padded.validate().is_err());
            if count > 1 {
                let mut reordered = request.clone();
                reordered.outputs.swap(0, 1);
                assert!(reordered.validate().is_err());
            }
            let request_leaves = request
                .outputs
                .iter()
                .enumerate()
                .map(|(index, output)| {
                    native_exchange_v3_output_leaf(
                        false,
                        index as u32,
                        &exact_b64::<16>(&output.output_id, "id").unwrap(),
                        &hex32(&output.request_output_commitment, "commitment").unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let expected_request_root = independent_root(&request_leaves);
            assert_eq!(
                hex::decode(&request.request_output_root).unwrap(),
                expected_request_root
            );
            for (index, output) in request.outputs.iter().enumerate() {
                assert_eq!(
                    Base64UrlUnpadded::decode_vec(&output.request_output_proof).unwrap(),
                    independent_proof(&request_leaves, index)
                );
            }

            let result_leaves = request_leaves
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    native_exchange_v3_output_leaf(
                        true,
                        index as u32,
                        &exact_b64::<16>(&request.outputs[index].output_id, "id").unwrap(),
                        &hex32(
                            &request.outputs[index].request_output_commitment,
                            "commitment",
                        )
                        .unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let result_root = independent_root(&result_leaves);
            let mut result = NativeExchangeV3Result {
                version: request.version,
                profile_id: request.profile_id.clone(),
                issuer_or_federation_id: request.issuer_or_federation_id.clone(),
                public_operation_id: request.public_operation_id.clone(),
                graph_id: request.graph_id.clone(),
                transition_id: request.transition_id.clone(),
                source_keyset_id: request.source_keyset_id.clone(),
                target_keyset_id: request.target_keyset_id.clone(),
                asset_id: request.asset_id.clone(),
                source_count: request.source_count,
                output_count: request.output_count,
                source_total_minor: request.source_total_minor.clone(),
                output_total_minor: request.output_total_minor.clone(),
                source_root: request.source_root.clone(),
                request_output_root: request.request_output_root.clone(),
                result_output_root: hex::encode(result_root),
                request_digest: hex::encode(request.request_digest().unwrap()),
                outputs: request
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(index, output)| NativeExchangeV3ResultOutput {
                        output_id: output.output_id.clone(),
                        descriptor_id: output.descriptor_id.clone(),
                        keyset_id: output.keyset_id.clone(),
                        slot_id: output.slot_id.clone(),
                        asset_id: output.asset_id.clone(),
                        amount_minor: output.amount_minor.clone(),
                        blinded_message: output.blinded_message.clone(),
                        handoff_commitment: output.handoff_commitment.clone(),
                        request_output_commitment: output.request_output_commitment.clone(),
                        request_output_proof: output.request_output_proof.clone(),
                        result_output_commitment: output.request_output_commitment.clone(),
                        result_output_proof: Base64UrlUnpadded::encode_string(&independent_proof(
                            &result_leaves,
                            index,
                        )),
                        blind_signature: raw::<384>(),
                    })
                    .collect(),
                result_digest: String::new(),
            };
            result.result_digest = hex::encode(result.result_digest().unwrap());
            result.validate().unwrap();

            if count == 1 {
                let mut forged = result.clone();
                let mut siblings =
                    Base64UrlUnpadded::decode_vec(&forged.outputs[0].result_output_proof).unwrap();
                siblings[0] ^= 0x80; // replace the canonical empty sibling
                forged.outputs[0].result_output_proof = Base64UrlUnpadded::encode_string(&siblings);

                let leaf = native_exchange_v3_output_leaf(
                    true,
                    0,
                    &exact_b64::<16>(&forged.outputs[0].output_id, "id").unwrap(),
                    &hex32(&forged.outputs[0].result_output_commitment, "commitment").unwrap(),
                );
                let mut node = leaf;
                for sibling in siblings.chunks_exact(32) {
                    let mut pair = Vec::from(node);
                    pair.extend_from_slice(sibling);
                    node = hash(NATIVE_EXCHANGE_V3_DOMAIN_MERKLE_NODE, &pair);
                }
                forged.result_output_root = hex::encode(node);
                native_exchange_v3_verify_output_proof(
                    true,
                    0,
                    &exact_b64::<16>(&forged.outputs[0].output_id, "id").unwrap(),
                    &hex32(&forged.outputs[0].result_output_commitment, "commitment").unwrap(),
                    &forged.outputs[0].result_output_proof,
                    &node,
                )
                .unwrap();
                forged.result_digest = hex::encode(unchecked_result_digest(&forged));
                assert!(forged.validate().is_err());
            }
        }
    }

    #[test]
    fn v7_exchange_rejects_legacy_versions_and_non_unit_slots() {
        let profile = NativeExchangeV3Profile {
            version: 2,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            graph_id: "aa".repeat(32),
            suite: NATIVE_EXCHANGE_V3_SUITE.into(),
            modulus_bits: 3072,
            exponent: 65_537,
        };
        assert!(profile.validate().is_err());
        let slot = NativeExchangeV3Slot {
            descriptor_id: "a".repeat(64),
            keyset_id: "b".repeat(64),
            slot_id: "slot".into(),
            quantity: 2,
        };
        assert!(slot.validate().is_err());
        assert!(exact_b64::<384>(&raw::<384>(), "raw384").is_ok());
        assert!(exact_b64::<384>(&raw::<32>(), "raw384").is_err());
    }

    #[test]
    fn v7_exchange_descriptor_id_matches_cross_language_vector() {
        let descriptor_id = derive_native_exchange_v3_descriptor_id(
            NATIVE_EXCHANGE_V3_PROFILE_ID,
            "issuer:test",
            &"11".repeat(32),
            "USD",
            42,
            NATIVE_EXCHANGE_V3_SUITE,
            3072,
            65_537,
            &[1, 2, 3],
            &"22".repeat(32),
            1,
            2,
        )
        .unwrap();
        assert_eq!(
            descriptor_id,
            "9a657cc791f6f42d624e4a11da7ddf3d81b066ab57fd25b5e05f8d2cdbf48d0b"
        );

        let tampered = derive_native_exchange_v3_descriptor_id(
            NATIVE_EXCHANGE_V3_PROFILE_ID,
            "issuer:test",
            &"11".repeat(32),
            "USD",
            43,
            NATIVE_EXCHANGE_V3_SUITE,
            3072,
            65_537,
            &[1, 2, 3],
            &"22".repeat(32),
            1,
            2,
        )
        .unwrap();
        assert_ne!(descriptor_id, tampered);
        assert!(derive_native_exchange_v3_descriptor_id(
            NATIVE_EXCHANGE_V3_PROFILE_ID,
            "issuer:é",
            &"11".repeat(32),
            "USD",
            42,
            NATIVE_EXCHANGE_V3_SUITE,
            3072,
            65_537,
            &[1, 2, 3],
            &"22".repeat(32),
            1,
            2,
        )
        .is_err());
    }
}
