// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Strict V4 native exchange contract.
//!
//! This is a new wire contract, rather than a compatibility spelling of the
//! V3 contract.  In particular, output leaves bind the output values that are
//! actually exchanged; they do not carry an application-defined opaque value.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::native_bearer_v7::validate_v7_identifier_namespace;

pub const NATIVE_EXCHANGE_V4_VERSION: u8 = 4;
pub const NATIVE_EXCHANGE_V4_PROFILE_ID: &str = "freebird/native-exchange/v4";
pub const NATIVE_EXCHANGE_V4_SUITE: &str = "RSABSSA-SHA384-PSS-Randomized-V7";
pub const NATIVE_EXCHANGE_V4_MAX_ITEMS: usize = 64;
pub const NATIVE_EXCHANGE_V4_QUANTITY: u32 = 1;
pub const NATIVE_EXCHANGE_V4_RECEIPT_LIFETIME_SECS: u64 = 2_592_000;
pub const EXCHANGE_V4_MAX_VALID_UNTIL: i64 = ((1u64 << 53) - 1) as i64;
pub const EXCHANGE_V4_MAX_BUDGET_LIMIT: u64 = (1u64 << 53) - 1;
pub const NATIVE_EXCHANGE_V4_RAW384_BYTES: usize = 384;

pub const NATIVE_EXCHANGE_V4_RECEIPT_KEY_ALGORITHM: &str = "Ed25519";
pub const NATIVE_EXCHANGE_V4_RECEIPT_KEY_PURPOSE: &str = "exchange_receipt_v4";

pub const NATIVE_EXCHANGE_V4_DOMAIN_SOURCE_LEAF: &[u8] =
    b"freebird native exchange source leaf v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_REQUEST_OUTPUT_LEAF: &[u8] =
    b"freebird native exchange request-output leaf v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_RESULT_OUTPUT_LEAF: &[u8] =
    b"freebird native exchange result-output leaf v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_EMPTY_LEAF: &[u8] = b"freebird native exchange empty leaf v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_MERKLE_NODE: &[u8] =
    b"freebird native exchange merkle node v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_REQUEST: &[u8] = b"freebird native exchange request v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_RESULT: &[u8] = b"freebird native exchange result v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_RECEIPT: &[u8] = b"freebird native exchange receipt v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_DESCRIPTOR: &[u8] = b"freebird native exchange descriptor v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_GRAPH: &[u8] = b"freebird native exchange graph v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_KEYSET: &[u8] = b"freebird native exchange keyset v4\0";
pub const NATIVE_EXCHANGE_V4_DOMAIN_TRANSITION: &[u8] = b"freebird native exchange transition v4\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Profile {
    pub version: u8,
    pub profile_id: String,
    pub graph_id: String,
    pub suite: String,
    pub modulus_bits: u16,
    pub exponent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Descriptor {
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
pub struct NativeExchangeV4Keyset {
    pub keyset_id: String,
    pub profile_id: String,
    pub descriptor_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Slot {
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
    pub quantity: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Transition {
    pub transition_id: String,
    pub profile_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub source_slots: Vec<NativeExchangeV4Slot>,
    pub output_slots: Vec<NativeExchangeV4Slot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4ReceiptKeyMetadata {
    pub key_id: String,
    pub algorithm: String,
    pub purpose: String,
    pub public_key_b64: String,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4ReceiptKeySet {
    pub active: NativeExchangeV4ReceiptKeyMetadata,
    pub retained: Vec<NativeExchangeV4ReceiptKeyMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Discovery {
    pub version: u8,
    pub profile: NativeExchangeV4Profile,
    pub active_descriptors: Vec<NativeExchangeV4Descriptor>,
    pub retained_descriptors: Vec<NativeExchangeV4Descriptor>,
    pub active_keysets: Vec<NativeExchangeV4Keyset>,
    pub retained_keysets: Vec<NativeExchangeV4Keyset>,
    pub transitions: Vec<NativeExchangeV4Transition>,
    pub receipt_key_set: NativeExchangeV4ReceiptKeySet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Source {
    pub artifact: String,
    pub source_artifact_digest: String,
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Output {
    pub output_id: String,
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
    pub asset_id: String,
    pub amount_minor: String,
    pub blinded_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4ResultOutput {
    pub output_id: String,
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
    pub asset_id: String,
    pub amount_minor: String,
    pub blinded_message: String,
    pub blind_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Request {
    pub version: u8,
    pub profile_id: String,
    pub issuer_or_federation_id: String,
    pub public_operation_id: String,
    pub status_capability_digest: String,
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
    pub sources: Vec<NativeExchangeV4Source>,
    pub outputs: Vec<NativeExchangeV4Output>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Result {
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
    pub outputs: Vec<NativeExchangeV4ResultOutput>,
    pub result_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeExchangeV4Receipt {
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
pub struct NativeExchangeV4Error(pub &'static str);

impl std::fmt::Display for NativeExchangeV4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for NativeExchangeV4Error {}

fn hex32(value: &str, error: &'static str) -> Result<[u8; 32], NativeExchangeV4Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(NativeExchangeV4Error(error));
    }
    hex::decode(value)
        .map_err(|_| NativeExchangeV4Error(error))?
        .try_into()
        .map_err(|_| NativeExchangeV4Error(error))
}

fn exact_b64<const N: usize>(
    value: &str,
    error: &'static str,
) -> Result<[u8; N], NativeExchangeV4Error> {
    if value.contains('=') {
        return Err(NativeExchangeV4Error(error));
    }
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| NativeExchangeV4Error(error))?;
    if bytes.len() != N || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(NativeExchangeV4Error(error));
    }
    bytes.try_into().map_err(|_| NativeExchangeV4Error(error))
}

fn canonical_b64(
    value: &str,
    max_bytes: usize,
    error: &'static str,
) -> Result<Vec<u8>, NativeExchangeV4Error> {
    if value.contains('=') {
        return Err(NativeExchangeV4Error(error));
    }
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| NativeExchangeV4Error(error))?;
    if bytes.is_empty()
        || bytes.len() > max_bytes
        || Base64UrlUnpadded::encode_string(&bytes) != value
    {
        return Err(NativeExchangeV4Error(error));
    }
    Ok(bytes)
}

fn text(value: &str, error: &'static str) -> Result<(), NativeExchangeV4Error> {
    if value.is_empty() || value.len() > 128 {
        Err(NativeExchangeV4Error(error))
    } else {
        Ok(())
    }
}

fn ascii_text(value: &str, error: &'static str) -> Result<(), NativeExchangeV4Error> {
    text(value, error)?;
    if value.is_ascii() {
        Ok(())
    } else {
        Err(NativeExchangeV4Error(error))
    }
}

fn amount(value: &str) -> Result<u64, NativeExchangeV4Error> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(NativeExchangeV4Error("invalid amount"));
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| NativeExchangeV4Error("invalid amount"))?;
    if value == 0 {
        Err(NativeExchangeV4Error("amount must be nonzero"))
    } else {
        Ok(value)
    }
}

fn profile_fields(
    version: u8,
    profile_id: &str,
    suite: &str,
    modulus_bits: u16,
    exponent: u32,
) -> Result<(), NativeExchangeV4Error> {
    if version != NATIVE_EXCHANGE_V4_VERSION
        || profile_id != NATIVE_EXCHANGE_V4_PROFILE_ID
        || suite != NATIVE_EXCHANGE_V4_SUITE
        || modulus_bits != 3072
        || exponent != 65_537
    {
        Err(NativeExchangeV4Error("invalid V4 exchange profile"))
    } else {
        Ok(())
    }
}

impl NativeExchangeV4Profile {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        profile_fields(
            self.version,
            &self.profile_id,
            &self.suite,
            self.modulus_bits,
            self.exponent,
        )?;
        hex32(&self.graph_id, "invalid V4 exchange graph id").map(|_| ())
    }
}

impl NativeExchangeV4Descriptor {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        hex32(&self.descriptor_id, "invalid descriptor id")?;
        ascii_text(&self.profile_id, "invalid profile id")?;
        ascii_text(&self.issuer_id, "invalid issuer id")?;
        hex32(&self.token_key_id, "invalid token key id")?;
        let amount_minor = amount(&self.amount_minor)?;
        ascii_text(&self.asset_id, "invalid asset id")?;
        profile_fields(
            4,
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
        .map_err(|_| NativeExchangeV4Error("descriptor identifiers must be distinct"))?;
        let computed_fingerprint: [u8; 32] = Sha256::digest(&spki).into();
        if computed_fingerprint != fingerprint {
            return Err(NativeExchangeV4Error("SPKI fingerprint mismatch"));
        }
        if self.valid_from >= self.valid_until
            || self.valid_until > EXCHANGE_V4_MAX_VALID_UNTIL as u64
        {
            return Err(NativeExchangeV4Error("invalid descriptor validity"));
        }
        let expected = derive_native_exchange_v4_descriptor_id(
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
        if expected != self.descriptor_id {
            return Err(NativeExchangeV4Error("non-canonical V4 descriptor id"));
        }
        let identity = freebird_crypto::V7KeyIdentity::new(
            self.issuer_id.clone(),
            freebird_crypto::V7TokenKeyId::new(hex32(&self.token_key_id, "invalid token key id")?),
        )
        .map_err(|_| NativeExchangeV4Error("invalid key identity"))?;
        freebird_crypto::V7PublicKeyBinding::new(identity, &spki)
            .map_err(|_| NativeExchangeV4Error("invalid SPKI"))?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn derive_native_exchange_v4_descriptor_id(
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
) -> Result<String, NativeExchangeV4Error> {
    let mut transcript = Vec::new();
    for value in [profile_id, issuer_id, token_key_id, asset_id] {
        put_ascii_text(&mut transcript, value, "invalid descriptor text")?;
    }
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
        NATIVE_EXCHANGE_V4_DOMAIN_DESCRIPTOR,
        &transcript,
    )))
}

pub fn derive_native_exchange_v4_keyset_id(
    keyset: &NativeExchangeV4Keyset,
) -> Result<String, NativeExchangeV4Error> {
    if keyset.profile_id != NATIVE_EXCHANGE_V4_PROFILE_ID
        || keyset.descriptor_ids.is_empty()
        || keyset.descriptor_ids.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
    {
        return Err(NativeExchangeV4Error("invalid V4 keyset"));
    }
    let mut transcript = Vec::new();
    put_text(
        &mut transcript,
        &keyset.profile_id,
        "invalid keyset profile",
    )?;
    transcript.extend_from_slice(&(keyset.descriptor_ids.len() as u32).to_be_bytes());
    for descriptor_id in &keyset.descriptor_ids {
        put_raw32(
            &mut transcript,
            descriptor_id,
            "invalid keyset descriptor id",
        )?;
    }
    Ok(hex::encode(hash(
        NATIVE_EXCHANGE_V4_DOMAIN_KEYSET,
        &transcript,
    )))
}

pub fn derive_native_exchange_v4_transition_id(
    transition: &NativeExchangeV4Transition,
) -> Result<String, NativeExchangeV4Error> {
    if transition.profile_id != NATIVE_EXCHANGE_V4_PROFILE_ID
        || transition.source_slots.is_empty()
        || transition.output_slots.is_empty()
        || transition.source_slots.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
        || transition.output_slots.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
    {
        return Err(NativeExchangeV4Error("invalid V4 transition"));
    }
    let mut transcript = Vec::new();
    put_text(
        &mut transcript,
        &transition.profile_id,
        "invalid transition profile",
    )?;
    put_raw32(
        &mut transcript,
        &transition.source_keyset_id,
        "invalid source keyset id",
    )?;
    put_raw32(
        &mut transcript,
        &transition.target_keyset_id,
        "invalid target keyset id",
    )?;
    append_slots(&mut transcript, &transition.source_slots)?;
    append_slots(&mut transcript, &transition.output_slots)?;
    Ok(hex::encode(hash(
        NATIVE_EXCHANGE_V4_DOMAIN_TRANSITION,
        &transcript,
    )))
}

pub fn derive_native_exchange_v4_graph_id(
    discovery: &NativeExchangeV4Discovery,
) -> Result<String, NativeExchangeV4Error> {
    if discovery.profile.profile_id != NATIVE_EXCHANGE_V4_PROFILE_ID {
        return Err(NativeExchangeV4Error("invalid V4 graph profile"));
    }
    let mut transcript = Vec::new();
    put_text(
        &mut transcript,
        &discovery.profile.profile_id,
        "invalid graph profile",
    )?;
    append_id_list(
        &mut transcript,
        discovery
            .active_descriptors
            .iter()
            .chain(&discovery.retained_descriptors)
            .map(|descriptor| descriptor.descriptor_id.as_str()),
        "invalid graph descriptor id",
    )?;
    append_id_list(
        &mut transcript,
        discovery
            .active_keysets
            .iter()
            .chain(&discovery.retained_keysets)
            .map(|keyset| keyset.keyset_id.as_str()),
        "invalid graph keyset id",
    )?;
    append_id_list(
        &mut transcript,
        discovery
            .transitions
            .iter()
            .map(|transition| transition.transition_id.as_str()),
        "invalid graph transition id",
    )?;
    Ok(hex::encode(hash(
        NATIVE_EXCHANGE_V4_DOMAIN_GRAPH,
        &transcript,
    )))
}

fn append_id_list<'a, I>(
    output: &mut Vec<u8>,
    values: I,
    error: &'static str,
) -> Result<(), NativeExchangeV4Error>
where
    I: IntoIterator<Item = &'a str>,
{
    let values = values.into_iter().collect::<Vec<_>>();
    output.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        put_raw32(output, value, error)?;
    }
    Ok(())
}

fn append_slots(
    output: &mut Vec<u8>,
    slots: &[NativeExchangeV4Slot],
) -> Result<(), NativeExchangeV4Error> {
    output.extend_from_slice(&(slots.len() as u32).to_be_bytes());
    for slot in slots {
        put_raw32(
            output,
            &slot.descriptor_id,
            "invalid transition descriptor id",
        )?;
        put_raw32(output, &slot.keyset_id, "invalid transition keyset id")?;
        put_text(output, &slot.slot_id, "invalid transition slot id")?;
        output.extend_from_slice(&slot.quantity.to_be_bytes());
    }
    Ok(())
}

fn keyset_by_id<'a>(
    discovery: &'a NativeExchangeV4Discovery,
    keyset_id: &str,
) -> Result<&'a NativeExchangeV4Keyset, NativeExchangeV4Error> {
    discovery
        .active_keysets
        .iter()
        .chain(&discovery.retained_keysets)
        .find(|keyset| keyset.keyset_id == keyset_id)
        .ok_or(NativeExchangeV4Error(
            "transition references unknown keyset",
        ))
}

impl NativeExchangeV4Keyset {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        hex32(&self.keyset_id, "invalid keyset id")?;
        if self.profile_id != NATIVE_EXCHANGE_V4_PROFILE_ID
            || self.descriptor_ids.is_empty()
            || self.descriptor_ids.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
        {
            return Err(NativeExchangeV4Error("invalid V4 keyset"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for id in &self.descriptor_ids {
            hex32(id, "invalid keyset descriptor id")?;
            if !ids.insert(id) {
                return Err(NativeExchangeV4Error("duplicate keyset descriptor id"));
            }
        }
        if derive_native_exchange_v4_keyset_id(self)?.as_str() != self.keyset_id {
            return Err(NativeExchangeV4Error("non-canonical V4 keyset id"));
        }
        Ok(())
    }
}

impl NativeExchangeV4Slot {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        hex32(&self.descriptor_id, "invalid slot descriptor id")?;
        hex32(&self.keyset_id, "invalid slot keyset id")?;
        ascii_text(&self.slot_id, "invalid slot id")?;
        if self.quantity != NATIVE_EXCHANGE_V4_QUANTITY {
            return Err(NativeExchangeV4Error("slot quantity must be one"));
        }
        Ok(())
    }
}

impl NativeExchangeV4Transition {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        hex32(&self.transition_id, "invalid transition id")?;
        hex32(&self.source_keyset_id, "invalid source keyset id")?;
        hex32(&self.target_keyset_id, "invalid target keyset id")?;
        if self.profile_id != NATIVE_EXCHANGE_V4_PROFILE_ID
            || self.source_keyset_id == self.target_keyset_id
            || self.source_slots.is_empty()
            || self.output_slots.is_empty()
            || self.source_slots.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
            || self.output_slots.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
        {
            return Err(NativeExchangeV4Error("invalid V4 transition"));
        }
        for slot in self.source_slots.iter().chain(self.output_slots.iter()) {
            slot.validate()?;
        }
        if derive_native_exchange_v4_transition_id(self)?.as_str() != self.transition_id {
            return Err(NativeExchangeV4Error("non-canonical V4 transition id"));
        }
        Ok(())
    }
}

impl NativeExchangeV4ReceiptKeyMetadata {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        let key_id = hex32(&self.key_id, "invalid receipt key id")?;
        if self.algorithm != NATIVE_EXCHANGE_V4_RECEIPT_KEY_ALGORITHM
            || self.purpose != NATIVE_EXCHANGE_V4_RECEIPT_KEY_PURPOSE
            || self.valid_from == 0
            || self.valid_from >= self.valid_until
            || self.valid_until > EXCHANGE_V4_MAX_VALID_UNTIL as u64
        {
            return Err(NativeExchangeV4Error("invalid receipt key metadata"));
        }
        let public = exact_b64::<32>(&self.public_key_b64, "invalid receipt public key")?;
        let computed_key_id: [u8; 32] = Sha256::digest(public).into();
        if computed_key_id != key_id {
            return Err(NativeExchangeV4Error("receipt key identity mismatch"));
        }
        Ok(())
    }
}

impl NativeExchangeV4ReceiptKeySet {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        self.active.validate()?;
        let mut ids = std::collections::BTreeSet::new();
        ids.insert(&self.active.key_id);
        for key in &self.retained {
            key.validate()?;
            if !ids.insert(&key.key_id) {
                return Err(NativeExchangeV4Error("duplicate receipt key id"));
            }
        }
        Ok(())
    }
}

impl NativeExchangeV4Discovery {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        if self.version != NATIVE_EXCHANGE_V4_VERSION {
            return Err(NativeExchangeV4Error("unsupported V4 exchange version"));
        }
        self.profile.validate()?;
        if self.active_descriptors.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
            || self.retained_descriptors.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
            || self.active_keysets.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
            || self.retained_keysets.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
            || self.transitions.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
            || self.receipt_key_set.retained.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
        {
            return Err(NativeExchangeV4Error(
                "V4 discovery collection is too large",
            ));
        }
        let mut descriptor_ids = std::collections::BTreeSet::new();
        let mut descriptor_issuer: Option<&str> = None;
        let mut token_key_ids = std::collections::BTreeSet::new();
        for descriptor in self
            .active_descriptors
            .iter()
            .chain(&self.retained_descriptors)
        {
            descriptor.validate()?;
            if let Some(issuer) = descriptor_issuer {
                if issuer != descriptor.issuer_id {
                    return Err(NativeExchangeV4Error("V4 descriptor issuer mismatch"));
                }
            } else {
                descriptor_issuer = Some(&descriptor.issuer_id);
            }
            if !descriptor_ids.insert(&descriptor.descriptor_id)
                || !token_key_ids.insert(&descriptor.token_key_id)
            {
                return Err(NativeExchangeV4Error(
                    "duplicate exchange descriptor identity",
                ));
            }
        }
        let mut keyset_ids = std::collections::BTreeSet::new();
        for keyset in self.active_keysets.iter().chain(&self.retained_keysets) {
            keyset.validate()?;
            if !keyset_ids.insert(&keyset.keyset_id) {
                return Err(NativeExchangeV4Error("duplicate exchange keyset"));
            }
            for descriptor_id in &keyset.descriptor_ids {
                if !descriptor_ids.contains(descriptor_id) {
                    return Err(NativeExchangeV4Error(
                        "V4 keyset references an unknown descriptor",
                    ));
                }
            }
        }
        let mut transition_ids = std::collections::BTreeSet::new();
        for transition in &self.transitions {
            transition.validate()?;
            if !transition_ids.insert(&transition.transition_id) {
                return Err(NativeExchangeV4Error("duplicate exchange transition"));
            }
            let source = keyset_by_id(self, &transition.source_keyset_id)?;
            let target = keyset_by_id(self, &transition.target_keyset_id)?;
            for slot in &transition.source_slots {
                if slot.keyset_id != transition.source_keyset_id
                    || !source.descriptor_ids.contains(&slot.descriptor_id)
                {
                    return Err(NativeExchangeV4Error("invalid V4 source slot membership"));
                }
            }
            for slot in &transition.output_slots {
                if slot.keyset_id != transition.target_keyset_id
                    || !target.descriptor_ids.contains(&slot.descriptor_id)
                {
                    return Err(NativeExchangeV4Error("invalid V4 output slot membership"));
                }
            }
        }
        self.receipt_key_set.validate()?;
        let graph_id = derive_native_exchange_v4_graph_id(self)?;
        if graph_id != self.profile.graph_id {
            return Err(NativeExchangeV4Error("non-canonical V4 graph id"));
        }
        Ok(())
    }
}

impl NativeExchangeV4Source {
    fn artifact_bytes(&self) -> Result<Vec<u8>, NativeExchangeV4Error> {
        canonical_b64(&self.artifact, usize::MAX, "invalid source artifact")
    }

    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        let artifact = self.artifact_bytes()?;
        let token = freebird_crypto::parse_native_bearer_v7_token(&artifact)
            .map_err(|_| NativeExchangeV4Error("invalid source artifact"))?;
        let digest = hex32(&self.source_artifact_digest, "invalid source digest")?;
        if token
            .artifact_digest()
            .map_err(|_| NativeExchangeV4Error("invalid source digest"))?
            != digest
        {
            return Err(NativeExchangeV4Error("source artifact digest mismatch"));
        }
        hex32(&self.descriptor_id, "invalid source descriptor id")?;
        hex32(&self.keyset_id, "invalid source keyset id")?;
        ascii_text(&self.slot_id, "invalid source slot id")
    }

    fn transcript(&self) -> Result<Vec<u8>, NativeExchangeV4Error> {
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
        put_text(&mut out, &self.slot_id, "invalid source slot id")?;
        Ok(out)
    }

    fn policy(&self) -> Result<(String, u64), NativeExchangeV4Error> {
        let token = freebird_crypto::parse_native_bearer_v7_token(&self.artifact_bytes()?)
            .map_err(|_| NativeExchangeV4Error("invalid source artifact"))?;
        Ok((
            token.body().asset_id().to_owned(),
            token.body().amount_minor(),
        ))
    }
}

pub fn native_exchange_v4_source_leaf(
    index: u32,
    artifact: &[u8],
    source_artifact_digest: &[u8; 32],
    descriptor_id: &[u8; 32],
    keyset_id: &[u8; 32],
    slot_id: &str,
) -> Result<[u8; 32], NativeExchangeV4Error> {
    if index as usize >= NATIVE_EXCHANGE_V4_MAX_ITEMS {
        return Err(NativeExchangeV4Error("invalid source leaf index"));
    }
    ascii_text(slot_id, "invalid source slot")?;
    let mut transcript = index.to_be_bytes().to_vec();
    put_lp32(&mut transcript, artifact)?;
    transcript.extend_from_slice(source_artifact_digest);
    transcript.extend_from_slice(descriptor_id);
    transcript.extend_from_slice(keyset_id);
    put_text(&mut transcript, slot_id, "invalid source slot")?;
    Ok(hash(NATIVE_EXCHANGE_V4_DOMAIN_SOURCE_LEAF, &transcript))
}

/// Hash a request or result output leaf.  The result form appends the raw384
/// blind signature after the request-output fields.
#[allow(clippy::too_many_arguments)]
pub fn native_exchange_v4_output_leaf(
    result: bool,
    index: u32,
    output_id: &[u8; 16],
    descriptor_id: &[u8; 32],
    keyset_id: &[u8; 32],
    slot_id: &str,
    asset_id: &str,
    amount_minor: u64,
    blinded_message: &[u8; 384],
    blind_signature: Option<&[u8; 384]>,
) -> Result<[u8; 32], NativeExchangeV4Error> {
    if index as usize >= NATIVE_EXCHANGE_V4_MAX_ITEMS {
        return Err(NativeExchangeV4Error("invalid output leaf index"));
    }
    ascii_text(slot_id, "invalid output slot id")?;
    text(asset_id, "invalid output asset id")?;
    if result && blind_signature.is_none() {
        return Err(NativeExchangeV4Error("missing blind signature"));
    }
    if !result && blind_signature.is_some() {
        return Err(NativeExchangeV4Error("unexpected blind signature"));
    }
    let mut transcript = index.to_be_bytes().to_vec();
    transcript.extend_from_slice(output_id);
    transcript.extend_from_slice(descriptor_id);
    transcript.extend_from_slice(keyset_id);
    put_text(&mut transcript, slot_id, "invalid output slot id")?;
    put_text(&mut transcript, asset_id, "invalid output asset id")?;
    if amount_minor == 0 {
        return Err(NativeExchangeV4Error("amount must be nonzero"));
    }
    transcript.extend_from_slice(&amount_minor.to_be_bytes());
    transcript.extend_from_slice(blinded_message);
    if let Some(signature) = blind_signature {
        transcript.extend_from_slice(signature);
    }
    Ok(hash(
        if result {
            NATIVE_EXCHANGE_V4_DOMAIN_RESULT_OUTPUT_LEAF
        } else {
            NATIVE_EXCHANGE_V4_DOMAIN_REQUEST_OUTPUT_LEAF
        },
        &transcript,
    ))
}

pub fn native_exchange_v4_request_output_leaf(
    index: u32,
    output: &NativeExchangeV4Output,
) -> Result<[u8; 32], NativeExchangeV4Error> {
    output.validate()?;
    let output_id = exact_b64::<16>(&output.output_id, "invalid output id")?;
    let descriptor_id = hex32(&output.descriptor_id, "invalid output descriptor id")?;
    let keyset_id = hex32(&output.keyset_id, "invalid output keyset id")?;
    let amount_minor = amount(&output.amount_minor)?;
    let blinded_message =
        exact_b64::<384>(&output.blinded_message, "blinded message must be raw384")?;
    native_exchange_v4_output_leaf(
        false,
        index,
        &output_id,
        &descriptor_id,
        &keyset_id,
        &output.slot_id,
        &output.asset_id,
        amount_minor,
        &blinded_message,
        None,
    )
}

pub fn native_exchange_v4_result_output_leaf(
    index: u32,
    output: &NativeExchangeV4ResultOutput,
) -> Result<[u8; 32], NativeExchangeV4Error> {
    output.validate()?;
    let output_id = exact_b64::<16>(&output.output_id, "invalid output id")?;
    let descriptor_id = hex32(&output.descriptor_id, "invalid output descriptor id")?;
    let keyset_id = hex32(&output.keyset_id, "invalid output keyset id")?;
    let amount_minor = amount(&output.amount_minor)?;
    let blinded_message =
        exact_b64::<384>(&output.blinded_message, "blinded message must be raw384")?;
    let blind_signature =
        exact_b64::<384>(&output.blind_signature, "blind signature must be raw384")?;
    native_exchange_v4_output_leaf(
        true,
        index,
        &output_id,
        &descriptor_id,
        &keyset_id,
        &output.slot_id,
        &output.asset_id,
        amount_minor,
        &blinded_message,
        Some(&blind_signature),
    )
}

pub fn native_exchange_v4_ordered_root(
    leaves: &[[u8; 32]],
) -> Result<[u8; 32], NativeExchangeV4Error> {
    if leaves.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS {
        return Err(NativeExchangeV4Error("too many Merkle leaves"));
    }
    let empty = hash(NATIVE_EXCHANGE_V4_DOMAIN_EMPTY_LEAF, &[]);
    let mut level = vec![empty; NATIVE_EXCHANGE_V4_MAX_ITEMS];
    level[..leaves.len()].copy_from_slice(leaves);
    let mut width = level.len();
    while width > 1 {
        let mut next = Vec::with_capacity(width / 2);
        let (pairs, remainder) = level[..width].as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(NativeExchangeV4Error("invalid Merkle tree width"));
        }
        for pair in pairs {
            next.push(hash(
                NATIVE_EXCHANGE_V4_DOMAIN_MERKLE_NODE,
                &[pair[0].as_slice(), pair[1].as_slice()].concat(),
            ));
        }
        level = next;
        width /= 2;
    }
    Ok(level[0])
}

fn put_text(
    out: &mut Vec<u8>,
    value: &str,
    error: &'static str,
) -> Result<(), NativeExchangeV4Error> {
    text(value, error)?;
    put_lp32(out, value.as_bytes())
}

fn put_ascii_text(
    out: &mut Vec<u8>,
    value: &str,
    error: &'static str,
) -> Result<(), NativeExchangeV4Error> {
    ascii_text(value, error)?;
    put_lp32(out, value.as_bytes())
}

fn put_raw32(
    out: &mut Vec<u8>,
    value: &str,
    error: &'static str,
) -> Result<(), NativeExchangeV4Error> {
    out.extend_from_slice(&hex32(value, error)?);
    Ok(())
}

fn put_lp32(out: &mut Vec<u8>, value: &[u8]) -> Result<(), NativeExchangeV4Error> {
    let length =
        u32::try_from(value.len()).map_err(|_| NativeExchangeV4Error("transcript too large"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn output_request_transcript(
    out: &mut Vec<u8>,
    index: u32,
    output: &NativeExchangeV4Output,
) -> Result<[u8; 32], NativeExchangeV4Error> {
    output.validate()?;
    let id = exact_b64::<16>(&output.output_id, "invalid output id")?;
    let descriptor = hex32(&output.descriptor_id, "invalid output descriptor id")?;
    let keyset = hex32(&output.keyset_id, "invalid output keyset id")?;
    let slot = &output.slot_id;
    let asset = &output.asset_id;
    let amount_minor = amount(&output.amount_minor)?;
    let blind = exact_b64::<384>(&output.blinded_message, "blinded message must be raw384")?;
    out.extend_from_slice(&id);
    out.extend_from_slice(&descriptor);
    out.extend_from_slice(&keyset);
    put_text(out, slot, "invalid output slot id")?;
    put_text(out, asset, "invalid output asset id")?;
    out.extend_from_slice(&amount_minor.to_be_bytes());
    out.extend_from_slice(&blind);
    native_exchange_v4_output_leaf(
        false,
        index,
        &id,
        &descriptor,
        &keyset,
        slot,
        asset,
        amount_minor,
        &blind,
        None,
    )
}

fn output_result_transcript(
    out: &mut Vec<u8>,
    index: u32,
    output: &NativeExchangeV4ResultOutput,
) -> Result<[u8; 32], NativeExchangeV4Error> {
    output.validate()?;
    let id = exact_b64::<16>(&output.output_id, "invalid output id")?;
    let descriptor = hex32(&output.descriptor_id, "invalid output descriptor id")?;
    let keyset = hex32(&output.keyset_id, "invalid output keyset id")?;
    let amount_minor = amount(&output.amount_minor)?;
    let blind = exact_b64::<384>(&output.blinded_message, "blinded message must be raw384")?;
    let signature = exact_b64::<384>(&output.blind_signature, "blind signature must be raw384")?;
    out.extend_from_slice(&id);
    out.extend_from_slice(&descriptor);
    out.extend_from_slice(&keyset);
    put_text(out, &output.slot_id, "invalid output slot id")?;
    put_text(out, &output.asset_id, "invalid output asset id")?;
    out.extend_from_slice(&amount_minor.to_be_bytes());
    out.extend_from_slice(&blind);
    out.extend_from_slice(&signature);
    native_exchange_v4_output_leaf(
        true,
        index,
        &id,
        &descriptor,
        &keyset,
        &output.slot_id,
        &output.asset_id,
        amount_minor,
        &blind,
        Some(&signature),
    )
}

impl NativeExchangeV4Output {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        exact_b64::<16>(&self.output_id, "invalid output id")?;
        hex32(&self.descriptor_id, "invalid output descriptor id")?;
        hex32(&self.keyset_id, "invalid output keyset id")?;
        ascii_text(&self.slot_id, "invalid output slot id")?;
        text(&self.asset_id, "invalid output asset id")?;
        amount(&self.amount_minor)?;
        exact_b64::<384>(&self.blinded_message, "blinded message must be raw384")?;
        Ok(())
    }
}

impl NativeExchangeV4ResultOutput {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        NativeExchangeV4Output {
            output_id: self.output_id.clone(),
            descriptor_id: self.descriptor_id.clone(),
            keyset_id: self.keyset_id.clone(),
            slot_id: self.slot_id.clone(),
            asset_id: self.asset_id.clone(),
            amount_minor: self.amount_minor.clone(),
            blinded_message: self.blinded_message.clone(),
        }
        .validate()?;
        exact_b64::<384>(&self.blind_signature, "blind signature must be raw384")?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn prefix(
    version: u8,
    profile_id: &str,
    issuer_or_federation_id: &str,
    public_operation_id: &str,
    status_capability_digest: Option<&str>,
    graph_id: &str,
    transition_id: &str,
    source_keyset_id: &str,
    target_keyset_id: &str,
    asset_id: &str,
) -> Result<Vec<u8>, NativeExchangeV4Error> {
    if version != 4 || profile_id != NATIVE_EXCHANGE_V4_PROFILE_ID {
        return Err(NativeExchangeV4Error(
            "unsupported V4 exchange version/profile",
        ));
    }
    text(issuer_or_federation_id, "invalid issuer or federation id")?;
    text(asset_id, "invalid exchange asset id")?;
    let mut out = vec![version];
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
    if let Some(digest) = status_capability_digest {
        out.extend_from_slice(&hex32(digest, "invalid status capability digest")?);
    }
    for value in [graph_id, transition_id, source_keyset_id, target_keyset_id] {
        out.extend_from_slice(&hex32(value, "invalid exchange selector")?);
    }
    put_text(&mut out, asset_id, "invalid exchange asset id")?;
    Ok(out)
}

fn unique_output_ids<I>(ids: I) -> Result<(), NativeExchangeV4Error>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(id.as_ref().to_owned()) {
            return Err(NativeExchangeV4Error("duplicate output id"));
        }
    }
    Ok(())
}

impl NativeExchangeV4Request {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        self.canonical_bytes().map(|_| ())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeExchangeV4Error> {
        let mut out = prefix(
            self.version,
            &self.profile_id,
            &self.issuer_or_federation_id,
            &self.public_operation_id,
            Some(&self.status_capability_digest),
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
            &self.asset_id,
        )?;
        if self.sources.is_empty()
            || self.sources.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
            || self.outputs.is_empty()
            || self.outputs.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
            || self.source_count as usize != self.sources.len()
            || self.output_count as usize != self.outputs.len()
        {
            return Err(NativeExchangeV4Error("invalid V4 exchange counts"));
        }
        let source_total = amount(&self.source_total_minor)?;
        let output_total = amount(&self.output_total_minor)?;
        if source_total != output_total {
            return Err(NativeExchangeV4Error("exchange conservation mismatch"));
        }
        out.extend_from_slice(&self.source_count.to_be_bytes());
        out.extend_from_slice(&self.output_count.to_be_bytes());
        out.extend_from_slice(&source_total.to_be_bytes());
        out.extend_from_slice(&output_total.to_be_bytes());
        let declared_source_root = hex32(&self.source_root, "invalid source root")?;
        let declared_request_root = hex32(&self.request_output_root, "invalid request root")?;
        out.extend_from_slice(&declared_source_root);
        out.extend_from_slice(&declared_request_root);
        let mut source_leaves = Vec::with_capacity(self.sources.len());
        let mut source_sum = 0u64;
        for (index, source) in self.sources.iter().enumerate() {
            out.extend_from_slice(&source.transcript()?);
            let artifact = source.artifact_bytes()?;
            let digest = hex32(&source.source_artifact_digest, "invalid source digest")?;
            let descriptor = hex32(&source.descriptor_id, "invalid source descriptor id")?;
            let keyset = hex32(&source.keyset_id, "invalid source keyset id")?;
            source_leaves.push(native_exchange_v4_source_leaf(
                index as u32,
                &artifact,
                &digest,
                &descriptor,
                &keyset,
                &source.slot_id,
            )?);
            let (asset, value) = source.policy()?;
            if asset != self.asset_id {
                return Err(NativeExchangeV4Error("mixed source assets"));
            }
            source_sum = source_sum
                .checked_add(value)
                .ok_or(NativeExchangeV4Error("source total overflow"))?;
        }
        if source_sum != source_total {
            return Err(NativeExchangeV4Error("declared source total mismatch"));
        }
        unique_output_ids(self.outputs.iter().map(|output| output.output_id.as_str()))?;
        let mut output_leaves = Vec::with_capacity(self.outputs.len());
        let mut output_sum = 0u64;
        for (index, output) in self.outputs.iter().enumerate() {
            if output.asset_id != self.asset_id {
                return Err(NativeExchangeV4Error("mixed exchange assets"));
            }
            output.validate()?;
            let amount_minor = amount(&output.amount_minor)?;
            output_sum = output_sum
                .checked_add(amount_minor)
                .ok_or(NativeExchangeV4Error("output total overflow"))?;
            output_leaves.push(output_request_transcript(&mut out, index as u32, output)?);
        }
        if output_sum != output_total {
            return Err(NativeExchangeV4Error("declared output total mismatch"));
        }
        let source_root = native_exchange_v4_ordered_root(&source_leaves)?;
        let request_root = native_exchange_v4_ordered_root(&output_leaves)?;
        if source_root != declared_source_root || request_root != declared_request_root {
            return Err(NativeExchangeV4Error("exchange root mismatch"));
        }
        Ok(out)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], NativeExchangeV4Error> {
        Ok(hash(
            NATIVE_EXCHANGE_V4_DOMAIN_REQUEST,
            &self.canonical_bytes()?,
        ))
    }
}

impl NativeExchangeV4Result {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        let expected = hex32(&self.result_digest, "invalid result digest")?;
        if expected != self.result_digest()? {
            return Err(NativeExchangeV4Error("result digest mismatch"));
        }
        Ok(())
    }

    pub fn result_digest(&self) -> Result<[u8; 32], NativeExchangeV4Error> {
        let mut out = prefix(
            self.version,
            &self.profile_id,
            &self.issuer_or_federation_id,
            &self.public_operation_id,
            None,
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
            &self.asset_id,
        )?;
        if self.outputs.is_empty()
            || self.outputs.len() > NATIVE_EXCHANGE_V4_MAX_ITEMS
            || self.output_count as usize != self.outputs.len()
            || self.source_count == 0
            || self.source_count > NATIVE_EXCHANGE_V4_MAX_ITEMS as u32
        {
            return Err(NativeExchangeV4Error("invalid V4 result count"));
        }
        let source_total = amount(&self.source_total_minor)?;
        let output_total = amount(&self.output_total_minor)?;
        if source_total != output_total {
            return Err(NativeExchangeV4Error("result conservation mismatch"));
        }
        out.extend_from_slice(&self.source_count.to_be_bytes());
        out.extend_from_slice(&self.output_count.to_be_bytes());
        out.extend_from_slice(&source_total.to_be_bytes());
        out.extend_from_slice(&output_total.to_be_bytes());
        let source_root = hex32(&self.source_root, "invalid source root")?;
        let request_root = hex32(&self.request_output_root, "invalid request root")?;
        let result_root = hex32(&self.result_output_root, "invalid result root")?;
        let request_digest = hex32(&self.request_digest, "invalid request digest")?;
        out.extend_from_slice(&source_root);
        out.extend_from_slice(&request_root);
        out.extend_from_slice(&result_root);
        out.extend_from_slice(&request_digest);
        unique_output_ids(self.outputs.iter().map(|output| output.output_id.as_str()))?;
        let mut request_leaves = Vec::with_capacity(self.outputs.len());
        let mut result_leaves = Vec::with_capacity(self.outputs.len());
        let mut output_sum = 0u64;
        for (index, output) in self.outputs.iter().enumerate() {
            if output.asset_id != self.asset_id {
                return Err(NativeExchangeV4Error("mixed result assets"));
            }
            let amount_minor = amount(&output.amount_minor)?;
            output_sum = output_sum
                .checked_add(amount_minor)
                .ok_or(NativeExchangeV4Error("result total overflow"))?;
            let mut result_transcript = Vec::new();
            let mut request_leaf_transcript = Vec::new();
            request_leaves.push(output_request_transcript(
                &mut request_leaf_transcript,
                index as u32,
                &NativeExchangeV4Output {
                    output_id: output.output_id.clone(),
                    descriptor_id: output.descriptor_id.clone(),
                    keyset_id: output.keyset_id.clone(),
                    slot_id: output.slot_id.clone(),
                    asset_id: output.asset_id.clone(),
                    amount_minor: output.amount_minor.clone(),
                    blinded_message: output.blinded_message.clone(),
                },
            )?);
            result_leaves.push(output_result_transcript(
                &mut result_transcript,
                index as u32,
                output,
            )?);
            out.extend_from_slice(&result_transcript);
        }
        if output_sum != output_total
            || native_exchange_v4_ordered_root(&request_leaves)? != request_root
            || native_exchange_v4_ordered_root(&result_leaves)? != result_root
        {
            return Err(NativeExchangeV4Error("result root or total mismatch"));
        }
        Ok(hash(NATIVE_EXCHANGE_V4_DOMAIN_RESULT, &out))
    }
}

impl NativeExchangeV4Receipt {
    pub fn validate(&self) -> Result<(), NativeExchangeV4Error> {
        prefix(
            self.version,
            &self.profile_id,
            &self.issuer_or_federation_id,
            &self.public_operation_id,
            None,
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
            &self.asset_id,
        )?;
        let source_total = amount(&self.source_total_minor)?;
        let output_total = amount(&self.output_total_minor)?;
        if self.source_count == 0
            || self.source_count > NATIVE_EXCHANGE_V4_MAX_ITEMS as u32
            || self.output_count == 0
            || self.output_count > NATIVE_EXCHANGE_V4_MAX_ITEMS as u32
            || source_total != output_total
            || self.expires_at < self.created_at
            || self.output_recovery_until < self.created_at
            || self.expires_at - self.created_at != NATIVE_EXCHANGE_V4_RECEIPT_LIFETIME_SECS
            || self.output_recovery_until - self.created_at
                != NATIVE_EXCHANGE_V4_RECEIPT_LIFETIME_SECS
        {
            return Err(NativeExchangeV4Error("invalid V4 receipt validity"));
        }
        for value in [
            &self.source_root,
            &self.request_output_root,
            &self.result_output_root,
            &self.request_digest,
            &self.result_digest,
            &self.receipt_key_id,
        ] {
            hex32(value, "invalid receipt digest field")?;
        }
        exact_b64::<64>(&self.signature, "invalid receipt signature")?;
        Ok(())
    }

    pub fn receipt_digest(&self) -> Result<[u8; 32], NativeExchangeV4Error> {
        self.validate()?;
        let mut out = prefix(
            self.version,
            &self.profile_id,
            &self.issuer_or_federation_id,
            &self.public_operation_id,
            None,
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
            put_raw32(&mut out, value, "invalid receipt digest field")?;
        }
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.output_recovery_until.to_be_bytes());
        Ok(hash(NATIVE_EXCHANGE_V4_DOMAIN_RECEIPT, &out))
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

    #[test]
    fn v4_contract_rejects_v3_profile_and_noncanonical_encodings() {
        let profile = NativeExchangeV4Profile {
            version: 3,
            profile_id: NATIVE_EXCHANGE_V4_PROFILE_ID.into(),
            graph_id: "aa".repeat(32),
            suite: NATIVE_EXCHANGE_V4_SUITE.into(),
            modulus_bits: 3072,
            exponent: 65_537,
        };
        assert!(profile.validate().is_err());
        assert!(exact_b64::<384>(&raw::<384>(), "raw384").is_ok());
        assert!(exact_b64::<384>(&raw::<32>(), "raw384").is_err());
        assert!(hex32(&"AA".repeat(32), "hex").is_err());
    }

    #[test]
    fn v4_output_leaves_bind_values_and_ordered_roots() {
        let first = native_exchange_v4_output_leaf(
            false, 0, &[1; 16], &[2; 32], &[3; 32], "slot", "USD", 1, &[4; 384], None,
        )
        .unwrap();
        let second = native_exchange_v4_output_leaf(
            false, 1, &[5; 16], &[6; 32], &[7; 32], "slot", "USD", 2, &[8; 384], None,
        )
        .unwrap();
        assert_ne!(first, second);
        assert_ne!(
            native_exchange_v4_ordered_root(&[first, second]).unwrap(),
            native_exchange_v4_ordered_root(&[second, first]).unwrap()
        );
        assert!(native_exchange_v4_ordered_root(&[[0; 32]; 65]).is_err());
    }

    #[test]
    fn v4_ordered_root_matches_independent_fixture() {
        let first = native_exchange_v4_output_leaf(
            false, 0, &[1; 16], &[2; 32], &[3; 32], "slot", "USD", 1, &[4; 384], None,
        )
        .unwrap();
        let second = native_exchange_v4_output_leaf(
            false, 1, &[5; 16], &[6; 32], &[7; 32], "slot", "USD", 2, &[8; 384], None,
        )
        .unwrap();
        assert_eq!(
            hex::encode(native_exchange_v4_ordered_root(&[first, second]).unwrap()),
            "d7a316c537709f1b1fbc8d19bffcfbdd32bde4312a089284c1bdb195cf9f1b2f"
        );
        assert_eq!(
            hex::encode(
                native_exchange_v4_output_leaf(
                    true,
                    0,
                    &[1; 16],
                    &[2; 32],
                    &[3; 32],
                    "slot",
                    "USD",
                    1,
                    &[4; 384],
                    Some(&[5; 384]),
                )
                .unwrap()
            ),
            "a9c1dbb50add9413a3a7324f6e00976b3f947b592d144e48b8d57b8d916910a2"
        );
    }

    #[test]
    fn v4_receipt_key_metadata_is_purpose_bound() {
        let public = [9; 32];
        let key = NativeExchangeV4ReceiptKeyMetadata {
            key_id: hex::encode(Sha256::digest(public)),
            algorithm: NATIVE_EXCHANGE_V4_RECEIPT_KEY_ALGORITHM.into(),
            purpose: "exchange_receipt_v3".into(),
            public_key_b64: Base64UrlUnpadded::encode_string(&public),
            valid_from: 1,
            valid_until: 2,
        };
        assert!(key.validate().is_err());
    }

    #[test]
    fn v4_descriptor_id_literal_vector_is_profile_and_domain_bound() {
        let descriptor_id = derive_native_exchange_v4_descriptor_id(
            NATIVE_EXCHANGE_V4_PROFILE_ID,
            "issuer:test",
            &"11".repeat(32),
            "USD",
            42,
            NATIVE_EXCHANGE_V4_SUITE,
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
            "a015ad94ad94a0d3ac45247ea3b9bce724f8115ac296107c45b3bc01d43fcb6a"
        );
    }

    #[test]
    fn v4_receipt_digest_matches_independent_fixture() {
        let receipt = NativeExchangeV4Receipt {
            version: 4,
            profile_id: NATIVE_EXCHANGE_V4_PROFILE_ID.into(),
            issuer_or_federation_id: "issuer".into(),
            public_operation_id: Base64UrlUnpadded::encode_string(&[1; 16]),
            graph_id: "02".repeat(32),
            transition_id: "03".repeat(32),
            source_keyset_id: "04".repeat(32),
            target_keyset_id: "05".repeat(32),
            asset_id: "USD".into(),
            source_count: 1,
            output_count: 1,
            source_total_minor: "1".into(),
            output_total_minor: "1".into(),
            source_root: "00".repeat(32),
            request_output_root: "00".repeat(32),
            result_output_root: "00".repeat(32),
            request_digest: "00".repeat(32),
            result_digest: "00".repeat(32),
            created_at: 10,
            expires_at: 10 + NATIVE_EXCHANGE_V4_RECEIPT_LIFETIME_SECS,
            output_recovery_until: 10 + NATIVE_EXCHANGE_V4_RECEIPT_LIFETIME_SECS,
            receipt_key_id: "11".repeat(32),
            signature: Base64UrlUnpadded::encode_string(&[6; 64]),
        };
        assert_eq!(
            hex::encode(receipt.receipt_digest().unwrap()),
            "604368f4bb02bb18269840a701b12fbbd96058d65536fb357c78094399167c11"
        );
    }
}
