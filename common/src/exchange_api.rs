// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Frozen, bounded exchange wire primitives.  This module intentionally does
//! not use the token/nullifier hashing code.
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EXCHANGE_PROFILE_V1: &str = "freebird/public-bearer-exchange/v1";
pub const EXCHANGE_PROFILE_V2: &str = "freebird/public-bearer-exchange/v2";
pub const EXCHANGE_VERSION_V2: u8 = 2;
pub const MAX_ITEMS: usize = 64;
pub const MAX_ID: usize = 128;
pub const MAX_ARTIFACT: usize = 16 * 1024;
pub const DIGEST_LEN: usize = 32;
pub const MAX_RSA_SIGNATURE: usize = 512;
pub const DOMAIN_REQUEST: &[u8] = b"freebird exchange request v1\0";
pub const DOMAIN_RESULT: &[u8] = b"freebird exchange result v1\0";
pub const DOMAIN_DESCRIPTOR: &[u8] = b"freebird exchange descriptor v1\0";
pub const DOMAIN_RECEIPT: &[u8] = b"freebird exchange receipt v1\0";
pub const DOMAIN_RULE: &[u8] = b"freebird exchange rule v1\0";
pub const DOMAIN_KEYSET: &[u8] = b"freebird exchange keyset v1\0";
pub const DOMAIN_REQUEST_V2: &[u8] = b"freebird exchange request v2\0";
pub const DOMAIN_RESULT_V2: &[u8] = b"freebird exchange result v2\0";
pub const DOMAIN_DESCRIPTOR_V2: &[u8] = b"freebird exchange descriptor v2\0";
pub const DOMAIN_RECEIPT_V2: &[u8] = b"freebird exchange receipt v2\0";
pub const DOMAIN_TRANSITION_V2: &[u8] = b"freebird exchange transition v2\0";
pub const DOMAIN_KEYSET_V2: &[u8] = b"freebird exchange keyset v2\0";
pub const DOMAIN_GRAPH_V2: &[u8] = b"freebird exchange graph v2\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeSlot {
    pub descriptor_id: String,
    pub keyset_id: String,
    pub slot_id: String,
    pub quantity: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeSource {
    pub slot: ExchangeSlot,
    pub artifact: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeOutput {
    pub slot: ExchangeSlot,
    pub blinded_value: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRequest {
    pub profile: String,
    pub rule_id: String,
    pub sources: Vec<ExchangeSource>,
    pub outputs: Vec<ExchangeOutput>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeResultOutput {
    pub slot: ExchangeSlot,
    pub blinded_value: String,
    pub blind_signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeResult {
    pub operation_id: String,
    pub profile: String,
    pub target_keyset_id: String,
    pub outputs: Vec<ExchangeResultOutput>,
    pub result_digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeReceipt {
    pub operation_id: String,
    pub profile: String,
    pub target_keyset_id: String,
    pub result_digest: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub receipt_key_id: String,
    pub signature: String,
}

/// V2 request selectors are explicit so an operation cannot be replayed on a
/// different graph edge or against a different revision of either keyset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRequestV2 {
    pub version: u8,
    pub public_operation_id: String,
    pub graph_id: String,
    pub transition_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub sources: Vec<ExchangeSource>,
    pub outputs: Vec<ExchangeOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeResultV2 {
    pub version: u8,
    pub public_operation_id: String,
    pub graph_id: String,
    pub transition_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub outputs: Vec<ExchangeResultOutput>,
    pub result_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeReceiptV2 {
    pub version: u8,
    pub public_operation_id: String,
    pub graph_id: String,
    pub transition_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub result_digest: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub receipt_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeError(pub &'static str);
impl std::fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ExchangeError {}
fn id(s: &str, error: &'static str) -> Result<(), ExchangeError> {
    if s.is_empty() || s.len() > MAX_ID || !s.is_ascii() {
        Err(ExchangeError(error))
    } else {
        Ok(())
    }
}
pub fn validate_profile(s: &str) -> Result<(), ExchangeError> {
    id(s, "invalid profile")
}
pub fn validate_descriptor_id(s: &str) -> Result<(), ExchangeError> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ExchangeError("invalid descriptor id"));
    }
    Ok(())
}
pub fn validate_keyset_id(s: &str) -> Result<(), ExchangeError> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ExchangeError("invalid keyset id"));
    }
    Ok(())
}
pub fn validate_rule_id(s: &str) -> Result<(), ExchangeError> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ExchangeError("invalid rule id"));
    }
    Ok(())
}
pub fn validate_receipt_key_id(s: &str) -> Result<(), ExchangeError> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ExchangeError("invalid receipt key id"));
    }
    Ok(())
}
pub fn validate_slot_id(s: &str) -> Result<(), ExchangeError> {
    id(s, "invalid slot id")
}
pub fn decode_base64url(s: &str, max: usize) -> Result<Vec<u8>, ExchangeError> {
    if s.contains('=') || s.len() > max.div_ceil(3) * 4 {
        return Err(ExchangeError("invalid base64url"));
    }
    let b = Base64UrlUnpadded::decode_vec(s).map_err(|_| ExchangeError("invalid base64url"))?;
    if b.len() > max || Base64UrlUnpadded::encode_string(&b) != s {
        Err(ExchangeError("non-canonical base64url"))
    } else {
        Ok(b)
    }
}
pub fn parse_operation_id(s: &str) -> Result<[u8; 16], ExchangeError> {
    decode_base64url(s, 16)?
        .try_into()
        .map_err(|_| ExchangeError("operation id must be 16 bytes"))
}
pub fn parse_operation_id_header(s: &str) -> Result<[u8; 16], ExchangeError> {
    parse_operation_id(s)
}
pub fn public_operation_id(operation_id: &[u8; 16]) -> String {
    Base64UrlUnpadded::encode_string(operation_id)
}
fn put(o: &mut Vec<u8>, b: &[u8]) {
    o.extend_from_slice(&(b.len() as u32).to_be_bytes());
    o.extend_from_slice(b);
}
fn slot(o: &mut Vec<u8>, s: &ExchangeSlot) -> Result<(), ExchangeError> {
    validate_descriptor_id(&s.descriptor_id)?;
    validate_keyset_id(&s.keyset_id)?;
    validate_slot_id(&s.slot_id)?;
    if s.quantity == 0 {
        return Err(ExchangeError("quantity must be nonzero"));
    }
    put(o, s.descriptor_id.as_bytes());
    put(o, s.keyset_id.as_bytes());
    put(o, s.slot_id.as_bytes());
    o.extend_from_slice(&s.quantity.to_be_bytes());
    Ok(())
}
pub fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
pub fn descriptor_id(canonical_descriptor: &[u8]) -> String {
    hex::encode(domain_hash(DOMAIN_DESCRIPTOR, canonical_descriptor))
}
pub fn rule_id(canonical_rule: &[u8]) -> String {
    hex::encode(domain_hash(DOMAIN_RULE, canonical_rule))
}
pub fn keyset_id(ordered_descriptor_ids: &[String]) -> String {
    let mut bytes = Vec::new();
    for id in ordered_descriptor_ids {
        put(&mut bytes, id.as_bytes());
    }
    hex::encode(domain_hash(DOMAIN_KEYSET, &bytes))
}

pub fn descriptor_id_v2(canonical_descriptor: &[u8]) -> String {
    hex::encode(domain_hash(DOMAIN_DESCRIPTOR_V2, canonical_descriptor))
}

pub fn keyset_id_v2(ordered_descriptor_ids: &[String]) -> String {
    let mut bytes = Vec::new();
    for id in ordered_descriptor_ids {
        put(&mut bytes, id.as_bytes());
    }
    hex::encode(domain_hash(DOMAIN_KEYSET_V2, &bytes))
}

pub fn transition_id_v2(canonical_stable_contract: &[u8]) -> String {
    hex::encode(domain_hash(DOMAIN_TRANSITION_V2, canonical_stable_contract))
}

pub fn graph_id_v2(canonical_graph: &[u8]) -> String {
    hex::encode(domain_hash(DOMAIN_GRAPH_V2, canonical_graph))
}

pub fn validate_graph_id(s: &str) -> Result<(), ExchangeError> {
    validate_sha256_id(s, "invalid graph id")
}

pub fn validate_transition_id(s: &str) -> Result<(), ExchangeError> {
    validate_sha256_id(s, "invalid transition id")
}

fn validate_sha256_id(s: &str, error: &'static str) -> Result<(), ExchangeError> {
    if s.len() != DIGEST_LEN * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ExchangeError(error));
    }
    Ok(())
}

fn v2_selectors(
    o: &mut Vec<u8>,
    version: u8,
    operation_id: &str,
    graph_id: &str,
    transition_id: &str,
    source_keyset_id: &str,
    target_keyset_id: &str,
) -> Result<(), ExchangeError> {
    if version != EXCHANGE_VERSION_V2 {
        return Err(ExchangeError("unsupported exchange version"));
    }
    o.push(version);
    put(o, &parse_operation_id(operation_id)?);
    validate_graph_id(graph_id)?;
    validate_transition_id(transition_id)?;
    validate_keyset_id(source_keyset_id)?;
    validate_keyset_id(target_keyset_id)?;
    if source_keyset_id == target_keyset_id {
        return Err(ExchangeError("source and target keysets must differ"));
    }
    for value in [graph_id, transition_id, source_keyset_id, target_keyset_id] {
        put(o, value.as_bytes());
    }
    Ok(())
}

fn nonempty_base64url(s: &str, max: usize, error: &'static str) -> Result<Vec<u8>, ExchangeError> {
    let value = decode_base64url(s, max)?;
    if value.is_empty() {
        Err(ExchangeError(error))
    } else {
        Ok(value)
    }
}

impl ExchangeRequestV2 {
    pub fn validate(&self) -> Result<(), ExchangeError> {
        self.canonical_bytes().map(|_| ())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExchangeError> {
        let mut o = Vec::new();
        v2_selectors(
            &mut o,
            self.version,
            &self.public_operation_id,
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
        )?;
        if self.sources.is_empty()
            || self.sources.len() > MAX_ITEMS
            || self.outputs.is_empty()
            || self.outputs.len() > MAX_ITEMS
        {
            return Err(ExchangeError("exchange bounds exceeded"));
        }
        o.extend_from_slice(&(self.sources.len() as u32).to_be_bytes());
        for source in &self.sources {
            if source.slot.keyset_id != self.source_keyset_id {
                return Err(ExchangeError("source keyset binding mismatch"));
            }
            slot(&mut o, &source.slot)?;
            put(
                &mut o,
                &nonempty_base64url(&source.artifact, MAX_ARTIFACT, "empty source artifact")?,
            );
        }
        o.extend_from_slice(&(self.outputs.len() as u32).to_be_bytes());
        for output in &self.outputs {
            if output.slot.keyset_id != self.target_keyset_id {
                return Err(ExchangeError("target keyset binding mismatch"));
            }
            slot(&mut o, &output.slot)?;
            put(
                &mut o,
                &nonempty_base64url(&output.blinded_value, MAX_ARTIFACT, "empty blinded value")?,
            );
        }
        Ok(o)
    }

    pub fn request_digest(&self) -> Result<[u8; DIGEST_LEN], ExchangeError> {
        Ok(domain_hash(DOMAIN_REQUEST_V2, &self.canonical_bytes()?))
    }

    pub fn validate_request_digest(&self, expected: &str) -> Result<(), ExchangeError> {
        let expected = decode_digest(expected, "invalid request digest")?;
        if expected != self.request_digest()? {
            return Err(ExchangeError("request digest mismatch"));
        }
        Ok(())
    }
}

impl ExchangeResultV2 {
    pub fn validate(&self) -> Result<(), ExchangeError> {
        self.canonical_bytes().map(|_| ())
    }

    fn bytes_without_digest(&self) -> Result<Vec<u8>, ExchangeError> {
        let mut o = Vec::new();
        v2_selectors(
            &mut o,
            self.version,
            &self.public_operation_id,
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
        )?;
        if self.outputs.is_empty() || self.outputs.len() > MAX_ITEMS {
            return Err(ExchangeError("result bounds exceeded"));
        }
        o.extend_from_slice(&(self.outputs.len() as u32).to_be_bytes());
        for output in &self.outputs {
            if output.slot.keyset_id != self.target_keyset_id {
                return Err(ExchangeError("target keyset binding mismatch"));
            }
            slot(&mut o, &output.slot)?;
            put(
                &mut o,
                &nonempty_base64url(&output.blinded_value, MAX_ARTIFACT, "empty blinded value")?,
            );
            put(
                &mut o,
                &nonempty_base64url(
                    &output.blind_signature,
                    MAX_RSA_SIGNATURE,
                    "empty blind signature",
                )?,
            );
        }
        Ok(o)
    }

    pub fn result_digest(&self) -> Result<[u8; DIGEST_LEN], ExchangeError> {
        Ok(domain_hash(DOMAIN_RESULT_V2, &self.bytes_without_digest()?))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExchangeError> {
        let mut o = self.bytes_without_digest()?;
        let digest = decode_digest(&self.result_digest, "invalid result digest")?;
        if digest != self.result_digest()? {
            return Err(ExchangeError("result digest mismatch"));
        }
        put(&mut o, &digest);
        Ok(o)
    }
}

impl ExchangeReceiptV2 {
    pub fn validate(&self) -> Result<(), ExchangeError> {
        self.canonical_payload()?;
        self.validate_signature()
    }

    pub fn canonical_payload(&self) -> Result<Vec<u8>, ExchangeError> {
        let mut o = Vec::new();
        v2_selectors(
            &mut o,
            self.version,
            &self.public_operation_id,
            &self.graph_id,
            &self.transition_id,
            &self.source_keyset_id,
            &self.target_keyset_id,
        )?;
        let result_digest = decode_digest(&self.result_digest, "invalid result digest")?;
        put(&mut o, &result_digest);
        if self.expires_at <= self.created_at {
            return Err(ExchangeError("invalid receipt validity"));
        }
        o.extend_from_slice(&self.created_at.to_be_bytes());
        o.extend_from_slice(&self.expires_at.to_be_bytes());
        validate_receipt_key_id(&self.receipt_key_id)?;
        put(&mut o, self.receipt_key_id.as_bytes());
        Ok(o)
    }

    pub fn receipt_digest(&self) -> Result<[u8; DIGEST_LEN], ExchangeError> {
        Ok(domain_hash(DOMAIN_RECEIPT_V2, &self.canonical_payload()?))
    }

    pub fn signing_digest(&self) -> Result<[u8; DIGEST_LEN], ExchangeError> {
        self.receipt_digest()
    }

    pub fn validate_signature(&self) -> Result<(), ExchangeError> {
        if decode_base64url(&self.signature, 64)?.len() != 64 {
            return Err(ExchangeError("invalid receipt signature"));
        }
        Ok(())
    }

    pub fn validate_result(&self, result: &ExchangeResultV2) -> Result<(), ExchangeError> {
        self.validate()?;
        result.canonical_bytes()?;
        if self.version != result.version
            || self.public_operation_id != result.public_operation_id
            || self.graph_id != result.graph_id
            || self.transition_id != result.transition_id
            || self.source_keyset_id != result.source_keyset_id
            || self.target_keyset_id != result.target_keyset_id
            || self.result_digest != result.result_digest
        {
            return Err(ExchangeError("receipt result binding mismatch"));
        }
        Ok(())
    }
}

fn decode_digest(s: &str, error: &'static str) -> Result<[u8; DIGEST_LEN], ExchangeError> {
    decode_base64url(s, DIGEST_LEN)?
        .try_into()
        .map_err(|_| ExchangeError(error))
}

impl ExchangeRequest {
    pub fn canonical_bytes(&self, op: &[u8; 16]) -> Result<Vec<u8>, ExchangeError> {
        if self.profile != EXCHANGE_PROFILE_V1 {
            return Err(ExchangeError("unsupported profile"));
        }
        if self.sources.is_empty()
            || self.sources.len() > MAX_ITEMS
            || self.outputs.is_empty()
            || self.outputs.len() > MAX_ITEMS
        {
            return Err(ExchangeError("exchange bounds exceeded"));
        }
        let mut o = vec![1];
        put(&mut o, op);
        put(&mut o, self.profile.as_bytes());
        validate_rule_id(&self.rule_id)?;
        put(&mut o, self.rule_id.as_bytes());
        o.extend_from_slice(&(self.sources.len() as u32).to_be_bytes());
        for x in &self.sources {
            slot(&mut o, &x.slot)?;
            put(&mut o, &decode_base64url(&x.artifact, MAX_ARTIFACT)?);
        }
        o.extend_from_slice(&(self.outputs.len() as u32).to_be_bytes());
        for x in &self.outputs {
            slot(&mut o, &x.slot)?;
            put(&mut o, &decode_base64url(&x.blinded_value, MAX_ARTIFACT)?);
        }
        Ok(o)
    }
    pub fn canonical_hash(&self, op: &[u8; 16]) -> Result<[u8; 32], ExchangeError> {
        Ok(domain_hash(DOMAIN_REQUEST, &self.canonical_bytes(op)?))
    }
}
impl ExchangeResult {
    fn bytes_without_digest(&self) -> Result<Vec<u8>, ExchangeError> {
        if self.profile != EXCHANGE_PROFILE_V1 {
            return Err(ExchangeError("unsupported profile"));
        }
        let mut o = vec![1];
        put(&mut o, &parse_operation_id(&self.operation_id)?);
        put(&mut o, self.profile.as_bytes());
        validate_keyset_id(&self.target_keyset_id)?;
        put(&mut o, self.target_keyset_id.as_bytes());
        if self.outputs.is_empty() || self.outputs.len() > MAX_ITEMS {
            return Err(ExchangeError("result bounds exceeded"));
        }
        o.extend_from_slice(&(self.outputs.len() as u32).to_be_bytes());
        for x in &self.outputs {
            slot(&mut o, &x.slot)?;
            put(&mut o, &decode_base64url(&x.blinded_value, MAX_ARTIFACT)?);
            let s = decode_base64url(&x.blind_signature, MAX_RSA_SIGNATURE)?;
            if s.is_empty() || s.len() > MAX_RSA_SIGNATURE {
                return Err(ExchangeError("invalid blind signature"));
            }
            put(&mut o, &s);
        }
        Ok(o)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExchangeError> {
        let mut o = self.bytes_without_digest()?;
        let d = decode_base64url(&self.result_digest, DIGEST_LEN)?;
        if d.len() != DIGEST_LEN || d.as_slice() != domain_hash(DOMAIN_RESULT, &o) {
            return Err(ExchangeError("result digest mismatch"));
        }
        put(&mut o, &d);
        Ok(o)
    }
    pub fn result_digest(&self) -> Result<[u8; 32], ExchangeError> {
        Ok(domain_hash(DOMAIN_RESULT, &self.bytes_without_digest()?))
    }
}
impl ExchangeReceipt {
    pub fn canonical_payload(&self) -> Result<Vec<u8>, ExchangeError> {
        let mut o = vec![1];
        put(&mut o, &parse_operation_id(&self.operation_id)?);
        if self.profile != EXCHANGE_PROFILE_V1 {
            return Err(ExchangeError("unsupported profile"));
        }
        put(&mut o, self.profile.as_bytes());
        validate_keyset_id(&self.target_keyset_id)?;
        put(&mut o, self.target_keyset_id.as_bytes());
        let d = decode_base64url(&self.result_digest, DIGEST_LEN)?;
        if d.len() != DIGEST_LEN {
            return Err(ExchangeError("invalid result digest"));
        }
        put(&mut o, &d);
        o.extend_from_slice(&self.created_at.to_be_bytes());
        o.extend_from_slice(&self.expires_at.to_be_bytes());
        validate_receipt_key_id(&self.receipt_key_id)?;
        if self.expires_at <= self.created_at {
            return Err(ExchangeError("invalid receipt validity"));
        }
        put(&mut o, self.receipt_key_id.as_bytes());
        Ok(o)
    }
    pub fn signing_digest(&self) -> Result<[u8; 32], ExchangeError> {
        Ok(domain_hash(DOMAIN_RECEIPT, &self.canonical_payload()?))
    }
    pub fn validate_signature(&self) -> Result<(), ExchangeError> {
        let sig = decode_base64url(&self.signature, 64)?;
        if sig.len() != 64 {
            return Err(ExchangeError("invalid receipt signature"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type RequestMutation = Box<dyn Fn(&mut ExchangeRequestV2)>;
    type ResultMutation = Box<dyn Fn(&mut ExchangeResultV2)>;

    fn b(v: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(v)
    }
    fn request() -> ExchangeRequest {
        ExchangeRequest {
            profile: EXCHANGE_PROFILE_V1.into(),
            rule_id: "c".repeat(64),
            sources: vec![ExchangeSource {
                slot: ExchangeSlot {
                    descriptor_id: "a".repeat(64),
                    keyset_id: "1".repeat(64),
                    slot_id: "0".into(),
                    quantity: 1,
                },
                artifact: b(b"artifact"),
            }],
            outputs: vec![ExchangeOutput {
                slot: ExchangeSlot {
                    descriptor_id: "b".repeat(64),
                    keyset_id: "2".repeat(64),
                    slot_id: "0".into(),
                    quantity: 1,
                },
                blinded_value: b(b"blind"),
            }],
        }
    }

    fn request_v2() -> ExchangeRequestV2 {
        ExchangeRequestV2 {
            version: EXCHANGE_VERSION_V2,
            public_operation_id: public_operation_id(&[7; 16]),
            graph_id: "3".repeat(64),
            transition_id: "4".repeat(64),
            source_keyset_id: "1".repeat(64),
            target_keyset_id: "2".repeat(64),
            sources: vec![ExchangeSource {
                slot: ExchangeSlot {
                    descriptor_id: "a".repeat(64),
                    keyset_id: "1".repeat(64),
                    slot_id: "source-0".into(),
                    quantity: 1,
                },
                artifact: b(b"source artifact"),
            }],
            outputs: vec![ExchangeOutput {
                slot: ExchangeSlot {
                    descriptor_id: "b".repeat(64),
                    keyset_id: "2".repeat(64),
                    slot_id: "output-0".into(),
                    quantity: 2,
                },
                blinded_value: b(b"blinded output"),
            }],
        }
    }

    fn result_v2(request: &ExchangeRequestV2) -> ExchangeResultV2 {
        let mut result = ExchangeResultV2 {
            version: request.version,
            public_operation_id: request.public_operation_id.clone(),
            graph_id: request.graph_id.clone(),
            transition_id: request.transition_id.clone(),
            source_keyset_id: request.source_keyset_id.clone(),
            target_keyset_id: request.target_keyset_id.clone(),
            outputs: vec![ExchangeResultOutput {
                slot: request.outputs[0].slot.clone(),
                blinded_value: request.outputs[0].blinded_value.clone(),
                blind_signature: b(b"blind signature"),
            }],
            result_digest: String::new(),
        };
        result.result_digest = b(&result.result_digest().unwrap());
        result
    }

    fn receipt_v2(result: &ExchangeResultV2) -> ExchangeReceiptV2 {
        ExchangeReceiptV2 {
            version: result.version,
            public_operation_id: result.public_operation_id.clone(),
            graph_id: result.graph_id.clone(),
            transition_id: result.transition_id.clone(),
            source_keyset_id: result.source_keyset_id.clone(),
            target_keyset_id: result.target_keyset_id.clone(),
            result_digest: result.result_digest.clone(),
            created_at: 1_700_000_000,
            expires_at: 1_700_003_600,
            receipt_key_id: "5".repeat(64),
            signature: b(&[9; 64]),
        }
    }
    #[test]
    fn frozen_domain_vector() {
        assert_eq!(
            hex::encode(domain_hash(DOMAIN_REQUEST, b"x")),
            "9ce2a575351b3724ace4f64cf34d705d8e3a7d5091eb3d4b1d05ef44bf09ac9a"
        );
        assert_ne!(
            domain_hash(DOMAIN_REQUEST, b"x"),
            domain_hash(DOMAIN_RESULT, b"x")
        );
        assert_ne!(
            domain_hash(DOMAIN_RECEIPT, b"x"),
            domain_hash(DOMAIN_DESCRIPTOR, b"x")
        );
    }
    #[test]
    fn result_digest_covers_signatures_and_rejects_tamper() {
        let mut r = ExchangeResult {
            operation_id: b(&[7; 16]),
            profile: EXCHANGE_PROFILE_V1.into(),
            target_keyset_id: "2".repeat(64),
            outputs: vec![ExchangeResultOutput {
                slot: request().outputs[0].slot.clone(),
                blinded_value: b(b"blind"),
                blind_signature: b(&[1; 32]),
            }],
            result_digest: String::new(),
        };
        let digest = r.result_digest().unwrap();
        assert_eq!(
            hex::encode(digest),
            "8d5f7a19a611d1546e511ae80b4f6d86b4118952cfe54b87aeb79dd3b99174a1"
        );
        r.result_digest = b(&digest);
        assert!(r.canonical_bytes().is_ok());
        r.outputs[0].blind_signature = b(&[2; 32]);
        assert!(r.canonical_bytes().is_err());
    }
    #[test]
    fn strict_request_bounds_and_canonical_hash() {
        let r = request();
        assert_eq!(
            hex::encode(r.canonical_hash(&[1; 16]).unwrap()),
            "c7852e51615ffb7b5ea941c93bdf158495f138f33a653b5299081cd6b48f62c2"
        );
        assert!(r.canonical_hash(&[1; 16]).is_ok());
        let mut bad = r.clone();
        bad.sources[0].slot.quantity = 0;
        assert!(bad.canonical_hash(&[1; 16]).is_err());
        let mut json = serde_json::to_value(r).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("unknown".into(), true.into());
        assert!(serde_json::from_value::<ExchangeRequest>(json).is_err());
    }

    #[test]
    fn v2_canonical_id_helpers_are_domain_separated_and_strict() {
        assert_eq!(public_operation_id(&[7; 16]), "BwcHBwcHBwcHBwcHBwcHBw");
        assert_eq!(
            parse_operation_id("BwcHBwcHBwcHBwcHBwcHBw").unwrap(),
            [7; 16]
        );

        let descriptor = descriptor_id_v2(b"descriptor");
        let keyset = keyset_id_v2(std::slice::from_ref(&descriptor));
        let transition = transition_id_v2(b"transition");
        let graph = graph_id_v2(b"graph");
        assert_eq!(
            descriptor,
            "f477f283e9f0f10b54b00bb910a99d0ff348a90d6ef22f663103fd79bb038301"
        );
        assert_eq!(
            keyset,
            "8a09c10f647f1ba2464cf2fb813bd91dc65dd5764b5f322e15bacacb9cdcea0d"
        );
        assert_eq!(
            transition,
            "3c2bcb3360cf8b4d21006b6c9dfb9caf1fcf95714a5b0484aa7fa3093726b824"
        );
        assert_eq!(
            graph,
            "e5ea5bd9641117e4b9f28d81daf6f80bbb5355532ccfa0e2e3cb1de7c0646b3e"
        );
        for value in [&descriptor, &keyset, &transition, &graph] {
            assert_eq!(value.len(), 64);
            assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert_ne!(descriptor, descriptor_id(b"descriptor"));
        assert_ne!(keyset, keyset_id(&[descriptor]));
        assert!(validate_transition_id(&transition).is_ok());
        assert!(validate_graph_id(&graph).is_ok());
        assert!(validate_transition_id(&"A".repeat(64)).is_err());
        assert!(validate_graph_id(&"0".repeat(63)).is_err());
    }

    #[test]
    fn v2_request_digest_binds_public_id_selectors_and_ordered_payloads() {
        let request = request_v2();
        let digest = request.request_digest().unwrap();
        assert_eq!(b(&digest), "IBYktiUpR2qjh5APuO2X38WRFbC4zm-ng3Q4dYV21wo");
        assert!(request.validate_request_digest(&b(&digest)).is_ok());
        assert!(request.validate().is_ok());

        let mutations: Vec<RequestMutation> = vec![
            Box::new(|value| value.public_operation_id = public_operation_id(&[8; 16])),
            Box::new(|value| value.graph_id = "6".repeat(64)),
            Box::new(|value| value.transition_id = "7".repeat(64)),
            Box::new(|value| {
                value.source_keyset_id = "8".repeat(64);
                value.sources[0].slot.keyset_id = "8".repeat(64);
            }),
            Box::new(|value| {
                value.target_keyset_id = "9".repeat(64);
                value.outputs[0].slot.keyset_id = "9".repeat(64);
            }),
            Box::new(|value| value.sources[0].artifact = b(b"altered artifact")),
            Box::new(|value| value.sources[0].slot.quantity += 1),
            Box::new(|value| value.outputs[0].blinded_value = b(b"altered output")),
            Box::new(|value| value.outputs[0].slot.slot_id = "altered-slot".into()),
        ];
        for mutate in mutations {
            let mut altered = request.clone();
            mutate(&mut altered);
            assert!(altered.validate_request_digest(&b(&digest)).is_err());
        }

        let mut same_keyset = request.clone();
        same_keyset.target_keyset_id = same_keyset.source_keyset_id.clone();
        same_keyset.outputs[0].slot.keyset_id = same_keyset.source_keyset_id.clone();
        assert!(same_keyset.request_digest().is_err());

        let mut unbounded = request;
        unbounded.sources = vec![unbounded.sources[0].clone(); MAX_ITEMS + 1];
        assert!(unbounded.request_digest().is_err());

        let mut ordered = request_v2();
        let mut second_source = ordered.sources[0].clone();
        second_source.slot.slot_id = "source-1".into();
        second_source.artifact = b(b"second artifact");
        ordered.sources.push(second_source);
        let mut second_output = ordered.outputs[0].clone();
        second_output.slot.slot_id = "output-1".into();
        second_output.blinded_value = b(b"second output");
        ordered.outputs.push(second_output);
        let ordered_digest = ordered.request_digest().unwrap();
        ordered.sources.swap(0, 1);
        assert_ne!(ordered.request_digest().unwrap(), ordered_digest);
        ordered.sources.swap(0, 1);
        ordered.outputs.swap(0, 1);
        assert_ne!(ordered.request_digest().unwrap(), ordered_digest);
    }

    #[test]
    fn v2_result_digest_rejects_selector_output_and_signature_tampering() {
        let request = request_v2();
        let result = result_v2(&request);
        assert_eq!(
            result.result_digest,
            "2nMU5h_eiOGSVvP0xU0Fb5hWpJdO4PrybdIxlfKtEhU"
        );
        assert!(result.canonical_bytes().is_ok());
        assert!(result.validate().is_ok());

        let mutations: Vec<ResultMutation> = vec![
            Box::new(|value| value.public_operation_id = public_operation_id(&[8; 16])),
            Box::new(|value| value.graph_id = "6".repeat(64)),
            Box::new(|value| value.transition_id = "7".repeat(64)),
            Box::new(|value| value.source_keyset_id = "8".repeat(64)),
            Box::new(|value| {
                value.target_keyset_id = "9".repeat(64);
                value.outputs[0].slot.keyset_id = "9".repeat(64);
            }),
            Box::new(|value| value.outputs[0].slot.quantity += 1),
            Box::new(|value| value.outputs[0].blinded_value = b(b"altered output")),
            Box::new(|value| value.outputs[0].blind_signature = b(b"altered signature")),
            Box::new(|value| value.result_digest = b(&[0; DIGEST_LEN])),
        ];
        for mutate in mutations {
            let mut altered = result.clone();
            mutate(&mut altered);
            assert!(altered.canonical_bytes().is_err());
        }

        let mut unbounded = result.clone();
        unbounded.outputs = vec![unbounded.outputs[0].clone(); MAX_ITEMS + 1];
        assert!(unbounded.canonical_bytes().is_err());

        let mut ordered = result.clone();
        let mut second_output = ordered.outputs[0].clone();
        second_output.slot.slot_id = "output-1".into();
        second_output.blinded_value = b(b"second output");
        second_output.blind_signature = b(b"second signature");
        ordered.outputs.push(second_output);
        let ordered_digest = ordered.result_digest().unwrap();
        ordered.outputs.swap(0, 1);
        assert_ne!(ordered.result_digest().unwrap(), ordered_digest);

        let mut empty_signature = result;
        empty_signature.outputs[0].blind_signature.clear();
        assert!(empty_signature.result_digest().is_err());

        let mut same_keyset = result_v2(&request);
        same_keyset.target_keyset_id = same_keyset.source_keyset_id.clone();
        same_keyset.outputs[0].slot.keyset_id = same_keyset.source_keyset_id.clone();
        assert!(same_keyset.result_digest().is_err());
    }

    #[test]
    fn v2_receipt_binds_result_and_has_no_status_capability() {
        let request = request_v2();
        let result = result_v2(&request);
        let receipt = receipt_v2(&result);
        assert!(receipt.validate_result(&result).is_ok());
        assert!(receipt.validate().is_ok());
        assert!(receipt.validate_signature().is_ok());

        let digest = receipt.receipt_digest().unwrap();
        assert_eq!(b(&digest), "Yg4v2w4lXlvGpwvf3yKn0Dgbb6yuDSXQ9udRqOwED5o");
        for mutate in [
            |value: &mut ExchangeReceiptV2| value.graph_id = "6".repeat(64),
            |value: &mut ExchangeReceiptV2| value.transition_id = "7".repeat(64),
            |value: &mut ExchangeReceiptV2| value.source_keyset_id = "8".repeat(64),
            |value: &mut ExchangeReceiptV2| value.target_keyset_id = "9".repeat(64),
            |value: &mut ExchangeReceiptV2| value.result_digest = b(&[0; DIGEST_LEN]),
        ] {
            let mut altered = receipt.clone();
            mutate(&mut altered);
            assert_ne!(altered.receipt_digest().unwrap(), digest);
            assert!(altered.validate_result(&result).is_err());
        }
        for mutate in [
            |value: &mut ExchangeReceiptV2| value.expires_at += 1,
            |value: &mut ExchangeReceiptV2| value.receipt_key_id = "a".repeat(64),
        ] {
            let mut altered = receipt.clone();
            mutate(&mut altered);
            assert_ne!(altered.receipt_digest().unwrap(), digest);
        }

        let mut invalid_validity = receipt.clone();
        invalid_validity.expires_at = invalid_validity.created_at;
        assert!(invalid_validity.receipt_digest().is_err());
        let mut invalid_signature = receipt.clone();
        invalid_signature.signature = b(&[0; 63]);
        assert!(invalid_signature.validate_signature().is_err());
        assert!(invalid_signature.validate().is_err());
        let mut same_keyset = receipt.clone();
        same_keyset.target_keyset_id = same_keyset.source_keyset_id.clone();
        assert!(same_keyset.receipt_digest().is_err());

        let mut result_json = serde_json::to_value(&result).unwrap();
        result_json
            .as_object_mut()
            .unwrap()
            .insert("status_capability".into(), "secret".into());
        assert!(serde_json::from_value::<ExchangeResultV2>(result_json).is_err());

        let mut receipt_json = serde_json::to_value(&receipt).unwrap();
        receipt_json
            .as_object_mut()
            .unwrap()
            .insert("status_capability".into(), "secret".into());
        assert!(serde_json::from_value::<ExchangeReceiptV2>(receipt_json).is_err());
    }
}
