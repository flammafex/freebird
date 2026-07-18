// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Frozen, bounded exchange wire primitives.  This module intentionally does
//! not use the token/nullifier hashing code.
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EXCHANGE_PROFILE_V1: &str = "freebird/public-bearer-exchange/v1";
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
}
