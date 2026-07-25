// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Canonical wire bindings for policy-authorized graph blind issuance.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GRAPH_ISSUANCE_VERSION_V1: u8 = 1;
pub const MAX_AUTHORIZATION: usize = 16 * 1024;
pub const MAX_BLINDED_MESSAGE: usize = 512;
const DOMAIN_REQUEST: &[u8] = b"freebird graph blind issuance request v1\0";
const DOMAIN_AUTHORIZATION_BINDING: &[u8] =
    b"freebird graph blind issuance authorization binding v1\0";
const DOMAIN_RESULT: &[u8] = b"freebird graph blind issuance result v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphIssuanceRequestV1 {
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
pub struct GraphIssuanceResultV1 {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphIssuanceError(pub &'static str);

impl std::fmt::Display for GraphIssuanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for GraphIssuanceError {}

fn put(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn id(value: &str) -> Result<(), GraphIssuanceError> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        Err(GraphIssuanceError("invalid issuance policy id"))
    } else {
        Ok(())
    }
}

fn sha256_id(value: &str) -> Result<(), GraphIssuanceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Err(GraphIssuanceError("invalid graph issuance selector"))
    } else {
        Ok(())
    }
}

fn decode(value: &str, maximum: usize) -> Result<Vec<u8>, GraphIssuanceError> {
    if value.contains('=') || value.len() > maximum.div_ceil(3) * 4 {
        return Err(GraphIssuanceError("invalid canonical base64url"));
    }
    let bytes = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| GraphIssuanceError("invalid canonical base64url"))?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || Base64UrlUnpadded::encode_string(&bytes) != value
    {
        Err(GraphIssuanceError("invalid canonical base64url"))
    } else {
        Ok(bytes)
    }
}

fn domain_hash(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    hash.finalize().into()
}

impl GraphIssuanceRequestV1 {
    pub fn operation_id(&self) -> Result<[u8; 16], GraphIssuanceError> {
        decode(&self.public_operation_id, 16)?
            .try_into()
            .map_err(|_| GraphIssuanceError("operation id must be 16 bytes"))
    }

    fn selector_bytes(&self) -> Result<Vec<u8>, GraphIssuanceError> {
        if self.version != GRAPH_ISSUANCE_VERSION_V1 {
            return Err(GraphIssuanceError("unsupported graph issuance version"));
        }
        let mut bytes = vec![self.version];
        put(&mut bytes, &self.operation_id()?);
        id(&self.issuance_policy_id)?;
        for selector in [&self.graph_id, &self.keyset_id, &self.descriptor_id] {
            sha256_id(selector)?;
        }
        for selector in [
            &self.issuance_policy_id,
            &self.graph_id,
            &self.keyset_id,
            &self.descriptor_id,
        ] {
            put(&mut bytes, selector.as_bytes());
        }
        put(
            &mut bytes,
            &decode(&self.blinded_message, MAX_BLINDED_MESSAGE)?,
        );
        Ok(bytes)
    }

    pub fn authorization_binding_digest(&self) -> Result<[u8; 32], GraphIssuanceError> {
        Ok(domain_hash(
            DOMAIN_AUTHORIZATION_BINDING,
            &self.selector_bytes()?,
        ))
    }

    pub fn request_digest(&self) -> Result<[u8; 32], GraphIssuanceError> {
        let mut bytes = self.selector_bytes()?;
        put(&mut bytes, &decode(&self.authorization, MAX_AUTHORIZATION)?);
        Ok(domain_hash(DOMAIN_REQUEST, &bytes))
    }
}

impl GraphIssuanceResultV1 {
    fn bytes_without_digest(&self) -> Result<Vec<u8>, GraphIssuanceError> {
        if self.version != GRAPH_ISSUANCE_VERSION_V1 {
            return Err(GraphIssuanceError("unsupported graph issuance version"));
        }
        let operation: [u8; 16] = decode(&self.public_operation_id, 16)?
            .try_into()
            .map_err(|_| GraphIssuanceError("operation id must be 16 bytes"))?;
        id(&self.issuance_policy_id)?;
        for selector in [
            &self.graph_id,
            &self.keyset_id,
            &self.descriptor_id,
            &self.token_key_id,
        ] {
            sha256_id(selector)?;
        }
        if self.quantity == 0 {
            return Err(GraphIssuanceError("quantity must be nonzero"));
        }
        let mut bytes = vec![self.version];
        put(&mut bytes, &operation);
        for selector in [
            &self.issuance_policy_id,
            &self.graph_id,
            &self.keyset_id,
            &self.descriptor_id,
            &self.token_key_id,
        ] {
            put(&mut bytes, selector.as_bytes());
        }
        bytes.extend_from_slice(&self.quantity.to_be_bytes());
        put(&mut bytes, &decode(&self.request_digest, 32)?);
        put(&mut bytes, &decode(&self.blind_signature, 512)?);
        Ok(bytes)
    }

    pub fn calculated_result_digest(&self) -> Result<[u8; 32], GraphIssuanceError> {
        Ok(domain_hash(DOMAIN_RESULT, &self.bytes_without_digest()?))
    }

    pub fn validate(&self) -> Result<(), GraphIssuanceError> {
        let expected: [u8; 32] = decode(&self.result_digest, 32)?
            .try_into()
            .map_err(|_| GraphIssuanceError("invalid result digest"))?;
        if expected != self.calculated_result_digest()? {
            return Err(GraphIssuanceError("result digest mismatch"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> GraphIssuanceRequestV1 {
        GraphIssuanceRequestV1 {
            version: 1,
            public_operation_id: Base64UrlUnpadded::encode_string(&[7; 16]),
            issuance_policy_id: "bootstrap-v1".into(),
            graph_id: "1".repeat(64),
            keyset_id: "2".repeat(64),
            descriptor_id: "3".repeat(64),
            blinded_message: Base64UrlUnpadded::encode_string(&[4; 256]),
            authorization: Base64UrlUnpadded::encode_string(&[5; 64]),
        }
    }

    #[test]
    fn request_digest_binds_authorization_and_every_selector() {
        let request = request();
        let digest = request.request_digest().unwrap();
        let mut changed = request.clone();
        changed.authorization = Base64UrlUnpadded::encode_string(&[6; 64]);
        assert_ne!(digest, changed.request_digest().unwrap());
        changed = request.clone();
        changed.descriptor_id = "4".repeat(64);
        assert_ne!(digest, changed.request_digest().unwrap());
        assert_eq!(request.operation_id().unwrap(), [7; 16]);
    }
}
