//! Experimental Scarcity V2 issuance primitive. This module is intentionally
//! private to the crypto crate until the contract and independent audit gates
//! are complete.
//! Public fixture publication and an independent audit are subsequent gates.

#![allow(dead_code)]

use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSRandomized};
use cbor2::Value;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SUITE: &str = "RSABSSA-SHA384-PSS-Randomized";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Keyset {
    #[serde(with = "serde_bytes")]
    pub issuer_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub keyset_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub asset_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub spend_domain: Vec<u8>,
    pub denomination: u64,
    pub issuance_epoch: u64,
    pub expiry_epoch: u64,
    #[serde(with = "serde_bytes")]
    pub modulus: Vec<u8>,
    pub public_exponent: u32,
    pub suite: String,
    #[serde(with = "serde_bytes")]
    pub authority_key_id: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MintRequest {
    pub version: u64,
    #[serde(with = "serde_bytes")]
    pub issuer_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub keyset_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub request_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub client_binding: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub blinded_message: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub blinded_message_digest: Vec<u8>,
    pub retry_attempt: u64,
    pub requested_at_epoch: u64,
    pub request_expiry_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalizedCredential {
    pub version: u64,
    pub suite: String,
    #[serde(with = "serde_bytes")]
    pub keyset_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub message_randomizer: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct KeysetIdentity<'a> {
    #[serde(with = "serde_bytes")]
    issuer_id: &'a [u8],
    #[serde(with = "serde_bytes")]
    asset_id: &'a [u8],
    #[serde(with = "serde_bytes")]
    spend_domain: &'a [u8],
    denomination: u64,
    issuance_epoch: u64,
    expiry_epoch: u64,
    #[serde(with = "serde_bytes")]
    modulus: &'a [u8],
    public_exponent: u32,
    suite: &'a str,
    #[serde(with = "serde_bytes")]
    authority_key_id: &'a [u8],
}

fn hash(label: &str, bytes: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(format!("scarcity/v2/{label}\0").as_bytes());
    h.update(bytes);
    h.finalize().to_vec()
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    cbor2::to_canonical_vec(value).map_err(|e| e.to_string())
}
fn bytes32(value: &[u8]) -> bool {
    value.len() == 32
}

pub(crate) fn keyset_id(keyset: &Keyset) -> Result<Vec<u8>, String> {
    let identity = KeysetIdentity {
        issuer_id: &keyset.issuer_id,
        asset_id: &keyset.asset_id,
        spend_domain: &keyset.spend_domain,
        denomination: keyset.denomination,
        issuance_epoch: keyset.issuance_epoch,
        expiry_epoch: keyset.expiry_epoch,
        modulus: &keyset.modulus,
        public_exponent: keyset.public_exponent,
        suite: &keyset.suite,
        authority_key_id: &keyset.authority_key_id,
    };
    Ok(hash("rsa-keyset", &canonical(&identity)?))
}
pub(crate) fn blinded_message_digest(message: &[u8]) -> Vec<u8> {
    hash("mint-blinded-message", message)
}
pub(crate) fn request_digest(request: &MintRequest) -> Result<Vec<u8>, String> {
    Ok(hash("mint-request", &canonical(request)?))
}

fn validate_value(value: &Value, depth: usize) -> Result<(), String> {
    if depth > 32 {
        return Err("decode-limit".into());
    }
    match value {
        Value::Integer(_) | Value::Bool(_) | Value::Null => Ok(()),
        Value::Text(s) if s.len() <= 4096 => Ok(()),
        Value::Bytes(b) if b.len() <= 65536 => Ok(()),
        Value::Array(a) if a.len() <= 256 => {
            a.iter().try_for_each(|v| validate_value(v, depth + 1))
        }
        Value::Map(map) if map.len() <= 256 => {
            let mut previous: Option<Vec<u8>> = None;
            for (key, value) in map {
                let Value::Text(key) = key else {
                    return Err("schema".into());
                };
                let encoded = cbor2::to_canonical_vec(key).map_err(|e| e.to_string())?;
                if previous.as_ref().is_some_and(|p| p >= &encoded) {
                    return Err("schema".into());
                }
                previous = Some(encoded);
                validate_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Float(_) | Value::Tag(_, _) | Value::Simple(_) => Err("decode-limit".into()),
        _ => Err("decode-limit".into()),
    }
}

pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > 1024 * 1024 {
        return Err("decode-limit".into());
    }
    let value: Value = cbor2::from_slice(bytes).map_err(|_| "decode-limit".to_string())?;
    validate_value(&value, 0)?;
    let encoded = cbor2::to_canonical_vec(&value).map_err(|e| e.to_string())?;
    if encoded != bytes {
        return Err("decode-limit".into());
    }
    Ok(value)
}

fn decode_typed<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    decode_canonical(bytes)?;
    cbor2::from_slice(bytes).map_err(|_| "schema".into())
}

pub(crate) fn decode_keyset(bytes: &[u8]) -> Result<Keyset, String> {
    decode_typed(bytes)
}
pub(crate) fn decode_request(bytes: &[u8]) -> Result<MintRequest, String> {
    decode_typed(bytes)
}

pub(crate) fn validate_keyset(keyset: &Keyset) -> Result<(), String> {
    if !bytes32(&keyset.issuer_id)
        || !bytes32(&keyset.keyset_id)
        || !bytes32(&keyset.asset_id)
        || !bytes32(&keyset.spend_domain)
        || !bytes32(&keyset.authority_key_id)
        || keyset.denomination == 0
        || keyset.issuance_epoch >= keyset.expiry_epoch
        || keyset.modulus.len() != 384
        || keyset.public_exponent != 65537
        || keyset.suite != SUITE
    {
        return Err("schema".into());
    }
    if keyset_id(keyset)? != keyset.keyset_id {
        return Err("hash-binding".into());
    }
    Ok(())
}
pub(crate) fn validate_request(request: &MintRequest) -> Result<(), String> {
    if request.version != 2
        || !bytes32(&request.issuer_id)
        || !bytes32(&request.keyset_id)
        || !bytes32(&request.request_id)
        || !bytes32(&request.client_binding)
        || !bytes32(&request.blinded_message_digest)
        || request.blinded_message.len() != 384
        || request.requested_at_epoch > request.request_expiry_epoch
    {
        return Err("schema".into());
    }
    if blinded_message_digest(&request.blinded_message) != request.blinded_message_digest {
        return Err("hash-binding".into());
    }
    Ok(())
}

pub(crate) fn validate_finalized_credential(
    credential: &FinalizedCredential,
    keyset: &Keyset,
) -> Result<(), String> {
    if credential.version != 2
        || credential.suite != SUITE
        || credential.keyset_id.len() != 32
        || credential.message_randomizer.len() != 32
        || credential.signature.len() != 384
    {
        return Err("schema".into());
    }
    if credential.keyset_id != keyset.keyset_id {
        return Err("hash-binding".into());
    }
    Ok(())
}

pub(crate) fn blind_finalize_verify(message: &[u8]) -> Result<(), String> {
    let mut rng = DefaultRng;
    let keypair =
        KeyPairSha384PSSRandomized::generate(&mut rng, 2048).map_err(|e| e.to_string())?;
    let result = keypair
        .pk
        .blind(&mut rng, message)
        .map_err(|e| e.to_string())?;
    let blind = keypair
        .sk
        .blind_sign(&result.blind_message)
        .map_err(|e| e.to_string())?;
    let signature = keypair
        .pk
        .finalize(&blind, &result, message)
        .map_err(|e| e.to_string())?;
    let randomizer = result
        .msg_randomizer
        .ok_or_else(|| "missing randomizer".to_string())?;
    keypair
        .pk
        .verify(&signature, Some(randomizer), message)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::Signature;

    #[test]
    fn randomized_roundtrip_uses_existing_library() {
        let mut rng = DefaultRng;
        let keypair = KeyPairSha384PSSRandomized::generate(&mut rng, 2048).unwrap();
        let message = b"scarcity-v2-test-message";
        let result = keypair.pk.blind(&mut rng, message).unwrap();
        let blind = keypair.sk.blind_sign(&result.blind_message).unwrap();
        let signature = keypair.pk.finalize(&blind, &result, message).unwrap();
        let randomizer = result.msg_randomizer.unwrap();
        let mut altered_signature = signature.0.clone();
        altered_signature[0] ^= 1;
        assert!(keypair
            .pk
            .verify(&Signature(altered_signature), Some(randomizer), message)
            .is_err());
        assert!(keypair
            .pk
            .verify(&signature, Some(randomizer), b"altered-payload")
            .is_err());
        blind_finalize_verify(b"scarcity-v2-test-message").unwrap();
    }

    #[test]
    fn request_and_keyset_bindings_reject_mutation() {
        let keyset = Keyset {
            issuer_id: vec![1; 32],
            keyset_id: vec![0; 32],
            asset_id: vec![2; 32],
            spend_domain: vec![3; 32],
            denomination: 10,
            issuance_epoch: 1,
            expiry_epoch: 2,
            modulus: vec![4; 384],
            public_exponent: 65537,
            suite: SUITE.into(),
            authority_key_id: vec![5; 32],
        };
        let mut request = MintRequest {
            version: 2,
            issuer_id: vec![1; 32],
            keyset_id: vec![6; 32],
            request_id: vec![7; 32],
            client_binding: vec![8; 32],
            blinded_message: vec![9; 384],
            blinded_message_digest: blinded_message_digest(&[9; 384]),
            retry_attempt: 0,
            requested_at_epoch: 1,
            request_expiry_epoch: 2,
        };
        validate_request(&request).unwrap();
        request.blinded_message_digest[0] ^= 1;
        assert_eq!(validate_request(&request), Err("hash-binding".into()));
        let valid_request = MintRequest {
            blinded_message_digest: blinded_message_digest(&[9; 384]),
            ..request.clone()
        };
        let encoded = cbor2::to_canonical_vec(&valid_request).unwrap();
        let mut value: Value = cbor2::from_slice(&encoded).unwrap();
        if let Value::Map(ref mut entries) = value {
            entries.push((Value::Text("unknown".into()), Value::Integer(0u8.into())));
        }
        let unknown = cbor2::to_canonical_vec(&value).unwrap();
        assert_eq!(decode_request(&unknown), Err("schema".into()));
        let keyset_bytes = cbor2::to_canonical_vec(&keyset).unwrap();
        let mut keyset_value: Value = cbor2::from_slice(&keyset_bytes).unwrap();
        if let Value::Map(ref mut entries) = keyset_value {
            entries.push((Value::Text("unknown".into()), Value::Integer(0u8.into())));
        }
        assert_eq!(
            decode_keyset(&cbor2::to_canonical_vec(&keyset_value).unwrap()),
            Err("schema".into())
        );
        assert!(validate_keyset(&keyset).is_err());

        let mut bound_keyset = keyset.clone();
        bound_keyset.keyset_id = keyset_id(&bound_keyset).unwrap();
        let credential = FinalizedCredential {
            version: 2,
            suite: SUITE.into(),
            keyset_id: bound_keyset.keyset_id.clone(),
            message_randomizer: vec![8; 32],
            signature: vec![9; 384],
        };
        validate_finalized_credential(&credential, &bound_keyset).unwrap();
        let mut other_keyset = bound_keyset.clone();
        other_keyset.denomination = 11;
        other_keyset.keyset_id = keyset_id(&other_keyset).unwrap();
        assert_eq!(
            validate_finalized_credential(&credential, &other_keyset),
            Err("hash-binding".into())
        );
    }

    #[test]
    fn canonical_negative_inputs_are_rejected() {
        assert_eq!(
            decode_canonical(&[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0, 0]),
            Err("decode-limit".into())
        );
        assert_eq!(decode_canonical(&[0xa1, 0x01, 0x00]), Err("schema".into()));
        assert_eq!(
            decode_canonical(&[0x81, 0x01, 0x00]),
            Err("decode-limit".into())
        );
    }
}
