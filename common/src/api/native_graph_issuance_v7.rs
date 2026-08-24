// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Closed native V7 graph-issuance contract.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::native_bearer_v7::validate_v7_identifier_namespace;
use super::native_exchange_v3::{NATIVE_EXCHANGE_V3_RAW384_BYTES, NATIVE_EXCHANGE_V3_SUITE};

pub const NATIVE_GRAPH_ISSUANCE_V7_VERSION: u8 = 7;
pub const NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID: &str = "freebird/native-graph-issuance/v7";
pub const NATIVE_GRAPH_ISSUANCE_V7_QUANTITY: u32 = 1;
pub const NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_REQUEST: &[u8] =
    b"freebird native graph issuance request v7\0";
pub const NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_AUTHORIZATION_BINDING: &[u8] =
    b"freebird native graph issuance authorization binding v7\0";
pub const NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_AUTHORIZATION_PROOF: &[u8] =
    b"freebird native graph issuance authorization proof v7\0";
pub const NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_RESULT: &[u8] =
    b"freebird native graph issuance result v7\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGraphIssuanceV7Policy {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGraphIssuanceV7Discovery {
    pub version: u8,
    pub profile_id: String,
    pub active_policies: Vec<NativeGraphIssuanceV7Policy>,
    pub retained_policies: Vec<NativeGraphIssuanceV7Policy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGraphIssuanceV7Request {
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
    pub request_commitment: String,
    /// Canonical V4-local admission credential, bound to this request digest.
    pub authorization: String,
    /// Raw Ed25519 signature over the V7 authorization-proof digest.
    pub authorization_proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeGraphIssuanceV7Result {
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
    pub request_commitment: String,
    /// SHA-256 identity derived from the authenticated V4 spend/nullifier.
    pub replay_identity: String,
    pub blind_signature: String,
    pub result_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeGraphIssuanceV7Error(pub &'static str);

impl std::fmt::Display for NativeGraphIssuanceV7Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for NativeGraphIssuanceV7Error {}

/// Digest signed by the holder of the Ed25519 public key carried in the V4
/// credential nonce. Credential bytes are hashed first so the proof transcript
/// cannot be confused with the request framing.
pub fn native_graph_issuance_v7_authorization_proof_digest(
    canonical_credential_bytes: &[u8],
    request_authorization_binding_digest: &[u8; 32],
) -> [u8; 32] {
    let credential_digest: [u8; 32] = sha2::Sha256::digest(canonical_credential_bytes).into();
    digest(
        NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_AUTHORIZATION_PROOF,
        &[
            &credential_digest[..],
            &request_authorization_binding_digest[..],
        ]
        .concat(),
    )
}

fn hex32(value: &str, error: &'static str) -> Result<[u8; 32], NativeGraphIssuanceV7Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(NativeGraphIssuanceV7Error(error));
    }
    hex::decode(value)
        .map_err(|_| NativeGraphIssuanceV7Error(error))?
        .try_into()
        .map_err(|_| NativeGraphIssuanceV7Error(error))
}

fn b64(
    value: &str,
    expected: usize,
    error: &'static str,
) -> Result<Vec<u8>, NativeGraphIssuanceV7Error> {
    if value.contains('=') {
        return Err(NativeGraphIssuanceV7Error(error));
    }
    let bytes =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| NativeGraphIssuanceV7Error(error))?;
    if bytes.len() != expected || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(NativeGraphIssuanceV7Error(error));
    }
    Ok(bytes)
}

fn bounded_b64(
    value: &str,
    maximum: usize,
    error: &'static str,
) -> Result<Vec<u8>, NativeGraphIssuanceV7Error> {
    if value.contains('=') {
        return Err(NativeGraphIssuanceV7Error(error));
    }
    let bytes =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| NativeGraphIssuanceV7Error(error))?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || Base64UrlUnpadded::encode_string(&bytes) != value
    {
        return Err(NativeGraphIssuanceV7Error(error));
    }
    Ok(bytes)
}

fn canonical_spki(value: &str) -> Result<Vec<u8>, NativeGraphIssuanceV7Error> {
    if value.contains('=') {
        return Err(NativeGraphIssuanceV7Error("invalid V7 policy SPKI"));
    }
    let bytes = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| NativeGraphIssuanceV7Error("invalid V7 policy SPKI"))?;
    if bytes.is_empty() || bytes.len() > 4096 || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(NativeGraphIssuanceV7Error("invalid V7 policy SPKI"));
    }
    Ok(bytes)
}

fn text(value: &str, error: &'static str) -> Result<(), NativeGraphIssuanceV7Error> {
    if value.is_empty() || value.len() > 128 {
        Err(NativeGraphIssuanceV7Error(error))
    } else {
        Ok(())
    }
}

fn amount(value: &str) -> Result<u64, NativeGraphIssuanceV7Error> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(NativeGraphIssuanceV7Error("invalid V7 amount"));
    }
    let amount = value
        .parse::<u64>()
        .map_err(|_| NativeGraphIssuanceV7Error("invalid V7 amount"))?;
    if amount == 0 {
        return Err(NativeGraphIssuanceV7Error("V7 amount must be nonzero"));
    }
    Ok(amount)
}

fn common(
    version: u8,
    profile_id: &str,
    issuer_id: &str,
    operation_id: &str,
    graph_id: &str,
    policy_id: &str,
    keyset_id: &str,
    descriptor_id: &str,
    token_key_id: &str,
    asset_id: &str,
    amount_minor: &str,
    quantity: u32,
) -> Result<Vec<u8>, NativeGraphIssuanceV7Error> {
    if version != NATIVE_GRAPH_ISSUANCE_V7_VERSION
        || profile_id != NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID
        || quantity != NATIVE_GRAPH_ISSUANCE_V7_QUANTITY
    {
        return Err(NativeGraphIssuanceV7Error(
            "invalid V7 graph-issuance profile",
        ));
    }
    text(issuer_id, "invalid V7 issuer id")?;
    text(asset_id, "invalid V7 asset id")?;
    amount(amount_minor)?;
    let mut transcript = vec![version];
    transcript.extend_from_slice(&b64(operation_id, 16, "invalid V7 operation id")?);
    for value in [graph_id, policy_id, keyset_id, descriptor_id, token_key_id] {
        transcript.extend_from_slice(&hex32(value, "invalid V7 graph selector")?);
    }
    for value in [issuer_id, asset_id, amount_minor] {
        transcript.extend_from_slice(&(value.len() as u32).to_be_bytes());
        transcript.extend_from_slice(value.as_bytes());
    }
    transcript.extend_from_slice(&quantity.to_be_bytes());
    Ok(transcript)
}

impl NativeGraphIssuanceV7Policy {
    pub fn validate(&self) -> Result<(), NativeGraphIssuanceV7Error> {
        hex32(&self.policy_id, "invalid V7 policy id")?;
        if self.profile_id != NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID {
            return Err(NativeGraphIssuanceV7Error("invalid V7 graph profile"));
        }
        text(&self.issuer_id, "invalid V7 issuer id")?;
        text(&self.asset_id, "invalid V7 asset id")?;
        amount(&self.amount_minor)?;
        for value in [
            &self.graph_id,
            &self.keyset_id,
            &self.descriptor_id,
            &self.token_key_id,
        ] {
            hex32(value, "invalid V7 policy selector")?;
        }
        if self.suite != NATIVE_EXCHANGE_V3_SUITE
            || self.modulus_bits != 3072
            || self.exponent != 65_537
            || self.quantity != NATIVE_GRAPH_ISSUANCE_V7_QUANTITY
        {
            return Err(NativeGraphIssuanceV7Error("invalid V7 graph policy"));
        }
        if self.valid_from < 0 || self.valid_from >= self.valid_until {
            return Err(NativeGraphIssuanceV7Error("invalid V7 policy validity"));
        }
        let spki = canonical_spki(&self.pubkey_spki_b64)?;
        let fingerprint = hex32(&self.spki_fingerprint, "invalid V7 policy SPKI fingerprint")?;
        validate_v7_identifier_namespace(
            &self.token_key_id,
            &self.descriptor_id,
            &self.spki_fingerprint,
        )
        .map_err(|_| NativeGraphIssuanceV7Error("V7 policy identifiers must be distinct"))?;
        let computed: [u8; 32] = sha2::Sha256::digest(&spki).into();
        if computed != fingerprint {
            return Err(NativeGraphIssuanceV7Error(
                "V7 policy SPKI fingerprint mismatch",
            ));
        }
        let identity = freebird_crypto::V7KeyIdentity::new(
            self.issuer_id.clone(),
            freebird_crypto::V7TokenKeyId::new(hex32(
                &self.token_key_id,
                "invalid V7 token key id",
            )?),
        )
        .map_err(|_| NativeGraphIssuanceV7Error("invalid V7 policy identity"))?;
        freebird_crypto::V7PublicKeyBinding::new(identity, &spki)
            .map_err(|_| NativeGraphIssuanceV7Error("invalid V7 policy SPKI"))?;
        Ok(())
    }
}

impl NativeGraphIssuanceV7Discovery {
    pub fn validate(&self) -> Result<(), NativeGraphIssuanceV7Error> {
        if self.version != NATIVE_GRAPH_ISSUANCE_V7_VERSION
            || self.profile_id != NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID
        {
            return Err(NativeGraphIssuanceV7Error("invalid V7 graph discovery"));
        }
        for policy in self
            .active_policies
            .iter()
            .chain(self.retained_policies.iter())
        {
            policy.validate()?;
        }
        Ok(())
    }
}

impl NativeGraphIssuanceV7Request {
    pub fn validate(&self) -> Result<(), NativeGraphIssuanceV7Error> {
        self.canonical_bytes().map(|_| ())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeGraphIssuanceV7Error> {
        let mut out = self.canonical_bytes_without_authorization()?;
        out.extend_from_slice(&self.authorization_bytes()?);
        out.extend_from_slice(&self.authorization_proof_bytes()?);
        Ok(out)
    }

    /// Decode the canonical raw V4 credential carried by this request.
    pub fn authorization_bytes(&self) -> Result<Vec<u8>, NativeGraphIssuanceV7Error> {
        bounded_b64(
            &self.authorization,
            16 * 1024,
            "V7 authorization must be canonical base64url",
        )
    }

    /// Decode the exact raw Ed25519 authorization proof.
    pub fn authorization_proof_bytes(&self) -> Result<[u8; 64], NativeGraphIssuanceV7Error> {
        b64(
            &self.authorization_proof,
            64,
            "V7 authorization proof must be raw64",
        )?
        .try_into()
        .map_err(|_| NativeGraphIssuanceV7Error("V7 authorization proof must be raw64"))
    }

    /// Digest supplied to the V4-local verifier before the credential itself
    /// is appended.  The existing V4 verifier remains responsible for
    /// parsing and authenticating the credential; this digest only gives the
    /// request a canonical, stable binding surface.
    pub fn authorization_binding_digest(&self) -> Result<[u8; 32], NativeGraphIssuanceV7Error> {
        Ok(digest(
            NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_AUTHORIZATION_BINDING,
            &self.canonical_bytes_without_authorization()?,
        ))
    }

    /// Digest verified with the Ed25519 public key carried in the V4 nonce.
    pub fn authorization_proof_digest(&self) -> Result<[u8; 32], NativeGraphIssuanceV7Error> {
        Ok(native_graph_issuance_v7_authorization_proof_digest(
            &self.authorization_bytes()?,
            &self.authorization_binding_digest()?,
        ))
    }

    fn canonical_bytes_without_authorization(&self) -> Result<Vec<u8>, NativeGraphIssuanceV7Error> {
        let mut out = common(
            self.version,
            &self.profile_id,
            &self.issuer_id,
            &self.public_operation_id,
            &self.graph_id,
            &self.policy_id,
            &self.keyset_id,
            &self.descriptor_id,
            &self.token_key_id,
            &self.asset_id,
            &self.amount_minor,
            self.quantity,
        )?;
        out.extend_from_slice(&b64(
            &self.blinded_message,
            NATIVE_EXCHANGE_V3_RAW384_BYTES,
            "V7 blind must be raw384",
        )?);
        out.extend_from_slice(&hex32(
            &self.request_commitment,
            "invalid V7 request commitment",
        )?);
        Ok(out)
    }

    pub fn request_digest(&self) -> Result<[u8; 32], NativeGraphIssuanceV7Error> {
        Ok(digest(
            NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_REQUEST,
            &self.canonical_bytes()?,
        ))
    }
}

impl NativeGraphIssuanceV7Result {
    pub fn validate(&self) -> Result<(), NativeGraphIssuanceV7Error> {
        let expected = hex32(&self.result_digest, "invalid V7 result digest")?;
        if expected != self.result_digest_bytes()? {
            return Err(NativeGraphIssuanceV7Error("V7 result digest mismatch"));
        }
        Ok(())
    }

    pub fn result_digest_bytes(&self) -> Result<[u8; 32], NativeGraphIssuanceV7Error> {
        Ok(digest(
            NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_RESULT,
            &self.canonical_bytes()?,
        ))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, NativeGraphIssuanceV7Error> {
        let mut out = common(
            self.version,
            &self.profile_id,
            &self.issuer_id,
            &self.public_operation_id,
            &self.graph_id,
            &self.policy_id,
            &self.keyset_id,
            &self.descriptor_id,
            &self.token_key_id,
            &self.asset_id,
            &self.amount_minor,
            self.quantity,
        )?;
        out.extend_from_slice(&b64(
            &self.blinded_message,
            NATIVE_EXCHANGE_V3_RAW384_BYTES,
            "V7 blind must be raw384",
        )?);
        out.extend_from_slice(&hex32(
            &self.request_commitment,
            "invalid V7 request commitment",
        )?);
        out.extend_from_slice(&hex32(&self.replay_identity, "invalid V7 replay identity")?);
        out.extend_from_slice(&b64(
            &self.blind_signature,
            NATIVE_EXCHANGE_V3_RAW384_BYTES,
            "V7 signature must be raw384",
        )?);
        Ok(out)
    }
}

fn digest(domain: &[u8], transcript: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest([domain, transcript].concat()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v7_graph_identifier_namespaces_are_canonical_and_distinct() {
        let token = "11".repeat(32);
        let descriptor = "22".repeat(32);
        let fingerprint = "33".repeat(32);
        assert!(validate_v7_identifier_namespace(&token, &descriptor, &fingerprint).is_ok());
        assert!(validate_v7_identifier_namespace(&token, &descriptor, &descriptor).is_err());
        assert!(validate_v7_identifier_namespace(&token, &token, &fingerprint).is_err());
    }

    #[test]
    fn v7_graph_contract_rejects_non_unit_quantity() {
        let policy = NativeGraphIssuanceV7Policy {
            policy_id: "a".repeat(64),
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            graph_id: "b".repeat(64),
            keyset_id: "c".repeat(64),
            descriptor_id: "d".repeat(64),
            token_key_id: "e".repeat(64),
            issuer_id: "issuer".into(),
            asset_id: "asset".into(),
            amount_minor: "1".into(),
            suite: NATIVE_EXCHANGE_V3_SUITE.into(),
            modulus_bits: 3072,
            exponent: 65_537,
            quantity: 2,
            pubkey_spki_b64: String::new(),
            spki_fingerprint: String::new(),
            valid_from: 1,
            valid_until: 2,
        };
        assert!(policy.validate().is_err());
    }

    fn request_fixture() -> NativeGraphIssuanceV7Request {
        NativeGraphIssuanceV7Request {
            version: 7,
            profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
            issuer_id: "issuer:test".into(),
            public_operation_id: Base64UrlUnpadded::encode_string(&[1; 16]),
            graph_id: "11".repeat(32),
            policy_id: "22".repeat(32),
            keyset_id: "33".repeat(32),
            descriptor_id: "44".repeat(32),
            token_key_id: "55".repeat(32),
            asset_id: "USD".into(),
            amount_minor: "42".into(),
            quantity: 1,
            blinded_message: Base64UrlUnpadded::encode_string(&[7; 384]),
            request_commitment: "66".repeat(32),
            authorization: Base64UrlUnpadded::encode_string(&[8; 64]),
            authorization_proof: Base64UrlUnpadded::encode_string(&[9; 64]),
        }
    }

    #[test]
    fn request_digest_binds_raw384_and_uses_request_domain() {
        let request = request_fixture();
        let request_digest = request.request_digest().unwrap();
        let mut mutated = request.clone();
        mutated.blinded_message = Base64UrlUnpadded::encode_string(&[8; 384]);
        assert_ne!(request_digest, mutated.request_digest().unwrap());
        assert_ne!(
            request_digest,
            digest(
                NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_RESULT,
                &request.canonical_bytes().unwrap()
            )
        );
    }

    #[test]
    fn authorization_proof_digest_vector_is_frozen() {
        let request = request_fixture();
        assert_eq!(
            hex::encode(request.authorization_binding_digest().unwrap()),
            "0594bb256f3369566ca9781e0751ac392a3b96d2ec3aff647f06c981658e3ab0"
        );
        assert_eq!(
            hex::encode(request.authorization_proof_digest().unwrap()),
            "a4f6304fcf600188a210d92ce16b42585a42e59ddcee2a33982c93611f8e15fb"
        );
    }

    #[test]
    fn authorization_and_proof_are_strict_json_and_exact_raw_forms() {
        let request = request_fixture();
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            serde_json::from_value::<NativeGraphIssuanceV7Request>(json.clone()).unwrap(),
            request
        );
        let mut unknown = json.clone();
        unknown["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<NativeGraphIssuanceV7Request>(unknown).is_err());
        let mut missing = json;
        missing
            .as_object_mut()
            .unwrap()
            .remove("authorization_proof");
        assert!(serde_json::from_value::<NativeGraphIssuanceV7Request>(missing).is_err());

        let mut malformed = request.clone();
        malformed.authorization = format!("{}=", malformed.authorization);
        assert!(malformed.validate().is_err());
        malformed = request;
        malformed.authorization_proof = Base64UrlUnpadded::encode_string(&[1; 63]);
        assert!(malformed.validate().is_err());
    }

    fn result_fixture() -> NativeGraphIssuanceV7Result {
        let request = request_fixture();
        NativeGraphIssuanceV7Result {
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
            request_commitment: request.request_commitment,
            replay_identity: "77".repeat(32),
            blind_signature: Base64UrlUnpadded::encode_string(&[9; 384]),
            result_digest: String::new(),
        }
    }

    #[test]
    fn result_digest_binds_raw384_blind_and_signature() {
        let result = result_fixture();
        let result_digest = result.result_digest_bytes().unwrap();
        let mut mutated = result.clone();
        mutated.blind_signature = Base64UrlUnpadded::encode_string(&[10; 384]);
        assert_ne!(result_digest, mutated.result_digest_bytes().unwrap());
        assert_ne!(
            result_digest,
            digest(
                NATIVE_GRAPH_ISSUANCE_V7_DOMAIN_REQUEST,
                &result.result_digest_bytes().unwrap()
            )
        );
    }

    #[test]
    fn result_digest_binds_every_result_member() {
        let base = result_fixture();
        let expected = base.result_digest_bytes().unwrap();
        let mut cases = Vec::new();
        let mut value = base.clone();
        value.version = 6;
        cases.push(value);
        let mut value = base.clone();
        value.profile_id = "freebird/native-graph-issuance/other".into();
        cases.push(value);
        let mut value = base.clone();
        value.issuer_id = "issuer:other".into();
        cases.push(value);
        let mut value = base.clone();
        value.public_operation_id = Base64UrlUnpadded::encode_string(&[2; 16]);
        cases.push(value);
        for field in [
            ("graph_id", "88"),
            ("policy_id", "99"),
            ("keyset_id", "aa"),
            ("descriptor_id", "bb"),
            ("token_key_id", "cc"),
        ] {
            let mut value = base.clone();
            match field.0 {
                "graph_id" => value.graph_id = field.1.repeat(32),
                "policy_id" => value.policy_id = field.1.repeat(32),
                "keyset_id" => value.keyset_id = field.1.repeat(32),
                "descriptor_id" => value.descriptor_id = field.1.repeat(32),
                _ => value.token_key_id = field.1.repeat(32),
            }
            cases.push(value);
        }
        let mut value = base.clone();
        value.asset_id = "EUR".into();
        cases.push(value);
        let mut value = base.clone();
        value.amount_minor = "43".into();
        cases.push(value);
        let mut value = base.clone();
        value.quantity = 2;
        cases.push(value);
        let mut value = base.clone();
        value.blinded_message = Base64UrlUnpadded::encode_string(&[8; 384]);
        cases.push(value);
        let mut value = base.clone();
        value.request_commitment = "aa".repeat(32);
        cases.push(value);
        let mut value = base.clone();
        value.replay_identity = "99".repeat(32);
        cases.push(value);
        let mut value = base.clone();
        value.blind_signature = Base64UrlUnpadded::encode_string(&[10; 384]);
        cases.push(value);
        for mutated in cases {
            assert_ne!(Some(expected), mutated.result_digest_bytes().ok());
        }
        let mut bad_digest = base;
        bad_digest.result_digest = "00".repeat(32);
        assert!(bad_digest.validate().is_err());
    }

    #[test]
    fn request_digest_binds_every_request_member() {
        let base = request_fixture();
        let expected = base.request_digest().unwrap();
        let mut cases = Vec::new();
        let mut value = base.clone();
        value.version = 6;
        cases.push(value);
        let mut value = base.clone();
        value.profile_id = "freebird/native-graph-issuance/other".into();
        cases.push(value);
        let mut value = base.clone();
        value.issuer_id = "issuer:other".into();
        cases.push(value);
        let mut value = base.clone();
        value.public_operation_id = Base64UrlUnpadded::encode_string(&[2; 16]);
        cases.push(value);
        for field in [
            ("graph_id", "88"),
            ("policy_id", "99"),
            ("keyset_id", "aa"),
            ("descriptor_id", "bb"),
            ("token_key_id", "cc"),
        ] {
            let mut value = base.clone();
            match field.0 {
                "graph_id" => value.graph_id = field.1.repeat(32),
                "policy_id" => value.policy_id = field.1.repeat(32),
                "keyset_id" => value.keyset_id = field.1.repeat(32),
                "descriptor_id" => value.descriptor_id = field.1.repeat(32),
                _ => value.token_key_id = field.1.repeat(32),
            }
            cases.push(value);
        }
        let mut value = base.clone();
        value.asset_id = "EUR".into();
        cases.push(value);
        let mut value = base.clone();
        value.amount_minor = "43".into();
        cases.push(value);
        let mut value = base.clone();
        value.quantity = 2;
        cases.push(value);
        let mut value = base.clone();
        value.blinded_message = Base64UrlUnpadded::encode_string(&[8; 384]);
        cases.push(value);
        let mut value = base.clone();
        value.request_commitment = "aa".repeat(32);
        cases.push(value);
        let mut value = base.clone();
        value.authorization = Base64UrlUnpadded::encode_string(&[9; 64]);
        cases.push(value);
        let mut value = base.clone();
        value.authorization_proof = Base64UrlUnpadded::encode_string(&[10; 64]);
        cases.push(value);
        for mutated in cases {
            assert_ne!(Some(expected), mutated.request_digest().ok());
        }
    }
}
