// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Strict discovery metadata for the native V7 randomized public bearer key.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NATIVE_BEARER_V7_PROFILE_ID: &str = "scarcity/native-bearer/v7";
pub const NATIVE_BEARER_V7_SUITE: &str = "RSABSSA-SHA384-PSS-Randomized-V7";
pub const NATIVE_BEARER_V7_MODULUS_BITS: u16 = 3072;
pub const NATIVE_BEARER_V7_EXPONENT: u32 = 65_537;
pub const NATIVE_BEARER_V7_TOKEN_KEY_ID_HEX_LEN: usize = 64;
pub const NATIVE_BEARER_V7_DESCRIPTOR_ID_HEX_LEN: usize = 64;
pub const NATIVE_BEARER_V7_FINGERPRINT_HEX_LEN: usize = 64;
pub const NATIVE_BEARER_V7_MAX_SPKI_BYTES: usize = 4096;
pub const NATIVE_BEARER_V7_MAX_VALID_UNTIL: i64 =
    super::native_exchange_v3::EXCHANGE_MAX_VALID_UNTIL;
pub const NATIVE_BEARER_V7_BLINDED_MESSAGE_LEN: usize =
    freebird_crypto::public_bearer_v7::V7_SIGNATURE_LEN;
pub const NATIVE_BEARER_V7_BLINDED_MESSAGE_B64_LEN: usize = 512;

/// Discovery metadata for one native V7 randomized bearer key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBearerV7KeyInfo {
    pub profile_id: String,
    pub issuer_id: String,
    /// Lowercase hexadecimal immutable descriptor identity for this signer.
    pub descriptor_id: String,
    /// Lowercase hexadecimal encoding of the raw 32-byte V7 token key ID.
    pub token_key_id: String,
    /// Fixed asset bound to this V7 signing key.
    pub asset_id: String,
    /// Fixed nonzero minor-unit amount bound to this V7 signing key.
    pub amount_minor: u64,
    pub suite: String,
    pub modulus_bits: u16,
    pub exponent: u32,
    pub pubkey_spki_b64: String,
    /// Lowercase hexadecimal SHA-256 digest of the canonical SPKI bytes.
    pub spki_fingerprint: String,
    pub valid_from: i64,
    pub valid_until: i64,
}

impl NativeBearerV7KeyInfo {
    /// Build strict discovery metadata from an already validated V7 binding.
    pub fn from_binding(
        binding: &freebird_crypto::V7PublicKeyBinding,
        profile_id: &str,
        descriptor_id: &str,
        policy: &freebird_crypto::V7BodyPolicy,
        valid_from: i64,
        valid_until: i64,
    ) -> Result<Self, String> {
        let descriptor_id = if profile_id == NATIVE_BEARER_V7_PROFILE_ID {
            derive_native_bearer_v7_descriptor_id(
                profile_id,
                binding.identity().issuer_id(),
                &hex::encode(binding.identity().token_key_id().as_bytes()),
                policy.asset_id(),
                NATIVE_BEARER_V7_SUITE,
                NATIVE_BEARER_V7_MODULUS_BITS,
                NATIVE_BEARER_V7_EXPONENT,
                binding.public_key_spki(),
                &hex::encode(binding.spki_fingerprint()),
                policy.amount_minor(),
                valid_from,
                valid_until,
            )?
        } else {
            descriptor_id.to_owned()
        };
        let info = Self {
            profile_id: profile_id.to_owned(),
            issuer_id: binding.identity().issuer_id().to_owned(),
            descriptor_id,
            token_key_id: hex::encode(binding.identity().token_key_id().as_bytes()),
            asset_id: policy.asset_id().to_owned(),
            amount_minor: policy.amount_minor(),
            suite: NATIVE_BEARER_V7_SUITE.to_owned(),
            modulus_bits: NATIVE_BEARER_V7_MODULUS_BITS,
            exponent: NATIVE_BEARER_V7_EXPONENT,
            pubkey_spki_b64: Base64UrlUnpadded::encode_string(binding.public_key_spki()),
            spki_fingerprint: hex::encode(binding.spki_fingerprint()),
            valid_from,
            valid_until,
        };
        info.validate().map(|_| info)
    }

    /// Decode and validate the metadata, returning the equivalent V7 binding.
    pub fn decode_binding(&self) -> Result<freebird_crypto::V7PublicKeyBinding, String> {
        self.validate_shape()?;

        validate_v7_identifier_namespace(
            &self.token_key_id,
            &self.descriptor_id,
            &self.spki_fingerprint,
        )?;
        let token_key_id = decode_lower_hex_32(&self.token_key_id, "token_key_id")?;
        let spki = crate::v7_wire::decode_base64url(
            &self.pubkey_spki_b64,
            NATIVE_BEARER_V7_MAX_SPKI_BYTES,
        )
        .map_err(|error| error.to_string())?;
        let identity = freebird_crypto::V7KeyIdentity::new(
            self.issuer_id.clone(),
            freebird_crypto::V7TokenKeyId::new(token_key_id),
        )
        .map_err(|error| format!("invalid V7 issuer/key identity: {error:?}"))?;
        let binding = freebird_crypto::V7PublicKeyBinding::new(identity, &spki)
            .map_err(|error| format!("invalid V7 public key binding: {error:?}"))?;

        if binding.public_key_spki() != spki.as_slice()
            || Base64UrlUnpadded::encode_string(binding.public_key_spki()) != self.pubkey_spki_b64
            || hex::encode(binding.spki_fingerprint()) != self.spki_fingerprint
        {
            return Err("non-canonical or mismatched V7 public key metadata".into());
        }
        if self.profile_id == NATIVE_BEARER_V7_PROFILE_ID {
            let expected = derive_native_bearer_v7_descriptor_id(
                &self.profile_id,
                &self.issuer_id,
                &self.token_key_id,
                &self.asset_id,
                &self.suite,
                self.modulus_bits,
                self.exponent,
                &spki,
                &self.spki_fingerprint,
                self.amount_minor,
                self.valid_from,
                self.valid_until,
            )?;
            if self.descriptor_id != expected {
                return Err("non-canonical native V7 direct descriptor ID".into());
            }
        }
        Ok(binding)
    }

    /// Strictly validate this discovery record.
    pub fn validate(&self) -> Result<(), String> {
        self.decode_binding().map(|_| ())
    }

    /// Return the fixed V7 body policy carried by this key record.
    pub fn body_policy(&self) -> Result<freebird_crypto::V7BodyPolicy, String> {
        self.validate_shape()?;
        freebird_crypto::V7BodyPolicy::new(self.asset_id.clone(), self.amount_minor)
            .map_err(|error| format!("invalid native V7 fixed body policy: {error:?}"))
    }

    fn validate_shape(&self) -> Result<(), String> {
        if self.profile_id.is_empty()
            || self.profile_id.len() > 128
            || !self.profile_id.is_ascii()
            || self.issuer_id.is_empty()
            || !self.issuer_id.is_ascii()
            || !self.asset_id.is_ascii()
            || self.suite != NATIVE_BEARER_V7_SUITE
            || self.modulus_bits != NATIVE_BEARER_V7_MODULUS_BITS
            || self.exponent != NATIVE_BEARER_V7_EXPONENT
            || self.valid_from <= 0
            || self.valid_from >= self.valid_until
            || self.valid_until > NATIVE_BEARER_V7_MAX_VALID_UNTIL
        {
            return Err("invalid native V7 discovery metadata".into());
        }
        freebird_crypto::V7BodyPolicy::new(self.asset_id.clone(), self.amount_minor)
            .map_err(|error| format!("invalid native V7 fixed body policy: {error:?}"))?;
        Ok(())
    }
}

/// Compute the SDK-frozen descriptor identity for a direct V7 bearer record.
///
/// Every variable-length value uses a big-endian u32 byte length followed by
/// its raw bytes. This framing is shared with the JavaScript SDK.
#[allow(clippy::too_many_arguments)]
pub fn derive_native_bearer_v7_descriptor_id(
    profile_id: &str,
    issuer_id: &str,
    token_key_id: &str,
    asset_id: &str,
    suite: &str,
    modulus_bits: u16,
    exponent: u32,
    spki: &[u8],
    spki_fingerprint: &str,
    amount_minor: u64,
    valid_from: i64,
    valid_until: i64,
) -> Result<String, String> {
    if [profile_id, issuer_id, token_key_id, asset_id, suite]
        .iter()
        .any(|value| !value.is_ascii())
        || !spki_fingerprint.is_ascii()
    {
        return Err("descriptor transcript text must be ASCII".into());
    }
    let valid_from = u64::try_from(valid_from).map_err(|_| "negative valid_from")?;
    let valid_until = u64::try_from(valid_until).map_err(|_| "negative valid_until")?;
    let mut transcript = Vec::new();
    for value in [profile_id, issuer_id, token_key_id, asset_id, suite] {
        append_length_prefixed(&mut transcript, value.as_bytes())?;
    }
    transcript.extend_from_slice(&modulus_bits.to_be_bytes());
    transcript.extend_from_slice(&exponent.to_be_bytes());
    append_length_prefixed(&mut transcript, spki)?;
    append_length_prefixed(&mut transcript, spki_fingerprint.as_bytes())?;
    transcript.extend_from_slice(&amount_minor.to_be_bytes());
    transcript.extend_from_slice(&valid_from.to_be_bytes());
    transcript.extend_from_slice(&valid_until.to_be_bytes());

    let mut input = b"scarcity native bearer descriptor v7\0".to_vec();
    input.extend_from_slice(&transcript);
    Ok(hex::encode(Sha256::digest(input)))
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "descriptor transcript value too long")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn decode_lower_hex_32(value: &str, field: &str) -> Result<[u8; 32], String> {
    if value.len() != NATIVE_BEARER_V7_TOKEN_KEY_ID_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("invalid lowercase raw32 {field}"));
    }
    let bytes = hex::decode(value).map_err(|_| format!("invalid lowercase raw32 {field}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("invalid raw32 {field}"))
}

/// Validate one canonical V7 identifier shared by token keys, descriptors, and
/// SPKI fingerprints.
pub fn validate_v7_canonical_id(value: &str, field: &str) -> Result<(), String> {
    if value.len() != NATIVE_BEARER_V7_TOKEN_KEY_ID_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || hex::decode(value).map(|bytes| bytes.len() == 32) != Ok(true)
    {
        return Err(format!(
            "{field} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

/// Enforce the separate identifier namespaces used by every V7 key boundary.
pub fn validate_v7_identifier_namespace(
    token_key_id: &str,
    descriptor_id: &str,
    spki_fingerprint: &str,
) -> Result<(), String> {
    validate_v7_canonical_id(token_key_id, "token_key_id")?;
    validate_v7_canonical_id(descriptor_id, "descriptor_id")?;
    validate_v7_canonical_id(spki_fingerprint, "spki_fingerprint")?;
    if token_key_id == descriptor_id
        || token_key_id == spki_fingerprint
        || descriptor_id == spki_fingerprint
    {
        return Err("V7 token, descriptor, and SPKI identifiers must be pairwise distinct".into());
    }
    Ok(())
}

pub fn validate_native_bearer_v7_discovery(
    issuer_id: &str,
    native: &NativeBearerV7KeyInfo,
    retained: &[NativeBearerV7KeyInfo],
) -> Result<(), String> {
    if native.issuer_id != issuer_id {
        return Err("native V7 discovery issuer mismatch".into());
    }
    if native.profile_id != NATIVE_BEARER_V7_PROFILE_ID {
        return Err("native V7 discovery profile mismatch".into());
    }
    native.validate()?;
    for retained_record in retained {
        if retained_record.issuer_id != issuer_id {
            return Err("retained native V7 discovery issuer mismatch".into());
        }
        if retained_record.profile_id != NATIVE_BEARER_V7_PROFILE_ID {
            return Err("retained native V7 discovery profile mismatch".into());
        }
        retained_record.validate()?;
        if retained_record.token_key_id == native.token_key_id {
            return Err("active and retained native V7 key IDs overlap".into());
        }
        if retained_record.spki_fingerprint == native.spki_fingerprint {
            return Err("active and retained native V7 SPKI fingerprints overlap".into());
        }
    }
    for (index, left) in retained.iter().enumerate() {
        for right in retained.iter().skip(index + 1) {
            if left.token_key_id == right.token_key_id
                || left.spki_fingerprint == right.spki_fingerprint
            {
                return Err("retained native V7 key bindings overlap".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::key_discovery::{V7KeyDiscoveryResp, V7VoprfKeyInfo};
    use super::*;
    use freebird_crypto::{V7KeyIdentity, V7PublicKeyBinding, V7TokenKeyId};

    fn provider_binding() -> (V7KeyIdentity, V7PublicKeyBinding) {
        let identity = V7KeyIdentity::new("issuer:test", V7TokenKeyId::new([7; 32])).unwrap();
        let provider = freebird_crypto::provider::software::SoftwareV7BlindRsaProvider::generate(
            identity.clone(),
        )
        .unwrap();
        (identity, provider.binding().clone())
    }

    fn policy() -> freebird_crypto::V7BodyPolicy {
        freebird_crypto::V7BodyPolicy::new("USD", 42).unwrap()
    }

    #[test]
    fn native_v7_metadata_round_trips_and_serializes_strictly() {
        let (identity, binding) = provider_binding();
        let info = NativeBearerV7KeyInfo::from_binding(
            &binding,
            NATIVE_BEARER_V7_PROFILE_ID,
            &"01".repeat(32),
            &policy(),
            1,
            2,
        )
        .unwrap();
        let decoded = info.decode_binding().unwrap();
        assert_eq!(decoded.identity(), &identity);
        assert_eq!(decoded.public_key_spki(), binding.public_key_spki());
        assert_eq!(
            serde_json::from_value::<NativeBearerV7KeyInfo>(serde_json::to_value(&info).unwrap())
                .unwrap(),
            info
        );
    }

    #[test]
    fn native_v7_metadata_derives_direct_descriptor_but_preserves_other_roles() {
        let (_, binding) = provider_binding();
        let descriptor = "09".repeat(32);
        let info = NativeBearerV7KeyInfo::from_binding(
            &binding,
            "freebird/native-exchange/v3",
            &descriptor,
            &policy(),
            1,
            2,
        )
        .unwrap();
        assert_eq!(info.profile_id, "freebird/native-exchange/v3");
        assert_eq!(info.descriptor_id, descriptor);
        assert!(info.decode_binding().is_ok());

        let direct = NativeBearerV7KeyInfo::from_binding(
            &binding,
            NATIVE_BEARER_V7_PROFILE_ID,
            &descriptor,
            &policy(),
            1,
            2,
        )
        .unwrap();
        assert_ne!(direct.descriptor_id, descriptor);
        assert!(direct.validate().is_ok());
    }

    #[test]
    fn native_v7_metadata_rejects_invalid_fields() {
        let (_, binding) = provider_binding();
        let info = NativeBearerV7KeyInfo::from_binding(
            &binding,
            NATIVE_BEARER_V7_PROFILE_ID,
            &"01".repeat(32),
            &policy(),
            1,
            2,
        )
        .unwrap();

        let mut invalid = info.clone();
        invalid.token_key_id.replace_range(0..1, "A");
        assert!(invalid.validate().is_err());
        let mut invalid = info.clone();
        invalid.descriptor_id = invalid.token_key_id.clone();
        assert!(invalid.validate().is_err());
        let mut invalid = info.clone();
        invalid.spki_fingerprint = invalid.token_key_id.clone();
        assert!(invalid.validate().is_err());
        let mut invalid = info.clone();
        invalid.descriptor_id = invalid.spki_fingerprint.clone();
        assert!(invalid.validate().is_err());
        let mut invalid = info.clone();
        let replacement = if invalid.descriptor_id.starts_with('f') {
            "0"
        } else {
            "f"
        };
        invalid.descriptor_id.replace_range(0..1, replacement);
        assert_ne!(invalid.descriptor_id, info.descriptor_id);
        assert!(invalid.validate().is_err());
        let mut invalid = info.clone();
        invalid.pubkey_spki_b64.push('=');
        assert!(invalid.validate().is_err());
        let mut invalid = info.clone();
        invalid.valid_until = NATIVE_BEARER_V7_MAX_VALID_UNTIL + 1;
        assert!(invalid.validate().is_err());
        let mut invalid = info;
        invalid.suite = "RSABSSA-SHA384-PSS-Deterministic".into();
        assert!(invalid.validate().is_err());
        let mut invalid = NativeBearerV7KeyInfo::from_binding(
            &binding,
            NATIVE_BEARER_V7_PROFILE_ID,
            &"01".repeat(32),
            &policy(),
            1,
            2,
        )
        .unwrap();
        invalid.asset_id.clear();
        assert!(invalid.validate().is_err());
        invalid.asset_id = "EÜ".into();
        assert!(invalid.validate().is_err());
        invalid.asset_id = "USD".into();
        invalid.issuer_id = "issuer:é".into();
        assert!(invalid.validate().is_err());
        invalid.amount_minor = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn direct_descriptor_transcript_matches_frozen_vector() {
        assert_eq!(
            derive_native_bearer_v7_descriptor_id(
                NATIVE_BEARER_V7_PROFILE_ID,
                "issuer:test",
                &"07".repeat(32),
                "USD",
                NATIVE_BEARER_V7_SUITE,
                3072,
                65_537,
                &[1, 2, 3],
                &"ab".repeat(32),
                42,
                1,
                2,
            )
            .unwrap(),
            "c293e13a215ac4ffcc1ac0683212aca1b3a693f4417dc2e11733c696e3ab07b2"
        );
    }

    #[test]
    fn key_discovery_requires_active_v7_and_retains_history_separately() {
        let missing_v7: Result<V7KeyDiscoveryResp, _> = serde_json::from_str(
            r#"{"issuer_id":"issuer:test","current_epoch":1,"valid_epochs":[1],"epoch_duration_sec":1,"voprf":{"suite":"suite","kid":"kid","pubkey":"pubkey"}}"#,
        );
        assert!(missing_v7.is_err());

        let (_, binding) = provider_binding();
        let native = NativeBearerV7KeyInfo::from_binding(
            &binding,
            NATIVE_BEARER_V7_PROFILE_ID,
            &"01".repeat(32),
            &policy(),
            1,
            2,
        )
        .unwrap();
        let response = V7KeyDiscoveryResp {
            issuer_id: "issuer:test".into(),
            current_epoch: 1,
            valid_epochs: vec![1],
            epoch_duration_sec: 1,
            voprf: V7VoprfKeyInfo {
                suite: "suite".into(),
                kid: "kid".into(),
                pubkey: "pubkey".into(),
            },
            native_bearer_v7: native,
            native_bearer_v7_retained: vec![],
            native_exchange_v7: None,
            native_graph_issuance_v7: None,
        };
        assert!(response.validate().is_ok());
        assert!(serde_json::to_string(&response)
            .unwrap()
            .contains("native_bearer_v7"));
    }
}
