// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Append-only native V7 bearer-key bindings.
//!
//! This registry has one namespace only.  A token key ID and canonical SPKI
//! binding is immutable; expired entries remain as retained tombstones so a
//! previously issued artifact can never be rebound to new key material.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::api::{
    NativeBearerV7KeyInfo, NativeExchangeV3Descriptor, NativeGraphIssuanceV7Policy,
    NATIVE_BEARER_V7_PROFILE_ID, NATIVE_EXCHANGE_V3_PROFILE_ID,
    NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
};

const MAX_CANONICAL_SPKI_BYTES: usize = 4096;
const HEX32_LEN: usize = 64;

/// One immutable native V7 key binding and its fixed body policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BearerKeyReservation {
    pub profile_id: String,
    pub issuer_id: String,
    pub descriptor_id: String,
    /// Lowercase hexadecimal encoding of the raw 32-byte V7 token key ID.
    pub token_key_id: String,
    /// Lowercase hexadecimal SHA-256 digest of the canonical SPKI bytes.
    pub spki_fingerprint: String,
    /// Unpadded base64url encoding of the canonical SPKI bytes.
    pub pubkey_spki_b64: String,
    pub suite: String,
    pub asset_id: String,
    pub amount_minor: u64,
    pub valid_from: i64,
    pub valid_until: i64,
}

impl BearerKeyReservation {
    pub fn from_exchange_descriptor(
        descriptor: &NativeExchangeV3Descriptor,
    ) -> Result<Self, BearerKeyRegistryError> {
        descriptor
            .validate()
            .map_err(|error| BearerKeyRegistryError::Invalid(error.to_string()))?;
        let amount_minor = descriptor
            .amount_minor
            .parse::<u64>()
            .map_err(|_| BearerKeyRegistryError::Invalid("invalid V7 descriptor amount".into()))?;
        Self::new(
            descriptor.profile_id.clone(),
            descriptor.issuer_id.clone(),
            descriptor.descriptor_id.clone(),
            descriptor.token_key_id.clone(),
            descriptor.spki_fingerprint.clone(),
            descriptor.pubkey_spki_b64.clone(),
            descriptor.suite.clone(),
            descriptor.asset_id.clone(),
            amount_minor,
            i64::try_from(descriptor.valid_from).map_err(|_| {
                BearerKeyRegistryError::Invalid("invalid V7 descriptor start".into())
            })?,
            i64::try_from(descriptor.valid_until)
                .map_err(|_| BearerKeyRegistryError::Invalid("invalid V7 descriptor end".into()))?,
        )
    }

    pub fn from_graph_policy(
        policy: &NativeGraphIssuanceV7Policy,
    ) -> Result<Self, BearerKeyRegistryError> {
        policy
            .validate()
            .map_err(|error| BearerKeyRegistryError::Invalid(error.to_string()))?;
        let amount_minor = policy
            .amount_minor
            .parse::<u64>()
            .map_err(|_| BearerKeyRegistryError::Invalid("invalid V7 policy amount".into()))?;
        Self::new(
            policy.profile_id.clone(),
            policy.issuer_id.clone(),
            policy.descriptor_id.clone(),
            policy.token_key_id.clone(),
            policy.spki_fingerprint.clone(),
            policy.pubkey_spki_b64.clone(),
            policy.suite.clone(),
            policy.asset_id.clone(),
            amount_minor,
            policy.valid_from,
            policy.valid_until,
        )
    }

    /// Build a permanent V7 reservation from an already validated binding and
    /// fixed body policy.
    pub fn from_v7_binding(
        binding: &freebird_crypto::V7PublicKeyBinding,
        profile_id: &str,
        descriptor_id: &str,
        policy: &freebird_crypto::V7BodyPolicy,
        valid_from: i64,
        valid_until: i64,
    ) -> Result<Self, BearerKeyRegistryError> {
        Self::new(
            profile_id.to_owned(),
            binding.issuer_id().to_owned(),
            descriptor_id.to_owned(),
            hex::encode(binding.token_key_id().as_bytes()),
            hex::encode(binding.spki_fingerprint()),
            Base64UrlUnpadded::encode_string(binding.public_key_spki()),
            crate::api::NATIVE_BEARER_V7_SUITE.to_owned(),
            policy.asset_id().to_owned(),
            policy.amount_minor(),
            valid_from,
            valid_until,
        )
    }

    /// Build a reservation from strict discovery metadata and its validated
    /// cryptographic binding.
    pub fn from_v7_discovery(
        metadata: &NativeBearerV7KeyInfo,
        binding: &freebird_crypto::V7PublicKeyBinding,
    ) -> Result<Self, BearerKeyRegistryError> {
        let decoded = metadata
            .decode_binding()
            .map_err(BearerKeyRegistryError::Invalid)?;
        if &decoded != binding {
            return Err(BearerKeyRegistryError::Invalid(
                "V7 discovery metadata does not match its crypto binding".into(),
            ));
        }
        let policy = metadata
            .body_policy()
            .map_err(BearerKeyRegistryError::Invalid)?;
        Self::from_v7_binding(
            binding,
            &metadata.profile_id,
            &metadata.descriptor_id,
            &policy,
            metadata.valid_from,
            metadata.valid_until,
        )
    }

    /// Construct a reservation while enforcing all canonical V7 wire forms.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: String,
        issuer_id: String,
        descriptor_id: String,
        token_key_id: String,
        spki_fingerprint: String,
        pubkey_spki_b64: String,
        suite: String,
        asset_id: String,
        amount_minor: u64,
        valid_from: i64,
        valid_until: i64,
    ) -> Result<Self, BearerKeyRegistryError> {
        let reservation = Self {
            profile_id,
            issuer_id,
            descriptor_id,
            token_key_id,
            spki_fingerprint,
            pubkey_spki_b64,
            suite,
            asset_id,
            amount_minor,
            valid_from,
            valid_until,
        };
        reservation.validate()?;
        Ok(reservation)
    }

    /// Validate the immutable V7 identity, SPKI binding, policy, and validity.
    pub fn validate(&self) -> Result<(), BearerKeyRegistryError> {
        if !matches!(
            self.profile_id.as_str(),
            NATIVE_BEARER_V7_PROFILE_ID
                | NATIVE_EXCHANGE_V3_PROFILE_ID
                | NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID
        ) || self.profile_id.is_empty()
            || self.profile_id.len() > 128
            || !self.profile_id.is_ascii()
            || self.issuer_id.is_empty()
            || !self.issuer_id.is_ascii()
            || !self.asset_id.is_ascii()
            || self.valid_from > self.valid_until
        {
            return Err(BearerKeyRegistryError::Invalid(
                "invalid V7 reservation identity or validity".into(),
            ));
        }
        let token_key_id = decode_raw32(&self.token_key_id, "token_key_id")?;
        let fingerprint = decode_raw32(&self.spki_fingerprint, "spki_fingerprint")?;
        crate::api::validate_v7_identifier_namespace(
            &self.token_key_id,
            &self.descriptor_id,
            &self.spki_fingerprint,
        )
        .map_err(BearerKeyRegistryError::Invalid)?;
        if self.suite != crate::api::NATIVE_BEARER_V7_SUITE {
            return Err(BearerKeyRegistryError::Invalid(
                "invalid V7 bearer reservation suite".into(),
            ));
        }
        let policy = freebird_crypto::V7BodyPolicy::new(self.asset_id.clone(), self.amount_minor)
            .map_err(|error| {
            BearerKeyRegistryError::Invalid(format!("invalid V7 fixed body policy: {error:?}"))
        })?;
        let spki =
            crate::v7_wire::decode_base64url(&self.pubkey_spki_b64, MAX_CANONICAL_SPKI_BYTES)
                .map_err(|error| BearerKeyRegistryError::Invalid(error.to_string()))?;
        if Base64UrlUnpadded::encode_string(&spki) != self.pubkey_spki_b64
            || hex::encode(Sha256::digest(&spki)) != self.spki_fingerprint
        {
            return Err(BearerKeyRegistryError::Invalid(
                "V7 SPKI is not canonical or has a mismatched fingerprint".into(),
            ));
        }
        let identity = freebird_crypto::V7KeyIdentity::new(
            self.issuer_id.clone(),
            freebird_crypto::V7TokenKeyId::new(token_key_id),
        )
        .map_err(|error| {
            BearerKeyRegistryError::Invalid(format!("invalid V7 identity: {error:?}"))
        })?;
        let binding =
            freebird_crypto::V7PublicKeyBinding::new(identity, &spki).map_err(|error| {
                BearerKeyRegistryError::Invalid(format!("invalid V7 binding: {error:?}"))
            })?;
        if binding.spki_fingerprint() != &fingerprint {
            return Err(BearerKeyRegistryError::Invalid(
                "invalid V7 SPKI fingerprint".into(),
            ));
        }
        if binding.issuer_id() != self.issuer_id {
            return Err(BearerKeyRegistryError::Invalid(
                "V7 binding issuer does not match reservation".into(),
            ));
        }
        if self.profile_id == NATIVE_BEARER_V7_PROFILE_ID {
            if self.valid_from <= 0
                || self.valid_from >= self.valid_until
                || self.valid_until > crate::api::NATIVE_BEARER_V7_MAX_VALID_UNTIL
            {
                return Err(BearerKeyRegistryError::Invalid(
                    "invalid native V7 direct validity window".into(),
                ));
            }
            let expected = crate::api::derive_native_bearer_v7_descriptor_id(
                &self.profile_id,
                &self.issuer_id,
                &self.token_key_id,
                &self.asset_id,
                &self.suite,
                crate::api::NATIVE_BEARER_V7_MODULUS_BITS,
                crate::api::NATIVE_BEARER_V7_EXPONENT,
                &spki,
                &self.spki_fingerprint,
                self.amount_minor,
                self.valid_from,
                self.valid_until,
            )
            .map_err(BearerKeyRegistryError::Invalid)?;
            if self.descriptor_id != expected {
                return Err(BearerKeyRegistryError::Invalid(
                    "non-canonical native V7 direct descriptor ID".into(),
                ));
            }
        } else if self.profile_id == NATIVE_EXCHANGE_V3_PROFILE_ID {
            if self.valid_from <= 0
                || self.valid_from >= self.valid_until
                || self.valid_until > crate::api::EXCHANGE_MAX_VALID_UNTIL
            {
                return Err(BearerKeyRegistryError::Invalid(
                    "invalid native V7 exchange validity window".into(),
                ));
            }
            let expected = crate::api::derive_native_exchange_v3_descriptor_id(
                &self.profile_id,
                &self.issuer_id,
                &self.token_key_id,
                &self.asset_id,
                self.amount_minor,
                &self.suite,
                3_072,
                65_537,
                &spki,
                &self.spki_fingerprint,
                u64::try_from(self.valid_from).map_err(|_| {
                    BearerKeyRegistryError::Invalid("invalid V7 exchange start".into())
                })?,
                u64::try_from(self.valid_until).map_err(|_| {
                    BearerKeyRegistryError::Invalid("invalid V7 exchange end".into())
                })?,
            )
            .map_err(|error| BearerKeyRegistryError::Invalid(error.to_string()))?;
            if self.descriptor_id != expected {
                return Err(BearerKeyRegistryError::Invalid(
                    "non-canonical native V7 exchange descriptor ID".into(),
                ));
            }
        }
        // Keep the policy validation explicit at this boundary.  The value is
        // intentionally not included in the key fingerprint or wire digest.
        let _ = policy;
        Ok(())
    }

    /// Return the raw token key ID after validating its canonical encoding.
    pub fn token_key_id_bytes(&self) -> Result<[u8; 32], BearerKeyRegistryError> {
        decode_raw32(&self.token_key_id, "token_key_id")
    }

    /// Whether this reservation is expired at the supplied inclusive time.
    pub fn is_expired_at(&self, now: i64) -> bool {
        self.valid_until < now
    }
}

/// Result of loading a reservation into the append-only registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerKeyReservationStatus {
    Inserted,
    AlreadyPresent,
}

/// A serializable append-only registry containing only native V7 bindings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BearerKeyRegistry {
    entries: Vec<BearerKeyReservation>,
}

impl<'de> Deserialize<'de> for BearerKeyRegistry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawBearerKeyRegistry {
            #[serde(default)]
            entries: Vec<BearerKeyReservation>,
        }

        let raw = RawBearerKeyRegistry::deserialize(deserializer)?;
        let raw_len = raw.entries.len();
        let registry = Self::from_entries(raw.entries).map_err(serde::de::Error::custom)?;
        if registry.entries.len() != raw_len {
            return Err(serde::de::Error::custom("duplicate V7 registry entry"));
        }
        Ok(registry)
    }
}

impl BearerKeyRegistry {
    /// Construct an empty V7 registry.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Load entries, retaining historical tombstones and accepting identical
    /// records as idempotent reloads.
    pub fn from_entries(
        entries: impl IntoIterator<Item = BearerKeyReservation>,
    ) -> Result<Self, BearerKeyRegistryError> {
        let mut registry = Self::new();
        for entry in entries {
            registry.register(entry)?;
        }
        Ok(registry)
    }

    /// Return every active and retained V7 reservation.
    pub fn entries(&self) -> &[BearerKeyReservation] {
        &self.entries
    }

    pub fn validate(&self) -> Result<(), BearerKeyRegistryError> {
        Self::from_entries(self.entries.clone()).map(|_| ())
    }

    /// Add a reservation, or accept an identical existing reservation.
    pub fn register(
        &mut self,
        entry: BearerKeyReservation,
    ) -> Result<BearerKeyReservationStatus, BearerKeyRegistryError> {
        entry.validate()?;
        for existing in &self.entries {
            if existing == &entry {
                return Ok(BearerKeyReservationStatus::AlreadyPresent);
            }
            if existing.token_key_id == entry.token_key_id {
                return Err(BearerKeyRegistryError::Conflict(
                    "V7 token key ID is already immutably reserved".into(),
                ));
            }
            if existing.descriptor_id == entry.descriptor_id {
                return Err(BearerKeyRegistryError::Conflict(
                    "V7 descriptor ID is already immutably reserved".into(),
                ));
            }
            if existing.spki_fingerprint == entry.spki_fingerprint {
                return Err(BearerKeyRegistryError::Conflict(
                    "V7 SPKI fingerprint is already immutably reserved".into(),
                ));
            }
        }
        self.entries.push(entry);
        Ok(BearerKeyReservationStatus::Inserted)
    }

    pub fn reserve(
        &mut self,
        entry: BearerKeyReservation,
    ) -> Result<BearerKeyReservationStatus, BearerKeyRegistryError> {
        self.register(entry)
    }

    pub fn validate_v7_discovery(
        &self,
        metadata: &NativeBearerV7KeyInfo,
        binding: &freebird_crypto::V7PublicKeyBinding,
    ) -> Result<(), BearerKeyRegistryError> {
        let entry = BearerKeyReservation::from_v7_discovery(metadata, binding)?;
        self.validate_candidate(&entry)
    }

    pub fn register_v7_discovery(
        &mut self,
        metadata: &NativeBearerV7KeyInfo,
        binding: &freebird_crypto::V7PublicKeyBinding,
    ) -> Result<BearerKeyReservationStatus, BearerKeyRegistryError> {
        self.register(BearerKeyReservation::from_v7_discovery(metadata, binding)?)
    }

    pub fn register_exchange_descriptor(
        &mut self,
        descriptor: &NativeExchangeV3Descriptor,
    ) -> Result<BearerKeyReservationStatus, BearerKeyRegistryError> {
        self.register(BearerKeyReservation::from_exchange_descriptor(descriptor)?)
    }

    pub fn register_graph_policy(
        &mut self,
        policy: &NativeGraphIssuanceV7Policy,
    ) -> Result<BearerKeyReservationStatus, BearerKeyRegistryError> {
        self.register(BearerKeyReservation::from_graph_policy(policy)?)
    }

    /// Find a V7 reservation by typed key ID, including retained tombstones.
    pub fn lookup_v7(
        &self,
        token_key_id: &freebird_crypto::V7TokenKeyId,
    ) -> Option<&BearerKeyReservation> {
        let encoded = hex::encode(token_key_id.as_bytes());
        self.entries
            .iter()
            .find(|entry| entry.token_key_id == encoded)
    }

    /// Active projection for discovery publication.
    pub fn active_at(&self, now: i64) -> impl Iterator<Item = &BearerKeyReservation> {
        self.entries
            .iter()
            .filter(move |entry| entry.valid_from <= now && now <= entry.valid_until)
    }

    /// Retained projection for discovery publication.  Expired tombstones are
    /// never removed from the backing registry.
    pub fn retained_at(&self, now: i64) -> impl Iterator<Item = &BearerKeyReservation> {
        self.entries
            .iter()
            .filter(move |entry| entry.valid_until < now)
    }

    fn validate_candidate(
        &self,
        candidate: &BearerKeyReservation,
    ) -> Result<(), BearerKeyRegistryError> {
        candidate.validate()?;
        for existing in &self.entries {
            if existing == candidate {
                continue;
            }
            if existing.token_key_id == candidate.token_key_id
                || existing.descriptor_id == candidate.descriptor_id
                || existing.spki_fingerprint == candidate.spki_fingerprint
            {
                return Err(BearerKeyRegistryError::Conflict(
                    "V7 key binding is already immutably reserved".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Registry validation or reservation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BearerKeyRegistryError {
    Invalid(String),
    Conflict(String),
}

impl fmt::Display for BearerKeyRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => {
                write!(formatter, "invalid V7 bearer registry entry: {message}")
            }
            Self::Conflict(message) => write!(formatter, "V7 bearer registry conflict: {message}"),
        }
    }
}

impl std::error::Error for BearerKeyRegistryError {}

fn decode_raw32(value: &str, field: &str) -> Result<[u8; 32], BearerKeyRegistryError> {
    if value.len() != HEX32_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(BearerKeyRegistryError::Invalid(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )));
    }
    hex::decode(value)
        .map_err(|_| BearerKeyRegistryError::Invalid(format!("invalid {field}")))?
        .try_into()
        .map_err(|_| BearerKeyRegistryError::Invalid(format!("invalid {field}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Encoding;
    use freebird_crypto::{V7KeyIdentity, V7TokenKeyId};

    fn binding(id: u8) -> freebird_crypto::V7PublicKeyBinding {
        let identity = V7KeyIdentity::new("issuer:test", V7TokenKeyId::new([id; 32])).unwrap();
        freebird_crypto::provider::software::SoftwareV7BlindRsaProvider::generate(identity)
            .unwrap()
            .binding()
            .clone()
    }

    fn policy() -> freebird_crypto::V7BodyPolicy {
        freebird_crypto::V7BodyPolicy::new("USD", 42).unwrap()
    }

    fn v7_entry(binding: &freebird_crypto::V7PublicKeyBinding) -> BearerKeyReservation {
        v7_entry_with_validity(binding, 2)
    }

    fn v7_entry_with_validity(
        binding: &freebird_crypto::V7PublicKeyBinding,
        valid_until: i64,
    ) -> BearerKeyReservation {
        let policy = policy();
        let descriptor_id = crate::api::derive_native_exchange_v3_descriptor_id(
            NATIVE_EXCHANGE_V3_PROFILE_ID,
            binding.issuer_id(),
            &hex::encode(binding.token_key_id().as_bytes()),
            policy.asset_id(),
            policy.amount_minor(),
            crate::api::NATIVE_EXCHANGE_V3_SUITE,
            3_072,
            65_537,
            binding.public_key_spki(),
            &hex::encode(binding.spki_fingerprint()),
            1,
            u64::try_from(valid_until).unwrap(),
        )
        .unwrap();
        BearerKeyReservation::from_v7_binding(
            binding,
            NATIVE_EXCHANGE_V3_PROFILE_ID,
            &descriptor_id,
            &policy,
            1,
            valid_until,
        )
        .unwrap()
    }

    fn direct_entry(binding: &freebird_crypto::V7PublicKeyBinding) -> BearerKeyReservation {
        let metadata = crate::api::NativeBearerV7KeyInfo::from_binding(
            binding,
            NATIVE_BEARER_V7_PROFILE_ID,
            &"00".repeat(32),
            &policy(),
            1,
            2,
        )
        .unwrap();
        BearerKeyReservation::from_v7_discovery(&metadata, binding).unwrap()
    }

    #[test]
    fn registry_accepts_distinct_entries_and_idempotent_reload() {
        let first = v7_entry(&binding(4));
        let second = v7_entry(&binding(5));
        let mut registry = BearerKeyRegistry::new();
        assert_eq!(
            registry.register(first.clone()).unwrap(),
            BearerKeyReservationStatus::Inserted
        );
        assert_eq!(
            registry.register(first.clone()).unwrap(),
            BearerKeyReservationStatus::AlreadyPresent
        );
        assert_eq!(
            registry.register(second).unwrap(),
            BearerKeyReservationStatus::Inserted
        );
        assert_eq!(registry.entries().len(), 2);
        let json = serde_json::to_string(&registry).unwrap();
        let loaded: BearerKeyRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded, registry);
    }

    #[test]
    fn registry_rejects_immutable_key_id_or_spki_rebinding() {
        let first = binding(2);
        let second_identity =
            V7KeyIdentity::new("issuer:test", V7TokenKeyId::new([3; 32])).unwrap();
        let second = freebird_crypto::V7PublicKeyBinding::from_identity_and_spki(
            second_identity,
            first.public_key_spki(),
        )
        .unwrap();
        let mut registry = BearerKeyRegistry::new();
        registry.register(v7_entry(&first)).unwrap();
        assert!(matches!(
            registry.register(v7_entry(&second)),
            Err(BearerKeyRegistryError::Conflict(_))
        ));

        let mut changed = v7_entry(&first);
        changed.asset_id = "EUR".into();
        changed.descriptor_id = crate::api::derive_native_exchange_v3_descriptor_id(
            NATIVE_EXCHANGE_V3_PROFILE_ID,
            &changed.issuer_id,
            &changed.token_key_id,
            &changed.asset_id,
            changed.amount_minor,
            &changed.suite,
            3_072,
            65_537,
            &base64ct::Base64UrlUnpadded::decode_vec(&changed.pubkey_spki_b64).unwrap(),
            &changed.spki_fingerprint,
            1,
            2,
        )
        .unwrap();
        assert!(matches!(
            registry.register(changed),
            Err(BearerKeyRegistryError::Conflict(_))
        ));

        let mut descriptor_collision = v7_entry(&binding(9));
        descriptor_collision.descriptor_id = registry.entries()[0].descriptor_id.clone();
        assert!(registry.register(descriptor_collision).is_err());
    }

    #[test]
    fn direct_registry_serialization_rejects_tampered_descriptor() {
        let mut registry = BearerKeyRegistry::new();
        registry.register(direct_entry(&binding(10))).unwrap();
        let value = serde_json::to_value(&registry).unwrap();
        assert!(serde_json::from_value::<BearerKeyRegistry>(value.clone()).is_ok());

        let mut tampered = value;
        let descriptor = tampered["entries"][0]["descriptor_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let replacement = if descriptor.starts_with('f') {
            '0'
        } else {
            'f'
        };
        let mut changed = descriptor.clone();
        changed.replace_range(0..1, &replacement.to_string());
        assert_ne!(changed, descriptor);
        tampered["entries"][0]["descriptor_id"] = changed.into();
        assert!(serde_json::from_value::<BearerKeyRegistry>(tampered).is_err());
    }

    #[test]
    fn exchange_registry_serialization_rejects_tampered_descriptor() {
        let mut registry = BearerKeyRegistry::new();
        registry.register(v7_entry(&binding(11))).unwrap();
        let value = serde_json::to_value(&registry).unwrap();
        assert!(serde_json::from_value::<BearerKeyRegistry>(value.clone()).is_ok());

        let mut tampered = value;
        let descriptor = tampered["entries"][0]["descriptor_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let replacement = if descriptor.starts_with('f') {
            '0'
        } else {
            'f'
        };
        let mut changed = descriptor.clone();
        changed.replace_range(0..1, &replacement.to_string());
        assert_ne!(changed, descriptor);
        tampered["entries"][0]["descriptor_id"] = changed.into();
        assert!(serde_json::from_value::<BearerKeyRegistry>(tampered).is_err());
    }

    #[test]
    fn active_and_retained_projections_preserve_tombstones() {
        let active = v7_entry_with_validity(&binding(6), 10);
        let retained = v7_entry_with_validity(&binding(7), 2);
        let mut registry = BearerKeyRegistry::new();
        registry.register(active).unwrap();
        registry.register(retained).unwrap();
        assert_eq!(registry.active_at(3).count(), 1);
        assert_eq!(registry.retained_at(3).count(), 1);
        assert_eq!(registry.entries().len(), 2);
    }

    #[test]
    fn malformed_or_unknown_registry_records_are_rejected() {
        let entry = v7_entry(&binding(9));
        let mut value = serde_json::json!({ "entries": [entry] });
        value["entries"][0]["amount_minor"] = serde_json::json!(0);
        assert!(serde_json::from_value::<BearerKeyRegistry>(value).is_err());

        let value = serde_json::json!({
            "entries": [],
            "v5": [],
        });
        assert!(serde_json::from_value::<BearerKeyRegistry>(value).is_err());
    }
}
