// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Immutable, locally pinned exchange profile and keyset configuration.
use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{EXCHANGE_MAX_BUDGET_LIMIT, EXCHANGE_MAX_VALID_UNTIL};
use freebird_common::exchange_api::{
    descriptor_id, descriptor_id_v2, graph_id_v2, keyset_id, keyset_id_v2, rule_id,
    transition_id_v2, EXCHANGE_PROFILE_V1, EXCHANGE_PROFILE_V2, MAX_ITEMS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use zeroize::Zeroizing;

pub const PROFILE_ID: &str = EXCHANGE_PROFILE_V1;
pub const PROFILE_ID_V2: &str = EXCHANGE_PROFILE_V2;
const MAX_ID: usize = 128;
const MAX_SPKI: usize = 4096;
const MAX_QUANTITY: u32 = 64;
const GLOBAL_QUANTITY_CAP: u32 = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDescriptor {
    pub id: String,
    pub profile_id: String,
    pub role: String,
    pub class: String,
    pub issuer_id: String,
    pub kid: String,
    pub audience: Option<String>,
    pub spki_b64: String,
    pub suite: String,
    pub max_quantity: u32,
    pub valid_from: i64,
    pub valid_until: i64,
}

impl ExchangeDescriptor {
    pub fn spki_bytes(&self) -> Result<Vec<u8>> {
        Base64UrlUnpadded::decode_vec(&self.spki_b64).context("invalid descriptor SPKI")
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        for s in [
            &self.profile_id,
            &self.role,
            &self.class,
            &self.issuer_id,
            &self.kid,
            &self.suite,
        ] {
            b.extend_from_slice(&(s.len() as u32).to_be_bytes());
            b.extend_from_slice(s.as_bytes());
        }
        if let Some(a) = &self.audience {
            b.push(1);
            b.extend_from_slice(&(a.len() as u32).to_be_bytes());
            b.extend_from_slice(a.as_bytes());
        } else {
            b.push(0);
            b.extend_from_slice(&0u32.to_be_bytes());
        }
        b.extend_from_slice(&self.spki_bytes()?);
        b.extend_from_slice(&self.max_quantity.to_be_bytes());
        b.extend_from_slice(&self.valid_from.to_be_bytes());
        b.extend_from_slice(&self.valid_until.to_be_bytes());
        Ok(b)
    }
    pub fn canonical_id(&self) -> Result<String> {
        Ok(descriptor_id(&self.canonical_bytes()?))
    }
    pub fn key_id(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.spki_bytes()?)))
    }
    fn validate(&self, role: &str) -> Result<()> {
        for (n, v) in [
            ("id", &self.id),
            ("profile_id", &self.profile_id),
            ("role", &self.role),
            ("class", &self.class),
            ("issuer_id", &self.issuer_id),
            ("kid", &self.kid),
            ("suite", &self.suite),
        ] {
            if v.is_empty() || v.len() > MAX_ID || !v.is_ascii() {
                bail!("exchange descriptor {n} is invalid")
            }
        }
        if self.id != self.canonical_id()? || self.profile_id != PROFILE_ID || self.role != role {
            bail!("exchange descriptor identity or role is invalid")
        }
        if self.kid != self.key_id()? {
            bail!("exchange descriptor kid does not match SPKI");
        }
        if self.max_quantity == 0
            || self.max_quantity > MAX_QUANTITY
            || self.valid_from >= self.valid_until
        {
            bail!("exchange descriptor policy is invalid")
        }
        if self.suite != "RSABSSA-SHA384-PSS-Deterministic" {
            bail!("unsupported exchange suite")
        }
        let spki = self.spki_bytes()?;
        if spki.is_empty()
            || spki.len() > MAX_SPKI
            || Base64UrlUnpadded::encode_string(&spki) != self.spki_b64
        {
            bail!("exchange descriptor SPKI is not canonical")
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeSourceAllowlist {
    pub descriptors: Vec<ExchangeDescriptor>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTargetKey {
    pub descriptor: ExchangeDescriptor,
    pub private_key_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeKeyset {
    pub id: String,
    pub targets: Vec<ExchangeTargetKey>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRuleSlot {
    pub descriptor_id: String,
    pub slot_id: String,
    pub class: String,
    pub quantity: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRule {
    pub id: String,
    pub sources: Vec<ExchangeRuleSlot>,
    pub outputs: Vec<ExchangeRuleSlot>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeProfile {
    pub profile_id: String,
    pub sources: ExchangeSourceAllowlist,
    pub target_keyset: ExchangeKeyset,
    pub rules: Vec<ExchangeRule>,
}
impl ExchangeProfile {
    pub fn validate(&self, legacy_spki: Option<&[u8]>) -> Result<()> {
        if self.profile_id != PROFILE_ID
            || self.sources.descriptors.is_empty()
            || self.sources.descriptors.len() > MAX_ITEMS
            || self.target_keyset.targets.is_empty()
            || self.target_keyset.targets.len() > MAX_ITEMS
        {
            bail!("invalid exchange profile bounds")
        }
        if self.target_keyset.id.is_empty()
            || self.target_keyset.id.len() > MAX_ID
            || !self.target_keyset.id.is_ascii()
        {
            bail!("invalid target keyset id")
        }
        let mut ids = std::collections::HashSet::new();
        for d in &self.sources.descriptors {
            d.validate("source")?;
            if !ids.insert(&d.id) {
                bail!("duplicate descriptor id")
            };
            let _ = d.key_id()?;
        }
        let mut source_spkis = std::collections::HashSet::new();
        for d in &self.sources.descriptors {
            if !source_spkis.insert(d.key_id()?) {
                bail!("duplicate source SPKI")
            }
        }
        let mut target_ids = std::collections::HashSet::new();
        let mut target_keys = std::collections::HashSet::new();
        let source_keys: std::collections::HashSet<String> = self
            .sources
            .descriptors
            .iter()
            .map(|d| d.key_id())
            .collect::<Result<_>>()?;
        for t in &self.target_keyset.targets {
            t.descriptor.validate("target")?;
            if !target_ids.insert(&t.descriptor.id) {
                bail!("duplicate target descriptor id")
            };
            if ids.contains(&t.descriptor.id) {
                bail!("source and target descriptor IDs collide")
            }
            let key = t.descriptor.key_id()?;
            if !target_keys.insert(key.clone()) {
                bail!("duplicate target SPKI")
            };
            if source_keys.contains(&key) {
                bail!("exchange target overlaps source key")
            }
            if legacy_spki.is_some_and(|x| {
                Sha256::digest(t.descriptor.spki_bytes().expect("validated")) == Sha256::digest(x)
            }) {
                bail!("exchange target overlaps legacy V5 key")
            }
        }
        let expected_keyset = keyset_id(
            &self
                .target_keyset
                .targets
                .iter()
                .map(|t| t.descriptor.id.clone())
                .collect::<Vec<_>>(),
        );
        if self.target_keyset.id != expected_keyset {
            bail!("target keyset id is not canonical")
        }
        if self.rules.is_empty() || self.rules.len() > MAX_ITEMS {
            bail!("exchange rule bounds invalid")
        }
        let mut rule_ids = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.sources.is_empty()
                || rule.outputs.is_empty()
                || rule.sources.len() > MAX_ITEMS
                || rule.outputs.len() > MAX_ITEMS
            {
                bail!("invalid exchange rule bounds")
            }
            let mut canonical = Vec::new();
            let mut aggregate = 0u32;
            let mut validate_slots = |slots: &[ExchangeRuleSlot], targets: bool| -> Result<()> {
                for s in slots.iter() {
                    if s.quantity == 0
                        || s.quantity > MAX_QUANTITY
                        || s.class.is_empty()
                        || !s.class.is_ascii()
                        || if targets {
                            !target_ids.contains(&s.descriptor_id)
                        } else {
                            !ids.contains(&s.descriptor_id)
                        }
                        || s.slot_id.is_empty()
                        || s.slot_id.len() > MAX_ID
                        || !s.slot_id.is_ascii()
                    {
                        bail!("invalid exchange rule slot")
                    }
                    let descriptor_class = if targets {
                        &self
                            .target_keyset
                            .targets
                            .iter()
                            .find(|t| t.descriptor.id == s.descriptor_id)
                            .expect("validated target")
                            .descriptor
                            .class
                    } else {
                        &self
                            .sources
                            .descriptors
                            .iter()
                            .find(|d| d.id == s.descriptor_id)
                            .expect("validated source")
                            .class
                    };
                    if descriptor_class != &s.class {
                        bail!("rule slot class mismatch")
                    }
                    let descriptor_max = if targets {
                        self.target_keyset
                            .targets
                            .iter()
                            .find(|t| t.descriptor.id == s.descriptor_id)
                            .expect("validated target")
                            .descriptor
                            .max_quantity
                    } else {
                        self.sources
                            .descriptors
                            .iter()
                            .find(|d| d.id == s.descriptor_id)
                            .expect("validated source")
                            .max_quantity
                    };
                    if s.quantity > descriptor_max {
                        bail!("rule slot quantity exceeds descriptor max_quantity")
                    }
                    aggregate = aggregate
                        .checked_add(s.quantity)
                        .ok_or_else(|| anyhow::anyhow!("quantity overflow"))?;
                    canonical.extend_from_slice(&(s.descriptor_id.len() as u32).to_be_bytes());
                    canonical.extend_from_slice(s.descriptor_id.as_bytes());
                    canonical.extend_from_slice(&(s.slot_id.len() as u32).to_be_bytes());
                    canonical.extend_from_slice(s.slot_id.as_bytes());
                    canonical.extend_from_slice(&(s.class.len() as u32).to_be_bytes());
                    canonical.extend_from_slice(s.class.as_bytes());
                    canonical.extend_from_slice(&s.quantity.to_be_bytes());
                }
                Ok(())
            };
            validate_slots(&rule.sources, false)?;
            validate_slots(&rule.outputs, true)?;
            if aggregate > GLOBAL_QUANTITY_CAP {
                bail!("rule aggregate quantity exceeds global cap")
            }
            if rule.id != rule_id(&canonical) || !rule_ids.insert(&rule.id) {
                bail!("rule id is not canonical or is duplicated")
            }
        }
        Ok(())
    }
    pub fn load(path: &Path, legacy_spki: Option<&[u8]>) -> Result<Self> {
        let p: Self = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("read {}", path.display()))?,
        )?;
        p.validate(legacy_spki)?;
        Ok(p)
    }
    pub fn validate_issuer_id(&self, issuer_id: &str) -> Result<()> {
        for descriptor in &self.sources.descriptors {
            if descriptor.issuer_id != issuer_id {
                bail!("source descriptor issuer binding mismatch")
            }
        }
        for target in &self.target_keyset.targets {
            if target.descriptor.issuer_id != issuer_id {
                bail!("target descriptor issuer binding mismatch")
            }
        }
        Ok(())
    }
    pub fn validate_target_keys(&self) -> Result<()> {
        use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};
        for target in &self.target_keyset.targets {
            let path = Path::new(&target.private_key_path);
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("stat target key {}", path.display()))?;
            if !metadata.file_type().is_file() {
                bail!("target key is not a regular file")
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    bail!("target key permissions must be 0600")
                }
            }
            let der = Zeroizing::new(fs::read(path)?);
            let provider = SoftwareBlindRsaProvider::from_der(&der)?;
            let kid = hex::encode(provider.token_key_id());
            if Base64UrlUnpadded::encode_string(provider.public_key_spki())
                != target.descriptor.spki_b64
                || kid != target.descriptor.kid
            {
                bail!("target private key does not match descriptor")
            }
        }
        Ok(())
    }
    pub fn validate_request(
        &self,
        request: &freebird_common::exchange_api::ExchangeRequest,
    ) -> Result<()> {
        if request.profile != PROFILE_ID {
            bail!("unsupported exchange profile")
        }
        let rule = self
            .rules
            .iter()
            .find(|r| r.id == request.rule_id)
            .ok_or_else(|| anyhow::anyhow!("unknown exchange rule"))?;
        if request.sources.len() != rule.sources.len()
            || request.outputs.len() != rule.outputs.len()
        {
            bail!("request cardinality does not match rule")
        }
        let source_map = self
            .sources
            .descriptors
            .iter()
            .map(|d| (&d.id, d))
            .collect::<std::collections::HashMap<_, _>>();
        for (actual, expected) in request.sources.iter().zip(&rule.sources) {
            let d = source_map
                .get(&actual.slot.descriptor_id)
                .ok_or_else(|| anyhow::anyhow!("unknown source descriptor"))?;
            if actual.slot.descriptor_id != expected.descriptor_id
                || actual.slot.slot_id != expected.slot_id
                || actual.slot.quantity != expected.quantity
                || actual.slot.keyset_id != d.kid
                || d.class != expected.class
            {
                bail!("source does not satisfy rule")
            }
        }
        let target_id = &self.target_keyset.id;
        let target_map = self
            .target_keyset
            .targets
            .iter()
            .map(|t| (&t.descriptor.id, &t.descriptor))
            .collect::<std::collections::HashMap<_, _>>();
        for (actual, expected) in request.outputs.iter().zip(&rule.outputs) {
            let d = target_map
                .get(&actual.slot.descriptor_id)
                .ok_or_else(|| anyhow::anyhow!("unknown target descriptor"))?;
            if actual.slot.descriptor_id != expected.descriptor_id
                || actual.slot.slot_id != expected.slot_id
                || actual.slot.quantity != expected.quantity
                || actual.slot.keyset_id != *target_id
                || d.class != expected.class
            {
                bail!("output does not satisfy rule")
            }
        }
        Ok(())
    }
}

/// A role-neutral V2 key descriptor. Local signer paths and transition roles
/// deliberately do not form part of this immutable identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDescriptorV2 {
    pub id: String,
    pub profile_id: String,
    pub issuer_id: String,
    pub kid: String,
    pub audience: Option<String>,
    pub spki_b64: String,
    pub suite: String,
    pub valid_from: i64,
    pub valid_until: i64,
}

impl ExchangeDescriptorV2 {
    pub fn spki_bytes(&self) -> Result<Vec<u8>> {
        Base64UrlUnpadded::decode_vec(&self.spki_b64).context("invalid V2 descriptor SPKI")
    }

    pub fn key_id(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.spki_bytes()?)))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for value in [&self.profile_id, &self.issuer_id, &self.kid, &self.suite] {
            put_v2(&mut bytes, value.as_bytes());
        }
        put_optional_v2(&mut bytes, self.audience.as_deref());
        put_v2(&mut bytes, &self.spki_bytes()?);
        bytes.extend_from_slice(&self.valid_from.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until.to_be_bytes());
        Ok(bytes)
    }

    pub fn canonical_id(&self) -> Result<String> {
        Ok(descriptor_id_v2(&self.canonical_bytes()?))
    }

    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("id", self.id.as_str()),
            ("profile_id", self.profile_id.as_str()),
            ("issuer_id", self.issuer_id.as_str()),
            ("kid", self.kid.as_str()),
            ("suite", self.suite.as_str()),
        ] {
            validate_v2_id(name, value)?;
        }
        if self.audience.as_ref().is_some_and(|audience| {
            audience.is_empty() || audience.len() > MAX_ID || !audience.is_ascii()
        }) {
            bail!("V2 descriptor audience is invalid")
        }
        if self.profile_id != PROFILE_ID_V2 || self.id != self.canonical_id()? {
            bail!("V2 descriptor identity is invalid")
        }
        if self.kid != self.key_id()? {
            bail!("V2 descriptor kid does not match SPKI")
        }
        if self.suite != "RSABSSA-SHA384-PSS-Deterministic"
            || self.valid_from <= 0
            || self.valid_from >= self.valid_until
            || self.valid_until > EXCHANGE_MAX_VALID_UNTIL
        {
            bail!("V2 descriptor policy is invalid")
        }
        let spki = self.spki_bytes()?;
        if spki.is_empty()
            || spki.len() > MAX_SPKI
            || Base64UrlUnpadded::encode_string(&spki) != self.spki_b64
        {
            bail!("V2 descriptor SPKI is not canonical")
        }
        Ok(())
    }
}

/// A keyset member may carry a local signer path, but the path is not part of
/// any public/stable identifier. A keyset can be used on either side of an edge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeKeyV2 {
    pub descriptor: ExchangeDescriptorV2,
    pub private_key_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeKeysetV2 {
    pub id: String,
    pub keys: Vec<ExchangeKeyV2>,
}

impl ExchangeKeysetV2 {
    pub fn canonical_id(&self) -> String {
        keyset_id_v2(
            &self
                .keys
                .iter()
                .map(|key| key.descriptor.id.clone())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTransitionSlotV2 {
    pub descriptor_id: String,
    pub slot_id: String,
    pub class: String,
    pub quantity: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeAdmissionStateV2 {
    AcceptingNew,
    RecoveryOnly,
    Disabled,
}

impl ExchangeAdmissionStateV2 {
    pub const fn admits_new(self) -> bool {
        matches!(self, Self::AcceptingNew)
    }

    pub const fn allows_recovery(self) -> bool {
        matches!(self, Self::AcceptingNew | Self::RecoveryOnly)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTransitionV2 {
    pub id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub sources: Vec<ExchangeTransitionSlotV2>,
    pub outputs: Vec<ExchangeTransitionSlotV2>,
    pub budget_id: String,
    pub budget_limit: u64,
    pub admission_state: ExchangeAdmissionStateV2,
}

impl ExchangeTransitionV2 {
    pub fn stable_contract_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_v2(&mut bytes, self.source_keyset_id.as_bytes());
        put_v2(&mut bytes, self.target_keyset_id.as_bytes());
        put_slots_v2(&mut bytes, &self.sources);
        put_slots_v2(&mut bytes, &self.outputs);
        put_v2(&mut bytes, self.budget_id.as_bytes());
        bytes.extend_from_slice(&self.budget_limit.to_be_bytes());
        bytes
    }

    pub fn canonical_id(&self) -> String {
        transition_id_v2(&self.stable_contract_bytes())
    }

    pub const fn admits_new(&self) -> bool {
        self.admission_state.admits_new()
    }

    pub const fn allows_recovery(&self) -> bool {
        self.admission_state.allows_recovery()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeProfileV2 {
    pub profile_id: String,
    pub graph_id: String,
    pub keysets: Vec<ExchangeKeysetV2>,
    pub transitions: Vec<ExchangeTransitionV2>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeProfileValidationModeV2 {
    Active,
    Retained,
}

impl ExchangeProfileV2 {
    pub fn canonical_graph_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_v2(&mut bytes, self.profile_id.as_bytes());
        for keyset in &self.keysets {
            put_v2(&mut bytes, keyset.id.as_bytes());
        }
        for transition in &self.transitions {
            put_v2(&mut bytes, transition.id.as_bytes());
        }
        bytes
    }

    pub fn canonical_graph_id(&self) -> String {
        graph_id_v2(&self.canonical_graph_bytes())
    }

    pub fn validate(
        &self,
        mode: ExchangeProfileValidationModeV2,
        runtime_issuer_id: &str,
        direct_v5_spki: Option<&[u8]>,
    ) -> Result<()> {
        if self.profile_id != PROFILE_ID_V2
            || self.keysets.is_empty()
            || self.keysets.len() > MAX_ITEMS
            || self.transitions.is_empty()
            || self.transitions.len() > MAX_ITEMS
        {
            bail!("invalid V2 graph profile bounds")
        }
        validate_v2_id("graph_id", &self.graph_id)?;
        validate_v2_id("runtime issuer_id", runtime_issuer_id)?;
        if direct_v5_spki.is_some_and(|spki| {
            spki.is_empty()
                || spki.len() > MAX_SPKI
                || freebird_crypto::validate_public_bearer_spki(spki).is_err()
        }) {
            bail!("runtime direct V5 issuance SPKI is invalid")
        }

        let mut keyset_ids = std::collections::HashSet::new();
        let mut descriptor_ids = std::collections::HashSet::new();
        let mut descriptor_metadata = std::collections::HashMap::new();
        let mut descriptors_by_keyset = std::collections::HashMap::new();
        for keyset in &self.keysets {
            validate_v2_id("keyset id", &keyset.id)?;
            if keyset.keys.is_empty() || keyset.keys.len() > MAX_ITEMS {
                bail!("invalid V2 keyset bounds")
            }
            if keyset.id != keyset.canonical_id() || !keyset_ids.insert(keyset.id.as_str()) {
                bail!("V2 keyset id is not canonical or is duplicated")
            }
            let mut members = std::collections::HashSet::new();
            for key in &keyset.keys {
                key.descriptor.validate()?;
                let descriptor_spki = key.descriptor.spki_bytes()?;
                if key.descriptor.issuer_id != runtime_issuer_id
                    || freebird_crypto::validate_public_bearer_spki(&descriptor_spki).is_err()
                {
                    bail!("V2 descriptor issuer or RSA SPKI is invalid")
                }
                if key
                    .private_key_path
                    .as_ref()
                    .is_some_and(|path| path.is_empty())
                {
                    bail!("V2 private key path is empty")
                }
                if !members.insert(key.descriptor.id.as_str())
                    || !descriptor_ids.insert(key.descriptor.id.as_str())
                {
                    bail!("duplicate V2 descriptor id")
                }
                if let Some(existing) =
                    descriptor_metadata.insert(key.descriptor.kid.as_str(), &key.descriptor)
                {
                    if existing != &key.descriptor {
                        bail!("conflicting V2 descriptor metadata for key id")
                    }
                    bail!("duplicate V2 descriptor key")
                }
            }
            descriptors_by_keyset.insert(keyset.id.as_str(), members);
        }

        let mut transition_ids = std::collections::HashSet::new();
        let mut budget_ids = std::collections::HashSet::new();
        let mut output_descriptor_ids = std::collections::HashSet::new();
        let mut fresh_output_descriptor_ids = std::collections::HashSet::new();
        for transition in &self.transitions {
            validate_v2_id("transition id", &transition.id)?;
            validate_v2_id("budget id", &transition.budget_id)?;
            if transition.source_keyset_id == transition.target_keyset_id {
                bail!("V2 transition source and target keysets must differ")
            }
            let source_members = descriptors_by_keyset
                .get(transition.source_keyset_id.as_str())
                .ok_or_else(|| anyhow::anyhow!("unknown V2 source keyset"))?;
            let target_members = descriptors_by_keyset
                .get(transition.target_keyset_id.as_str())
                .ok_or_else(|| anyhow::anyhow!("unknown V2 target keyset"))?;
            if transition.id != transition.canonical_id()
                || !transition_ids.insert(transition.id.as_str())
            {
                bail!("V2 transition id is not canonical or is duplicated")
            }
            if transition.budget_limit == 0
                || transition.budget_limit > EXCHANGE_MAX_BUDGET_LIMIT
                || !budget_ids.insert(transition.budget_id.as_str())
            {
                bail!("V2 transition budget contract is invalid or duplicated")
            }
            if mode == ExchangeProfileValidationModeV2::Retained
                && transition.admission_state == ExchangeAdmissionStateV2::AcceptingNew
            {
                bail!("retained V2 transitions cannot accept new exchanges")
            }
            validate_transition_slots_v2(&transition.sources, source_members)?;
            validate_transition_slots_v2(&transition.outputs, target_members)?;
            for output in &transition.outputs {
                output_descriptor_ids.insert(output.descriptor_id.as_str());
                if transition.admits_new() {
                    fresh_output_descriptor_ids.insert(output.descriptor_id.as_str());
                }
            }
            let output_quantity = transition.outputs.iter().try_fold(0u64, |sum, slot| {
                sum.checked_add(u64::from(slot.quantity))
                    .ok_or_else(|| anyhow::anyhow!("V2 output quantity overflow"))
            })?;
            if output_quantity > transition.budget_limit {
                bail!("V2 transition output exceeds its lifetime budget")
            }
        }
        if self.graph_id != self.canonical_graph_id() {
            bail!("V2 graph id is not canonical")
        }
        for descriptor_id in output_descriptor_ids {
            let output_key = self
                .keysets
                .iter()
                .flat_map(|keyset| &keyset.keys)
                .find(|key| key.descriptor.id == descriptor_id)
                .expect("validated output descriptor");
            let descriptor_spki = output_key.descriptor.spki_bytes()?;
            if direct_v5_spki.is_some_and(|direct| direct == descriptor_spki) {
                bail!("exchange output overlaps direct V5 issuance key")
            }
            if fresh_output_descriptor_ids.contains(descriptor_id) {
                validate_output_signer_v2(output_key)?;
            }
        }
        Ok(())
    }

    pub fn load(
        path: &Path,
        mode: ExchangeProfileValidationModeV2,
        runtime_issuer_id: &str,
        direct_v5_spki: Option<&[u8]>,
    ) -> Result<Self> {
        let profile: Self = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("read {}", path.display()))?,
        )?;
        profile.validate(mode, runtime_issuer_id, direct_v5_spki)?;
        Ok(profile)
    }
}

pub(crate) fn validate_output_signer_v2(key: &ExchangeKeyV2) -> Result<()> {
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};

    let path = Path::new(
        key.private_key_path
            .as_deref()
            .filter(|path| !path.is_empty())
            .context("V2 transition output signer is unavailable")?,
    );
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat V2 output signer {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("V2 output signer is not a regular file")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!("V2 output signer permissions must be 0600")
        }
    }
    let der = Zeroizing::new(
        fs::read(path).with_context(|| format!("read V2 output signer {}", path.display()))?,
    );
    let provider = SoftwareBlindRsaProvider::from_der(&der)?;
    if provider.public_key_spki() != key.descriptor.spki_bytes()?
        || hex::encode(provider.token_key_id()) != key.descriptor.kid
    {
        bail!("V2 output signer does not match its descriptor")
    }
    Ok(())
}

pub fn validate_exchange_profile_set_v2(
    active: &ExchangeProfileV2,
    retained: &[ExchangeProfileV2],
    runtime_issuer_id: &str,
    direct_v5_spki: Option<&[u8]>,
) -> Result<()> {
    active.validate(
        ExchangeProfileValidationModeV2::Active,
        runtime_issuer_id,
        direct_v5_spki,
    )?;
    let mut graph_ids = std::collections::HashSet::new();
    graph_ids.insert(active.graph_id.as_str());
    let mut budgets = std::collections::HashMap::<String, Vec<u8>>::new();
    for transition in &active.transitions {
        budgets.insert(
            transition.budget_id.clone(),
            transition.stable_contract_bytes(),
        );
    }
    for graph in retained {
        graph.validate(
            ExchangeProfileValidationModeV2::Retained,
            runtime_issuer_id,
            direct_v5_spki,
        )?;
        if !graph_ids.insert(graph.graph_id.as_str()) {
            bail!("duplicate active or retained V2 graph")
        }
        for transition in &graph.transitions {
            let contract = transition.stable_contract_bytes();
            match budgets.get(&transition.budget_id) {
                Some(existing) if existing != &contract => {
                    bail!("V2 budget id reused with a different stable contract")
                }
                Some(_) => {}
                None => {
                    budgets.insert(transition.budget_id.clone(), contract);
                }
            }
        }
    }
    Ok(())
}

fn put_v2(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn put_optional_v2(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            output.push(1);
            put_v2(output, value.as_bytes());
        }
        None => {
            output.push(0);
            put_v2(output, &[]);
        }
    }
}

fn put_slots_v2(output: &mut Vec<u8>, slots: &[ExchangeTransitionSlotV2]) {
    output.extend_from_slice(&(slots.len() as u32).to_be_bytes());
    for slot in slots {
        put_v2(output, slot.descriptor_id.as_bytes());
        put_v2(output, slot.slot_id.as_bytes());
        put_v2(output, slot.class.as_bytes());
        output.extend_from_slice(&slot.quantity.to_be_bytes());
    }
}

fn validate_v2_id(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_ID || !value.is_ascii() {
        bail!("{name} is invalid")
    }
    Ok(())
}

fn validate_transition_slots_v2(
    slots: &[ExchangeTransitionSlotV2],
    keyset_members: &std::collections::HashSet<&str>,
) -> Result<()> {
    if slots.is_empty() || slots.len() > MAX_ITEMS {
        bail!("invalid V2 transition slot bounds")
    }
    let mut slot_ids = std::collections::HashSet::new();
    let mut descriptor_ids = std::collections::HashSet::new();
    for slot in slots {
        validate_v2_id("slot id", &slot.slot_id)?;
        validate_v2_id("slot class", &slot.class)?;
        if slot.quantity == 0
            || slot.quantity > MAX_QUANTITY
            || !keyset_members.contains(slot.descriptor_id.as_str())
            || !slot_ids.insert(slot.slot_id.as_str())
            || !descriptor_ids.insert(slot.descriptor_id.as_str())
        {
            bail!("invalid or duplicate V2 transition slot")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};
    fn descriptor(audience: Option<String>) -> ExchangeDescriptor {
        let spki = Base64UrlUnpadded::encode_string(&[1]);
        let kid = hex::encode(Sha256::digest([1]));
        let mut d = ExchangeDescriptor {
            id: String::new(),
            profile_id: PROFILE_ID.into(),
            role: "source".into(),
            class: "source".into(),
            issuer_id: "issuer:freebird:v4".into(),
            kid,
            audience,
            spki_b64: spki,
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            max_quantity: 1,
            valid_from: 1,
            valid_until: 2,
        };
        d.id = d.canonical_id().unwrap();
        d
    }
    #[test]
    fn profile_success_and_canonical_keyset_rule() {
        let source = descriptor(None);
        let mut target = source.clone();
        target.role = "target".into();
        target.class = "target".into();
        target.spki_b64 = Base64UrlUnpadded::encode_string(&[2]);
        target.kid = hex::encode(Sha256::digest([2]));
        target.id = target.canonical_id().unwrap();
        let mut rb = Vec::new();
        for (id, slot, class, q) in [
            (source.id.clone(), "in", "source", 1u32),
            (target.id.clone(), "out", "target", 1u32),
        ] {
            rb.extend_from_slice(&(id.len() as u32).to_be_bytes());
            rb.extend_from_slice(id.as_bytes());
            rb.extend_from_slice(&(slot.len() as u32).to_be_bytes());
            rb.extend_from_slice(slot.as_bytes());
            rb.extend_from_slice(&(class.len() as u32).to_be_bytes());
            rb.extend_from_slice(class.as_bytes());
            rb.extend_from_slice(&q.to_be_bytes());
        }
        let profile = ExchangeProfile {
            profile_id: PROFILE_ID.into(),
            sources: ExchangeSourceAllowlist {
                descriptors: vec![source.clone()],
            },
            target_keyset: ExchangeKeyset {
                id: keyset_id(std::slice::from_ref(&target.id)),
                targets: vec![ExchangeTargetKey {
                    descriptor: target.clone(),
                    private_key_path: "target.der".into(),
                }],
            },
            rules: vec![ExchangeRule {
                id: rule_id(&rb),
                sources: vec![ExchangeRuleSlot {
                    descriptor_id: source.id.clone(),
                    slot_id: "in".into(),
                    class: "source".into(),
                    quantity: 1,
                }],
                outputs: vec![ExchangeRuleSlot {
                    descriptor_id: target.id.clone(),
                    slot_id: "out".into(),
                    class: "target".into(),
                    quantity: 1,
                }],
            }],
        };
        assert!(profile.validate(None).is_ok());
        assert!(profile.validate(Some(&[1])).is_ok());
        let mut duplicate = source;
        duplicate.audience = Some("different".into());
        duplicate.id = duplicate.canonical_id().unwrap();
        let mut duplicate_profile = profile.clone();
        duplicate_profile.sources.descriptors.push(duplicate);
        assert!(duplicate_profile.validate(None).is_err());
    }
    #[test]
    fn optional_audience_is_presence_sensitive() {
        assert_ne!(
            descriptor(None).canonical_bytes().unwrap(),
            descriptor(Some(String::new())).canonical_bytes().unwrap()
        );
    }
    #[test]
    fn committed_example_profile_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/examples/public-bearer-exchange-profile.json");
        let mut profile: ExchangeProfileV2 =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(profile.graph_id, profile.canonical_graph_id());
        assert_eq!(profile.transitions.len(), 2);
        for transition in &mut profile.transitions {
            transition.admission_state = ExchangeAdmissionStateV2::Disabled;
        }
        profile
            .validate(
                ExchangeProfileValidationModeV2::Retained,
                "issuer:docker:v4",
                None,
            )
            .unwrap();
    }
    #[test]
    fn descriptor_mutation_changes_canonical_id() {
        let d = descriptor(None);
        assert_eq!(
            d.id,
            "7a9b2a4af87c740c06796b051df0b9ffc9a86a988fcb42c3f9fe7c9ee31cafd5"
        );
        assert_eq!(
            keyset_id(std::slice::from_ref(&d.id)),
            "896b0a27a2c56f684f0b01ac857959dd7b3475b8fd433152454504805dd1653c"
        );
        let mut rb = Vec::new();
        for (id, slot, class, q) in [
            (d.id.clone(), "0", "source", 1u32),
            ("b".repeat(64), "0", "target", 1u32),
        ] {
            rb.extend_from_slice(&(id.len() as u32).to_be_bytes());
            rb.extend_from_slice(id.as_bytes());
            rb.extend_from_slice(&(slot.len() as u32).to_be_bytes());
            rb.extend_from_slice(slot.as_bytes());
            rb.extend_from_slice(&(class.len() as u32).to_be_bytes());
            rb.extend_from_slice(class.as_bytes());
            rb.extend_from_slice(&q.to_be_bytes());
        }
        assert_eq!(
            rule_id(&rb),
            "12ee90fa63efe64b13d88f0ddf46b3983f4756256ebd83856bd7add1a399ce55"
        );
        let mut changed = d.clone();
        changed.class = "other".into();
        assert_ne!(d.canonical_id().unwrap(), changed.canonical_id().unwrap());
    }

    const TEST_ISSUER_ID: &str = "issuer:freebird:v4";

    fn descriptor_v2(provider: &SoftwareBlindRsaProvider) -> ExchangeDescriptorV2 {
        let spki_b64 = Base64UrlUnpadded::encode_string(provider.public_key_spki());
        let mut descriptor = ExchangeDescriptorV2 {
            id: String::new(),
            profile_id: PROFILE_ID_V2.into(),
            issuer_id: TEST_ISSUER_ID.into(),
            kid: hex::encode(provider.token_key_id()),
            audience: Some("exchange".into()),
            spki_b64,
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: 10,
            valid_until: 20,
        };
        descriptor.id = descriptor.canonical_id().unwrap();
        descriptor
    }

    fn keyset_v2(descriptor: ExchangeDescriptorV2, path: &Path) -> ExchangeKeysetV2 {
        let mut keyset = ExchangeKeysetV2 {
            id: String::new(),
            keys: vec![ExchangeKeyV2 {
                descriptor,
                private_key_path: Some(path.display().to_string()),
            }],
        };
        keyset.id = keyset.canonical_id();
        keyset
    }

    fn transition_v2(
        source: &ExchangeKeysetV2,
        target: &ExchangeKeysetV2,
        budget_id: &str,
    ) -> ExchangeTransitionV2 {
        let mut transition = ExchangeTransitionV2 {
            id: String::new(),
            source_keyset_id: source.id.clone(),
            target_keyset_id: target.id.clone(),
            sources: vec![ExchangeTransitionSlotV2 {
                descriptor_id: source.keys[0].descriptor.id.clone(),
                slot_id: "input".into(),
                class: "bearer".into(),
                quantity: 1,
            }],
            outputs: vec![ExchangeTransitionSlotV2 {
                descriptor_id: target.keys[0].descriptor.id.clone(),
                slot_id: "output".into(),
                class: "bearer".into(),
                quantity: 1,
            }],
            budget_id: budget_id.into(),
            budget_limit: 100,
            admission_state: ExchangeAdmissionStateV2::AcceptingNew,
        };
        transition.id = transition.canonical_id();
        transition
    }

    struct GraphFixtureV2 {
        graph: ExchangeProfileV2,
        direct_spki: Vec<u8>,
        _dir: tempfile::TempDir,
    }

    impl std::ops::Deref for GraphFixtureV2 {
        type Target = ExchangeProfileV2;

        fn deref(&self) -> &Self::Target {
            &self.graph
        }
    }

    impl std::ops::DerefMut for GraphFixtureV2 {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.graph
        }
    }

    impl GraphFixtureV2 {
        fn validate(&self) -> Result<()> {
            self.graph.validate(
                ExchangeProfileValidationModeV2::Active,
                TEST_ISSUER_ID,
                Some(&self.direct_spki),
            )
        }
    }

    fn write_signer(path: &Path, provider: &SoftwareBlindRsaProvider) {
        std::fs::write(path, provider.to_der().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn graph_v2() -> GraphFixtureV2 {
        let dir = tempfile::tempdir().unwrap();
        let a_provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let b_provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let a_path = dir.path().join("a.der");
        let b_path = dir.path().join("b.der");
        write_signer(&a_path, &a_provider);
        write_signer(&b_path, &b_provider);
        let a = keyset_v2(descriptor_v2(&a_provider), &a_path);
        let b = keyset_v2(descriptor_v2(&b_provider), &b_path);
        let direct = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let ab = transition_v2(&a, &b, "budget-a-to-b");
        let ba = transition_v2(&b, &a, "budget-b-to-a");
        let mut graph = ExchangeProfileV2 {
            profile_id: PROFILE_ID_V2.into(),
            graph_id: String::new(),
            keysets: vec![a, b],
            transitions: vec![ab, ba],
        };
        graph.graph_id = graph.canonical_graph_id();
        GraphFixtureV2 {
            graph,
            direct_spki: direct.public_key_spki().to_vec(),
            _dir: dir,
        }
    }

    #[test]
    fn v2_accepts_bidirectional_graph_and_state_is_not_identity() {
        let graph = graph_v2();
        assert!(graph.validate().is_ok());

        assert!(graph.transitions[0].admits_new());
        assert!(graph.transitions[0].allows_recovery());
        let stable_id = graph.transitions[0].id.clone();
        let stable_graph_id = graph.graph_id.clone();

        let mut recovery = graph.graph.clone();
        recovery.transitions[0].admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
        assert!(!recovery.transitions[0].admits_new());
        assert!(recovery.transitions[0].allows_recovery());
        assert_eq!(recovery.transitions[0].canonical_id(), stable_id);
        assert_eq!(recovery.canonical_graph_id(), stable_graph_id);
        assert!(recovery
            .validate(
                ExchangeProfileValidationModeV2::Active,
                TEST_ISSUER_ID,
                Some(&graph.direct_spki),
            )
            .is_ok());

        recovery.transitions[0].admission_state = ExchangeAdmissionStateV2::Disabled;
        assert!(!recovery.transitions[0].admits_new());
        assert!(!recovery.transitions[0].allows_recovery());
        assert!(recovery
            .validate(
                ExchangeProfileValidationModeV2::Active,
                TEST_ISSUER_ID,
                Some(&graph.direct_spki),
            )
            .is_ok());
    }

    #[test]
    fn v2_pending_references_is_not_operator_configurable() {
        let graph = graph_v2();
        let mut value = serde_json::to_value(&graph.graph).unwrap();
        value["transitions"][0]["pending_references"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ExchangeProfileV2>(value).is_err());

        let mut value = serde_json::to_value(&graph.graph).unwrap();
        value["issuer_id"] = serde_json::json!(TEST_ISSUER_ID);
        assert!(serde_json::from_value::<ExchangeProfileV2>(value).is_err());

        let mut value = serde_json::to_value(&graph.graph).unwrap();
        value["direct_v5_spki_b64"] =
            serde_json::json!(Base64UrlUnpadded::encode_string(&graph.direct_spki));
        assert!(serde_json::from_value::<ExchangeProfileV2>(value).is_err());
    }

    #[test]
    fn v2_budget_ids_are_unique_and_allow_only_exact_cross_revision_reuse() {
        let mut graph = graph_v2();
        graph.transitions[1].budget_id = graph.transitions[0].budget_id.clone();
        graph.transitions[1].budget_limit = graph.transitions[0].budget_limit;
        graph.transitions[1].id = graph.transitions[1].canonical_id();
        graph.graph_id = graph.canonical_graph_id();
        assert!(graph.validate().is_err());

        let active = graph_v2();
        let mut retained = active.graph.clone();
        for transition in &mut retained.transitions {
            transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
        }
        retained.transitions[0].budget_id = "retained-only-budget".into();
        retained.transitions[0].id = retained.transitions[0].canonical_id();
        retained.graph_id = retained.canonical_graph_id();
        assert!(validate_exchange_profile_set_v2(
            &active.graph,
            std::slice::from_ref(&retained),
            TEST_ISSUER_ID,
            Some(&active.direct_spki),
        )
        .is_ok());

        retained.transitions[1].budget_limit += 1;
        retained.transitions[1].id = retained.transitions[1].canonical_id();
        retained.graph_id = retained.canonical_graph_id();
        assert!(validate_exchange_profile_set_v2(
            &active.graph,
            &[retained],
            TEST_ISSUER_ID,
            Some(&active.direct_spki),
        )
        .is_err());
    }

    #[test]
    fn v2_enforces_numeric_redis_bounds() {
        let mut graph = graph_v2();
        graph.keysets[0].keys[0].descriptor.valid_until = i64::MAX;
        graph.keysets[0].keys[0].descriptor.id =
            graph.keysets[0].keys[0].descriptor.canonical_id().unwrap();
        assert!(graph.validate().is_err());

        let mut graph = graph_v2();
        graph.transitions[0].budget_limit = EXCHANGE_MAX_BUDGET_LIMIT + 1;
        graph.transitions[0].id = graph.transitions[0].canonical_id();
        graph.graph_id = graph.canonical_graph_id();
        assert!(graph.validate().is_err());
    }

    #[test]
    fn v2_requires_issuer_rsa_signers_and_direct_key_separation() {
        let mut graph = graph_v2();
        graph.keysets[1].keys[0].private_key_path = None;
        assert!(graph.validate().is_err());

        let mut graph = graph_v2();
        graph.keysets[0].keys[0].descriptor.issuer_id = "issuer:other".into();
        graph.keysets[0].keys[0].descriptor.id =
            graph.keysets[0].keys[0].descriptor.canonical_id().unwrap();
        assert!(graph.validate().is_err());

        let graph = graph_v2();
        let output_spki = graph.keysets[1].keys[0].descriptor.spki_bytes().unwrap();
        assert!(graph
            .graph
            .validate(
                ExchangeProfileValidationModeV2::Active,
                TEST_ISSUER_ID,
                Some(&output_spki),
            )
            .is_err());

        let mut source_only = graph.graph.clone();
        source_only.transitions.truncate(1);
        source_only.graph_id = source_only.canonical_graph_id();
        let source_spki = source_only.keysets[0].keys[0]
            .descriptor
            .spki_bytes()
            .unwrap();
        assert!(source_only
            .validate(
                ExchangeProfileValidationModeV2::Active,
                TEST_ISSUER_ID,
                Some(&source_spki),
            )
            .is_ok());
    }

    #[test]
    fn v2_retained_mode_rejects_accepting_new_and_allows_drained_signer_retirement() {
        let mut graph = graph_v2();
        assert!(graph
            .graph
            .validate(
                ExchangeProfileValidationModeV2::Retained,
                TEST_ISSUER_ID,
                Some(&graph.direct_spki),
            )
            .is_err());
        for transition in &mut graph.transitions {
            transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
        }
        assert!(graph
            .graph
            .validate(
                ExchangeProfileValidationModeV2::Retained,
                TEST_ISSUER_ID,
                Some(&graph.direct_spki),
            )
            .is_ok());

        for keyset in &mut graph.keysets {
            for key in &mut keyset.keys {
                key.private_key_path = None;
            }
        }
        assert!(graph
            .graph
            .validate(
                ExchangeProfileValidationModeV2::Retained,
                TEST_ISSUER_ID,
                Some(&graph.direct_spki),
            )
            .is_ok());
    }

    #[test]
    fn v2_rejects_self_edge() {
        let mut graph = graph_v2();
        graph.transitions[0].target_keyset_id = graph.transitions[0].source_keyset_id.clone();
        graph.transitions[0].outputs[0].descriptor_id =
            graph.transitions[0].sources[0].descriptor_id.clone();
        graph.transitions[0].id = graph.transitions[0].canonical_id();
        graph.graph_id = graph.canonical_graph_id();
        assert!(graph.validate().is_err());
    }

    #[test]
    fn v2_rejects_duplicate_ids_and_keysets() {
        let mut duplicate_keyset = graph_v2();
        let repeated_keyset = duplicate_keyset.keysets[0].clone();
        duplicate_keyset.keysets.push(repeated_keyset);
        duplicate_keyset.graph_id = duplicate_keyset.canonical_graph_id();
        assert!(duplicate_keyset.validate().is_err());

        let mut duplicate_transition = graph_v2();
        let repeated_transition = duplicate_transition.transitions[0].clone();
        duplicate_transition.transitions.push(repeated_transition);
        duplicate_transition.graph_id = duplicate_transition.canonical_graph_id();
        assert!(duplicate_transition.validate().is_err());
    }

    #[test]
    fn v2_rejects_conflicting_descriptor_metadata() {
        let mut graph = graph_v2();
        let source = graph.keysets[0].keys[0].descriptor.clone();
        let target = &mut graph.keysets[1].keys[0].descriptor;
        target.spki_b64 = source.spki_b64;
        target.kid = source.kid;
        target.audience = Some("conflicting-audience".into());
        target.id = target.canonical_id().unwrap();
        assert!(graph.validate().is_err());
    }
}
