// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Immutable, locally pinned exchange profile and keyset configuration.
use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::exchange_api::{
    descriptor_id, keyset_id, rule_id, EXCHANGE_PROFILE_V1, MAX_ITEMS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use zeroize::Zeroizing;

pub const PROFILE_ID: &str = EXCHANGE_PROFILE_V1;
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

#[cfg(test)]
mod tests {
    use super::*;
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
        let profile = ExchangeProfile::load(&path, None).unwrap();
        assert!(!profile.sources.descriptors.is_empty());
        assert!(!profile.target_keyset.targets.is_empty());
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
}
