// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::{
    api::{
        ExchangeDiscoveryV2, ExchangeGraphDiscoveryV2, ExchangePublicHistory,
        ExchangeReceiptKeyInfo, PublicKeyInfo,
    },
    exchange_api::validate_receipt_key_id,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
};

use super::receipt::validate_receipt_key_metadata;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangePublicHistoryV2 {
    #[serde(default)]
    pub retained_graphs: Vec<ExchangeGraphDiscoveryV2>,
    #[serde(default)]
    pub retained_receipt_keys: Vec<ExchangeReceiptKeyInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalV5KeyIdentity {
    pub issuer_id: String,
    pub spki: Vec<u8>,
    pub key_id: String,
    pub suite: String,
    pub audience: Option<String>,
    pub longest_valid_until: i64,
}

impl GlobalV5KeyIdentity {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [&self.issuer_id, &self.key_id, &self.suite] {
            put(&mut bytes, value.as_bytes());
        }
        put(&mut bytes, &self.spki);
        match &self.audience {
            Some(audience) => {
                bytes.push(1);
                put(&mut bytes, audience.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&self.longest_valid_until.to_be_bytes());
        bytes
    }
}

fn put(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

pub fn load_public_history_v2(path: &Path) -> Result<ExchangePublicHistoryV2> {
    serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse V2 public history {}", path.display()))
}

pub fn merge_public_history_v2(
    discovery: &mut ExchangeDiscoveryV2,
    history: ExchangePublicHistoryV2,
) -> Result<()> {
    for graph in history.retained_graphs {
        if let Some(existing) = std::iter::once(&discovery.active_graph)
            .chain(&discovery.retained_graphs)
            .find(|existing| existing.graph_id == graph.graph_id)
        {
            if existing != &graph {
                bail!("conflicting V2 public graph history")
            }
        } else {
            discovery.retained_graphs.push(graph);
        }
    }
    for key in history.retained_receipt_keys {
        if key.purpose != "exchange_receipt_retained" {
            bail!("V2 public history receipt key is not retained")
        }
        if let Some(existing) = std::iter::once(&discovery.active_receipt_key)
            .chain(&discovery.retained_receipt_keys)
            .find(|existing| existing.key_id == key.key_id)
        {
            if existing != &key {
                bail!("conflicting V2 public receipt key history")
            }
        } else {
            discovery.retained_receipt_keys.push(key);
        }
    }
    Ok(())
}

pub fn global_key_identities_v2(
    issuer_id: &str,
    direct: Option<&PublicKeyInfo>,
    discovery: &ExchangeDiscoveryV2,
) -> Result<BTreeMap<String, GlobalV5KeyIdentity>> {
    let mut identities = BTreeMap::new();
    let direct_key_id = direct.map(|metadata| metadata.token_key_id.as_str());
    if let Some(direct) = direct {
        if direct.issuer_id != issuer_id
            || direct.token_type != freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE
            || direct.rfc9474_variant != freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT
        {
            bail!("invalid direct V5 global key identity")
        }
        insert_global_identity(
            &mut identities,
            GlobalV5KeyIdentity {
                issuer_id: direct.issuer_id.clone(),
                spki: Base64UrlUnpadded::decode_vec(&direct.pubkey_spki_b64)
                    .context("invalid direct V5 global SPKI")?,
                key_id: direct.token_key_id.clone(),
                suite: freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT.into(),
                audience: direct.audience.clone(),
                longest_valid_until: direct.valid_until,
            },
        )?;
    }
    for descriptor in std::iter::once(&discovery.active_graph)
        .chain(&discovery.retained_graphs)
        .flat_map(|graph| &graph.descriptors)
    {
        insert_global_identity(
            &mut identities,
            GlobalV5KeyIdentity {
                issuer_id: descriptor.issuer_id.clone(),
                spki: Base64UrlUnpadded::decode_vec(&descriptor.pubkey_spki_b64)
                    .context("invalid graph V5 global SPKI")?,
                key_id: descriptor.token_key_id.clone(),
                suite: descriptor.suite.clone(),
                audience: descriptor.audience.clone(),
                longest_valid_until: descriptor.valid_until,
            },
        )?;
    }
    if direct_key_id.is_some_and(|direct_key_id| {
        std::iter::once(&discovery.active_graph)
            .chain(&discovery.retained_graphs)
            .flat_map(|graph| {
                let descriptors = graph
                    .descriptors
                    .iter()
                    .map(|descriptor| (&descriptor.descriptor_id, &descriptor.token_key_id))
                    .collect::<std::collections::HashMap<_, _>>();
                graph
                    .transitions
                    .iter()
                    .flat_map(|transition| &transition.output_slots)
                    .filter_map(move |slot| descriptors.get(&slot.descriptor_id).copied())
            })
            .any(|key_id| key_id == direct_key_id)
    }) {
        bail!("exchange output overlaps direct V5 issuance key")
    }
    for identity in identities.values() {
        if identity.issuer_id != issuer_id
            || hex::encode(Sha256::digest(&identity.spki)) != identity.key_id
            || identity.suite != freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT
            || identity.longest_valid_until <= 0
            || identity.longest_valid_until > freebird_common::api::EXCHANGE_MAX_VALID_UNTIL
        {
            bail!("invalid global V5 key identity")
        }
    }
    Ok(identities)
}

fn insert_global_identity(
    identities: &mut BTreeMap<String, GlobalV5KeyIdentity>,
    candidate: GlobalV5KeyIdentity,
) -> Result<()> {
    if let Some(existing) = identities.get_mut(&candidate.key_id) {
        if existing.issuer_id != candidate.issuer_id
            || existing.spki != candidate.spki
            || existing.suite != candidate.suite
            || existing.audience != candidate.audience
        {
            bail!("conflicting global V5 key identity metadata")
        }
        existing.longest_valid_until = existing
            .longest_valid_until
            .max(candidate.longest_valid_until);
    } else {
        identities.insert(candidate.key_id.clone(), candidate);
    }
    Ok(())
}

pub fn load_public_history(
    path: &Path,
    issuer_id: &str,
    legacy_public_spki: Option<&[u8]>,
) -> Result<ExchangePublicHistory> {
    let history: ExchangePublicHistory = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )?;
    validate_public_history(&history, issuer_id, legacy_public_spki)?;
    Ok(history)
}

pub fn validate_public_history(
    history: &ExchangePublicHistory,
    issuer_id: &str,
    legacy_public_spki: Option<&[u8]>,
) -> Result<()> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    freebird_common::api::validate_exchange_target_metadata(
        freebird_common::exchange_api::EXCHANGE_PROFILE_V1,
        issuer_id,
        &history.target_keysets,
        &history.target_descriptors,
    )
    .map_err(anyhow::Error::msg)?;
    for descriptor in &history.target_descriptors {
        if descriptor.purpose != "exchange_target" || descriptor.valid_until < now {
            bail!("invalid historical exchange target descriptor")
        }
        if let Some(legacy_spki) = legacy_public_spki {
            let descriptor_spki = Base64UrlUnpadded::decode_vec(&descriptor.pubkey_spki_b64)
                .context("invalid historical target SPKI")?;
            let legacy_key_id = hex::encode(Sha256::digest(legacy_spki));
            if descriptor_spki == legacy_spki || descriptor.token_key_id == legacy_key_id {
                bail!("historical exchange target overlaps active legacy public issuance key")
            }
        }
    }
    let mut receipt_ids = HashSet::new();
    for receipt in &history.receipt_keys {
        validate_receipt_key_id(&receipt.key_id).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        validate_receipt_key_metadata(receipt, "exchange_receipt_retained")
            .context("invalid historical receipt verification key")?;
        // Validity is immutable identity metadata, not a startup admission
        // window. Expired keys remain published so old receipts can be checked.
        if !receipt_ids.insert(&receipt.key_id) {
            bail!("invalid historical receipt verification key")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freebird_common::api::{
        ExchangeDescriptorDiscoveryV2, ExchangeDescriptorInfo, ExchangeGraphDiscoveryV2,
        ExchangeReceiptKeyInfo, ExchangeTargetKeysetInfo, PublicKeyInfo,
    };
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};

    #[test]
    fn rejects_historical_target_overlapping_active_legacy_public_key() {
        let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let spki = provider.public_key_spki();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut descriptor = ExchangeDescriptorInfo {
            descriptor_id: String::new(),
            keyset_id: String::new(),
            purpose: "exchange_target".into(),
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
            role: "target".into(),
            issuer_id: "issuer:test:history".into(),
            class: "target".into(),
            token_key_id: hex::encode(provider.token_key_id()),
            pubkey_spki_b64: Base64UrlUnpadded::encode_string(spki),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: now - 60,
            valid_until: now + 3600,
            max_quantity: 1,
            audience: None,
        };
        descriptor.descriptor_id = descriptor.canonical_descriptor_id().unwrap();
        let mut keyset = ExchangeTargetKeysetInfo {
            keyset_id: String::new(),
            descriptor_ids: vec![descriptor.descriptor_id.clone()],
        };
        keyset.keyset_id = keyset.canonical_keyset_id();
        descriptor.keyset_id = keyset.keyset_id.clone();
        let history = ExchangePublicHistory {
            target_keysets: vec![keyset],
            target_descriptors: vec![descriptor],
            receipt_keys: vec![],
        };

        validate_public_history(&history, "issuer:test:history", None).unwrap();
        let error =
            validate_public_history(&history, "issuer:test:history", Some(spki)).unwrap_err();
        assert!(error
            .to_string()
            .contains("overlaps active legacy public issuance key"));
    }

    fn retained_receipt_key(valid_from: u64, valid_until: u64) -> ExchangeReceiptKeyInfo {
        let public = SigningKey::from_bytes(&[7; 32]).verifying_key();
        ExchangeReceiptKeyInfo {
            key_id: hex::encode(Sha256::digest(public.as_bytes())),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_retained".into(),
            public_key_b64: Base64UrlUnpadded::encode_string(public.as_bytes()),
            valid_from,
            valid_until,
        }
    }

    fn history_with_receipts(receipt_keys: Vec<ExchangeReceiptKeyInfo>) -> ExchangePublicHistory {
        let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut descriptor = ExchangeDescriptorInfo {
            descriptor_id: String::new(),
            keyset_id: String::new(),
            purpose: "exchange_target".into(),
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
            role: "target".into(),
            issuer_id: "issuer:test:history".into(),
            class: "target".into(),
            token_key_id: hex::encode(provider.token_key_id()),
            pubkey_spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: now - 60,
            valid_until: now + 3600,
            max_quantity: 1,
            audience: None,
        };
        descriptor.descriptor_id = descriptor.canonical_descriptor_id().unwrap();
        let mut keyset = ExchangeTargetKeysetInfo {
            keyset_id: String::new(),
            descriptor_ids: vec![descriptor.descriptor_id.clone()],
        };
        keyset.keyset_id = keyset.canonical_keyset_id();
        descriptor.keyset_id = keyset.keyset_id.clone();
        ExchangePublicHistory {
            target_keysets: vec![keyset],
            target_descriptors: vec![descriptor],
            receipt_keys,
        }
    }

    #[test]
    fn expired_immutable_receipt_validity_survives_restart_and_history_load() {
        let history = history_with_receipts(vec![retained_receipt_key(1, 2)]);
        validate_public_history(&history, "issuer:test:history", None).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        std::fs::write(&path, serde_json::to_vec(&history).unwrap()).unwrap();
        let first = load_public_history(&path, "issuer:test:history", None).unwrap();
        let second = load_public_history(&path, "issuer:test:history", None).unwrap();
        assert_eq!(first, history);
        assert_eq!(second.receipt_keys, first.receipt_keys);
    }

    #[test]
    fn history_rejects_conflicting_receipt_metadata() {
        let key = retained_receipt_key(1, 100);
        let mut conflict = key.clone();
        conflict.valid_until = 101;
        let history = history_with_receipts(vec![key, conflict]);
        assert!(validate_public_history(&history, "issuer:test:history", None).is_err());
    }

    #[test]
    fn public_history_has_no_private_key_fields() {
        let history = history_with_receipts(vec![retained_receipt_key(1, 100)]);
        let serialized = serde_json::to_value(&history).unwrap();
        let text = serde_json::to_string(&serialized).unwrap();
        assert!(!text.contains("private_key"));
        assert!(!text.contains("private_key_path"));

        let mut with_private_path = serialized;
        with_private_path["receipt_keys"][0]["private_key_path"] =
            serde_json::json!("/private/receipt.key");
        assert!(serde_json::from_value::<ExchangePublicHistory>(with_private_path).is_err());
    }

    #[test]
    fn v2_global_identity_unifies_direct_and_graph_metadata_at_longest_validity() {
        let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let spki = Base64UrlUnpadded::encode_string(provider.public_key_spki());
        let key_id = hex::encode(provider.token_key_id());
        let issuer_id = "issuer:test:global";
        let direct = PublicKeyInfo {
            token_key_id: key_id.clone(),
            token_type: freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE.into(),
            rfc9474_variant: freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT.into(),
            modulus_bits: provider.modulus_bits(),
            pubkey_spki_b64: spki.clone(),
            issuer_id: issuer_id.into(),
            valid_from: 1,
            valid_until: 500,
            audience: Some("audience".into()),
            spend_policy: freebird_crypto::PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE.into(),
            max_uses: Some(1),
        };
        let descriptor = ExchangeDescriptorDiscoveryV2 {
            descriptor_id: "a".repeat(64),
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V2.into(),
            issuer_id: issuer_id.into(),
            token_key_id: key_id.clone(),
            audience: Some("audience".into()),
            pubkey_spki_b64: spki,
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: 1,
            valid_until: 300,
        };
        let discovery = ExchangeDiscoveryV2 {
            active_graph: ExchangeGraphDiscoveryV2 {
                profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V2.into(),
                graph_id: "b".repeat(64),
                descriptors: vec![descriptor],
                keysets: vec![],
                transitions: vec![],
            },
            retained_graphs: vec![],
            active_receipt_key: retained_receipt_key(1, 2),
            retained_receipt_keys: vec![],
        };
        let identities = global_key_identities_v2(issuer_id, Some(&direct), &discovery).unwrap();
        assert_eq!(identities[&key_id].longest_valid_until, 500);
        let mut conflict = direct;
        conflict.audience = Some("other".into());
        assert!(global_key_identities_v2(issuer_id, Some(&conflict), &discovery).is_err());
    }

    #[test]
    fn v2_public_history_is_additive_and_rejects_private_fields() {
        let graph = ExchangeGraphDiscoveryV2 {
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V2.into(),
            graph_id: "c".repeat(64),
            descriptors: vec![],
            keysets: vec![],
            transitions: vec![],
        };
        let history = ExchangePublicHistoryV2 {
            retained_graphs: vec![graph.clone()],
            retained_receipt_keys: vec![retained_receipt_key(1, 2)],
        };
        let mut value = serde_json::to_value(&history).unwrap();
        value["retained_graphs"][0]["private_key_path"] = serde_json::json!("/secret");
        assert!(serde_json::from_value::<ExchangePublicHistoryV2>(value).is_err());

        let active_public = SigningKey::from_bytes(&[8; 32]).verifying_key();
        let mut discovery = ExchangeDiscoveryV2 {
            active_graph: ExchangeGraphDiscoveryV2 {
                graph_id: "d".repeat(64),
                ..graph
            },
            retained_graphs: vec![],
            active_receipt_key: ExchangeReceiptKeyInfo {
                key_id: hex::encode(Sha256::digest(active_public.as_bytes())),
                algorithm: "Ed25519".into(),
                purpose: "exchange_receipt_active".into(),
                public_key_b64: Base64UrlUnpadded::encode_string(active_public.as_bytes()),
                valid_from: 3,
                valid_until: 4,
            },
            retained_receipt_keys: vec![],
        };
        merge_public_history_v2(&mut discovery, history).unwrap();
        assert_eq!(discovery.retained_graphs.len(), 1);
        assert_eq!(discovery.retained_receipt_keys.len(), 1);
    }
}
