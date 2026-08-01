// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Immutable, locally pinned exchange profile and keyset configuration.
use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{EXCHANGE_MAX_BUDGET_LIMIT, EXCHANGE_MAX_VALID_UNTIL};
use freebird_common::exchange_api::{
    descriptor_id_v2, graph_id_v2, keyset_id_v2, transition_id_v2, EXCHANGE_PROFILE_V2, MAX_ITEMS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use zeroize::Zeroizing;

pub const PROFILE_ID_V2: &str = EXCHANGE_PROFILE_V2;
const MAX_ID: usize = 128;
const MAX_SPKI: usize = 4096;
const MAX_QUANTITY: u32 = 64;

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
    const TEST_ISSUER_ID: &str = "issuer:freebird:v4";

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
