// common/src/api.rs
use serde::{Deserialize, Serialize};

/// Largest positive integer represented exactly by Redis Lua numbers.
pub const EXCHANGE_LUA_MAX_EXACT_INTEGER: u64 = (1u64 << 53) - 1;
/// Largest inclusive exchange validity timestamp accepted by Redis/Lua paths.
pub const EXCHANGE_MAX_VALID_UNTIL: i64 = EXCHANGE_LUA_MAX_EXACT_INTEGER as i64;
/// Largest exchange budget represented exactly by Redis/Lua paths.
pub const EXCHANGE_MAX_BUDGET_LIMIT: u64 = EXCHANGE_LUA_MAX_EXACT_INTEGER;

// ============================================================================
// VOPRF Issuance Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueReq {
    /// Blinded element for VOPRF (base64url encoded)
    #[serde(alias = "blinded")]
    pub blinded_element_b64: String,

    /// Optional context (currently unused but reserved)
    #[serde(default)]
    pub ctx_b64: Option<String>,

    /// Optional Sybil resistance proof
    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueResp {
    /// Base64url-encoded VOPRF evaluation [VERSION|A|B|DLEQ_proof] (131 bytes)
    pub token: String,
    /// Key identifier used for issuance
    pub kid: String,
    /// Issuer identifier
    pub issuer_id: String,
    /// Optional Sybil resistance verification info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SybilInfo {
    pub required: bool,
    pub passed: bool,
    pub cost: u64,
}

// ============================================================================
// Batch Issuance Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchIssueReq {
    pub blinded_elements: Vec<String>,

    #[serde(default)]
    pub ctx_b64: Option<String>,

    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchIssueResp {
    pub results: Vec<TokenResult>,
    pub successful: usize,
    pub failed: usize,
    pub processing_time_ms: u64,
    pub throughput: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum TokenResult {
    Success {
        token: String,
        kid: String,
        issuer_id: String,
    },
    Error {
        message: String,
        code: String,
    },
}

// ============================================================================
// V5 Public Bearer Pass Issuance Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIssueReq {
    /// RFC 9474 blinded message for a V5 public bearer pass.
    pub blinded_msg_b64: String,

    /// Optional active token key requested by the client.
    #[serde(default)]
    pub token_key_id: Option<String>,

    /// Optional Sybil resistance proof.
    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicIssueResp {
    /// Base64url-encoded RFC 9474 blind signature.
    pub blind_signature_b64: String,
    /// Strict lowercase hex SHA-256 digest of the V5 SPKI public key.
    pub token_key_id: String,
    /// Issuer identifier embedded in the client-finalized V5 token.
    pub issuer_id: String,
    /// Optional Sybil resistance verification info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicBatchIssueReq {
    pub blinded_msgs: Vec<String>,

    #[serde(default)]
    pub token_key_id: Option<String>,

    #[serde(default)]
    pub sybil_proof: Option<SybilProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicBatchIssueResp {
    pub blind_signatures: Vec<String>,
    pub token_key_id: String,
    pub issuer_id: String,
    pub successful: usize,
    pub failed: usize,
    pub processing_time_ms: u64,
    pub throughput: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sybil_info: Option<SybilInfo>,
}

// ============================================================================
// Verification Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyReq {
    /// Base64url-encoded V4 private-verification redemption token.
    pub token_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResp {
    pub ok: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    #[serde(default)]
    pub verified_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifierMetadataResp {
    pub verifier_id: String,
    pub audience: String,
    /// Base64url-encoded SHA-256 scope digest clients must bind into V4 token input.
    pub scope_digest_b64: String,
    /// Token families accepted by this verifier (for example `v4`, `v5`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_token_versions: Option<Vec<String>>,
}

// ============================================================================
// Batch Verification Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifyReq {
    pub tokens: Vec<TokenToVerify>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenToVerify {
    pub token_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchVerifyResp {
    pub results: Vec<VerifyResult>,
    pub successful: usize,
    pub failed: usize,
    pub processing_time_ms: u64,
    pub throughput: f64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum VerifyResult {
    Success { verified_at: i64 },
    Error { message: String, code: String },
}

// ============================================================================
// Sybil Proof Types
// ============================================================================

/// A single vouch proof for Multi-Party Vouching
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VouchProof {
    pub voucher_id: String,
    pub vouchee_id: String,
    pub timestamp: i64,
    pub signature: String,
    /// Voucher's public key (SEC1 uncompressed, base64url encoded)
    /// Required for signature verification
    pub voucher_pubkey_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SybilProof {
    ProofOfWork {
        nonce: u64,
        input: String,
        timestamp: u64,
    },
    RateLimit {
        client_id: String,
        timestamp: u64,
    },
    Invitation {
        code: String,
        signature: String,
    },
    /// Registered user proof - for users already in the system (e.g., instance owner)
    /// This bypasses invitation requirement for users who exist in the users table
    RegisteredUser {
        user_id: String,
    },
    // Note: WebAuthn fields are strings/integers, so they verify
    // fine even if the backend doesn't have the webauthn crate enabled.
    WebAuthn {
        subject_hash: String,
        auth_proof: String,
        timestamp: i64,
    },
    ProgressiveTrust {
        user_id_hash: String, // Blake3(username + salt) - privacy preserving
        first_seen: i64,      // Unix timestamp of first issuance
        tokens_issued: u32,   // Lifetime token count
        last_issuance: i64,   // Unix timestamp of last issuance
        hmac_proof: String,   // HMAC(secret, all fields) - prevents forgery
    },
    ProofOfDiversity {
        user_id_hash: String, // Blake3(username + salt)
        diversity_score: u8,  // 0-100 score
        unique_networks: u32, // Count of unique networks observed
        unique_devices: u32,  // Count of unique devices observed
        first_seen: i64,      // Unix timestamp of first observation
        hmac_proof: String,   // HMAC(secret, all fields)
    },
    MultiPartyVouching {
        vouchee_id_hash: String,  // Blake3(username + salt)
        vouches: Vec<VouchProof>, // List of vouch proofs
        hmac_proof: String,       // HMAC(secret, all fields)
        timestamp: i64,           // Unix timestamp of proof generation
    },
    SocialGraph {
        /// The complete cred.presentation artifact as JSON string
        attestation: String,
        /// The presentation_signature field as hex string
        presentation: String,
    },
    /// Multiple proofs for AND/threshold combination modes
    Multi {
        proofs: Vec<SybilProof>,
    },
    None,
}

// ============================================================================
// Key Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDiscoveryResp {
    pub issuer_id: String,
    pub current_epoch: u32,
    pub valid_epochs: Vec<u32>,
    pub epoch_duration_sec: u64,
    pub voprf: VoprfKeyInfo,
    #[serde(default)]
    pub public: Vec<PublicKeyInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange: Option<ExchangeDiscoveryV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDiscoveryInfo {
    pub profile_id: String,
    pub target_keysets: Vec<ExchangeTargetKeysetInfo>,
    pub descriptors: Vec<ExchangeDescriptorInfo>,
    pub receipt_keys: Vec<ExchangeReceiptKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTargetKeysetInfo {
    pub keyset_id: String,
    /// Canonical ordered descriptor membership.
    pub descriptor_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeReceiptKeyInfo {
    pub key_id: String,
    pub algorithm: String,
    pub purpose: String,
    pub public_key_b64: String,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDescriptorInfo {
    pub descriptor_id: String,
    pub keyset_id: String,
    pub purpose: String,
    pub profile_id: String,
    pub role: String,
    pub issuer_id: String,
    pub class: String,
    pub token_key_id: String,
    pub pubkey_spki_b64: String,
    pub suite: String,
    pub valid_from: i64,
    pub valid_until: i64,
    pub max_quantity: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangePublicHistory {
    #[serde(default)]
    pub target_keysets: Vec<ExchangeTargetKeysetInfo>,
    #[serde(default)]
    pub target_descriptors: Vec<ExchangeDescriptorInfo>,
    #[serde(default)]
    pub receipt_keys: Vec<ExchangeReceiptKeyInfo>,
}

/// Public, immutable V2 exchange graph metadata. The active graph is kept
/// separate from retained graphs so consumers never have to infer lifecycle
/// state from graph contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDiscoveryV2 {
    pub active_graph: ExchangeGraphDiscoveryV2,
    #[serde(default)]
    pub retained_graphs: Vec<ExchangeGraphDiscoveryV2>,
    pub active_receipt_key: ExchangeReceiptKeyInfo,
    #[serde(default)]
    pub retained_receipt_keys: Vec<ExchangeReceiptKeyInfo>,
}

/// A role-neutral exchange graph. Descriptors and keysets can appear on either
/// side of a transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeGraphDiscoveryV2 {
    pub profile_id: String,
    pub graph_id: String,
    pub descriptors: Vec<ExchangeDescriptorDiscoveryV2>,
    pub keysets: Vec<ExchangeKeysetDiscoveryV2>,
    pub transitions: Vec<ExchangeTransitionDiscoveryV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeDescriptorDiscoveryV2 {
    pub descriptor_id: String,
    pub profile_id: String,
    pub issuer_id: String,
    pub token_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub pubkey_spki_b64: String,
    pub suite: String,
    pub valid_from: i64,
    pub valid_until: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeKeysetDiscoveryV2 {
    pub keyset_id: String,
    /// Canonical ordered descriptor membership.
    pub descriptor_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTransitionSlotDiscoveryV2 {
    pub descriptor_id: String,
    pub slot_id: String,
    pub class: String,
    pub quantity: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeAdmissionStateV2 {
    AcceptingNew,
    RecoveryOnly,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTransitionDiscoveryV2 {
    pub transition_id: String,
    pub source_keyset_id: String,
    pub target_keyset_id: String,
    pub source_slots: Vec<ExchangeTransitionSlotDiscoveryV2>,
    pub output_slots: Vec<ExchangeTransitionSlotDiscoveryV2>,
    pub budget_id: String,
    pub budget_limit: u64,
    pub admission_state: ExchangeAdmissionStateV2,
}

// Alternate `Info` names keep these discovery DTOs consistent with the
// existing V1 naming without duplicating wire models.
pub type ExchangeGraphInfoV2 = ExchangeGraphDiscoveryV2;
pub type ExchangeDescriptorInfoV2 = ExchangeDescriptorDiscoveryV2;
pub type ExchangeKeysetInfoV2 = ExchangeKeysetDiscoveryV2;
pub type ExchangeTransitionInfoV2 = ExchangeTransitionDiscoveryV2;
pub type ExchangeTransitionSlotInfoV2 = ExchangeTransitionSlotDiscoveryV2;

fn put_exchange_v2(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn put_optional_exchange_v2(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            output.push(1);
            put_exchange_v2(output, value.as_bytes());
        }
        None => {
            output.push(0);
            put_exchange_v2(output, &[]);
        }
    }
}

impl ExchangeDescriptorDiscoveryV2 {
    pub fn canonical_descriptor_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        for value in [
            &self.profile_id,
            &self.issuer_id,
            &self.token_key_id,
            &self.suite,
        ] {
            put_exchange_v2(&mut bytes, value.as_bytes());
        }
        put_optional_exchange_v2(&mut bytes, self.audience.as_deref());
        let spki = crate::exchange_api::decode_base64url(&self.pubkey_spki_b64, 4096)
            .map_err(|error| error.to_string())?;
        put_exchange_v2(&mut bytes, &spki);
        bytes.extend_from_slice(&self.valid_from.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until.to_be_bytes());
        Ok(bytes)
    }

    pub fn canonical_descriptor_id(&self) -> Result<String, String> {
        Ok(crate::exchange_api::descriptor_id_v2(
            &self.canonical_descriptor_bytes()?,
        ))
    }
}

impl ExchangeKeysetDiscoveryV2 {
    pub fn canonical_keyset_id(&self) -> String {
        crate::exchange_api::keyset_id_v2(&self.descriptor_ids)
    }
}

impl ExchangeTransitionDiscoveryV2 {
    pub fn stable_contract_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_exchange_v2(&mut bytes, self.source_keyset_id.as_bytes());
        put_exchange_v2(&mut bytes, self.target_keyset_id.as_bytes());
        put_exchange_transition_slots_v2(&mut bytes, &self.source_slots);
        put_exchange_transition_slots_v2(&mut bytes, &self.output_slots);
        put_exchange_v2(&mut bytes, self.budget_id.as_bytes());
        bytes.extend_from_slice(&self.budget_limit.to_be_bytes());
        bytes
    }

    pub fn canonical_transition_id(&self) -> String {
        crate::exchange_api::transition_id_v2(&self.stable_contract_bytes())
    }

    /// The immutable transition and policy contract pinned by `budget_id`.
    /// Admission state is deliberately excluded so lifecycle-only revisions
    /// can reuse the same lifetime budget.
    pub fn budget_contract_bytes(&self) -> Vec<u8> {
        self.stable_contract_bytes()
    }
}

fn put_exchange_transition_slots_v2(
    output: &mut Vec<u8>,
    slots: &[ExchangeTransitionSlotDiscoveryV2],
) {
    output.extend_from_slice(&(slots.len() as u32).to_be_bytes());
    for slot in slots {
        put_exchange_v2(output, slot.descriptor_id.as_bytes());
        put_exchange_v2(output, slot.slot_id.as_bytes());
        put_exchange_v2(output, slot.class.as_bytes());
        output.extend_from_slice(&slot.quantity.to_be_bytes());
    }
}

impl ExchangeGraphDiscoveryV2 {
    pub fn canonical_graph_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_exchange_v2(&mut bytes, self.profile_id.as_bytes());
        for keyset in &self.keysets {
            put_exchange_v2(&mut bytes, keyset.keyset_id.as_bytes());
        }
        for transition in &self.transitions {
            put_exchange_v2(&mut bytes, transition.transition_id.as_bytes());
        }
        bytes
    }

    pub fn canonical_graph_id(&self) -> String {
        crate::exchange_api::graph_id_v2(&self.canonical_graph_bytes())
    }
}

impl ExchangeReceiptKeyInfo {
    pub fn canonical_key_id(&self) -> Result<String, String> {
        use sha2::{Digest, Sha256};

        let public = crate::exchange_api::decode_base64url(&self.public_key_b64, 32)
            .map_err(|error| error.to_string())?;
        if public.len() != 32 {
            return Err("Ed25519 receipt verification key must be 32 bytes".into());
        }
        Ok(hex::encode(Sha256::digest(public)))
    }
}

/// Validate one complete V2 discovery trust container. No graph or receipt key
/// is trustworthy unless this all-or-nothing validation succeeds.
pub fn validate_exchange_discovery_v2(
    issuer_id: &str,
    discovery: &ExchangeDiscoveryV2,
) -> Result<(), String> {
    use std::collections::{HashMap, HashSet};

    if discovery.retained_graphs.len() >= crate::exchange_api::MAX_ITEMS
        || discovery.retained_receipt_keys.len() >= crate::exchange_api::MAX_ITEMS
    {
        return Err("too many retained V2 exchange trust objects".into());
    }

    let mut graph_ids = HashSet::new();
    let mut descriptor_contracts = HashMap::new();
    let mut budget_contracts = HashMap::<String, Vec<u8>>::new();
    for (graph, retained) in std::iter::once((&discovery.active_graph, false))
        .chain(discovery.retained_graphs.iter().map(|graph| (graph, true)))
    {
        if !graph_ids.insert(graph.graph_id.as_str()) {
            return Err("duplicate active or retained V2 exchange graph".into());
        }
        validate_exchange_graph_v2(
            issuer_id,
            graph,
            retained,
            &mut descriptor_contracts,
            &mut budget_contracts,
        )?;
    }

    let mut receipt_ids = HashSet::new();
    validate_exchange_receipt_key_v2(
        &discovery.active_receipt_key,
        "exchange_receipt_active",
        &mut receipt_ids,
    )?;
    for key in &discovery.retained_receipt_keys {
        validate_exchange_receipt_key_v2(key, "exchange_receipt_retained", &mut receipt_ids)?;
    }
    Ok(())
}

fn validate_exchange_receipt_key_v2<'a>(
    key: &'a ExchangeReceiptKeyInfo,
    purpose: &str,
    ids: &mut std::collections::HashSet<&'a str>,
) -> Result<(), String> {
    crate::exchange_api::validate_receipt_key_id(&key.key_id).map_err(|error| error.to_string())?;
    if key.algorithm != "Ed25519"
        || key.purpose != purpose
        || key.valid_from == 0
        || key.valid_from >= key.valid_until
        || key.valid_until > EXCHANGE_MAX_VALID_UNTIL as u64
        || key.canonical_key_id()? != key.key_id
        || !ids.insert(key.key_id.as_str())
    {
        return Err("invalid V2 exchange receipt verification key".into());
    }
    Ok(())
}

fn validate_exchange_graph_v2<'a>(
    issuer_id: &str,
    graph: &'a ExchangeGraphDiscoveryV2,
    retained: bool,
    descriptor_contracts: &mut std::collections::HashMap<
        &'a str,
        &'a ExchangeDescriptorDiscoveryV2,
    >,
    budget_contracts: &mut std::collections::HashMap<String, Vec<u8>>,
) -> Result<(), String> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};

    let max_items = crate::exchange_api::MAX_ITEMS;
    if graph.profile_id != crate::exchange_api::EXCHANGE_PROFILE_V2
        || graph.descriptors.is_empty()
        || graph.descriptors.len() > max_items
        || graph.keysets.is_empty()
        || graph.keysets.len() > max_items
        || graph.transitions.is_empty()
        || graph.transitions.len() > max_items
    {
        return Err("invalid V2 exchange graph bounds".into());
    }
    crate::exchange_api::validate_graph_id(&graph.graph_id).map_err(|error| error.to_string())?;
    if graph.graph_id != graph.canonical_graph_id() {
        return Err("non-canonical V2 exchange graph id".into());
    }

    let mut descriptors = HashMap::new();
    let mut graph_key_ids = HashSet::new();
    for descriptor in &graph.descriptors {
        crate::exchange_api::validate_descriptor_id(&descriptor.descriptor_id)
            .map_err(|error| error.to_string())?;
        let spki = crate::exchange_api::decode_base64url(&descriptor.pubkey_spki_b64, 4096)
            .map_err(|error| error.to_string())?;
        if descriptor.profile_id != crate::exchange_api::EXCHANGE_PROFILE_V2
            || descriptor.issuer_id != issuer_id
            || descriptor.suite != "RSABSSA-SHA384-PSS-Deterministic"
            || descriptor.valid_from <= 0
            || descriptor.valid_from >= descriptor.valid_until
            || descriptor.valid_until > EXCHANGE_MAX_VALID_UNTIL
            || descriptor.audience.as_ref().is_some_and(|audience| {
                audience.is_empty()
                    || audience.len() > crate::exchange_api::MAX_ID
                    || !audience.is_ascii()
            })
            || descriptor.canonical_descriptor_id()? != descriptor.descriptor_id
            || Base64UrlUnpadded::encode_string(&spki) != descriptor.pubkey_spki_b64
            || hex::encode(Sha256::digest(&spki)) != descriptor.token_key_id
            || freebird_crypto::validate_public_bearer_spki(&spki).is_err()
            || !graph_key_ids.insert(descriptor.token_key_id.as_str())
            || descriptors
                .insert(descriptor.descriptor_id.as_str(), descriptor)
                .is_some()
        {
            return Err("invalid immutable V2 exchange descriptor".into());
        }
        if let Some(existing) =
            descriptor_contracts.insert(descriptor.token_key_id.as_str(), descriptor)
        {
            if existing != descriptor {
                return Err("conflicting reused V2 exchange key metadata".into());
            }
        }
    }

    let mut keysets = HashMap::new();
    let mut memberships = HashSet::new();
    for keyset in &graph.keysets {
        crate::exchange_api::validate_keyset_id(&keyset.keyset_id)
            .map_err(|error| error.to_string())?;
        if keyset.descriptor_ids.is_empty()
            || keyset.descriptor_ids.len() > max_items
            || keyset.keyset_id != keyset.canonical_keyset_id()
        {
            return Err("invalid canonical V2 exchange keyset".into());
        }
        let mut members = HashSet::new();
        for descriptor_id in &keyset.descriptor_ids {
            if !descriptors.contains_key(descriptor_id.as_str())
                || !members.insert(descriptor_id.as_str())
                || !memberships.insert(descriptor_id.as_str())
            {
                return Err("invalid V2 exchange keyset membership".into());
            }
        }
        if keysets.insert(keyset.keyset_id.as_str(), members).is_some() {
            return Err("duplicate V2 exchange keyset id".into());
        }
    }
    if memberships.len() != descriptors.len() {
        return Err("unpublished V2 exchange keyset membership".into());
    }

    let mut transition_ids = HashSet::new();
    let mut graph_budget_ids = HashSet::new();
    for transition in &graph.transitions {
        crate::exchange_api::validate_transition_id(&transition.transition_id)
            .map_err(|error| error.to_string())?;
        validate_exchange_ascii_v2("transition budget", &transition.budget_id)?;
        let source_members = keysets
            .get(transition.source_keyset_id.as_str())
            .ok_or_else(|| "unknown V2 source keyset selector".to_string())?;
        let target_members = keysets
            .get(transition.target_keyset_id.as_str())
            .ok_or_else(|| "unknown V2 target keyset selector".to_string())?;
        if transition.source_keyset_id == transition.target_keyset_id
            || transition.transition_id != transition.canonical_transition_id()
            || !transition_ids.insert(transition.transition_id.as_str())
            || transition.budget_limit == 0
            || transition.budget_limit > EXCHANGE_MAX_BUDGET_LIMIT
            || !graph_budget_ids.insert(transition.budget_id.as_str())
            || retained && transition.admission_state == ExchangeAdmissionStateV2::AcceptingNew
        {
            return Err("invalid stable V2 exchange transition metadata".into());
        }
        let budget_contract = transition.budget_contract_bytes();
        if let Some(existing) = budget_contracts.get(&transition.budget_id) {
            if existing != &budget_contract {
                return Err("conflicting reused V2 exchange budget contract".into());
            }
        } else {
            budget_contracts.insert(transition.budget_id.clone(), budget_contract);
        }
        validate_exchange_slots_v2(&transition.source_slots, source_members)?;
        validate_exchange_slots_v2(&transition.output_slots, target_members)?;
        let output_quantity = transition.output_slots.iter().try_fold(0u64, |sum, slot| {
            sum.checked_add(u64::from(slot.quantity))
                .ok_or_else(|| "V2 output quantity overflow".to_string())
        })?;
        if output_quantity > transition.budget_limit {
            return Err("V2 output quantity exceeds static budget".into());
        }
    }
    Ok(())
}

fn validate_exchange_slots_v2(
    slots: &[ExchangeTransitionSlotDiscoveryV2],
    keyset_members: &std::collections::HashSet<&str>,
) -> Result<(), String> {
    use std::collections::HashSet;

    if slots.is_empty() || slots.len() > crate::exchange_api::MAX_ITEMS {
        return Err("invalid V2 transition slot bounds".into());
    }
    let mut slot_ids = HashSet::new();
    let mut descriptor_ids = HashSet::new();
    for slot in slots {
        crate::exchange_api::validate_descriptor_id(&slot.descriptor_id)
            .map_err(|error| error.to_string())?;
        validate_exchange_ascii_v2("transition slot id", &slot.slot_id)?;
        validate_exchange_ascii_v2("transition slot class", &slot.class)?;
        if slot.quantity == 0
            || slot.quantity > 64
            || !keyset_members.contains(slot.descriptor_id.as_str())
            || !slot_ids.insert(slot.slot_id.as_str())
            || !descriptor_ids.insert(slot.descriptor_id.as_str())
        {
            return Err("invalid V2 transition slot membership".into());
        }
    }
    Ok(())
}

fn validate_exchange_ascii_v2(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > crate::exchange_api::MAX_ID || !value.is_ascii() {
        return Err(format!("invalid {name}"));
    }
    Ok(())
}

impl ExchangeDescriptorInfo {
    pub fn canonical_descriptor_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        for value in [
            &self.profile_id,
            &self.role,
            &self.class,
            &self.issuer_id,
            &self.token_key_id,
            &self.suite,
        ] {
            bytes.extend_from_slice(
                &u32::try_from(value.len())
                    .map_err(|_| "descriptor field too large")?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(value.as_bytes());
        }
        if let Some(audience) = &self.audience {
            bytes.push(1);
            bytes.extend_from_slice(
                &u32::try_from(audience.len())
                    .map_err(|_| "audience too large")?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(audience.as_bytes());
        } else {
            bytes.push(0);
            bytes.extend_from_slice(&0u32.to_be_bytes());
        }
        let spki = crate::exchange_api::decode_base64url(&self.pubkey_spki_b64, 4096)
            .map_err(|error| error.to_string())?;
        bytes.extend_from_slice(&spki);
        bytes.extend_from_slice(&self.max_quantity.to_be_bytes());
        bytes.extend_from_slice(&self.valid_from.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until.to_be_bytes());
        Ok(bytes)
    }

    pub fn canonical_descriptor_id(&self) -> Result<String, String> {
        Ok(crate::exchange_api::descriptor_id(
            &self.canonical_descriptor_bytes()?,
        ))
    }
}

impl ExchangeTargetKeysetInfo {
    pub fn canonical_keyset_id(&self) -> String {
        crate::exchange_api::keyset_id(&self.descriptor_ids)
    }
}

/// Validate the complete immutable target descriptor/keyset graph shared by
/// issuer history publication and verifier trust ingestion.
pub fn validate_exchange_target_metadata(
    profile_id: &str,
    issuer_id: &str,
    keysets: &[ExchangeTargetKeysetInfo],
    descriptors: &[ExchangeDescriptorInfo],
) -> Result<(), String> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};

    if profile_id != crate::exchange_api::EXCHANGE_PROFILE_V1 || keysets.is_empty() {
        return Err("invalid exchange profile or keyset bounds".into());
    }
    let mut descriptor_map = HashMap::new();
    let mut spkis = HashSet::new();
    for descriptor in descriptors
        .iter()
        .filter(|descriptor| descriptor.purpose == "exchange_target")
    {
        crate::exchange_api::validate_descriptor_id(&descriptor.descriptor_id)
            .map_err(|error| error.to_string())?;
        crate::exchange_api::validate_keyset_id(&descriptor.keyset_id)
            .map_err(|error| error.to_string())?;
        if descriptor.profile_id != profile_id
            || descriptor.role != "target"
            || descriptor.issuer_id != issuer_id
            || descriptor.suite != "RSABSSA-SHA384-PSS-Deterministic"
            || descriptor.class.is_empty()
            || descriptor.class.len() > 128
            || !descriptor.class.is_ascii()
            || descriptor.max_quantity == 0
            || descriptor.max_quantity > 64
            || descriptor.valid_from >= descriptor.valid_until
            || descriptor.audience.as_ref().is_some_and(|audience| {
                audience.is_empty() || audience.len() > 128 || !audience.is_ascii()
            })
            || descriptor.canonical_descriptor_id()? != descriptor.descriptor_id
        {
            return Err("invalid immutable exchange target descriptor".into());
        }
        let spki = crate::exchange_api::decode_base64url(&descriptor.pubkey_spki_b64, 4096)
            .map_err(|error| error.to_string())?;
        if Base64UrlUnpadded::encode_string(&spki) != descriptor.pubkey_spki_b64
            || hex::encode(Sha256::digest(&spki)) != descriptor.token_key_id
            || freebird_crypto::validate_public_bearer_spki(&spki).is_err()
            || !spkis.insert(spki)
            || descriptor_map
                .insert(descriptor.descriptor_id.clone(), descriptor)
                .is_some()
        {
            return Err("exchange target identity collision".into());
        }
    }
    if descriptor_map.is_empty() {
        return Err("exchange target descriptors are empty".into());
    }
    let mut keyset_ids = HashSet::new();
    let mut memberships = HashSet::new();
    for keyset in keysets {
        crate::exchange_api::validate_keyset_id(&keyset.keyset_id)
            .map_err(|error| error.to_string())?;
        if keyset.descriptor_ids.is_empty()
            || keyset.canonical_keyset_id() != keyset.keyset_id
            || !keyset_ids.insert(&keyset.keyset_id)
        {
            return Err("invalid canonical exchange target keyset".into());
        }
        for descriptor_id in &keyset.descriptor_ids {
            let descriptor = descriptor_map
                .get(descriptor_id)
                .ok_or_else(|| "keyset references unknown descriptor".to_string())?;
            if descriptor.keyset_id != keyset.keyset_id
                || !memberships.insert(descriptor_id.clone())
            {
                return Err("descriptor keyset membership mismatch".into());
            }
        }
    }
    if memberships.len() != descriptor_map.len() {
        return Err("unpublished target keyset membership".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoprfKeyInfo {
    pub suite: String,
    pub kid: String,
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub token_key_id: String,
    pub token_type: String,
    pub rfc9474_variant: String,
    pub modulus_bits: u16,
    pub pubkey_spki_b64: String,
    pub issuer_id: String,
    pub valid_from: i64,
    pub valid_until: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub spend_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
}

#[cfg(test)]
mod exchange_metadata_tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};
    use sha2::{Digest, Sha256};

    fn graph_v2() -> ExchangeGraphDiscoveryV2 {
        let mut descriptors = Vec::new();
        for _ in 0..2 {
            let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
            let spki = provider.public_key_spki();
            let mut descriptor = ExchangeDescriptorDiscoveryV2 {
                descriptor_id: String::new(),
                profile_id: crate::exchange_api::EXCHANGE_PROFILE_V2.into(),
                issuer_id: "issuer:test".into(),
                token_key_id: hex::encode(Sha256::digest(spki)),
                audience: Some("audience".into()),
                pubkey_spki_b64: Base64UrlUnpadded::encode_string(spki),
                suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
                valid_from: 1,
                valid_until: 2,
            };
            descriptor.descriptor_id = descriptor.canonical_descriptor_id().unwrap();
            descriptors.push(descriptor);
        }
        let mut keysets: Vec<_> = descriptors
            .iter()
            .map(|descriptor| {
                let mut keyset = ExchangeKeysetDiscoveryV2 {
                    keyset_id: String::new(),
                    descriptor_ids: vec![descriptor.descriptor_id.clone()],
                };
                keyset.keyset_id = keyset.canonical_keyset_id();
                keyset
            })
            .collect();
        let transition = |source: usize, target: usize, budget: &str| {
            let mut transition = ExchangeTransitionDiscoveryV2 {
                transition_id: String::new(),
                source_keyset_id: keysets[source].keyset_id.clone(),
                target_keyset_id: keysets[target].keyset_id.clone(),
                source_slots: vec![ExchangeTransitionSlotDiscoveryV2 {
                    descriptor_id: descriptors[source].descriptor_id.clone(),
                    slot_id: "input".into(),
                    class: "bearer".into(),
                    quantity: 1,
                }],
                output_slots: vec![ExchangeTransitionSlotDiscoveryV2 {
                    descriptor_id: descriptors[target].descriptor_id.clone(),
                    slot_id: "output".into(),
                    class: "bearer".into(),
                    quantity: 1,
                }],
                budget_id: budget.into(),
                budget_limit: 100,
                admission_state: ExchangeAdmissionStateV2::AcceptingNew,
            };
            transition.transition_id = transition.canonical_transition_id();
            transition
        };
        let transitions = vec![transition(0, 1, "a-to-b"), transition(1, 0, "b-to-a")];
        let mut graph = ExchangeGraphDiscoveryV2 {
            profile_id: crate::exchange_api::EXCHANGE_PROFILE_V2.into(),
            graph_id: String::new(),
            descriptors,
            keysets: std::mem::take(&mut keysets),
            transitions,
        };
        graph.graph_id = graph.canonical_graph_id();
        graph
    }

    fn receipt_key(purpose: &str) -> ExchangeReceiptKeyInfo {
        let public = [if purpose == "exchange_receipt_active" {
            7u8
        } else {
            8u8
        }; 32];
        ExchangeReceiptKeyInfo {
            key_id: hex::encode(Sha256::digest(public)),
            algorithm: "Ed25519".into(),
            purpose: purpose.into(),
            public_key_b64: Base64UrlUnpadded::encode_string(&public),
            valid_from: 1,
            valid_until: EXCHANGE_MAX_VALID_UNTIL as u64,
        }
    }

    fn assert_no_sensitive_keys(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    assert!(![
                        "artifact",
                        "artifacts",
                        "source_value",
                        "source_values",
                        "status_capability",
                        "private_key_path",
                        "pending_references",
                        "spent_count",
                        "issued_count",
                    ]
                    .contains(&key.as_str()));
                    assert_no_sensitive_keys(value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    assert_no_sensitive_keys(value);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn receipt_metadata_round_trips_and_legacy_discovery_remains_compatible() {
        let key = ExchangeReceiptKeyInfo {
            key_id: "a".repeat(64),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_active".into(),
            public_key_b64: "AQ".into(),
            valid_from: 0,
            valid_until: u64::MAX,
        };
        assert_eq!(
            serde_json::from_value::<ExchangeReceiptKeyInfo>(serde_json::to_value(&key).unwrap())
                .unwrap(),
            key
        );
        let legacy = serde_json::json!({
            "issuer_id":"issuer:test",
            "current_epoch":1,
            "valid_epochs":[1],
            "epoch_duration_sec":86400,
            "voprf":{"suite":"suite","kid":"kid","pubkey":"key"},
            "public":[]
        });
        assert!(serde_json::from_value::<KeyDiscoveryResp>(legacy)
            .unwrap()
            .exchange
            .is_none());
    }

    #[test]
    fn v2_graph_model_is_role_neutral_stable_and_public_only() {
        let graph = graph_v2();
        assert_eq!(graph.graph_id, graph.canonical_graph_id());
        assert_eq!(graph.transitions.len(), 2);
        assert_ne!(
            graph.transitions[0].transition_id,
            graph.transitions[1].transition_id
        );

        let discovery = ExchangeDiscoveryV2 {
            active_graph: graph.clone(),
            retained_graphs: vec![ExchangeGraphDiscoveryV2 {
                transitions: graph
                    .transitions
                    .iter()
                    .cloned()
                    .map(|mut transition| {
                        transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
                        transition
                    })
                    .collect(),
                ..graph
            }],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![receipt_key("exchange_receipt_retained")],
        };
        assert_eq!(
            discovery.retained_graphs[0].graph_id,
            discovery.retained_graphs[0].canonical_graph_id()
        );
        assert_no_sensitive_keys(&serde_json::to_value(discovery).unwrap());
    }

    #[test]
    fn v2_discovery_validates_graphs_receipts_and_shared_budget_contracts_atomically() {
        let active = graph_v2();
        let mut retained = active.clone();
        retained.transitions[0].source_slots[0].class = "retained-bearer".into();
        retained.transitions[0].budget_id = "retained-a-to-b".into();
        retained.transitions[0].transition_id = retained.transitions[0].canonical_transition_id();
        for transition in &mut retained.transitions {
            transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
        }
        retained.graph_id = retained.canonical_graph_id();
        let valid = ExchangeDiscoveryV2 {
            active_graph: active,
            retained_graphs: vec![retained],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![receipt_key("exchange_receipt_retained")],
        };
        assert!(validate_exchange_discovery_v2("issuer:test", &valid).is_ok());

        let mut bad_budget = valid.clone();
        bad_budget.retained_graphs[0].transitions[1].budget_limit += 1;
        bad_budget.retained_graphs[0].transitions[1].transition_id =
            bad_budget.retained_graphs[0].transitions[1].canonical_transition_id();
        bad_budget.retained_graphs[0].graph_id = bad_budget.retained_graphs[0].canonical_graph_id();
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_budget).is_err());

        let mut bad_receipt = valid.clone();
        bad_receipt.active_receipt_key.algorithm = "operator-selected".into();
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_receipt).is_err());

        let mut bad_receipt = valid.clone();
        bad_receipt.active_receipt_key.purpose = "exchange_receipt_retained".into();
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_receipt).is_err());

        let mut bad_receipt = valid.clone();
        bad_receipt.active_receipt_key.public_key_b64.push('=');
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_receipt).is_err());

        let mut bad_receipt = valid.clone();
        bad_receipt.active_receipt_key.valid_until = i64::MAX as u64;
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_receipt).is_err());

        let mut bad_retained = valid;
        bad_retained.retained_graphs[0].transitions[0].admission_state =
            ExchangeAdmissionStateV2::AcceptingNew;
        assert!(validate_exchange_discovery_v2("issuer:test", &bad_retained).is_err());
    }

    #[test]
    fn v2_budget_ids_are_unique_per_graph_and_pin_the_full_contract_across_revisions() {
        let active = graph_v2();
        let mut duplicate = active.clone();
        duplicate.transitions[1].budget_id = duplicate.transitions[0].budget_id.clone();
        duplicate.transitions[1].transition_id = duplicate.transitions[1].canonical_transition_id();
        duplicate.graph_id = duplicate.canonical_graph_id();
        let discovery = ExchangeDiscoveryV2 {
            active_graph: duplicate,
            retained_graphs: vec![],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![],
        };
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());

        let mut retained = active.clone();
        for transition in &mut retained.transitions {
            transition.admission_state = ExchangeAdmissionStateV2::RecoveryOnly;
        }
        retained.transitions[0].budget_id = "revision-only-budget".into();
        retained.transitions[0].transition_id = retained.transitions[0].canonical_transition_id();
        retained.graph_id = retained.canonical_graph_id();
        let mut discovery = ExchangeDiscoveryV2 {
            active_graph: active,
            retained_graphs: vec![retained],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![receipt_key("exchange_receipt_retained")],
        };
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_ok());
        discovery.retained_graphs[0].transitions[1].source_slots[0].class = "changed".into();
        discovery.retained_graphs[0].transitions[1].transition_id =
            discovery.retained_graphs[0].transitions[1].canonical_transition_id();
        discovery.retained_graphs[0].graph_id = discovery.retained_graphs[0].canonical_graph_id();
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());
    }

    #[test]
    fn v2_uses_the_lua_exact_positive_integer_bound_for_all_numeric_trust() {
        let mut discovery = ExchangeDiscoveryV2 {
            active_graph: graph_v2(),
            retained_graphs: vec![],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![],
        };
        discovery.active_graph.transitions[0].budget_limit = EXCHANGE_MAX_BUDGET_LIMIT;
        discovery.active_graph.transitions[0].transition_id =
            discovery.active_graph.transitions[0].canonical_transition_id();
        discovery.active_graph.graph_id = discovery.active_graph.canonical_graph_id();
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_ok());

        discovery.active_graph.transitions[0].budget_limit = EXCHANGE_MAX_BUDGET_LIMIT + 1;
        discovery.active_graph.transitions[0].transition_id =
            discovery.active_graph.transitions[0].canonical_transition_id();
        discovery.active_graph.graph_id = discovery.active_graph.canonical_graph_id();
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());

        let mut discovery = ExchangeDiscoveryV2 {
            active_graph: graph_v2(),
            retained_graphs: vec![],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![],
        };
        discovery.active_graph.descriptors[0].valid_from = 0;
        discovery.active_graph.descriptors[0].descriptor_id = discovery.active_graph.descriptors[0]
            .canonical_descriptor_id()
            .unwrap();
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());

        let mut discovery = ExchangeDiscoveryV2 {
            active_graph: graph_v2(),
            retained_graphs: vec![],
            active_receipt_key: receipt_key("exchange_receipt_active"),
            retained_receipt_keys: vec![],
        };
        discovery.active_receipt_key.valid_from = 0;
        assert!(validate_exchange_discovery_v2("issuer:test", &discovery).is_err());
    }
}
