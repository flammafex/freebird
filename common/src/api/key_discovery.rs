// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::graph_discovery::{ExchangeDiscoveryV2, GraphIssuanceDiscoveryV2};
use serde::{Deserialize, Serialize};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_issuance: Option<GraphIssuanceDiscoveryV2>,
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
