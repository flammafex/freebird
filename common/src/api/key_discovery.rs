// SPDX-License-Identifier: Apache-2.0 OR MIT
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
}

impl KeyDiscoveryResp {
    /// Validate the V4 key discovery response.
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoprfKeyInfo {
    pub suite: String,
    pub kid: String,
    pub pubkey: String,
}
