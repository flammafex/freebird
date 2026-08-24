// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::native_bearer_v7::{validate_native_bearer_v7_discovery, NativeBearerV7KeyInfo};
use super::{
    NativeExchangeV3Discovery, NativeGraphIssuanceV7Discovery, NATIVE_BEARER_V7_PROFILE_ID,
};
use crate::v7_registry::{BearerKeyRegistry, BearerKeyRegistryError};
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
    /// Preserve the legacy V4 discovery validation hook. V7 publication is
    /// validated exclusively through [`V7KeyDiscoveryResp`].
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

/// Strict V7-only issuer discovery metadata.
///
/// This is deliberately nominally separate from [`KeyDiscoveryResp`] and must
/// not acquire legacy V4-only fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V7KeyDiscoveryResp {
    pub issuer_id: String,
    pub current_epoch: u32,
    pub valid_epochs: Vec<u32>,
    pub epoch_duration_sec: u64,
    pub voprf: V7VoprfKeyInfo,
    pub native_bearer_v7: NativeBearerV7KeyInfo,
    pub native_bearer_v7_retained: Vec<NativeBearerV7KeyInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_exchange_v7: Option<NativeExchangeV3Discovery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_graph_issuance_v7: Option<NativeGraphIssuanceV7Discovery>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V7VoprfKeyInfo {
    pub suite: String,
    pub kid: String,
    pub pubkey: String,
}

impl V7KeyDiscoveryResp {
    /// Validate the complete response and return one issuer-local V7 registry.
    ///
    /// The registry is built locally and returned only after every direct,
    /// exchange, and graph binding has passed. No partially trusted projection
    /// escapes this method.
    pub fn validated_registry(&self) -> Result<BearerKeyRegistry, String> {
        validate_v7_envelope(self)?;
        let mut registry = BearerKeyRegistry::new();

        registry
            .register_v7_discovery(
                &self.native_bearer_v7,
                &self
                    .native_bearer_v7
                    .decode_binding()
                    .map_err(|error| error.to_string())?,
            )
            .map_err(registry_error)?;
        for record in &self.native_bearer_v7_retained {
            let binding = record.decode_binding().map_err(|error| error.to_string())?;
            registry
                .register_v7_discovery(record, &binding)
                .map_err(registry_error)?;
        }

        if let Some(exchange) = &self.native_exchange_v7 {
            for descriptor in exchange
                .active_descriptors
                .iter()
                .chain(exchange.retained_descriptors.iter())
            {
                registry
                    .register_exchange_descriptor(descriptor)
                    .map_err(registry_error)?;
            }
        }
        if let Some(graph) = &self.native_graph_issuance_v7 {
            for policy in graph
                .active_policies
                .iter()
                .chain(graph.retained_policies.iter())
            {
                registry
                    .register_graph_policy(policy)
                    .map_err(registry_error)?;
            }
        }
        Ok(registry)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validated_registry().map(|_| ())
    }
}

fn validate_v7_envelope(response: &V7KeyDiscoveryResp) -> Result<(), String> {
    if response.issuer_id.is_empty()
        || response.issuer_id.len() > 128
        || response.epoch_duration_sec == 0
        || response.valid_epochs.is_empty()
        || response
            .valid_epochs
            .windows(2)
            .any(|epochs| epochs[0] >= epochs[1])
    {
        return Err("invalid V7 issuer discovery envelope".into());
    }
    if !v7_text(&response.voprf.suite)
        || !v7_text(&response.voprf.kid)
        || !v7_text(&response.voprf.pubkey)
    {
        return Err("invalid V7 VOPRF metadata".into());
    }
    if response.native_bearer_v7.profile_id != NATIVE_BEARER_V7_PROFILE_ID {
        return Err("V7 discovery active direct key has the wrong profile".into());
    }
    validate_native_bearer_v7_discovery(
        &response.issuer_id,
        &response.native_bearer_v7,
        &response.native_bearer_v7_retained,
    )?;
    for record in &response.native_bearer_v7_retained {
        if record.profile_id != NATIVE_BEARER_V7_PROFILE_ID {
            return Err("V7 discovery retained direct key has the wrong profile".into());
        }
    }
    if let Some(exchange) = &response.native_exchange_v7 {
        exchange.validate().map_err(|error| error.to_string())?;
        for descriptor in exchange
            .active_descriptors
            .iter()
            .chain(exchange.retained_descriptors.iter())
        {
            if descriptor.issuer_id != response.issuer_id {
                return Err("V7 exchange descriptor issuer mismatch".into());
            }
        }
    }
    if let Some(graph) = &response.native_graph_issuance_v7 {
        graph.validate().map_err(|error| error.to_string())?;
        for policy in graph
            .active_policies
            .iter()
            .chain(graph.retained_policies.iter())
        {
            if policy.issuer_id != response.issuer_id {
                return Err("V7 graph policy issuer mismatch".into());
            }
        }
    }
    Ok(())
}

fn v7_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && value.is_ascii()
}

fn registry_error(error: BearerKeyRegistryError) -> String {
    error.to_string()
}
