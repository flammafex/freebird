// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::native_bearer_v7::{validate_native_bearer_v7_discovery, NativeBearerV7KeyInfo};
use super::native_exchange_v4::{NativeExchangeV4Descriptor, NativeExchangeV4Discovery};
use super::native_graph_issuance_v8::{
    NativeGraphIssuanceV8Discovery, NativeGraphIssuanceV8Policy,
};
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

/// Strict V2 discovery metadata for the V7 issuer surface.
///
/// This is intentionally a new nominal contract rather than a versioned view
/// of [`V7KeyDiscoveryResp`].  In particular, deserializing this type never
/// falls back to the legacy discovery envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V7KeyDiscoveryRespV2 {
    pub discovery_version: u8,
    pub issuer_id: String,
    pub current_epoch: u32,
    pub valid_epochs: Vec<u32>,
    pub epoch_duration_sec: u64,
    pub voprf: V7VoprfKeyInfo,
    pub native_bearer_v7: NativeBearerV7KeyInfo,
    pub native_bearer_v7_retained: Vec<NativeBearerV7KeyInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_exchange_v4: Option<NativeExchangeV4Discovery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_graph_issuance_v8: Option<NativeGraphIssuanceV8Discovery>,
}

impl V7KeyDiscoveryRespV2 {
    /// Validate the complete response and return its trusted direct-key
    /// registry.  Exchange and graph metadata are validated before the
    /// registry is exposed, but are not projected into the legacy V7-only
    /// registry.
    pub fn validated_registry(&self) -> Result<BearerKeyRegistry, String> {
        validate_v7_v2_envelope(self)?;

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

        Ok(registry)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validated_registry().map(|_| ())
    }
}

fn validate_v7_v2_envelope(response: &V7KeyDiscoveryRespV2) -> Result<(), String> {
    if response.discovery_version != 2
        || response.issuer_id.is_empty()
        || response.issuer_id.len() > 128
        || response.epoch_duration_sec == 0
        || response.valid_epochs.is_empty()
        || response
            .valid_epochs
            .windows(2)
            .any(|epochs| epochs[0] >= epochs[1])
    {
        return Err("invalid V7 discovery V2 issuer envelope".into());
    }
    if !v7_text(&response.voprf.suite)
        || !v7_text(&response.voprf.kid)
        || !v7_text(&response.voprf.pubkey)
    {
        return Err("invalid V7 discovery V2 VOPRF metadata".into());
    }
    if response.native_bearer_v7.profile_id != NATIVE_BEARER_V7_PROFILE_ID {
        return Err("V7 discovery V2 active direct key has the wrong profile".into());
    }
    validate_native_bearer_v7_discovery(
        &response.issuer_id,
        &response.native_bearer_v7,
        &response.native_bearer_v7_retained,
    )?;
    for record in &response.native_bearer_v7_retained {
        if record.profile_id != NATIVE_BEARER_V7_PROFILE_ID {
            return Err("V7 discovery V2 retained direct key has the wrong profile".into());
        }
    }

    if let Some(exchange) = &response.native_exchange_v4 {
        // This call is also the authoritative validation path for active and
        // retained receipt-key metadata carried by the exchange discovery.
        exchange.validate().map_err(|error| error.to_string())?;
        if let Some(graph) = &response.native_graph_issuance_v8 {
            graph.validate().map_err(|error| error.to_string())?;
            validate_v7_v2_issuer_bindings(
                &response.issuer_id,
                exchange,
                graph,
                &response.native_bearer_v7,
                &response.native_bearer_v7_retained,
            )?;
        }
    } else if response.native_graph_issuance_v8.is_some() {
        return Err("V8 graph discovery requires V4 exchange discovery".into());
    }
    Ok(())
}

/// Validate the issuer and descriptor identity shared by the V4 exchange and
/// V8 graph contracts.  The contracts deliberately remain sibling modules;
/// this keeps the legacy V7 registry decoupled from V4/V8 key projections.
fn validate_v7_v2_issuer_bindings(
    issuer_id: &str,
    exchange: &NativeExchangeV4Discovery,
    graph: &NativeGraphIssuanceV8Discovery,
    direct: &NativeBearerV7KeyInfo,
    retained_direct: &[NativeBearerV7KeyInfo],
) -> Result<(), String> {
    let descriptors = exchange
        .active_descriptors
        .iter()
        .chain(&exchange.retained_descriptors)
        .collect::<Vec<_>>();
    for descriptor in &descriptors {
        if descriptor.issuer_id != issuer_id {
            return Err("V4 exchange descriptor issuer mismatch".into());
        }
    }

    for policy in &graph.policies {
        if policy.issuer_id != issuer_id {
            return Err("V8 graph policy issuer mismatch".into());
        }
        let descriptor = descriptors
            .iter()
            .find(|candidate| candidate.descriptor_id == policy.descriptor_id)
            .ok_or_else(|| "V8 graph output binding has no V4 descriptor".to_owned())?;
        validate_exact_descriptor_binding(policy, descriptor)?;
        let admission = std::iter::once(direct)
            .chain(retained_direct.iter())
            .find(|record| {
                record.profile_id == policy.admission_profile_id
                    && record.issuer_id == policy.admission_issuer_id
                    && record.token_key_id == policy.admission_token_key_id
                    && record.asset_id == policy.admission_asset_id
                    && record.amount_minor.to_string() == policy.admission_amount_minor
            })
            .ok_or_else(|| "V8 graph admission binding has no direct V7 record".to_owned())?;
        admission.validate().map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn validate_exact_descriptor_binding(
    policy: &NativeGraphIssuanceV8Policy,
    descriptor: &NativeExchangeV4Descriptor,
) -> Result<(), String> {
    if policy.descriptor_id != descriptor.descriptor_id
        || policy.issuer_id != descriptor.issuer_id
        || policy.token_key_id != descriptor.token_key_id
        || policy.asset_id != descriptor.asset_id
        || policy.amount_minor != descriptor.amount_minor
        || policy.suite != descriptor.suite
        || policy.modulus_bits != descriptor.modulus_bits
        || policy.exponent != descriptor.exponent
        || policy.pubkey_spki_b64 != descriptor.pubkey_spki_b64
        || policy.spki_fingerprint != descriptor.spki_fingerprint
        || u64::try_from(policy.valid_from).ok() != Some(descriptor.valid_from)
        || u64::try_from(policy.valid_until).ok() != Some(descriptor.valid_until)
    {
        return Err("V8 graph output binding does not match V4 descriptor".into());
    }
    Ok(())
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    fn empty_response() -> V7KeyDiscoveryRespV2 {
        V7KeyDiscoveryRespV2 {
            discovery_version: 2,
            issuer_id: "issuer".into(),
            current_epoch: 0,
            valid_epochs: vec![1],
            epoch_duration_sec: 1,
            voprf: V7VoprfKeyInfo {
                suite: "suite".into(),
                kid: "kid".into(),
                pubkey: "pubkey".into(),
            },
            native_bearer_v7: NativeBearerV7KeyInfo::default(),
            native_bearer_v7_retained: Vec::new(),
            native_exchange_v4: None,
            native_graph_issuance_v8: None,
        }
    }

    #[test]
    fn discovery_version_is_exactly_two() {
        let mut response = empty_response();
        response.discovery_version = 1;
        assert_eq!(
            response
                .validate()
                .expect_err("version one must be rejected"),
            "invalid V7 discovery V2 issuer envelope"
        );
    }

    #[test]
    fn unknown_fields_are_not_accepted_as_legacy_fallback() {
        let error = serde_json::from_value::<V7KeyDiscoveryRespV2>(serde_json::json!({
            "legacy_version": 7
        }))
        .expect_err("legacy fields must not deserialize as V2 discovery");
        assert!(error.to_string().contains("unknown field"));
    }
}
