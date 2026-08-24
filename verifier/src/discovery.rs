// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::V7KeyDiscoveryResp;
use std::collections::HashMap;

use crate::state::{V7DescriptorIdentity, V7IssuerTrustEntry, V7IssuerTrustSnapshot};

/// Validate the approved V7 discovery container and materialize the complete
/// issuer-local trust snapshot. Direct, retained, exchange, and graph records
/// are all included before the result is returned.
pub fn trusted_v7_keys(
    issuer_id: &str,
    discovery: V7KeyDiscoveryResp,
) -> Result<V7IssuerTrustSnapshot> {
    if discovery.issuer_id != issuer_id {
        return Err(anyhow!("V7 key discovery issuer_id mismatch"));
    }
    let registry = discovery.validated_registry().map_err(anyhow::Error::msg)?;
    let mut by_token_key_id = HashMap::new();
    for reservation in registry.entries() {
        if reservation.issuer_id != issuer_id {
            return Err(anyhow!("V7 key discovery record issuer_id mismatch"));
        }
        let token_key_id = decode_v7_key_id(&reservation.token_key_id)?;
        let spki = Base64UrlUnpadded::decode_vec(&reservation.pubkey_spki_b64)
            .context("decode V7 SPKI")?;
        if Base64UrlUnpadded::encode_string(&spki) != reservation.pubkey_spki_b64 {
            return Err(anyhow!("non-canonical V7 SPKI encoding"));
        }
        let identity =
            freebird_crypto::V7KeyIdentity::new(reservation.issuer_id.clone(), token_key_id)
                .map_err(|error| anyhow!("invalid V7 issuer/key identity: {error:?}"))?;
        let binding = freebird_crypto::V7PublicKeyBinding::new(identity, &spki)
            .map_err(|error| anyhow!("invalid V7 public key binding: {error:?}"))?;
        if hex::encode(binding.spki_fingerprint()) != reservation.spki_fingerprint {
            return Err(anyhow!("V7 SPKI fingerprint does not match binding"));
        }
        let policy = freebird_crypto::V7BodyPolicy::new(
            reservation.asset_id.clone(),
            reservation.amount_minor,
        )
        .map_err(|error| anyhow!("invalid V7 body policy: {error:?}"))?;
        let entry = V7IssuerTrustEntry {
            binding,
            policy,
            identity: V7DescriptorIdentity {
                profile_id: reservation.profile_id.clone(),
                descriptor_id: reservation.descriptor_id.clone(),
            },
            valid_from: reservation.valid_from,
            valid_until: reservation.valid_until,
        };
        if by_token_key_id.insert(token_key_id, entry).is_some() {
            return Err(anyhow!("conflicting V7 token key ID"));
        }
    }
    Ok(V7IssuerTrustSnapshot { by_token_key_id })
}

fn decode_v7_key_id(value: &str) -> Result<freebird_crypto::V7TokenKeyId> {
    let bytes = hex::decode(value).map_err(|_| anyhow!("invalid V7 token_key_id"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid V7 token_key_id"))?;
    Ok(freebird_crypto::V7TokenKeyId::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_common::api::{
        NativeBearerV7KeyInfo, V7KeyDiscoveryResp, V7VoprfKeyInfo, EXCHANGE_MAX_VALID_UNTIL,
        NATIVE_BEARER_V7_PROFILE_ID,
    };
    use freebird_crypto::{
        provider::software::SoftwareV7BlindRsaProvider, V7BodyPolicy, V7KeyIdentity, V7TokenKeyId,
    };

    fn record(issuer_id: &str, key: u8, descriptor: u8) -> NativeBearerV7KeyInfo {
        let identity = V7KeyIdentity::new(issuer_id, V7TokenKeyId::new([key; 32])).unwrap();
        let provider = SoftwareV7BlindRsaProvider::generate(identity).unwrap();
        NativeBearerV7KeyInfo::from_binding(
            provider.binding(),
            NATIVE_BEARER_V7_PROFILE_ID,
            &format!("{descriptor:02x}").repeat(32),
            &V7BodyPolicy::new("USD", 42).unwrap(),
            1,
            EXCHANGE_MAX_VALID_UNTIL,
        )
        .unwrap()
    }

    fn discovery(issuer_id: &str) -> V7KeyDiscoveryResp {
        V7KeyDiscoveryResp {
            issuer_id: issuer_id.into(),
            current_epoch: 1,
            valid_epochs: vec![1],
            epoch_duration_sec: 86_400,
            voprf: V7VoprfKeyInfo {
                suite: "VOPRF-P256-SHA256".into(),
                kid: "voprf-kid".into(),
                pubkey: "voprf-pubkey".into(),
            },
            native_bearer_v7: record(issuer_id, 1, 2),
            native_bearer_v7_retained: vec![record(issuer_id, 3, 4)],
            native_exchange_v7: None,
            native_graph_issuance_v7: None,
        }
    }

    #[test]
    fn materializes_direct_and_retained_typed_v7_trust() {
        let snapshot = trusted_v7_keys("issuer:test:v7", discovery("issuer:test:v7")).unwrap();
        assert_eq!(snapshot.by_token_key_id.len(), 2);
        assert_eq!(
            snapshot
                .get(&V7TokenKeyId::new([1; 32]))
                .unwrap()
                .policy
                .amount_minor(),
            42
        );
    }

    #[test]
    fn rejects_mismatched_issuer_and_noncanonical_spki() {
        let valid = discovery("issuer:test:v7");
        assert!(trusted_v7_keys("issuer:other", valid.clone()).is_err());
        let mut malformed = valid;
        malformed.native_bearer_v7.pubkey_spki_b64.push('=');
        assert!(trusted_v7_keys("issuer:test:v7", malformed).is_err());
    }
}
