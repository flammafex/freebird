// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::{
    api::{ExchangeDescriptorInfo, KeyDiscoveryResp, PublicKeyInfo},
    exchange_api::{validate_descriptor_id, validate_keyset_id},
};
use std::collections::HashMap;

use crate::routes::admin::PublicIssuerKey;

pub fn trusted_public_keys(
    issuer_id: &str,
    discovery: KeyDiscoveryResp,
) -> Result<HashMap<[u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN], PublicIssuerKey>> {
    if discovery.issuer_id != issuer_id {
        return Err(anyhow!("issuer key discovery issuer_id mismatch"));
    }
    let mut keys = HashMap::new();
    for info in discovery.public {
        match parse_legacy_public_key(issuer_id, info) {
            Ok(key) => {
                if let Err(error) = insert_unique(&mut keys, key) {
                    tracing::warn!(?error, "dropping conflicting legacy public bearer key");
                }
            }
            Err(error) => tracing::warn!(?error, "dropping invalid legacy public bearer key"),
        }
    }
    if let Some(exchange) = discovery.exchange {
        if let Err(error) = freebird_common::api::validate_exchange_target_metadata(
            &exchange.profile_id,
            issuer_id,
            &exchange.target_keysets,
            &exchange.descriptors,
        ) {
            tracing::warn!(?error, "ignoring non-canonical exchange target metadata");
            return Ok(keys);
        }
        for descriptor in exchange
            .descriptors
            .into_iter()
            .filter(|descriptor| descriptor.purpose == "exchange_target")
        {
            match parse_exchange_target(issuer_id, descriptor) {
                Ok(key) => {
                    if let Err(error) = insert_unique(&mut keys, key) {
                        tracing::warn!(?error, "dropping conflicting exchange target key");
                    }
                }
                Err(error) => tracing::warn!(?error, "dropping invalid exchange target key"),
            }
        }
    }
    Ok(keys)
}

fn insert_unique(
    keys: &mut HashMap<[u8; 32], PublicIssuerKey>,
    key: PublicIssuerKey,
) -> Result<()> {
    if let Some(existing) = keys.get(&key.token_key_id) {
        if existing.pubkey_spki != key.pubkey_spki
            || existing.issuer_id != key.issuer_id
            || existing.valid_from != key.valid_from
            || existing.valid_until != key.valid_until
            || existing.audience != key.audience
        {
            return Err(anyhow!("conflicting public bearer key metadata"));
        }
        return Ok(());
    }
    keys.insert(key.token_key_id, key);
    Ok(())
}

fn parse_legacy_public_key(issuer_id: &str, info: PublicKeyInfo) -> Result<PublicIssuerKey> {
    if info.issuer_id != issuer_id
        || info.token_type != freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE
        || info.rfc9474_variant != freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT
        || info.spend_policy != freebird_crypto::PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE
        || matches!(info.max_uses, Some(max_uses) if max_uses != 1)
        || !(2048..=4096).contains(&info.modulus_bits)
        || info.valid_from >= info.valid_until
    {
        return Err(anyhow!("invalid legacy public bearer key metadata"));
    }
    build_key(
        issuer_id,
        info.token_key_id,
        info.pubkey_spki_b64,
        info.valid_from,
        info.valid_until,
        info.audience,
    )
}

fn parse_exchange_target(issuer_id: &str, info: ExchangeDescriptorInfo) -> Result<PublicIssuerKey> {
    validate_descriptor_id(&info.descriptor_id).map_err(|e| anyhow!(e.to_string()))?;
    validate_keyset_id(&info.keyset_id).map_err(|e| anyhow!(e.to_string()))?;
    if info.purpose != "exchange_target"
        || info.issuer_id != issuer_id
        || info.suite != "RSABSSA-SHA384-PSS-Deterministic"
        || info.class.is_empty()
        || !info.class.is_ascii()
        || info.valid_from >= info.valid_until
        || info.audience.as_ref().is_some_and(|audience| {
            audience.is_empty() || audience.len() > 128 || !audience.is_ascii()
        })
    {
        return Err(anyhow!("invalid exchange target descriptor"));
    }
    build_key(
        issuer_id,
        info.token_key_id,
        info.pubkey_spki_b64,
        info.valid_from,
        info.valid_until,
        info.audience,
    )
}

fn build_key(
    issuer_id: &str,
    token_key_id_hex: String,
    spki_b64: String,
    valid_from: i64,
    valid_until: i64,
    audience: Option<String>,
) -> Result<PublicIssuerKey> {
    let token_key_id = freebird_crypto::decode_token_key_id_hex(&token_key_id_hex)
        .map_err(|_| anyhow!("invalid token_key_id"))?;
    let pubkey_spki = Base64UrlUnpadded::decode_vec(&spki_b64).context("decode SPKI")?;
    if Base64UrlUnpadded::encode_string(&pubkey_spki) != spki_b64 {
        return Err(anyhow!("non-canonical SPKI encoding"));
    }
    freebird_crypto::validate_public_bearer_spki(&pubkey_spki)
        .map_err(|_| anyhow!("invalid public bearer SPKI"))?;
    if freebird_crypto::token_key_id_from_spki(&pubkey_spki) != token_key_id {
        return Err(anyhow!("token_key_id does not match SPKI"));
    }
    Ok(PublicIssuerKey {
        token_key_id,
        token_key_id_hex,
        pubkey_spki,
        issuer_id: issuer_id.into(),
        valid_from,
        valid_until,
        audience,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_common::api::{
        ExchangeDiscoveryInfo, ExchangeReceiptKeyInfo, ExchangeTargetKeysetInfo, VoprfKeyInfo,
    };
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};

    fn discovery() -> KeyDiscoveryResp {
        let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let token_key_id = hex::encode(provider.token_key_id());
        let mut descriptor = ExchangeDescriptorInfo {
            descriptor_id: String::new(),
            keyset_id: String::new(),
            purpose: "exchange_target".into(),
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
            role: "target".into(),
            issuer_id: "issuer:test:exchange".into(),
            class: "target".into(),
            token_key_id,
            pubkey_spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: 1,
            valid_until: i64::MAX,
            max_quantity: 1,
            audience: Some("audience".into()),
        };
        descriptor.descriptor_id = descriptor.canonical_descriptor_id().unwrap();
        let mut keyset = ExchangeTargetKeysetInfo {
            keyset_id: String::new(),
            descriptor_ids: vec![descriptor.descriptor_id.clone()],
        };
        keyset.keyset_id = keyset.canonical_keyset_id();
        descriptor.keyset_id = keyset.keyset_id.clone();
        KeyDiscoveryResp {
            issuer_id: "issuer:test:exchange".into(),
            current_epoch: 1,
            valid_epochs: vec![1],
            epoch_duration_sec: 86_400,
            voprf: VoprfKeyInfo {
                suite: "suite".into(),
                kid: "kid".into(),
                pubkey: "public".into(),
            },
            public: vec![],
            exchange: Some(ExchangeDiscoveryInfo {
                profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
                target_keysets: vec![keyset],
                descriptors: vec![descriptor],
                receipt_keys: Vec::<ExchangeReceiptKeyInfo>::new(),
            }),
        }
    }

    #[test]
    fn trusts_valid_exchange_target_and_rejects_identity_tampering() {
        let discovery = discovery();
        let keys = trusted_public_keys("issuer:test:exchange", discovery.clone()).unwrap();
        assert_eq!(keys.len(), 1);
        let mut bad = discovery.clone();
        bad.exchange.as_mut().unwrap().descriptors[0].suite = "wrong".into();
        assert!(trusted_public_keys("issuer:test:exchange", bad)
            .unwrap()
            .is_empty());
        let mut bad = discovery;
        bad.exchange.as_mut().unwrap().descriptors[0].issuer_id = "other".into();
        assert!(trusted_public_keys("issuer:test:exchange", bad)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rejects_audience_validity_policy_keyset_and_spki_duplication_tampering() {
        let valid = discovery();
        for mutate in [
            |metadata: &mut ExchangeDiscoveryInfo| {
                metadata.descriptors[0].audience = Some("widened".into())
            },
            |metadata: &mut ExchangeDiscoveryInfo| metadata.descriptors[0].valid_until -= 1,
            |metadata: &mut ExchangeDiscoveryInfo| metadata.descriptors[0].max_quantity = 2,
            |metadata: &mut ExchangeDiscoveryInfo| {
                metadata.target_keysets[0].descriptor_ids.clear()
            },
        ] {
            let mut tampered = valid.clone();
            mutate(tampered.exchange.as_mut().unwrap());
            assert!(trusted_public_keys("issuer:test:exchange", tampered)
                .unwrap()
                .is_empty());
        }

        let mut duplicated = valid;
        let exchange = duplicated.exchange.as_mut().unwrap();
        let mut second = exchange.descriptors[0].clone();
        second.class = "different-policy".into();
        second.descriptor_id = second.canonical_descriptor_id().unwrap();
        let mut keyset = ExchangeTargetKeysetInfo {
            keyset_id: String::new(),
            descriptor_ids: vec![
                exchange.descriptors[0].descriptor_id.clone(),
                second.descriptor_id.clone(),
            ],
        };
        keyset.keyset_id = keyset.canonical_keyset_id();
        exchange.descriptors[0].keyset_id = keyset.keyset_id.clone();
        second.keyset_id = keyset.keyset_id.clone();
        exchange.target_keysets = vec![keyset];
        exchange.descriptors.push(second);
        assert!(trusted_public_keys("issuer:test:exchange", duplicated)
            .unwrap()
            .is_empty());
    }
}
