// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::{api::ExchangePublicHistory, exchange_api::validate_receipt_key_id};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, path::Path};

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
        let public = Base64UrlUnpadded::decode_vec(&receipt.public_key_b64)
            .context("invalid historical receipt key encoding")?;
        if receipt.algorithm != "Ed25519"
            || receipt.purpose != "exchange_receipt_retained"
            || public.len() != 32
            || Base64UrlUnpadded::encode_string(&public) != receipt.public_key_b64
            || hex::encode(Sha256::digest(&public)) != receipt.key_id
            || receipt.valid_from >= receipt.valid_until
            || receipt.valid_until < u64::try_from(now).unwrap_or_default()
            || !receipt_ids.insert(&receipt.key_id)
        {
            bail!("invalid historical receipt verification key")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_common::api::{ExchangeDescriptorInfo, ExchangeTargetKeysetInfo};
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

        assert!(validate_public_history(&history, "issuer:test:history", None).is_ok());
        let error =
            validate_public_history(&history, "issuer:test:history", Some(spki)).unwrap_err();
        assert!(error
            .to_string()
            .contains("overlaps active legacy public issuance key"));
    }
}
