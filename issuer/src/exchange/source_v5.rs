// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pure V5 source and RSA-output validation. No function in this module mutates
//! Redis, and source artifacts never enter durable work records.

use crate::exchange::{
    profiles::{ExchangeKeysetV2, ExchangeProfile, ExchangeProfileV2, ExchangeTransitionSlotV2},
    store::OutputWork,
};
use anyhow::{bail, Context, Result};
use freebird_common::{
    exchange_api::{decode_base64url, ExchangeOutput, MAX_ARTIFACT},
    spend_key::v5_spend_key,
};
use freebird_crypto::{
    nullifier_key_v5, parse_public_bearer_pass, provider::BlindRsaProvider,
    verify_public_bearer_signature, PublicBearerPass,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedSource {
    pub descriptor_id: String,
    pub spend_key: String,
}

pub fn validate_source_v5(
    profile: &ExchangeProfile,
    descriptor_id: &str,
    artifact: &[u8],
    expected_issuer: &str,
) -> Result<ValidatedSource> {
    let descriptor = profile
        .sources
        .descriptors
        .iter()
        .find(|d| d.id == descriptor_id)
        .context("source descriptor is not pinned")?;
    let token: PublicBearerPass = parse_public_bearer_pass(artifact)
        .map_err(|_| anyhow::anyhow!("invalid source artifact"))?;
    let expected_kid: [u8; 32] = hex::decode(&descriptor.kid)
        .context("invalid source key id")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid source key id"))?;
    if token.issuer_id != expected_issuer
        || token.issuer_id != descriptor.issuer_id
        || token.token_key_id != expected_kid
    {
        bail!("source identity does not match pinned descriptor")
    }
    verify_public_bearer_signature(&descriptor.spki_bytes()?, &token)
        .map_err(|_| anyhow::anyhow!("invalid source signature"))?;
    Ok(ValidatedSource {
        descriptor_id: descriptor.id.clone(),
        spend_key: v5_spend_key(
            &nullifier_key_v5(&token).map_err(|_| anyhow::anyhow!("source spend key failure"))?,
        ),
    })
}

pub fn validate_source_v5_v2(
    source_keyset: &ExchangeKeysetV2,
    descriptor_id: &str,
    artifact: &[u8],
    expected_issuer: &str,
) -> Result<ValidatedSource> {
    let descriptor = source_keyset
        .keys
        .iter()
        .find(|key| key.descriptor.id == descriptor_id)
        .map(|key| &key.descriptor)
        .context("source descriptor is not in the selected keyset")?;
    let token: PublicBearerPass = parse_public_bearer_pass(artifact)
        .map_err(|_| anyhow::anyhow!("invalid source artifact"))?;
    let expected_kid: [u8; 32] = hex::decode(&descriptor.kid)
        .context("invalid source key id")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid source key id"))?;
    if token.issuer_id != expected_issuer
        || token.issuer_id != descriptor.issuer_id
        || token.token_key_id != expected_kid
    {
        bail!("source identity does not match selected descriptor")
    }
    verify_public_bearer_signature(&descriptor.spki_bytes()?, &token)
        .map_err(|_| anyhow::anyhow!("invalid source signature"))?;
    Ok(ValidatedSource {
        descriptor_id: descriptor.id.clone(),
        spend_key: v5_spend_key(
            &nullifier_key_v5(&token).map_err(|_| anyhow::anyhow!("source spend key failure"))?,
        ),
    })
}

pub struct PinnedTargetSigners {
    providers: HashMap<String, Arc<freebird_crypto::provider::software::SoftwareBlindRsaProvider>>,
    keysets: HashMap<String, HashSet<String>>,
}

impl PinnedTargetSigners {
    pub fn load(active: &ExchangeProfile, retained: &[ExchangeProfile]) -> Result<Self> {
        use freebird_crypto::provider::software::SoftwareBlindRsaProvider;
        let mut providers: HashMap<String, Arc<SoftwareBlindRsaProvider>> = HashMap::new();
        let mut keysets = HashMap::new();
        for profile in std::iter::once(active).chain(retained) {
            let mut descriptors = HashSet::new();
            for target in &profile.target_keyset.targets {
                let der = zeroize::Zeroizing::new(
                    std::fs::read(&target.private_key_path).context("read exchange target key")?,
                );
                let provider = SoftwareBlindRsaProvider::from_der(&der)?;
                if provider.token_key_id().as_slice()
                    != hex::decode(&target.descriptor.kid)?.as_slice()
                    || provider.public_key_spki() != target.descriptor.spki_bytes()?.as_slice()
                {
                    bail!("target key identity mismatch")
                }
                descriptors.insert(target.descriptor.id.clone());
                if let Some(existing) = providers.get(&target.descriptor.id) {
                    if existing.public_key_spki() != provider.public_key_spki() {
                        bail!("target descriptor maps to conflicting signers")
                    }
                } else {
                    providers.insert(target.descriptor.id.clone(), Arc::new(provider));
                }
            }
            if keysets
                .insert(profile.target_keyset.id.clone(), descriptors)
                .is_some()
            {
                bail!("duplicate retained target keyset id")
            }
        }
        Ok(Self { providers, keysets })
    }

    /// Decode canonically and validate every output before reservation.
    pub fn validate_outputs(
        &self,
        target_keyset_id: &str,
        outputs: &[ExchangeOutput],
    ) -> Result<Vec<OutputWork>> {
        if outputs.is_empty() || outputs.len() > freebird_common::exchange_api::MAX_ITEMS {
            bail!("invalid exchange output count")
        }
        let descriptors = self
            .keysets
            .get(target_keyset_id)
            .context("target keyset is not pinned")?;
        outputs
            .iter()
            .map(|output| {
                if output.slot.keyset_id != target_keyset_id
                    || !descriptors.contains(&output.slot.descriptor_id)
                {
                    bail!("output does not belong to pinned target keyset")
                }
                let provider = self
                    .providers
                    .get(&output.slot.descriptor_id)
                    .context("target descriptor is not pinned")?;
                let blinded = decode_base64url(&output.blinded_value, MAX_ARTIFACT)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                validate_representative(provider.public_key_spki(), &blinded)?;
                Ok(OutputWork {
                    descriptor_id: output.slot.descriptor_id.clone(),
                    keyset_id: output.slot.keyset_id.clone(),
                    slot_id: output.slot.slot_id.clone(),
                    quantity: output.slot.quantity,
                    blinded_value: blinded,
                })
            })
            .collect()
    }

    pub fn supports_work(&self, target_keyset_id: &str, outputs: &[OutputWork]) -> bool {
        self.keysets
            .get(target_keyset_id)
            .is_some_and(|descriptors| {
                outputs.iter().all(|output| {
                    output.keyset_id == target_keyset_id
                        && descriptors.contains(&output.descriptor_id)
                        && self.providers.contains_key(&output.descriptor_id)
                })
            })
    }

    pub async fn sign_work(
        &self,
        target_keyset_id: &str,
        outputs: &[OutputWork],
    ) -> Result<Vec<Vec<u8>>> {
        if !self.supports_work(target_keyset_id, outputs) {
            bail!("pinned target signer unavailable")
        }
        let mut signatures = Vec::with_capacity(outputs.len());
        for output in outputs {
            let provider = self
                .providers
                .get(&output.descriptor_id)
                .context("pinned target signer unavailable")?;
            validate_representative(provider.public_key_spki(), &output.blinded_value)?;
            signatures.push(provider.blind_sign(&output.blinded_value).await?);
        }
        Ok(signatures)
    }
}

/// Signers pinned by immutable V2 descriptor identity. Providers are loaded
/// once, while request validation is always scoped to one selected keyset and
/// transition.
pub struct PinnedTargetSignersV2 {
    providers: HashMap<String, Arc<freebird_crypto::provider::software::SoftwareBlindRsaProvider>>,
    keysets: HashMap<String, HashSet<String>>,
    key_ids: HashMap<String, String>,
}

impl PinnedTargetSignersV2 {
    pub fn load(active: &ExchangeProfileV2, retained: &[ExchangeProfileV2]) -> Result<Self> {
        use freebird_crypto::provider::software::SoftwareBlindRsaProvider;

        let mut providers: HashMap<String, Arc<SoftwareBlindRsaProvider>> = HashMap::new();
        let mut keysets: HashMap<String, HashSet<String>> = HashMap::new();
        let mut key_ids = HashMap::new();
        for graph in std::iter::once(active).chain(retained) {
            for keyset in &graph.keysets {
                let descriptors = keysets.entry(keyset.id.clone()).or_default();
                for key in &keyset.keys {
                    descriptors.insert(key.descriptor.id.clone());
                    if let Some(existing) =
                        key_ids.insert(key.descriptor.id.clone(), key.descriptor.kid.clone())
                    {
                        if existing != key.descriptor.kid {
                            bail!("V2 descriptor maps to conflicting key identities")
                        }
                    }
                    let Some(path) = key.private_key_path.as_deref() else {
                        continue;
                    };
                    let der = zeroize::Zeroizing::new(
                        std::fs::read(path).context("read V2 exchange target key")?,
                    );
                    let provider = SoftwareBlindRsaProvider::from_der(&der)?;
                    if provider.token_key_id().as_slice()
                        != hex::decode(&key.descriptor.kid)?.as_slice()
                        || provider.public_key_spki() != key.descriptor.spki_bytes()?.as_slice()
                    {
                        bail!("V2 target key identity mismatch")
                    }
                    if let Some(existing) = providers.get(&key.descriptor.id) {
                        if existing.public_key_spki() != provider.public_key_spki() {
                            bail!("V2 target descriptor maps to conflicting signers")
                        }
                    } else {
                        providers.insert(key.descriptor.id.clone(), Arc::new(provider));
                    }
                }
            }
        }
        Ok(Self {
            providers,
            keysets,
            key_ids,
        })
    }

    pub fn validate_outputs(
        &self,
        target_keyset_id: &str,
        expected: &[ExchangeTransitionSlotV2],
        outputs: &[ExchangeOutput],
    ) -> Result<Vec<OutputWork>> {
        if outputs.len() != expected.len() || outputs.is_empty() {
            bail!("output cardinality does not match selected transition")
        }
        let descriptors = self
            .keysets
            .get(target_keyset_id)
            .context("selected target keyset is not pinned")?;
        outputs
            .iter()
            .zip(expected)
            .map(|(output, slot)| {
                if output.slot.keyset_id != target_keyset_id
                    || output.slot.descriptor_id != slot.descriptor_id
                    || output.slot.slot_id != slot.slot_id
                    || output.slot.quantity != slot.quantity
                    || !descriptors.contains(&output.slot.descriptor_id)
                {
                    bail!("output does not satisfy selected transition")
                }
                let provider = self
                    .providers
                    .get(&output.slot.descriptor_id)
                    .context("selected target signer is not pinned")?;
                let blinded = decode_base64url(&output.blinded_value, MAX_ARTIFACT)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                validate_representative(provider.public_key_spki(), &blinded)?;
                Ok(OutputWork {
                    descriptor_id: output.slot.descriptor_id.clone(),
                    keyset_id: output.slot.keyset_id.clone(),
                    slot_id: output.slot.slot_id.clone(),
                    quantity: output.slot.quantity,
                    blinded_value: blinded,
                })
            })
            .collect()
    }

    pub fn signer_ref_keys(&self, outputs: &[OutputWork]) -> Result<Vec<String>> {
        let mut refs = Vec::new();
        for output in outputs {
            let key_id = self
                .key_ids
                .get(&output.descriptor_id)
                .context("V2 output key identity is unavailable")?;
            let reference = crate::exchange::store::ExchangeStore::signer_ref_key_v2(key_id);
            if !refs.contains(&reference) {
                refs.push(reference);
            }
        }
        Ok(refs)
    }

    pub fn supports_work(
        &self,
        target_keyset_id: &str,
        outputs: &[OutputWork],
        signer_refs: &[String],
    ) -> bool {
        self.keysets
            .get(target_keyset_id)
            .is_some_and(|descriptors| {
                outputs.iter().all(|output| {
                    output.keyset_id == target_keyset_id
                        && descriptors.contains(&output.descriptor_id)
                        && self.providers.contains_key(&output.descriptor_id)
                })
            })
            && self
                .signer_ref_keys(outputs)
                .is_ok_and(|expected| expected == signer_refs)
    }

    pub async fn sign_work(
        &self,
        target_keyset_id: &str,
        outputs: &[OutputWork],
        signer_refs: &[String],
    ) -> Result<Vec<Vec<u8>>> {
        if !self.supports_work(target_keyset_id, outputs, signer_refs) {
            bail!("persisted V2 target signer references are unavailable")
        }
        let mut signatures = Vec::with_capacity(outputs.len());
        for output in outputs {
            let provider = self
                .providers
                .get(&output.descriptor_id)
                .context("pinned V2 target signer unavailable")?;
            validate_representative(provider.public_key_spki(), &output.blinded_value)?;
            signatures.push(provider.blind_sign(&output.blinded_value).await?);
        }
        Ok(signatures)
    }

    /// Validate and blind-sign one explicitly selected graph descriptor without
    /// treating the operation as an exchange output.
    pub(crate) async fn sign_graph_issuance(
        &self,
        keyset_id: &str,
        descriptor_id: &str,
        blinded_message: &[u8],
    ) -> Result<(String, Vec<u8>)> {
        let members = self
            .keysets
            .get(keyset_id)
            .context("graph issuance keyset is not pinned")?;
        if !members.contains(descriptor_id) {
            bail!("graph issuance descriptor is not in the selected keyset")
        }
        let provider = self
            .providers
            .get(descriptor_id)
            .context("graph issuance signer is not pinned")?;
        validate_representative(provider.public_key_spki(), blinded_message)?;
        let key_id = self
            .key_ids
            .get(descriptor_id)
            .context("graph issuance signer identity is unavailable")?
            .clone();
        Ok((key_id, provider.blind_sign(blinded_message).await?))
    }
}

pub(crate) fn validate_representative(spki: &[u8], representative: &[u8]) -> Result<()> {
    let modulus = rsa_modulus(spki).context("invalid target RSA SPKI")?;
    if representative.len() != modulus.len()
        || representative.iter().all(|byte| *byte == 0)
        || representative >= modulus.as_slice()
    {
        bail!("blinded RSA representative out of range")
    }
    Ok(())
}

fn rsa_modulus(spki: &[u8]) -> Option<Vec<u8>> {
    fn tlv<'a>(bytes: &'a [u8], position: &mut usize, tag: u8) -> Option<&'a [u8]> {
        if *bytes.get(*position)? != tag {
            return None;
        }
        *position += 1;
        let first = *bytes.get(*position)?;
        *position += 1;
        let length = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0
                || count > 4
                || *bytes.get(*position)? == 0
                || *position + count > bytes.len()
            {
                return None;
            }
            let mut value = 0usize;
            for byte in &bytes[*position..*position + count] {
                value = value.checked_mul(256)?.checked_add(usize::from(*byte))?;
            }
            *position += count;
            if value < 128 {
                return None;
            }
            value
        };
        let end = position.checked_add(length)?;
        let value = bytes.get(*position..end)?;
        *position = end;
        Some(value)
    }
    let mut outer_position = 0;
    let outer = tlv(spki, &mut outer_position, 0x30)?;
    if outer_position != spki.len() {
        return None;
    }
    let mut position = 0;
    let _algorithm = tlv(outer, &mut position, 0x30)?;
    let bits = tlv(outer, &mut position, 0x03)?;
    if position != outer.len() || bits.first().copied()? != 0 {
        return None;
    }
    let mut bit_position = 0;
    let rsa = tlv(&bits[1..], &mut bit_position, 0x30)?;
    if bit_position != bits.len() - 1 {
        return None;
    }
    let mut rsa_position = 0;
    let encoded_modulus = tlv(rsa, &mut rsa_position, 0x02)?;
    let exponent = tlv(rsa, &mut rsa_position, 0x02)?;
    if rsa_position != rsa.len() || exponent.is_empty() || encoded_modulus.is_empty() {
        return None;
    }
    let modulus = if encoded_modulus[0] == 0 {
        if encoded_modulus.len() < 2 || encoded_modulus[1] & 0x80 == 0 {
            return None;
        }
        &encoded_modulus[1..]
    } else {
        if encoded_modulus[0] & 0x80 != 0 {
            return None;
        }
        encoded_modulus
    };
    if modulus.is_empty() {
        None
    } else {
        Some(modulus.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};

    #[test]
    fn generated_rsa_representative_boundaries() {
        let provider = SoftwareBlindRsaProvider::generate(2048).unwrap();
        let modulus = rsa_modulus(provider.public_key_spki()).unwrap();
        let mut valid = vec![0; modulus.len()];
        valid[modulus.len() - 1] = 1;
        assert!(
            validate_representative(provider.public_key_spki(), &valid).is_ok(),
            "valid representative"
        );
        assert!(
            validate_representative(provider.public_key_spki(), &vec![0; modulus.len()]).is_err(),
            "zero"
        );
        assert!(
            validate_representative(provider.public_key_spki(), &modulus).is_err(),
            "equal"
        );
        let greater = vec![0xff; modulus.len()];
        assert!(
            validate_representative(provider.public_key_spki(), &greater).is_err(),
            "greater"
        );
        assert!(
            validate_representative(provider.public_key_spki(), &valid[..valid.len() - 1]).is_err(),
            "short"
        );
        let mut long = valid;
        long.push(0);
        assert!(
            validate_representative(provider.public_key_spki(), &long).is_err(),
            "long"
        );
    }
}
