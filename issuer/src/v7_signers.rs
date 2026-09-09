// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The issuer-owned inventory of native V7 randomized RSA signers.
//!
//! This inventory is deliberately role-neutral.  Direct issuance uses the
//! active entry today; exchange and graph issuance can add entries without
//! introducing another key store or another signer type.

use anyhow::{bail, Context, Result};
use base64ct::Encoding;
use blind_rsa_signatures::PublicKeySha384PSSRandomized;
use freebird_common::api::{validate_v7_canonical_id, NativeBearerV7KeyInfo};
use freebird_crypto::{
    provider::software::SoftwareV7BlindRsaProvider, V7BlindMessage, V7BlindSignature, V7BodyPolicy,
    V7KeyIdentity, V7PublicKeyBinding, V7TokenKeyId,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use time::OffsetDateTime;

use crate::{config::NativeBearerV7Config, v7_registry};

/// Immutable identity used to select one V7 signer.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct V7SignerIdentity {
    issuer_id: String,
    profile_id: String,
    descriptor_id: String,
    token_key_id: V7TokenKeyId,
}

impl V7SignerIdentity {
    /// Construct an explicit issuer/profile/descriptor/key identity.
    pub fn new(
        issuer_id: impl Into<String>,
        profile_id: impl Into<String>,
        descriptor_id: impl Into<String>,
        token_key_id: V7TokenKeyId,
    ) -> Result<Self> {
        let identity = Self {
            issuer_id: issuer_id.into(),
            profile_id: profile_id.into(),
            descriptor_id: descriptor_id.into(),
            token_key_id,
        };
        if identity.issuer_id.trim().is_empty()
            || identity.profile_id.trim().is_empty()
            || identity.descriptor_id.trim().is_empty()
        {
            bail!("V7 signer identity fields must not be empty");
        }
        validate_v7_canonical_id(&identity.descriptor_id, "descriptor_id")
            .map_err(anyhow::Error::msg)?;
        if hex::encode(identity.token_key_id.as_bytes()) == identity.descriptor_id {
            bail!("V7 token and descriptor identifiers must be distinct");
        }
        V7KeyIdentity::new(&identity.issuer_id, token_key_id)
            .map_err(|error| anyhow::anyhow!("invalid V7 signer identity: {error:?}"))?;
        Ok(identity)
    }

    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub fn descriptor_id(&self) -> &str {
        &self.descriptor_id
    }
    pub const fn token_key_id(&self) -> &V7TokenKeyId {
        &self.token_key_id
    }

    pub(crate) fn crypto_identity(&self) -> Result<V7KeyIdentity> {
        V7KeyIdentity::new(self.issuer_id.clone(), self.token_key_id)
            .map_err(|error| anyhow::anyhow!("invalid V7 signer identity: {error:?}"))
    }
}

/// File-backed configuration for one V7 signer in the inventory.
#[derive(Clone, Debug)]
pub struct V7SignerSpec {
    pub identity: V7SignerIdentity,
    /// Exchange descriptors are derived after key generation when this is
    /// absent; a supplied value is an operator pin, never a bootstrap value.
    configured_descriptor_id: Option<String>,
    pub sk_path: PathBuf,
    pub metadata_path: PathBuf,
    pub asset_id: String,
    pub amount_minor: u64,
    pub validity_secs: u64,
}

impl V7SignerSpec {
    /// Convert the direct V7 configuration into the shared inventory shape.
    pub fn from_native_config(config: &NativeBearerV7Config, issuer_id: &str) -> Result<Self> {
        let token_key_id: [u8; 32] = hex::decode(&config.token_key_id)
            .map_err(|error| anyhow::anyhow!("invalid configured V7 token key ID: {error}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid configured V7 token key ID length"))?;
        let configured_descriptor_id =
            (!config.descriptor_id.trim().is_empty()).then(|| config.descriptor_id.clone());
        let identity_descriptor = configured_descriptor_id.clone().unwrap_or_else(|| {
            let mut placeholder = token_key_id;
            placeholder[0] ^= 1;
            hex::encode(placeholder)
        });
        Ok(Self {
            identity: V7SignerIdentity::new(
                issuer_id,
                config.profile_id.clone(),
                identity_descriptor,
                V7TokenKeyId::new(token_key_id),
            )?,
            configured_descriptor_id,
            sk_path: config.sk_path.clone(),
            metadata_path: config.metadata_path.clone(),
            asset_id: config.asset_id.clone(),
            amount_minor: config.amount_minor,
            validity_secs: config.validity_secs,
        })
    }
}

/// One validated V7 signer and its immutable policy/discovery binding.
pub struct V7Signer {
    identity: V7SignerIdentity,
    provider: SoftwareV7BlindRsaProvider,
    metadata: NativeBearerV7KeyInfo,
    policy: V7BodyPolicy,
    #[cfg(test)]
    sign_attempts: std::sync::atomic::AtomicUsize,
}

/// Bounded pre-admission failures, without provider or storage details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V7PreflightError {
    Unavailable,
    InvalidRepresentative,
}

impl std::fmt::Display for V7PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "V7 signer unavailable",
            Self::InvalidRepresentative => "invalid V7 blinded representative",
        })
    }
}

impl std::error::Error for V7PreflightError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum V7SignerRole {
    Direct,
    Exchange,
    GraphIssuance,
}

fn signer_role(profile_id: &str) -> Result<V7SignerRole> {
    match profile_id {
        freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID => Ok(V7SignerRole::Direct),
        freebird_common::api::NATIVE_EXCHANGE_V3_PROFILE_ID => Ok(V7SignerRole::Exchange),
        freebird_common::api::NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID => {
            Ok(V7SignerRole::GraphIssuance)
        }
        _ => bail!("unsupported native V7 signer profile"),
    }
}

impl V7Signer {
    fn load_or_generate(spec: &V7SignerSpec) -> Result<Self> {
        let role = signer_role(spec.identity.profile_id())?;
        let key_exists = spec.sk_path.exists();
        let metadata_exists = spec.metadata_path.exists();
        if matches!(role, V7SignerRole::Direct | V7SignerRole::Exchange)
            && spec.configured_descriptor_id.is_some()
            && !metadata_exists
        {
            bail!("native V7 descriptor ID is a pin, not a bootstrap value; start once without it to create V7 key material, then configure the persisted descriptor ID");
        }
        let policy = V7BodyPolicy::new(spec.asset_id.clone(), spec.amount_minor)
            .map_err(|error| anyhow::anyhow!("invalid V7 fixed body policy: {error:?}"))?;
        let provider = if key_exists {
            SoftwareV7BlindRsaProvider::from_der(
                &std::fs::read(&spec.sk_path)
                    .with_context(|| format!("read V7 secret key {}", spec.sk_path.display()))?,
                spec.identity.crypto_identity()?,
            )?
        } else {
            let provider = SoftwareV7BlindRsaProvider::generate(spec.identity.crypto_identity()?)?;
            write_secret_key(&spec.sk_path, &provider.to_der()?)?;
            provider
        };
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let metadata = if metadata_exists {
            let metadata = read_metadata(&spec.metadata_path)?;
            let identity = identity_for_metadata(spec, &metadata)?;
            validate_configured_descriptor(spec, &metadata)?;
            validate_metadata(&metadata, &metadata, &identity, &policy, now, false)?;
            if role == V7SignerRole::Exchange {
                validate_exchange_metadata(&metadata, provider.binding(), spec)?;
            }
            metadata
        } else {
            let valid_until = now
                .checked_add(i64::try_from(spec.validity_secs).context("V7 validity too large")?)
                .context("V7 validity overflow")?;
            let computed = match role {
                V7SignerRole::Direct => NativeBearerV7KeyInfo::from_binding(
                    provider.binding(),
                    &spec.identity.profile_id,
                    &spec.identity.descriptor_id,
                    &policy,
                    now,
                    valid_until,
                )
                .map_err(anyhow::Error::msg)?,
                V7SignerRole::Exchange => {
                    exchange_metadata(provider.binding(), spec, &policy, now, valid_until)?
                }
                V7SignerRole::GraphIssuance => NativeBearerV7KeyInfo::from_binding(
                    provider.binding(),
                    &spec.identity.profile_id,
                    &spec.identity.descriptor_id,
                    &policy,
                    now,
                    valid_until,
                )
                .map_err(anyhow::Error::msg)?,
            };
            if let Some(expected) = &spec.configured_descriptor_id {
                if computed.descriptor_id != *expected {
                    bail!(
                        "configured native V7 descriptor ID does not match generated key material"
                    );
                }
            }
            write_metadata(&spec.metadata_path, &computed)?;
            computed
        };
        let identity = identity_for_metadata(spec, &metadata)?;
        Self::from_parts(identity, provider, metadata, policy)
    }

    pub(crate) fn load_existing(spec: &V7SignerSpec, allow_expired: bool) -> Result<Self> {
        let role = signer_role(spec.identity.profile_id())?;
        if !spec.sk_path.is_file() || !spec.metadata_path.is_file() {
            bail!("V7 signer key and metadata must both exist");
        }
        let policy = V7BodyPolicy::new(spec.asset_id.clone(), spec.amount_minor)
            .map_err(|error| anyhow::anyhow!("invalid V7 fixed body policy: {error:?}"))?;
        let provider = SoftwareV7BlindRsaProvider::from_der(
            &std::fs::read(&spec.sk_path)?,
            spec.identity.crypto_identity()?,
        )?;
        let metadata = read_metadata(&spec.metadata_path)?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let identity = identity_for_metadata(spec, &metadata)?;
        validate_configured_descriptor(spec, &metadata)?;
        validate_metadata(&metadata, &metadata, &identity, &policy, now, allow_expired)?;
        if role == V7SignerRole::Exchange {
            validate_exchange_metadata(&metadata, provider.binding(), spec)?;
        }
        Self::from_parts(identity, provider, metadata, policy)
    }

    fn from_parts(
        identity: V7SignerIdentity,
        provider: SoftwareV7BlindRsaProvider,
        metadata: NativeBearerV7KeyInfo,
        policy: V7BodyPolicy,
    ) -> Result<Self> {
        if metadata.decode_binding().map_err(anyhow::Error::msg)? != *provider.binding() {
            bail!("V7 signer metadata does not match private key");
        }
        if metadata.profile_id != identity.profile_id
            || metadata.issuer_id != identity.issuer_id
            || metadata.descriptor_id != identity.descriptor_id
            || metadata.token_key_id != hex::encode(identity.token_key_id.as_bytes())
        {
            bail!("V7 signer metadata identity does not match descriptor");
        }
        Ok(Self {
            identity,
            provider,
            metadata,
            policy,
            #[cfg(test)]
            sign_attempts: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Check availability and the existing modulus rules without signing or mutation.
    pub fn preflight_at(&self, message: &V7BlindMessage, now: i64) -> Result<(), V7PreflightError> {
        if !self.is_valid_at(now) {
            return Err(V7PreflightError::Unavailable);
        }
        validate_blind_representative(self.binding(), message)
            .map_err(|_| V7PreflightError::InvalidRepresentative)
    }

    #[cfg(test)]
    pub(crate) fn sign_attempts(&self) -> usize {
        self.sign_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Sign a validated raw384 blind representative.
    pub async fn sign(&self, message: &V7BlindMessage) -> Result<V7BlindSignature> {
        self.sign_at(message, OffsetDateTime::now_utc().unix_timestamp())
            .await
    }

    /// Sign only when the signer is valid at the supplied Unix timestamp.
    pub async fn sign_at(&self, message: &V7BlindMessage, now: i64) -> Result<V7BlindSignature> {
        #[cfg(test)]
        self.sign_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Recheck at signing time: preflight does not reserve a validity window.
        self.preflight_at(message, now)?;
        self.provider
            .blind_sign(&self.identity.crypto_identity()?, message)
            .await
    }

    pub fn is_valid_at(&self, now: i64) -> bool {
        self.metadata.valid_from <= now && now <= self.metadata.valid_until
    }

    pub fn validate_policy(&self, asset_id: &str, amount_minor: u64) -> Result<()> {
        if self.policy.asset_id() != asset_id || self.policy.amount_minor() != amount_minor {
            bail!("V7 signer policy does not match requested asset and amount");
        }
        Ok(())
    }

    pub fn identity(&self) -> &V7SignerIdentity {
        &self.identity
    }
    pub fn metadata(&self) -> &NativeBearerV7KeyInfo {
        &self.metadata
    }
    pub fn binding(&self) -> &V7PublicKeyBinding {
        self.provider.binding()
    }
    pub fn policy(&self) -> &V7BodyPolicy {
        &self.policy
    }
}

/// One inventory containing active and retained V7 signers.
pub struct V7SignerInventory {
    active: V7SignerIdentity,
    signers: HashMap<V7SignerIdentity, Arc<V7Signer>>,
    registry: freebird_common::v7_registry::BearerKeyRegistry,
}

impl V7SignerInventory {
    #[cfg(test)]
    pub(crate) fn set_test_validity(&mut self, from: i64, until: i64) {
        let signer = Arc::get_mut(self.signers.get_mut(&self.active).unwrap()).unwrap();
        signer.metadata.valid_from = from;
        signer.metadata.valid_until = until;
    }

    /// Load the active signer, optional retained signers, and reserve all of
    /// their immutable bindings in the pure V7 registry.
    pub fn load_or_generate(
        active: V7SignerSpec,
        retained: Vec<V7SignerSpec>,
        registry_path: &Path,
    ) -> Result<Self> {
        let active_signer = Arc::new(V7Signer::load_or_generate(&active)?);
        let mut loaded = vec![active_signer.clone()];
        for spec in retained {
            loaded.push(Arc::new(
                if spec.sk_path.exists() && spec.metadata_path.exists() {
                    V7Signer::load_existing(&spec, true)?
                } else {
                    V7Signer::load_or_generate(&spec)?
                },
            ));
        }
        Self::from_signers(active_signer, loaded, Some(registry_path))
    }

    /// Build an inventory from already loaded signers, optionally reserving it.
    pub fn from_signers(
        active: Arc<V7Signer>,
        signers: Vec<Arc<V7Signer>>,
        registry_path: Option<&Path>,
    ) -> Result<Self> {
        let mut map: HashMap<V7SignerIdentity, Arc<V7Signer>> = HashMap::new();
        let bindings = signers
            .iter()
            .map(|signer| (signer.metadata(), signer.binding()))
            .collect::<Vec<_>>();
        for signer in &signers {
            let identity = signer.identity().clone();
            if map
                .keys()
                .any(|existing| existing.token_key_id == identity.token_key_id)
            {
                bail!("duplicate V7 token-key ID in signer inventory");
            }
            if map.values().any(|existing: &Arc<V7Signer>| {
                existing.binding().spki_fingerprint() == signer.binding().spki_fingerprint()
            }) {
                bail!("duplicate V7 SPKI fingerprint in signer inventory");
            }
            if map.insert(identity.clone(), signer.clone()).is_some() {
                bail!("duplicate V7 signer descriptor/key identity");
            }
        }
        let registry = if let Some(path) = registry_path {
            v7_registry::load_and_reserve_all(path, &bindings)?
        } else {
            freebird_common::v7_registry::BearerKeyRegistry::from_entries(
                bindings
                    .iter()
                    .map(|(metadata, binding)| {
                        freebird_common::v7_registry::BearerKeyReservation::from_v7_discovery(
                            metadata, binding,
                        )
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            )?
        };
        if !map.contains_key(active.identity()) {
            bail!("active V7 signer is not present in inventory");
        }
        Ok(Self {
            active: active.identity().clone(),
            signers: map,
            registry,
        })
    }

    pub fn active(&self) -> &V7Signer {
        self.signers[&self.active].as_ref()
    }
    pub fn registry(&self) -> &freebird_common::v7_registry::BearerKeyRegistry {
        &self.registry
    }
    pub fn len(&self) -> usize {
        self.signers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }

    /// Look up a signer using the complete immutable descriptor/key identity.
    pub fn lookup(&self, identity: &V7SignerIdentity) -> Result<&V7Signer> {
        self.signers
            .get(identity)
            .map(Arc::as_ref)
            .ok_or_else(|| anyhow::anyhow!("V7 signer descriptor/key identity is not registered"))
    }

    pub async fn sign(
        &self,
        identity: &V7SignerIdentity,
        message: &V7BlindMessage,
    ) -> Result<V7BlindSignature> {
        self.lookup(identity)?.sign(message).await
    }
}

fn validate_blind_representative(
    binding: &V7PublicKeyBinding,
    message: &V7BlindMessage,
) -> Result<()> {
    let representative = message.as_bytes();
    if representative.iter().all(|byte| *byte == 0) {
        bail!("V7 blinded representative must be nonzero");
    }
    let public_key = PublicKeySha384PSSRandomized::from_spki(binding.public_key_spki())
        .map_err(|error| anyhow::anyhow!("invalid V7 public key: {error}"))?;
    let modulus = public_key.components().n();
    if representative.len() != modulus.len() || representative.as_slice() >= modulus.as_slice() {
        bail!("V7 blinded representative must be strictly below the modulus");
    }
    Ok(())
}

fn identity_for_metadata(
    spec: &V7SignerSpec,
    metadata: &NativeBearerV7KeyInfo,
) -> Result<V7SignerIdentity> {
    let binding = metadata.decode_binding().map_err(anyhow::Error::msg)?;
    if metadata.profile_id != spec.identity.profile_id()
        || metadata.issuer_id != spec.identity.issuer_id()
        || metadata.token_key_id != hex::encode(spec.identity.token_key_id().as_bytes())
        || binding.issuer_id() != spec.identity.issuer_id()
    {
        bail!("V7 signer metadata identity does not match configuration");
    }
    let descriptor_id = metadata.descriptor_id.clone();
    V7SignerIdentity::new(
        spec.identity.issuer_id(),
        spec.identity.profile_id(),
        descriptor_id,
        *spec.identity.token_key_id(),
    )
}

fn validate_configured_descriptor(
    spec: &V7SignerSpec,
    metadata: &NativeBearerV7KeyInfo,
) -> Result<()> {
    if let Some(expected) = &spec.configured_descriptor_id {
        if metadata.descriptor_id != *expected {
            bail!("configured V7 descriptor ID does not match persisted metadata");
        }
    }
    Ok(())
}

fn read_metadata(path: &Path) -> Result<NativeBearerV7KeyInfo> {
    serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read V7 metadata {}", path.display()))?,
    )
    .context("parse V7 native bearer metadata")
}

fn validate_metadata(
    actual: &NativeBearerV7KeyInfo,
    expected: &NativeBearerV7KeyInfo,
    identity: &V7SignerIdentity,
    policy: &V7BodyPolicy,
    now: i64,
    allow_expired: bool,
) -> Result<()> {
    if actual.decode_binding().map_err(anyhow::Error::msg)?
        != expected.decode_binding().map_err(anyhow::Error::msg)?
    {
        bail!("V7 signer metadata does not match the secret key");
    }
    if actual.profile_id != identity.profile_id
        || actual.issuer_id != identity.issuer_id
        || actual.token_key_id != hex::encode(identity.token_key_id.as_bytes())
    {
        bail!("V7 signer metadata identity does not match descriptor");
    }
    if actual.body_policy().map_err(anyhow::Error::msg)? != *policy {
        bail!("V7 signer metadata policy does not match configuration");
    }
    if actual.valid_from >= actual.valid_until || (!allow_expired && actual.valid_until <= now) {
        bail!("V7 signer metadata has an invalid validity window");
    }
    Ok(())
}

fn exchange_metadata(
    binding: &V7PublicKeyBinding,
    spec: &V7SignerSpec,
    policy: &V7BodyPolicy,
    valid_from: i64,
    valid_until: i64,
) -> Result<NativeBearerV7KeyInfo> {
    let valid_from_u64 = u64::try_from(valid_from).context("invalid V7 exchange start")?;
    let valid_until_u64 = u64::try_from(valid_until).context("invalid V7 exchange end")?;
    let token_key_id = hex::encode(binding.identity().token_key_id().as_bytes());
    let spki_fingerprint = hex::encode(binding.spki_fingerprint());
    let descriptor_id = freebird_common::api::derive_native_exchange_v3_descriptor_id(
        &spec.identity.profile_id,
        binding.identity().issuer_id(),
        &token_key_id,
        policy.asset_id(),
        policy.amount_minor(),
        freebird_common::api::NATIVE_EXCHANGE_V3_SUITE,
        3_072,
        65_537,
        binding.public_key_spki(),
        &spki_fingerprint,
        valid_from_u64,
        valid_until_u64,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let metadata = NativeBearerV7KeyInfo {
        profile_id: spec.identity.profile_id.clone(),
        issuer_id: binding.identity().issuer_id().to_owned(),
        descriptor_id,
        token_key_id,
        asset_id: policy.asset_id().to_owned(),
        amount_minor: policy.amount_minor(),
        suite: freebird_common::api::NATIVE_EXCHANGE_V3_SUITE.to_owned(),
        modulus_bits: 3_072,
        exponent: 65_537,
        pubkey_spki_b64: base64ct::Base64UrlUnpadded::encode_string(binding.public_key_spki()),
        spki_fingerprint,
        valid_from,
        valid_until,
    };
    validate_exchange_metadata(&metadata, binding, spec)?;
    Ok(metadata)
}

fn validate_exchange_metadata(
    metadata: &NativeBearerV7KeyInfo,
    binding: &V7PublicKeyBinding,
    spec: &V7SignerSpec,
) -> Result<()> {
    if metadata.profile_id != freebird_common::api::NATIVE_EXCHANGE_V3_PROFILE_ID
        || metadata.profile_id != spec.identity.profile_id
        || metadata.issuer_id != spec.identity.issuer_id
        || metadata.token_key_id != hex::encode(spec.identity.token_key_id().as_bytes())
        || metadata.asset_id != spec.asset_id
        || metadata.amount_minor != spec.amount_minor
        || metadata.suite != freebird_common::api::NATIVE_EXCHANGE_V3_SUITE
        || metadata.modulus_bits != 3_072
        || metadata.exponent != 65_537
        || metadata.valid_from <= 0
        || metadata.valid_from >= metadata.valid_until
        || metadata.valid_until > freebird_common::api::EXCHANGE_MAX_VALID_UNTIL
    {
        bail!("invalid native V7 exchange signer metadata");
    }
    if metadata.decode_binding().map_err(anyhow::Error::msg)? != *binding {
        bail!("V7 exchange signer metadata does not match private key");
    }
    let descriptor = freebird_common::api::NativeExchangeV3Descriptor {
        descriptor_id: metadata.descriptor_id.clone(),
        profile_id: metadata.profile_id.clone(),
        issuer_id: metadata.issuer_id.clone(),
        token_key_id: metadata.token_key_id.clone(),
        asset_id: metadata.asset_id.clone(),
        amount_minor: metadata.amount_minor.to_string(),
        suite: metadata.suite.clone(),
        modulus_bits: metadata.modulus_bits,
        exponent: metadata.exponent,
        pubkey_spki_b64: metadata.pubkey_spki_b64.clone(),
        spki_fingerprint: metadata.spki_fingerprint.clone(),
        valid_from: u64::try_from(metadata.valid_from).context("invalid V7 exchange start")?,
        valid_until: u64::try_from(metadata.valid_until).context("invalid V7 exchange end")?,
    };
    descriptor
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(())
}

fn write_secret_key(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn write_metadata(path: &Path, metadata: &NativeBearerV7KeyInfo) -> Result<()> {
    let tmp = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
    let mut file = std::fs::File::create(&tmp)?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(metadata)?)?;
    file.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn spec_with_profile(root: &Path, id: u8, profile: &str, descriptor: &str) -> V7SignerSpec {
        let config = NativeBearerV7Config {
            sk_path: root.join(format!("{id}.der")),
            metadata_path: root.join(format!("{id}.json")),
            registry_path: root.join("registry.json"),
            profile_id: profile.into(),
            descriptor_id: descriptor.into(),
            token_key_id: format!("{id:02x}").repeat(32),
            asset_id: "USD".into(),
            amount_minor: 42,
            validity_secs: 3600,
        };
        V7SignerSpec::from_native_config(&config, "issuer:test").unwrap()
    }

    fn spec(root: &Path, id: u8, descriptor: &str) -> V7SignerSpec {
        let _ = descriptor;
        spec_with_profile(root, id, "scarcity/native-bearer/v7", "")
    }

    #[test]
    fn inventory_rejects_duplicate_token_key_id_and_spki_fingerprint() {
        let root = tempdir().unwrap();
        let first = spec(root.path(), 1, &"06".repeat(32));
        let duplicate_key = spec(root.path(), 1, &"02".repeat(32));
        assert!(V7SignerInventory::load_or_generate(
            first.clone(),
            vec![duplicate_key],
            &root.path().join("registry.json")
        )
        .is_err());

        let first_descriptor = V7Signer::load_or_generate(&first)
            .unwrap()
            .metadata()
            .descriptor_id
            .clone();
        let duplicate_descriptor = spec_with_profile(
            root.path(),
            2,
            "freebird/native-exchange/v3",
            &first_descriptor,
        );
        assert!(V7SignerInventory::load_or_generate(
            first.clone(),
            vec![duplicate_descriptor],
            &root.path().join("registry-descriptor.json")
        )
        .is_err());

        let second = spec(root.path(), 3, &"04".repeat(32));
        let duplicate_spki = V7Signer::load_or_generate(&first).unwrap();
        std::fs::write(&second.sk_path, std::fs::read(&first.sk_path).unwrap()).unwrap();
        assert!(V7SignerInventory::load_or_generate(
            first,
            vec![second],
            &root.path().join("registry2.json")
        )
        .is_err());
        assert!(!duplicate_spki.metadata().spki_fingerprint.is_empty());

        let durable = spec(root.path(), 4, &"08".repeat(32));
        V7SignerInventory::load_or_generate(
            durable.clone(),
            Vec::new(),
            &root.path().join("registry-durable.json"),
        )
        .unwrap();
        let changed_descriptor = spec_with_profile(
            root.path(),
            4,
            "scarcity/native-bearer/v7",
            &"09".repeat(32),
        );
        assert!(V7SignerInventory::load_or_generate(
            changed_descriptor,
            Vec::new(),
            &root.path().join("registry-durable.json"),
        )
        .is_err());

        let exchange = spec_with_profile(root.path(), 5, "freebird/native-exchange/v3", "");
        let exchange = V7SignerInventory::load_or_generate(
            exchange,
            Vec::new(),
            &root.path().join("registry-exchange.json"),
        )
        .unwrap();
        assert_eq!(
            exchange.active().identity().profile_id(),
            "freebird/native-exchange/v3"
        );
        assert_eq!(
            exchange.active().identity().descriptor_id(),
            exchange.active().metadata().descriptor_id
        );
    }

    #[test]
    fn exchange_bootstrap_can_be_pinned_only_to_its_derived_descriptor() {
        let root = tempdir().unwrap();
        let bootstrap = spec_with_profile(root.path(), 6, "freebird/native-exchange/v3", "");
        let registry = root.path().join("exchange-pin-registry.json");
        let signer = V7SignerInventory::load_or_generate(bootstrap, Vec::new(), &registry).unwrap();
        let descriptor = signer.active().metadata().descriptor_id.clone();

        let pinned = spec_with_profile(root.path(), 6, "freebird/native-exchange/v3", &descriptor);
        V7SignerInventory::load_or_generate(pinned, Vec::new(), &registry).unwrap();

        let arbitrary = spec_with_profile(
            root.path(),
            6,
            "freebird/native-exchange/v3",
            &"aa".repeat(32),
        );
        assert!(V7SignerInventory::load_or_generate(arbitrary, Vec::new(), &registry).is_err());
    }

    #[test]
    fn fresh_pinned_exchange_never_creates_key_or_metadata() {
        let root = tempdir().unwrap();
        let spec = spec_with_profile(
            root.path(),
            7,
            "freebird/native-exchange/v3",
            &"aa".repeat(32),
        );
        let sk_path = spec.sk_path.clone();
        let metadata_path = spec.metadata_path.clone();
        assert!(V7SignerInventory::load_or_generate(
            spec,
            Vec::new(),
            &root.path().join("fresh-pin-registry.json"),
        )
        .is_err());
        assert!(!sk_path.exists());
        assert!(!metadata_path.exists());
    }

    #[test]
    fn graph_signer_bootstraps_and_restarts_without_exchange_validation() {
        let root = tempdir().unwrap();
        let config = spec_with_profile(
            root.path(),
            8,
            freebird_common::api::NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
            &"bb".repeat(32),
        );
        let registry = root.path().join("graph-registry.json");
        let first =
            V7SignerInventory::load_or_generate(config.clone(), Vec::new(), &registry).unwrap();
        assert_eq!(
            first.active().metadata().profile_id,
            freebird_common::api::NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID
        );
        assert_eq!(first.active().metadata().descriptor_id, "bb".repeat(32));

        let restarted = V7SignerInventory::load_or_generate(config, Vec::new(), &registry).unwrap();
        assert_eq!(restarted.active().metadata().descriptor_id, "bb".repeat(32));
    }

    #[tokio::test]
    async fn lookup_policy_expiry_and_blind_boundaries_are_enforced() {
        let root = tempdir().unwrap();
        let signer = V7Signer::load_or_generate(&spec(root.path(), 3, &"04".repeat(32))).unwrap();
        assert!(signer.validate_policy("USD", 42).is_ok());
        assert!(signer.validate_policy("EUR", 42).is_err());
        assert!(signer.is_valid_at(signer.metadata().valid_until));
        assert!(!signer.is_valid_at(signer.metadata().valid_until + 1));

        let signer = Arc::new(signer);
        let identity = signer.identity().clone();
        let wrong = V7SignerIdentity::new(
            identity.issuer_id(),
            identity.profile_id(),
            "05".repeat(32),
            *identity.token_key_id(),
        )
        .unwrap();
        // The complete descriptor/key tuple, rather than only the key ID, is
        // the lookup identity.
        let inventory =
            V7SignerInventory::from_signers(signer.clone(), vec![signer.clone()], None).unwrap();
        assert!(inventory.lookup(&wrong).is_err());

        for bytes in [vec![0; 383], vec![0; 385]] {
            assert!(V7BlindMessage::from_bytes(&bytes).is_err());
        }
        assert!(signer
            .sign(&V7BlindMessage::from_bytes(&[0; 384]).unwrap())
            .await
            .is_err());
        let key =
            PublicKeySha384PSSRandomized::from_spki(signer.binding().public_key_spki()).unwrap();
        let modulus = key.components().n().clone();
        let mut one = [0; 384];
        one[383] = 1;
        let one = V7BlindMessage::from_bytes(&one).unwrap();
        for now in [signer.metadata().valid_from, signer.metadata().valid_until] {
            assert_eq!(signer.preflight_at(&one, now), Ok(()));
        }
        for now in [
            signer.metadata().valid_from - 1,
            signer.metadata().valid_until + 1,
        ] {
            assert_eq!(
                signer.preflight_at(&one, now),
                Err(V7PreflightError::Unavailable)
            );
            assert!(signer.sign_at(&one, now).await.is_err());
        }
        for bytes in [vec![0; 384], modulus.clone(), vec![0xff; 384]] {
            assert_eq!(
                signer.preflight_at(
                    &V7BlindMessage::from_bytes(&bytes).unwrap(),
                    signer.metadata().valid_from
                ),
                Err(V7PreflightError::InvalidRepresentative)
            );
        }
        let mut below = modulus.clone();
        // An RSA modulus is odd, so subtracting one cannot borrow here.
        *below.last_mut().unwrap() -= 1;
        assert_eq!(
            signer.preflight_at(
                &V7BlindMessage::from_bytes(&below).unwrap(),
                signer.metadata().valid_from
            ),
            Ok(())
        );
        assert!(signer
            .sign(&V7BlindMessage::from_bytes(&modulus).unwrap())
            .await
            .is_err());
    }
}
