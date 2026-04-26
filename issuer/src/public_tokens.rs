use crate::config::PublicKeyConfig;
use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::PublicKeyInfo;
use freebird_crypto::provider::software::SoftwareBlindRsaProvider;
use freebird_crypto::provider::BlindRsaProvider;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use time::OffsetDateTime;

pub struct PublicTokenIssuer {
    provider: SoftwareBlindRsaProvider,
    metadata: PublicKeyInfo,
    token_key_id: [u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN],
}

impl PublicTokenIssuer {
    pub fn load_or_generate(config: &PublicKeyConfig, issuer_id: &str) -> Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        let provider = load_or_generate_provider(&config.sk_path, config.modulus_bits)
            .with_context(|| format!("load V5 public bearer key {}", config.sk_path.display()))?;
        let token_key_id = *provider.token_key_id();
        let token_key_id_hex = freebird_crypto::encode_token_key_id_hex(&token_key_id);
        let pubkey_spki_b64 = Base64UrlUnpadded::encode_string(provider.public_key_spki());

        let computed = PublicKeyInfo {
            token_key_id: token_key_id_hex.clone(),
            token_type: freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE.to_string(),
            rfc9474_variant: freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT.to_string(),
            modulus_bits: provider.modulus_bits(),
            pubkey_spki_b64: pubkey_spki_b64.clone(),
            issuer_id: issuer_id.to_string(),
            valid_from: OffsetDateTime::now_utc().unix_timestamp(),
            valid_until: OffsetDateTime::now_utc().unix_timestamp()
                + i64::try_from(config.validity_secs)
                    .context("PUBLIC_BEARER_VALIDITY too large")?,
            audience: config.audience.clone(),
            spend_policy: freebird_crypto::PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE.to_string(),
            max_uses: None,
        };

        let metadata = if config.metadata_path.exists() {
            let bytes = fs::read(&config.metadata_path)
                .with_context(|| format!("read {}", config.metadata_path.display()))?;
            let metadata: PublicKeyInfo =
                serde_json::from_slice(&bytes).context("parse V5 public bearer metadata")?;
            validate_metadata(&metadata, &computed)?;
            metadata
        } else {
            write_metadata(&config.metadata_path, &computed)?;
            computed
        };

        Ok(Some(Self {
            provider,
            metadata,
            token_key_id,
        }))
    }

    pub async fn blind_sign(&self, blinded_msg: &[u8]) -> Result<Vec<u8>> {
        self.provider.blind_sign(blinded_msg).await
    }

    pub fn metadata(&self) -> &PublicKeyInfo {
        &self.metadata
    }

    pub fn token_key_id(&self) -> &[u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN] {
        &self.token_key_id
    }

    pub fn token_key_id_hex(&self) -> &str {
        &self.metadata.token_key_id
    }

    pub fn modulus_bytes(&self) -> usize {
        usize::from(self.metadata.modulus_bits) / 8
    }
}

fn load_or_generate_provider(path: &Path, modulus_bits: usize) -> Result<SoftwareBlindRsaProvider> {
    if path.exists() {
        let der = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        return SoftwareBlindRsaProvider::from_der(&der);
    }

    let provider = SoftwareBlindRsaProvider::generate(modulus_bits)?;
    let der = provider.to_der()?;
    write_secret_key(path, &der)?;
    Ok(provider)
}

fn validate_metadata(actual: &PublicKeyInfo, expected: &PublicKeyInfo) -> Result<()> {
    if actual.token_key_id != expected.token_key_id {
        bail!("V5 public bearer metadata token_key_id does not match private key");
    }
    if actual.token_type != freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE {
        bail!("unsupported V5 public bearer token_type");
    }
    if actual.rfc9474_variant != freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT {
        bail!("unsupported V5 public bearer RFC 9474 variant");
    }
    if actual.modulus_bits != expected.modulus_bits {
        bail!("V5 public bearer metadata modulus_bits does not match private key");
    }
    if actual.pubkey_spki_b64 != expected.pubkey_spki_b64 {
        bail!("V5 public bearer metadata SPKI does not match private key");
    }
    if actual.issuer_id != expected.issuer_id {
        bail!("V5 public bearer metadata issuer_id does not match config");
    }
    if actual.spend_policy != freebird_crypto::PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE {
        bail!("V5 public bearer spend_policy must be single_use");
    }
    if actual.valid_from >= actual.valid_until {
        bail!("V5 public bearer metadata has invalid validity window");
    }
    if actual.valid_until <= OffsetDateTime::now_utc().unix_timestamp() {
        bail!("V5 public bearer metadata has expired; rotate the public bearer key");
    }
    Ok(())
}

fn write_secret_key(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp_path = tmp_path(path);

    #[cfg(unix)]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("open {}", tmp_path.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut file =
            fs::File::create(&tmp_path).with_context(|| format!("open {}", tmp_path.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, path).with_context(|| format!("persist {}", path.display()))?;
    Ok(())
}

fn write_metadata(path: &Path, metadata: &PublicKeyInfo) -> Result<()> {
    let tmp_path = tmp_path(path);
    let bytes = serde_json::to_vec_pretty(metadata).context("serialize V5 public metadata")?;
    fs::write(&tmp_path, bytes).with_context(|| format!("write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).with_context(|| format!("persist {}", path.display()))?;
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.tmp"))
        .unwrap_or_else(|| "tmp".to_string());
    tmp.set_extension(ext);
    tmp
}
