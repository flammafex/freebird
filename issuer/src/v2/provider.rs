use anyhow::{bail, Context, Result};
use freebird_crypto::scarcity_v2::{validate_keyset, Keyset, V2SigningProvider};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct V2IssuerConfig {
    pub keyset_json_path: PathBuf,
    pub private_key_path: PathBuf,
}

impl V2IssuerConfig {
    pub fn from_env() -> Result<Option<Self>> {
        let keyset = std::env::var("SCARCITY_V2_KEYSET_JSON_PATH").ok();
        let private = std::env::var("SCARCITY_V2_PRIVATE_KEY_PATH").ok();
        match (keyset, private) { (None, None) => Ok(None), (Some(keyset_json_path), Some(private_key_path)) => Ok(Some(Self { keyset_json_path: keyset_json_path.into(), private_key_path: private_key_path.into() })), _ => bail!("SCARCITY_V2_KEYSET_JSON_PATH and SCARCITY_V2_PRIVATE_KEY_PATH must be set together") }
    }
    pub fn load_provider(&self) -> Result<V2SigningProvider> {
        let json = fs::read(&self.keyset_json_path)
            .with_context(|| format!("read V2 keyset JSON {}", self.keyset_json_path.display()))?;
        let public: V2KeysetJson =
            serde_json::from_slice(&json).context("parse strict V2 keyset JSON")?;
        let keyset = public.into_keyset()?;
        validate_keyset(&keyset).map_err(|e| anyhow::anyhow!("invalid V2 keyset: {e}"))?;
        reject_private_permissions(&self.private_key_path)?;
        let private = fs::read(&self.private_key_path).context("read V2 private RSA key")?;
        V2SigningProvider::from_der(&private, &keyset.modulus)
            .map_err(|e| anyhow::anyhow!("load V2 signing provider: {e}"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V2KeysetJson {
    issuer_id: String,
    keyset_id: String,
    asset_id: String,
    spend_domain: String,
    denomination: u64,
    issuance_epoch: u64,
    expiry_epoch: u64,
    modulus: String,
    public_exponent: u32,
    suite: String,
    authority_key_id: String,
}

impl V2KeysetJson {
    fn into_keyset(self) -> Result<Keyset> {
        Ok(Keyset {
            issuer_id: hex32(&self.issuer_id)?,
            keyset_id: hex32(&self.keyset_id)?,
            asset_id: hex32(&self.asset_id)?,
            spend_domain: hex32(&self.spend_domain)?,
            denomination: self.denomination,
            issuance_epoch: self.issuance_epoch,
            expiry_epoch: self.expiry_epoch,
            modulus: hex_exact(&self.modulus, 384)?,
            public_exponent: self.public_exponent,
            suite: self.suite,
            authority_key_id: hex32(&self.authority_key_id)?,
        })
    }
}
fn hex_exact(value: &str, bytes: usize) -> Result<Vec<u8>> {
    if value.len() != bytes * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid hex field");
    }
    Ok(hex::decode(value)?)
}
fn hex32(value: &str) -> Result<Vec<u8>> {
    hex_exact(value, 32)
}
fn reject_private_permissions(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).context("stat V2 private RSA key")?;
    if !metadata.is_file() {
        bail!("V2 private RSA key is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("V2 private RSA key permissions are too broad");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSRandomized};
    use freebird_crypto::scarcity_v2::keyset_id;
    use serde_json::json;
    use serial_test::serial;
    use tempfile::TempDir;
    #[test]
    #[serial]
    fn v2_config_is_disabled_without_both_paths() {
        std::env::remove_var("SCARCITY_V2_KEYSET_JSON_PATH");
        std::env::remove_var("SCARCITY_V2_PRIVATE_KEY_PATH");
        assert!(V2IssuerConfig::from_env().unwrap().is_none());
    }
    #[test]
    fn v2_keyset_json_rejects_unknown_and_malformed_fields() {
        let value = json!({"issuer_id":"00","keyset_id":"00","asset_id":"00","spend_domain":"00","denomination":1,"issuance_epoch":1,"expiry_epoch":2,"modulus":"00","public_exponent":65537,"suite":"RSABSSA-SHA384-PSS-Randomized","authority_key_id":"00","unknown":true});
        assert!(serde_json::from_value::<V2KeysetJson>(value).is_err());
        assert!(hex32("00").is_err());
        assert!(hex_exact("zz", 1).is_err());
    }

    fn valid_case() -> (TempDir, V2IssuerConfig) {
        let mut rng = DefaultRng;
        let pair = KeyPairSha384PSSRandomized::generate(&mut rng, 3072).unwrap();
        let modulus = pair.pk.components().n();
        let mut keyset = Keyset {
            issuer_id: vec![1; 32],
            keyset_id: vec![0; 32],
            asset_id: vec![2; 32],
            spend_domain: vec![3; 32],
            denomination: 10,
            issuance_epoch: 1,
            expiry_epoch: 2,
            modulus: modulus.clone(),
            public_exponent: 65537,
            suite: "RSABSSA-SHA384-PSS-Randomized".into(),
            authority_key_id: vec![4; 32],
        };
        keyset.keyset_id = keyset_id(&keyset).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keyset_path = dir.path().join("keyset.json");
        let private_path = dir.path().join("private.der");
        let json = json!({"issuer_id":hex::encode(&keyset.issuer_id),"keyset_id":hex::encode(&keyset.keyset_id),"asset_id":hex::encode(&keyset.asset_id),"spend_domain":hex::encode(&keyset.spend_domain),"denomination":10,"issuance_epoch":1,"expiry_epoch":2,"modulus":hex::encode(&modulus),"public_exponent":65537,"suite":keyset.suite,"authority_key_id":hex::encode(&keyset.authority_key_id)});
        std::fs::write(&keyset_path, serde_json::to_vec(&json).unwrap()).unwrap();
        std::fs::write(&private_path, pair.sk.to_der().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        (
            dir,
            V2IssuerConfig {
                keyset_json_path: keyset_path,
                private_key_path: private_path,
            },
        )
    }

    #[test]
    fn v2_valid_provider_loads() {
        let (_dir, config) = valid_case();
        config.load_provider().unwrap();
    }

    #[test]
    #[serial]
    fn v2_partial_path_configuration_rejected() {
        std::env::set_var("SCARCITY_V2_KEYSET_JSON_PATH", "keyset.json");
        std::env::remove_var("SCARCITY_V2_PRIVATE_KEY_PATH");
        assert!(V2IssuerConfig::from_env().is_err());
        std::env::remove_var("SCARCITY_V2_KEYSET_JSON_PATH");
    }

    #[test]
    fn v2_wrong_suite_exponent_and_keyset_identity_rejected() {
        for (field, value) in [
            ("suite", json!("wrong")),
            ("public_exponent", json!(3)),
            ("keyset_id", json!(hex::encode([9u8; 32]))),
        ] {
            let (_dir, config) = valid_case();
            let mut object: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&config.keyset_json_path).unwrap()).unwrap();
            object[field] = value;
            std::fs::write(
                &config.keyset_json_path,
                serde_json::to_vec(&object).unwrap(),
            )
            .unwrap();
            assert!(config.load_provider().is_err(), "{field} must be rejected");
        }
    }

    #[cfg(unix)]
    #[test]
    fn v2_unsafe_private_key_permissions_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, config) = valid_case();
        std::fs::set_permissions(
            &config.private_key_path,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(config.load_provider().is_err());
    }
}
