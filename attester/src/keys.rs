// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::types::SocialGraphAttestation;
use anyhow::{Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::{fs, io::Write, path::Path};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct AttesterKey {
    pub kid: String,
    signing: SigningKey,
}

impl AttesterKey {
    pub fn load_or_generate(path: &str, kid: String) -> Result<Self> {
        let p = Path::new(path);
        let seed = if p.exists() {
            Zeroizing::new(fs::read(p).context("read attester key")?)
        } else {
            let sk = SigningKey::generate(&mut OsRng);
            let bytes = sk.to_bytes();
            write_key_file(p, &bytes)?;
            Zeroizing::new(bytes.to_vec())
        };
        let arr: [u8; 32] = seed
            .as_slice()
            .try_into()
            .context("attester key must be 32 bytes")?;
        Ok(Self {
            kid,
            signing: SigningKey::from_bytes(&arr),
        })
    }
    pub fn from_signing_key(kid: String, signing: SigningKey) -> Self {
        Self { kid, signing }
    }
    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
    pub fn sign_attestation(&self, att: &mut SocialGraphAttestation) -> Result<()> {
        att.signature.clear();
        let msg = canonical_attestation(att)?;
        att.signature = hex::encode(self.signing.sign(msg.as_bytes()).to_bytes());
        Ok(())
    }
    pub fn jwks(&self) -> Value {
        json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":self.kid,"use":"sig","alg":"EdDSA","x":Base64UrlUnpadded::encode_string(self.public_key().as_bytes())}]})
    }
}

pub fn canonical_attestation(att: &SocialGraphAttestation) -> Result<String> {
    let mut v = serde_json::to_value(att)?;
    if let Value::Object(ref mut m) = v {
        m.remove("signature");
    }
    String::from_utf8(canonical_json(&v)?).context("canonical JSON must be UTF-8")
}

pub fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let out = match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (idx, key) in keys.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                out.push_str(&String::from_utf8(canonical_json(&map[*key])?)?);
            }
            out.push('}');
            out
        }
        Value::Array(values) => {
            let parts: Result<Vec<_>> = values
                .iter()
                .map(|value| Ok(String::from_utf8(canonical_json(value)?)?))
                .collect();
            format!("[{}]", parts?.join(","))
        }
        _ => serde_json::to_string(value)?,
    };
    Ok(out.into_bytes())
}

fn write_key_file(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(tmp, path)?;
    Ok(())
}
