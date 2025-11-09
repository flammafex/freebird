// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    pkcs8::DecodePrivateKey,
    SecretKey,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{env, fs, io::Write, path::Path};
use tracing::{info, warn};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt; // for mode 0o600

const DEFAULT_PATH: &str = "issuer_sk.bin";

/// Returns (raw_secret_32, pubkey_sec1_b64url, kid)
pub fn load_or_generate_keypair_b64() -> Result<([u8; 32], String, String)> {
    let path = env::var("ISSUER_SK_PATH").unwrap_or_else(|_| DEFAULT_PATH.to_string());
    let p = Path::new(&path);

    // 1) Try to read an existing key (strict parsing: try PKCS#8 DER first, then raw 32)
    if let Ok(bytes) = fs::read(p) {
        // a) PKCS#8 DER (preferred for future portability)
        if let Ok(sk_pkcs8) = SecretKey::from_pkcs8_der(&bytes) {
            let sk = SigningKey::from(&sk_pkcs8);
            let (sk_bytes, pubkey_b64, kid) = finalize(sk)?;
            info!("issuer key loaded (PKCS#8) path={} kid={}", path, kid);
            return Ok((sk_bytes, pubkey_b64, kid));
        }

        // b) Raw 32-byte scalar
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("32-byte key copy failed (unexpected)"))?;
            let sk = SigningKey::from_bytes(&arr.into())
                .map_err(|_| anyhow!("stored 32-byte scalar is not a valid P-256 key"))?;
            let (sk_bytes, pubkey_b64, kid) = finalize(sk)?;
            info!("issuer key loaded (raw 32B) path={} kid={}", path, kid);
            return Ok((sk_bytes, pubkey_b64, kid));
        }

        // c) Unknown format
        warn!(
            "unrecognized key format: {} bytes (expected PKCS#8 DER or 32 bytes)",
            bytes.len()
        );
        return Err(anyhow!(
            "unrecognized key format: {} bytes (expected PKCS#8 DER or 32 bytes)",
            bytes.len()
        ));
    }

    // 2) No file: generate a new key and write raw 32 bytes to disk
    let sk = SigningKey::random(&mut OsRng);
    let raw = sk.to_bytes(); // SecretBytes (zeroizes on drop)
    atomic_write_secure(p, raw.as_ref()).context("write issuer secret key atomically")?;
    let (sk_bytes, pubkey_b64, kid) = finalize(sk)?;
    info!("issuer key created path={} kid={}", path, kid);
    Ok((sk_bytes, pubkey_b64, kid))
}

// ---------- helpers ----------

fn finalize(sk: SigningKey) -> Result<([u8; 32], String, String)> {
    let pk = VerifyingKey::from(&sk);
    let pk_sec1 = pk.to_encoded_point(true); // compressed, 33 bytes
    let pubkey_b64 = Base64UrlUnpadded::encode_string(pk_sec1.as_bytes());
    let kid = make_kid(pk_sec1.as_bytes());

    let secret = sk.to_bytes();
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(secret.as_ref());

    Ok((sk_bytes, pubkey_b64, kid))
}

fn make_kid(sec1_compressed: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"freebird:issuer:pk:");
    h.update(sec1_compressed);
    let digest = h.finalize();
    let mut s = Base64UrlUnpadded::encode_string(&digest);
    s.truncate(24);
    s
}

/// Atomic write with restrictive permissions where possible.
fn atomic_write_secure(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }

    fs::rename(&tmp, path)?;
    Ok(())
}
