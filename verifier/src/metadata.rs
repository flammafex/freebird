// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use anyhow::{anyhow, Context};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::KeyDiscoveryResp;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tracing::{info, instrument, warn};

use crate::readiness::{MetadataStatus, TokenFamily};
use crate::state::{family_enabled, AppState};

/// Information about a trusted issuer.
///
/// This type remains publicly available through
/// `freebird_verifier::routes::admin::IssuerInfo`.
#[derive(Clone, Debug)]
pub struct IssuerInfo {
    pub pubkey_bytes: Vec<u8>,
    pub kid: String,
    pub ctx: Vec<u8>,
    pub verification_key: Option<[u8; 32]>,
    pub deprecated_verification_keys: HashMap<String, [u8; 32]>,
    pub public_keys:
        HashMap<[u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN], PublicIssuerKey>,
    /// When this issuer's metadata was last refreshed.
    pub last_refreshed: Option<Instant>,
}

#[derive(Clone, Debug)]
pub struct PublicIssuerKey {
    pub token_key_id: [u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN],
    pub token_key_id_hex: String,
    pub pubkey_spki: Vec<u8>,
    pub issuer_id: String,
    pub valid_from: i64,
    pub valid_until: i64,
    pub audience: Option<String>,
}

impl IssuerInfo {
    pub fn verification_key_for(&self, kid: &str) -> Option<[u8; 32]> {
        if self.kid == kid {
            self.verification_key
        } else {
            self.deprecated_verification_keys.get(kid).copied()
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct WellKnown {
    issuer_id: String,
    voprf: VoprfInfo,
}

#[derive(Clone, Debug, Deserialize)]
struct VoprfInfo {
    /// VOPRF suite identifier from the issuer well-known JSON (e.g. "P256-SHA256").
    /// Deserialized for completeness; the V4 verifier does not branch on suite name.
    #[allow(dead_code)]
    suite: String,
    kid: String,
    pubkey: String,
}

fn decode_secret_key_b64(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = Base64UrlUnpadded::decode_vec(value.trim()).context("base64 decode secret key")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("secret key must decode to exactly 32 bytes"))
}

fn read_secret_key_file(path: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = std::fs::read(path).with_context(|| format!("read secret key file {path}"))?;
    if bytes.len() == 32 {
        return bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("32-byte secret key copy failed"));
    }

    let text = std::str::from_utf8(&bytes)
        .context("secret key file must be raw 32 bytes or base64url text")?;
    decode_secret_key_b64(text)
}

fn load_default_verification_key() -> anyhow::Result<Option<[u8; 32]>> {
    if let Ok(value) = std::env::var("VERIFIER_SK_B64") {
        return decode_secret_key_b64(&value).map(Some);
    }

    let path = std::env::var("VERIFIER_SK_PATH")
        .or_else(|_| std::env::var("ISSUER_SK_PATH"))
        .ok();
    match path {
        Some(path) => read_secret_key_file(&path).map(Some),
        None => Ok(None),
    }
}

fn load_verification_keyring() -> anyhow::Result<HashMap<String, [u8; 32]>> {
    let Some(raw) = std::env::var("VERIFIER_KEYRING_B64").ok() else {
        return Ok(HashMap::new());
    };

    let encoded: HashMap<String, String> =
        serde_json::from_str(&raw).context("parse VERIFIER_KEYRING_B64 JSON")?;
    encoded
        .into_iter()
        .map(|(kid, key_b64)| decode_secret_key_b64(&key_b64).map(|key| (kid, key)))
        .collect()
}

fn issuer_keys_url(issuer_url: &str) -> anyhow::Result<String> {
    let mut url = reqwest::Url::parse(issuer_url).context("parse issuer metadata URL")?;
    url.set_path("/.well-known/keys");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

async fn load_public_keys(
    issuer_url: &str,
    issuer_id: &str,
) -> anyhow::Result<HashMap<[u8; freebird_crypto::PUBLIC_BEARER_TOKEN_KEY_ID_LEN], PublicIssuerKey>>
{
    let keys_url = issuer_keys_url(issuer_url)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build HTTP client")?;
    let url = reqwest::Url::parse(&keys_url).context("parse keys URL")?;
    let res = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("issuer key discovery request failed: {keys_url}"))?;
    let discovery: KeyDiscoveryResp = res.json().await?;
    crate::discovery::trusted_public_keys(issuer_id, discovery)
}

fn validate_secret_key_matches_pubkey(
    secret_key: [u8; 32],
    ctx: &[u8],
    pubkey_bytes: &[u8],
) -> anyhow::Result<()> {
    let server = freebird_crypto::Server::from_secret_key(secret_key, ctx)
        .map_err(|e| anyhow!("invalid verifier secret key: {:?}", e))?;
    let derived = server.public_key_sec1_compressed();
    if derived.as_slice() != pubkey_bytes {
        return Err(anyhow!(
            "verifier secret key does not match issuer metadata public key"
        ));
    }
    Ok(())
}

#[instrument(skip(state), fields(url = %issuer_url))]
pub(crate) async fn refresh_issuer_metadata(
    state: &Arc<AppState>,
    issuer_url: &str,
) -> anyhow::Result<()> {
    info!(%issuer_url, "fetching issuer metadata");
    let url = reqwest::Url::parse(issuer_url).context("parse issuer metadata URL")?;
    let require_tls = std::env::var("REQUIRE_TLS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if require_tls && url.scheme() != "https" {
        anyhow::bail!("issuer metadata URL must use HTTPS: {}", issuer_url);
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build HTTP client")?;
    let res = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .context("issuer metadata request failed")?;
    let wk: WellKnown = res.json().await?;
    let public_keys = if family_enabled(&state.accepted_token_families, TokenFamily::V5) {
        match load_public_keys(issuer_url, &wk.issuer_id).await {
            Ok(keys) => keys,
            Err(e) => {
                warn!(?e, issuer = %wk.issuer_id, "V5 public bearer key discovery failed");
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };

    // Do not even parse issuer VOPRF key material or read verifier key files
    // when V4 is disabled.  This keeps V5-only deployments independent of V4.
    let (pubkey_bytes, ctx, keyring, verification_key) = if family_enabled(
        &state.accepted_token_families,
        TokenFamily::V4,
    ) {
        let pubkey_bytes =
            Base64UrlUnpadded::decode_vec(&wk.voprf.pubkey).context("base64 decode pubkey")?;
        let ctx = freebird_crypto::VOPRF_CONTEXT_V4.to_vec();
        let mut keyring = load_verification_keyring()?;
        let verification_key = if let Some(key) = keyring.remove(&wk.voprf.kid) {
            validate_secret_key_matches_pubkey(key, &ctx, &pubkey_bytes)?;
            Some(key)
        } else if let Some(key) = load_default_verification_key()? {
            validate_secret_key_matches_pubkey(key, &ctx, &pubkey_bytes)?;
            Some(key)
        } else {
            warn!(issuer = %wk.issuer_id, kid = %wk.voprf.kid, "V4 private verification key unavailable");
            None
        };
        (pubkey_bytes, ctx, keyring, verification_key)
    } else {
        (Vec::new(), Vec::new(), HashMap::new(), None)
    };

    let kid_for_log = wk.voprf.kid.clone();
    let ctx_len = ctx.len();
    let mut issuers = state.issuers.write().await;
    let mut deprecated_verification_keys = issuers
        .get(&wk.issuer_id)
        .map(|info| info.deprecated_verification_keys.clone())
        .unwrap_or_default();
    if let Some(previous) = issuers.get(&wk.issuer_id) {
        if previous.kid != wk.voprf.kid {
            if let Some(previous_key) = previous.verification_key {
                deprecated_verification_keys.insert(previous.kid.clone(), previous_key);
            }
        }
    }
    for (kid, key) in keyring {
        if kid != wk.voprf.kid {
            deprecated_verification_keys.insert(kid, key);
        }
    }

    let has_private_key = verification_key.is_some();
    let public_key_count = public_keys.len();
    let info = IssuerInfo {
        pubkey_bytes,
        kid: wk.voprf.kid,
        ctx,
        verification_key,
        deprecated_verification_keys,
        public_keys,
        last_refreshed: Some(Instant::now()),
    };

    issuers.insert(wk.issuer_id.clone(), info);
    drop(issuers);
    state.metadata.write().await.insert(
        issuer_url.to_string(),
        MetadataStatus {
            issuer_id: Some(wk.issuer_id.clone()),
            last_refresh: Some(Instant::now()),
        },
    );
    info!(issuer = %wk.issuer_id, kid = %kid_for_log, ctx_len, has_private_key, public_key_count, "updated issuer metadata");
    Ok(())
}
