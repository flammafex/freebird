// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use anyhow::{anyhow, Context};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::V7KeyDiscoveryResp;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tracing::{info, instrument, warn};

use crate::readiness::{MetadataStatus, TokenFamily};
use crate::state::{commit_v7_trust, family_enabled, AppState, V7IssuerTrustSnapshot};

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
    /// When this issuer's metadata was last refreshed.
    pub last_refreshed: Option<Instant>,
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

async fn load_v7_trust(issuer_url: &str, issuer_id: &str) -> anyhow::Result<V7IssuerTrustSnapshot> {
    let keys_url = issuer_keys_url(issuer_url)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build HTTP client")?;
    let url = reqwest::Url::parse(&keys_url).context("parse V7 keys URL")?;
    let response = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("V7 issuer key discovery request failed: {keys_url}"))?;
    let discovery: V7KeyDiscoveryResp = response
        .json()
        .await
        .context("deserialize V7 issuer key discovery")?;
    crate::discovery::trusted_v7_keys(issuer_id, discovery)
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
    let v7_trust = if family_enabled(&state.accepted_token_families, TokenFamily::V7) {
        Some(load_v7_trust(issuer_url, &wk.issuer_id).await?)
    } else {
        None
    };

    // Do not even parse issuer VOPRF key material or read verifier key files
    // when V4 is disabled. This keeps V7-only deployments independent of V4.
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
    // Hold both state locks until the validated trust snapshot and freshness
    // marker have been committed.  Validation/history failures therefore
    // leave the last good issuer state and freshness untouched.
    let mut issuers = state.issuers.write().await;
    let mut metadata = state.metadata.write().await;
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
    if let Some(snapshot) = v7_trust {
        // Discovery has been completely fetched and validated, including all
        // direct, retained, exchange, and graph records.  Only now can the
        // process-lifetime trust history advance.  Any failure leaves both
        // the prior snapshot and metadata freshness untouched.
        commit_v7_trust(&wk.issuer_id, snapshot)?;
    }
    let refreshed_at = Instant::now();

    let has_private_key = verification_key.is_some();
    let public_key_count = v7_trust_snapshot_count(&wk.issuer_id);
    let info = IssuerInfo {
        pubkey_bytes,
        kid: wk.voprf.kid,
        ctx,
        verification_key,
        deprecated_verification_keys,
        last_refreshed: Some(refreshed_at),
    };

    issuers.insert(wk.issuer_id.clone(), info);
    metadata.insert(
        issuer_url.to_string(),
        MetadataStatus {
            issuer_id: Some(wk.issuer_id.clone()),
            last_refresh: Some(refreshed_at),
        },
    );
    info!(issuer = %wk.issuer_id, kid = %kid_for_log, ctx_len, has_private_key, public_key_count, "updated issuer metadata");
    Ok(())
}

fn v7_trust_snapshot_count(issuer_id: &str) -> usize {
    crate::state::v7_trust_snapshot(issuer_id)
        .map(|snapshot| snapshot.by_token_key_id.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::load_v7_trust;
    use axum::{routing::get, Json, Router};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use freebird_common::api::{
        NativeBearerV7KeyInfo, V7KeyDiscoveryResp, V7VoprfKeyInfo, EXCHANGE_MAX_VALID_UNTIL,
        NATIVE_BEARER_V7_PROFILE_ID,
    };
    use freebird_crypto::{
        provider::software::SoftwareV7BlindRsaProvider, V7BodyPolicy, V7KeyIdentity, V7TokenKeyId,
    };

    fn strict_v7_discovery() -> V7KeyDiscoveryResp {
        let issuer_id = "issuer:test:v7-metadata";
        let identity = V7KeyIdentity::new(issuer_id, V7TokenKeyId::new([1; 32])).unwrap();
        let provider = SoftwareV7BlindRsaProvider::generate(identity).unwrap();
        let policy = V7BodyPolicy::new("USD", 1).unwrap();
        let direct = NativeBearerV7KeyInfo::from_binding(
            provider.binding(),
            NATIVE_BEARER_V7_PROFILE_ID,
            &"11".repeat(32),
            &policy,
            1,
            EXCHANGE_MAX_VALID_UNTIL,
        )
        .unwrap();
        V7KeyDiscoveryResp {
            issuer_id: issuer_id.into(),
            current_epoch: 1,
            valid_epochs: vec![1],
            epoch_duration_sec: 86_400,
            voprf: V7VoprfKeyInfo {
                suite: "VOPRF-P256-SHA256".into(),
                kid: "v7-kid".into(),
                pubkey: "v7-pubkey".into(),
            },
            native_bearer_v7: direct,
            native_bearer_v7_retained: vec![],
            native_exchange_v7: None,
            native_graph_issuance_v7: None,
        }
    }

    async fn serve(discovery: serde_json::Value) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/.well-known/keys",
            get(move || {
                let discovery = discovery.clone();
                async move { Json(discovery) }
            }),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn load_v7_trust_consumes_strict_keys_only() {
        let discovery = strict_v7_discovery();
        let (url, task) = serve(serde_json::to_value(&discovery).unwrap()).await;
        let trust = load_v7_trust(&url, &discovery.issuer_id).await.unwrap();
        assert_eq!(trust.by_token_key_id.len(), 1);
        task.abort();

        let legacy = serde_json::json!({
            "issuer_id": discovery.issuer_id,
            "current_epoch": 1,
            "valid_epochs": [1],
            "epoch_duration_sec": 86400,
            "voprf": {"suite": "suite", "kid": "kid", "pubkey": "pubkey"},
            "public": [{
                "token_key_id": "11",
                "token_type": "public-bearer",
                "rfc9474_variant": "legacy",
                "modulus_bits": 2048,
                "pubkey_spki_b64": Base64UrlUnpadded::encode_string(&[1, 2, 3]),
                "issuer_id": "issuer:test:v7-metadata",
                "valid_from": 1,
                "valid_until": 2,
                "spend_policy": "single_use"
            }]
        });
        let (url, task) = serve(legacy).await;
        assert!(load_v7_trust(&url, "issuer:test:v7-metadata")
            .await
            .is_err());
        task.abort();
    }
}
