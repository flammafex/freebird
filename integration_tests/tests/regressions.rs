// SPDX-License-Identifier: Apache-2.0 OR MIT
// Minimal regression suite for high-impact bug classes.

use anyhow::Result;
use async_trait::async_trait;
use axum::{extract::State, http::HeaderMap, Json};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{BatchIssueReq, SybilProof, TokenResult};
use freebird_crypto::{Client, Server, VOPRF_CONTEXT_V4};
use freebird_issuer::{
    multi_key_voprf::MultiKeyVoprfCore, routes::batch_issue, sybil_resistance::SybilResistance,
    AppStateWithSybil,
};
use freebird_verifier::store::{InMemoryStore, SpendStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyCode {
    Success,
    ReplayDetected,
    StoreError,
}

async fn verify_once(store: &dyn SpendStore, key: &str, ttl: Duration) -> VerifyCode {
    match store.mark_spent(key, Some(ttl)).await {
        Ok(true) => VerifyCode::Success,
        Ok(false) => VerifyCode::ReplayDetected,
        Err(_) => VerifyCode::StoreError,
    }
}

struct FlakyInMemoryStore {
    inner: Arc<InMemoryStore>,
    failures_remaining: Mutex<usize>,
}

impl FlakyInMemoryStore {
    fn new(inner: Arc<InMemoryStore>, fail_first_n: usize) -> Self {
        Self {
            inner,
            failures_remaining: Mutex::new(fail_first_n),
        }
    }
}

#[async_trait]
impl SpendStore for FlakyInMemoryStore {
    async fn mark_spent(&self, key: &str, ttl: Option<Duration>) -> anyhow::Result<bool> {
        let mut guard = self.failures_remaining.lock().await;
        if *guard > 0 {
            *guard -= 1;
            anyhow::bail!("injected transient store failure");
        }
        drop(guard);
        self.inner.mark_spent(key, ttl).await
    }
}

struct MockNoneSybil;
impl SybilResistance for MockNoneSybil {
    fn verify(&self, proof: &SybilProof) -> anyhow::Result<()> {
        match proof {
            SybilProof::None => Ok(()),
            _ => Err(anyhow::anyhow!("unsupported")),
        }
    }
    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::None)
    }
    fn cost(&self) -> u64 {
        0
    }
}

async fn build_issuer_state(
    sybil_checker: Option<Arc<dyn SybilResistance>>,
) -> Result<(Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)> {
    let sk = [0x7Au8; 32];
    let server = Server::from_secret_key(sk, VOPRF_CONTEXT_V4)
        .map_err(|e| anyhow::anyhow!("server init failed: {:?}", e))?;
    let pubkey = server.public_key_sec1_compressed();
    let pubkey_b64 = Base64UrlUnpadded::encode_string(&pubkey);
    let kid = "kid-regression".to_string();

    let voprf = Arc::new(MultiKeyVoprfCore::new(
        sk,
        pubkey_b64.clone(),
        kid.clone(),
        VOPRF_CONTEXT_V4,
    )?);
    let state = Arc::new(AppStateWithSybil {
        issuer_id: "issuer:test:regression".to_string(),
        kid,
        pubkey_b64,
        require_tls: false,
        behind_proxy: false,
        sybil_checker,
        invitation_system: None,
        public_issuer: None,
        epoch_duration_sec: 86400,
        epoch_retention: 2,
    });
    Ok((state, voprf))
}

fn blinded_inputs(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let mut c = Client::new(VOPRF_CONTEXT_V4);
            let mut input = [0u8; 32];
            input[0] = i as u8;
            c.blind(&input).expect("blind").0
        })
        .collect()
}

#[tokio::test]
async fn regression_batch_issuance_emits_v4_evaluation_only() -> Result<()> {
    let (state, voprf) = build_issuer_state(None).await?;
    let req = BatchIssueReq {
        blinded_elements: blinded_inputs(3),
        ctx_b64: None,
        sybil_proof: None,
    };

    let Json(resp) =
        batch_issue::handle_batch(State((state, voprf)), None, HeaderMap::new(), Json(req))
            .await
            .map_err(|(s, m)| anyhow::anyhow!("batch issue failed: {} {}", s, m))?;

    assert_eq!(resp.successful, 3);
    for r in resp.results {
        match r {
            TokenResult::Success { token, .. } => {
                let raw = Base64UrlUnpadded::decode_vec(&token)?;
                assert_eq!(raw.len(), 131, "VOPRF evaluation token should be 131 bytes");
            }
            TokenResult::Error { message, code } => {
                anyhow::bail!("unexpected issuance error {code}: {message}");
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn regression_batch_parallel_path_no_runtime_panic_under_load() -> Result<()> {
    // Uses enough elements to force issuer batch parallel path (Rayon bridge).
    let (state, voprf) = build_issuer_state(Some(Arc::new(MockNoneSybil))).await?;
    let req = BatchIssueReq {
        blinded_elements: blinded_inputs(256),
        ctx_b64: None,
        sybil_proof: Some(SybilProof::None),
    };

    let Json(resp) =
        batch_issue::handle_batch(State((state, voprf)), None, HeaderMap::new(), Json(req))
            .await
            .map_err(|(s, m)| anyhow::anyhow!("batch issue failed: {} {}", s, m))?;

    assert_eq!(resp.successful, 256);
    assert_eq!(resp.failed, 0);
    Ok(())
}

#[tokio::test]
async fn regression_store_transient_failure_then_retry_then_replay() -> Result<()> {
    let base = Arc::new(InMemoryStore::default());
    let flaky = FlakyInMemoryStore::new(base, 1);
    let key = format!("test:regression:{}", uuid::Uuid::new_v4());
    let ttl = Duration::from_secs(60);

    let first = verify_once(&flaky, &key, ttl).await;
    let second = verify_once(&flaky, &key, ttl).await;
    let third = verify_once(&flaky, &key, ttl).await;

    assert_eq!(first, VerifyCode::StoreError);
    assert_eq!(second, VerifyCode::Success);
    assert_eq!(third, VerifyCode::ReplayDetected);
    Ok(())
}
