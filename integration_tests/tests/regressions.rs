// SPDX-License-Identifier: Apache-2.0 OR MIT
// Minimal regression suite for high-impact bug classes.

use anyhow::Result;
use async_trait::async_trait;
use axum::{extract::State, http::HeaderMap, Json};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{BatchIssueReq, SybilProof, TokenResult};
use freebird_common::federation::Vouch;
use freebird_crypto::{Client, Server, TOKEN_LEN_V2};
use freebird_issuer::{
    AppStateWithSybil, federation_store::FederationStore, multi_key_voprf::MultiKeyVoprfCore,
    routes::batch_issue, sybil_resistance::SybilResistance,
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
    match store.mark_spent(key, ttl).await {
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
    async fn mark_spent(&self, key: &str, ttl: Duration) -> anyhow::Result<bool> {
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
    let server = Server::from_secret_key(sk, b"freebird:v1")
        .map_err(|e| anyhow::anyhow!("server init failed: {:?}", e))?;
    let pubkey = server.public_key_sec1_compressed();
    let pubkey_b64 = Base64UrlUnpadded::encode_string(&pubkey);
    let kid = "kid-regression".to_string();

    let voprf = Arc::new(MultiKeyVoprfCore::new(sk, pubkey_b64.clone(), kid.clone(), b"freebird:v1")?);
    let temp_dir = tempfile::tempdir()?;
    let federation_store = FederationStore::new(temp_dir.path()).await?;

    let state = Arc::new(AppStateWithSybil {
        issuer_id: "issuer:test:regression".to_string(),
        kid,
        exp_sec: 3600,
        pubkey_b64,
        require_tls: false,
        behind_proxy: false,
        sybil_checker,
        invitation_system: None,
        epoch_duration_sec: 86400,
        epoch_retention: 2,
        federation_store,
    });
    Ok((state, voprf))
}

fn blinded_inputs(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let mut c = Client::new(b"freebird:v1");
            let mut input = [0u8; 32];
            input[0] = i as u8;
            c.blind(&input).expect("blind").0
        })
        .collect()
}

#[tokio::test]
async fn regression_batch_issuance_emits_v2_signature_envelope() -> Result<()> {
    let (state, voprf) = build_issuer_state(None).await?;
    let req = BatchIssueReq {
        blinded_elements: blinded_inputs(3),
        ctx_b64: None,
        sybil_proof: None,
    };

    let Json(resp) = batch_issue::handle_batch(
        State((state, voprf)),
        None,
        HeaderMap::new(),
        Json(req),
    )
    .await
    .map_err(|(s, m)| anyhow::anyhow!("batch issue failed: {} {}", s, m))?;

    assert_eq!(resp.successful, 3);
    for r in resp.results {
        match r {
            TokenResult::Success { token, .. } => {
                let raw = Base64UrlUnpadded::decode_vec(&token)?;
                assert_eq!(raw.len(), TOKEN_LEN_V2);
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

    let Json(resp) = batch_issue::handle_batch(
        State((state, voprf)),
        None,
        HeaderMap::new(),
        Json(req),
    )
    .await
    .map_err(|(s, m)| anyhow::anyhow!("batch issue failed: {} {}", s, m))?;

    assert_eq!(resp.successful, 256);
    assert_eq!(resp.failed, 0);
    Ok(())
}

#[test]
fn regression_vouch_trust_level_tamper_rejected() {
    let ctx = b"freebird:v1";
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, ctx).expect("server");
    let pk = server.public_key_sec1_compressed();

    let mut vouch = Vouch {
        voucher_issuer_id: "issuer:a:v1".to_string(),
        vouched_issuer_id: "issuer:b:v1".to_string(),
        vouched_pubkey: pk.to_vec(),
        expires_at: 9_999_999_999,
        created_at: 1_234_567_890,
        trust_level: Some(5),
        signature: [0u8; 64],
    };
    vouch.signature = vouch.sign(&sk).expect("sign");
    assert!(vouch.verify(&pk));

    vouch.trust_level = Some(99);
    assert!(!vouch.verify(&pk));
}

#[test]
fn regression_vouch_created_after_expiry_rejected() {
    let now = 1_700_000_000i64;
    let skew = 300i64;
    let invalid = Vouch {
        voucher_issuer_id: "issuer:a:v1".to_string(),
        vouched_issuer_id: "issuer:b:v1".to_string(),
        vouched_pubkey: vec![1, 2, 3],
        created_at: now + 10,
        expires_at: now - 10,
        trust_level: Some(50),
        signature: [0u8; 64],
    };
    assert!(!invalid.is_valid_at(now, skew));
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
