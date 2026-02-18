// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: Sybil mode matrix parity for single and batch issuance.

use anyhow::Result;
use axum::{extract::State, http::HeaderMap, http::StatusCode, Json};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{BatchIssueReq, IssueReq, SybilProof, TokenResult};
use freebird_crypto::{Client, Server, TOKEN_LEN_V2};
use freebird_issuer::{
    AppStateWithSybil, federation_store::FederationStore, multi_key_voprf::MultiKeyVoprfCore,
    routes::{batch_issue, issue},
    sybil_resistance::SybilResistance,
};
use std::sync::Arc;

struct MockNoneSybil {
    allow: bool,
}

impl SybilResistance for MockNoneSybil {
    fn verify(&self, proof: &SybilProof) -> anyhow::Result<()> {
        match proof {
            SybilProof::None => {
                if self.allow {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("forced failure"))
                }
            }
            _ => Err(anyhow::anyhow!("unsupported proof for mock")),
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::None)
    }

    fn cost(&self) -> u64 {
        1
    }
}

async fn build_state(
    sybil_checker: Option<Arc<dyn SybilResistance>>,
) -> Result<(Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)> {
    let sk = [0x77u8; 32];
    let server = Server::from_secret_key(sk, b"freebird:v1")
        .map_err(|e| anyhow::anyhow!("server init failed: {:?}", e))?;
    let pubkey = server.public_key_sec1_compressed();
    let pubkey_b64 = Base64UrlUnpadded::encode_string(&pubkey);
    let kid = "kid-sybil-matrix".to_string();

    let voprf = Arc::new(MultiKeyVoprfCore::new(sk, pubkey_b64.clone(), kid.clone(), b"freebird:v1")?);

    let temp_dir = tempfile::tempdir()?;
    let federation_store = FederationStore::new(temp_dir.path()).await?;

    let state = Arc::new(AppStateWithSybil {
        issuer_id: "issuer:test:sybil-matrix".to_string(),
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

fn blinded_element_b64() -> String {
    let mut client = Client::new(b"freebird:v1");
    client
        .blind(&[0x42; 32])
        .expect("blinding should succeed")
        .0
}

async fn run_single(
    state: Arc<AppStateWithSybil>,
    voprf: Arc<MultiKeyVoprfCore>,
    proof: Option<SybilProof>,
) -> Result<Result<usize, StatusCode>> {
    let req = IssueReq {
        blinded_element_b64: blinded_element_b64(),
        ctx_b64: None,
        sybil_proof: proof,
    };

    let result = issue::handle(
        State((state, voprf)),
        None,
        HeaderMap::new(),
        Json(req),
    )
    .await;

    Ok(match result {
        Ok(Json(resp)) => {
            let token = Base64UrlUnpadded::decode_vec(&resp.token)?;
            Ok(token.len())
        }
        Err((status, _)) => Err(status),
    })
}

async fn run_batch(
    state: Arc<AppStateWithSybil>,
    voprf: Arc<MultiKeyVoprfCore>,
    proof: Option<SybilProof>,
) -> Result<Result<usize, StatusCode>> {
    let req = BatchIssueReq {
        blinded_elements: vec![blinded_element_b64()],
        ctx_b64: None,
        sybil_proof: proof,
    };

    let result = batch_issue::handle_batch(
        State((state, voprf)),
        None,
        HeaderMap::new(),
        Json(req),
    )
    .await;

    Ok(match result {
        Ok(Json(resp)) => match &resp.results[0] {
            TokenResult::Success { token, .. } => {
                let raw = Base64UrlUnpadded::decode_vec(token)?;
                Ok(raw.len())
            }
            TokenResult::Error { .. } => Err(StatusCode::BAD_REQUEST),
        },
        Err((status, _)) => Err(status),
    })
}

#[tokio::test]
async fn sybil_none_mode_accepts_with_or_without_proof_on_both_endpoints() -> Result<()> {
    // No checker configured.
    let (state, voprf) = build_state(None).await?;

    // No proof.
    let single_no_proof = run_single(state.clone(), voprf.clone(), None).await?;
    let batch_no_proof = run_batch(state.clone(), voprf.clone(), None).await?;
    assert_eq!(single_no_proof, Ok(TOKEN_LEN_V2));
    assert_eq!(batch_no_proof, Ok(TOKEN_LEN_V2));

    // Irrelevant proof present (should be ignored in none mode).
    let irrelevant_proof = Some(SybilProof::RateLimit {
        client_id: "ignored".to_string(),
        timestamp: 0,
    });
    let single_with_proof = run_single(state.clone(), voprf.clone(), irrelevant_proof.clone()).await?;
    let batch_with_proof = run_batch(state, voprf, irrelevant_proof).await?;
    assert_eq!(single_with_proof, Ok(TOKEN_LEN_V2));
    assert_eq!(batch_with_proof, Ok(TOKEN_LEN_V2));

    Ok(())
}

#[tokio::test]
async fn sybil_required_mode_requires_proof_on_both_endpoints() -> Result<()> {
    let checker: Arc<dyn SybilResistance> = Arc::new(MockNoneSybil { allow: true });
    let (state, voprf) = build_state(Some(checker)).await?;

    let single = run_single(state.clone(), voprf.clone(), None).await?;
    let batch = run_batch(state, voprf, None).await?;
    assert_eq!(single, Err(StatusCode::BAD_REQUEST));
    assert_eq!(batch, Err(StatusCode::BAD_REQUEST));
    Ok(())
}

#[tokio::test]
async fn sybil_required_mode_pass_and_fail_match_on_single_and_batch() -> Result<()> {
    // Passing checker.
    let pass_checker: Arc<dyn SybilResistance> = Arc::new(MockNoneSybil { allow: true });
    let (state_pass, voprf_pass) = build_state(Some(pass_checker)).await?;
    let proof = Some(SybilProof::None);

    let single_pass = run_single(state_pass.clone(), voprf_pass.clone(), proof.clone()).await?;
    let batch_pass = run_batch(state_pass, voprf_pass, proof.clone()).await?;
    assert_eq!(single_pass, Ok(TOKEN_LEN_V2));
    assert_eq!(batch_pass, Ok(TOKEN_LEN_V2));

    // Failing checker.
    let fail_checker: Arc<dyn SybilResistance> = Arc::new(MockNoneSybil { allow: false });
    let (state_fail, voprf_fail) = build_state(Some(fail_checker)).await?;

    let single_fail = run_single(state_fail.clone(), voprf_fail.clone(), proof.clone()).await?;
    let batch_fail = run_batch(state_fail, voprf_fail, proof).await?;
    assert_eq!(single_fail, Err(StatusCode::FORBIDDEN));
    assert_eq!(batch_fail, Err(StatusCode::FORBIDDEN));

    Ok(())
}
