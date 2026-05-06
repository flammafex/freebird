// SPDX-License-Identifier: Apache-2.0 OR MIT
// HTTP integration tests for issuer Sybil enforcement across issuance routes.

use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    routing::post,
    Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use blind_rsa_signatures::{DefaultRng, PublicKeySha384PSSDeterministic};
use freebird_common::api::SybilProof;
use freebird_crypto::{build_public_bearer_message_from_parts, Client, Server, VOPRF_CONTEXT_V4};
use freebird_issuer::{
    config::PublicKeyConfig,
    multi_key_voprf::MultiKeyVoprfCore,
    public_tokens::PublicTokenIssuer,
    routes::{batch_issue, issue, public_issue},
    sybil_resistance::{
        invitation::{InvitationConfig, InvitationSystem},
        multi_party_vouching::{MultiPartyVouchingConfig, MultiPartyVouchingSystem},
        progressive_trust::{ProgressiveTrustConfig, ProgressiveTrustSystem, TrustLevel},
        proof_of_diversity::{ProofOfDiversityConfig, ProofOfDiversitySystem},
        CombinedAnd, CombinedOr, CombinedThreshold, ProofOfWork, RateLimit, SybilResistance,
    },
    AppStateWithSybil,
};
use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tempfile::TempDir;
use tower::ServiceExt;

const ISSUER_ID: &str = "issuer:test:sybil-http";
const USER_AGENT: &str = "freebird-sybil-http-test";

struct TestApp {
    router: Router,
    public_issuer: Arc<PublicTokenIssuer>,
    _tmp: TempDir,
}

struct EndpointRequest {
    path: &'static str,
    body: Value,
    binding: String,
}

async fn build_app(sybil_checker: Option<Arc<dyn SybilResistance>>) -> Result<TestApp> {
    let sk = [0x88u8; 32];
    let server = Server::from_secret_key(sk, VOPRF_CONTEXT_V4)
        .map_err(|e| anyhow::anyhow!("server init failed: {:?}", e))?;
    let pubkey_b64 = Base64UrlUnpadded::encode_string(&server.public_key_sec1_compressed());
    let kid = "kid-sybil-http".to_string();
    let voprf = Arc::new(MultiKeyVoprfCore::new(
        sk,
        pubkey_b64.clone(),
        kid.clone(),
        VOPRF_CONTEXT_V4,
    )?);

    let tmp = tempfile::tempdir()?;
    let public_config = PublicKeyConfig {
        enabled: true,
        sk_path: tmp.path().join("public.der"),
        metadata_path: tmp.path().join("public-metadata.json"),
        validity_secs: 3600,
        audience: None,
        modulus_bits: 2048,
    };
    let public_issuer = Arc::new(
        PublicTokenIssuer::load_or_generate(&public_config, ISSUER_ID)?
            .context("public issuer disabled")?,
    );

    let state = Arc::new(AppStateWithSybil {
        issuer_id: ISSUER_ID.to_string(),
        kid,
        pubkey_b64,
        require_tls: false,
        behind_proxy: false,
        sybil_checker,
        invitation_system: None,
        public_issuer: Some(public_issuer.clone()),
        epoch_duration_sec: 86400,
        epoch_retention: 2,
    });

    let router = Router::new()
        .route("/v1/oprf/issue", post(issue::handle))
        .route("/v1/oprf/issue/batch", post(batch_issue::handle_batch))
        .route("/v1/public/issue", post(public_issue::handle))
        .route("/v1/public/issue/batch", post(public_issue::handle_batch))
        .with_state((state, voprf));

    Ok(TestApp {
        router,
        public_issuer,
        _tmp: tmp,
    })
}

async fn post_json(router: &Router, path: &str, body: Value) -> Result<StatusCode> {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, USER_AGENT)
        .body(Body::from(serde_json::to_vec(&body)?))?;
    Ok(router.clone().oneshot(req).await?.status())
}

fn blinded_element_b64(byte: u8) -> String {
    let mut client = Client::new(VOPRF_CONTEXT_V4);
    client.blind(&[byte; 32]).expect("blind V4 input").0
}

fn public_blinded_msg_b64(public_issuer: &PublicTokenIssuer, byte: u8) -> Result<String> {
    let spki = Base64UrlUnpadded::decode_vec(&public_issuer.metadata().pubkey_spki_b64)?;
    let pk = PublicKeySha384PSSDeterministic::from_spki(&spki)
        .map_err(|e| anyhow::anyhow!("parse public key SPKI: {e}"))?;
    let nonce = [byte; freebird_crypto::PUBLIC_BEARER_NONCE_LEN];
    let msg =
        build_public_bearer_message_from_parts(&nonce, public_issuer.token_key_id(), ISSUER_ID)
            .map_err(|e| anyhow::anyhow!("build V5 public bearer message: {:?}", e))?;
    let blinded = pk
        .blind(&mut DefaultRng, msg)
        .map_err(|e| anyhow::anyhow!("blind V5 message: {e}"))?;
    Ok(Base64UrlUnpadded::encode_string(&blinded.blind_message))
}

fn batch_request_binding(route_scope: &str, elements: &[String]) -> String {
    let mut hasher = Sha256::new();
    for element in elements {
        hasher.update((element.len() as u64).to_le_bytes());
        hasher.update(element.as_bytes());
    }
    let digest = hasher.finalize();
    format!(
        "freebird:{}:v1:{}:{}:{}",
        route_scope,
        ISSUER_ID,
        elements.len(),
        Base64UrlUnpadded::encode_string(&digest[..16])
    )
}

fn endpoint_requests(public_issuer: &PublicTokenIssuer) -> Result<Vec<EndpointRequest>> {
    let v4_single = blinded_element_b64(0x11);
    let v4_batch = vec![blinded_element_b64(0x12)];
    let v5_single = public_blinded_msg_b64(public_issuer, 0x13)?;
    let v5_batch = vec![public_blinded_msg_b64(public_issuer, 0x14)?];

    Ok(vec![
        EndpointRequest {
            path: "/v1/oprf/issue",
            binding: format!("freebird:issue:v1:{ISSUER_ID}:{v4_single}"),
            body: json!({"blinded_element_b64": v4_single}),
        },
        EndpointRequest {
            path: "/v1/oprf/issue/batch",
            binding: batch_request_binding("issue-batch", &v4_batch),
            body: json!({"blinded_elements": v4_batch}),
        },
        EndpointRequest {
            path: "/v1/public/issue",
            binding: format!("freebird:public-issue:v1:{ISSUER_ID}:{v5_single}"),
            body: json!({"blinded_msg_b64": v5_single}),
        },
        EndpointRequest {
            path: "/v1/public/issue/batch",
            binding: batch_request_binding("public-issue-batch", &v5_batch),
            body: json!({"blinded_msgs": v5_batch}),
        },
    ])
}

fn with_proof(mut body: Value, proof: SybilProof) -> Value {
    body.as_object_mut()
        .expect("request body should be object")
        .insert(
            "sybil_proof".to_string(),
            serde_json::to_value(proof).unwrap(),
        );
    body
}

fn current_timestamp_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn temp_path(prefix: &str, suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "freebird_{prefix}_{}_{}",
        uuid::Uuid::new_v4(),
        suffix
    ))
}

#[tokio::test]
async fn http_none_mode_accepts_all_issuance_routes() -> Result<()> {
    let app = build_app(None).await?;
    for endpoint in endpoint_requests(&app.public_issuer)? {
        assert_eq!(
            post_json(&app.router, endpoint.path, endpoint.body).await?,
            StatusCode::OK,
            "{} should accept without Sybil proof when no checker is configured",
            endpoint.path
        );
    }
    Ok(())
}

#[tokio::test]
async fn http_required_mode_rejects_missing_proofs_on_all_issuance_routes() -> Result<()> {
    let checker: Arc<dyn SybilResistance> = Arc::new(ProofOfWork::new(8));
    let app = build_app(Some(checker)).await?;
    for endpoint in endpoint_requests(&app.public_issuer)? {
        assert_eq!(
            post_json(&app.router, endpoint.path, endpoint.body).await?,
            StatusCode::BAD_REQUEST,
            "{} should require a Sybil proof",
            endpoint.path
        );
    }
    Ok(())
}

#[tokio::test]
async fn http_pow_accepts_bound_proofs_and_rejects_replay_or_wrong_binding() -> Result<()> {
    let checker: Arc<dyn SybilResistance> = Arc::new(ProofOfWork::new(8));
    let app = build_app(Some(checker)).await?;

    for endpoint in endpoint_requests(&app.public_issuer)? {
        let timestamp = current_timestamp_u64();
        let (nonce, _) = ProofOfWork::compute(8, &endpoint.binding, timestamp)?;
        let proof = SybilProof::ProofOfWork {
            nonce,
            input: endpoint.binding.clone(),
            timestamp,
        };
        let body = with_proof(endpoint.body.clone(), proof);
        assert_eq!(
            post_json(&app.router, endpoint.path, body.clone()).await?,
            StatusCode::OK
        );
        assert_eq!(
            post_json(&app.router, endpoint.path, body).await?,
            StatusCode::FORBIDDEN,
            "{} should reject replayed PoW",
            endpoint.path
        );
    }

    let endpoint = endpoint_requests(&app.public_issuer)?.remove(0);
    let timestamp = current_timestamp_u64();
    let (nonce, _) = ProofOfWork::compute(8, "freebird:wrong-binding", timestamp)?;
    let wrong = SybilProof::ProofOfWork {
        nonce,
        input: "freebird:wrong-binding".to_string(),
        timestamp,
    };
    assert_eq!(
        post_json(&app.router, endpoint.path, with_proof(endpoint.body, wrong)).await?,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
async fn http_rate_limit_uses_server_observed_client_identity() -> Result<()> {
    let checker: Arc<dyn SybilResistance> = Arc::new(RateLimit::new(Duration::from_secs(0)));
    let app = build_app(Some(checker)).await?;

    for endpoint in endpoint_requests(&app.public_issuer)? {
        let proof = SybilProof::RateLimit {
            client_id: String::new(),
            timestamp: current_timestamp_u64(),
        };
        assert_eq!(
            post_json(&app.router, endpoint.path, with_proof(endpoint.body, proof)).await?,
            StatusCode::OK,
            "{} should accept server-derived rate-limit identity",
            endpoint.path
        );
    }

    let endpoint = endpoint_requests(&app.public_issuer)?.remove(0);
    let forged = SybilProof::RateLimit {
        client_id: "attacker-selected-client".to_string(),
        timestamp: current_timestamp_u64(),
    };
    assert_eq!(
        post_json(
            &app.router,
            endpoint.path,
            with_proof(endpoint.body, forged)
        )
        .await?,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_invitation_redeems_codes_and_rejects_registered_user_bypass() -> Result<()> {
    let config = InvitationConfig {
        invites_per_user: 10,
        invite_cooldown_secs: 0,
        invite_expires_secs: 3600,
        new_user_can_invite_after_secs: 0,
        persistence_path: temp_path("invite", "state.json"),
        autosave_interval_secs: 3600,
    };
    let system = Arc::new(
        InvitationSystem::load_or_create(SigningKey::random(&mut OsRng), config.clone()).await?,
    );
    system.add_bootstrap_user("admin".to_string(), 20).await;
    let checker: Arc<dyn SybilResistance> = system.clone();
    let app = build_app(Some(checker)).await?;

    for endpoint in endpoint_requests(&app.public_issuer)? {
        let (code, signature, _) = system.generate_invite("admin").await?;
        let invitation = SybilProof::Invitation {
            code,
            signature: Base64UrlUnpadded::encode_string(&signature),
        };
        assert_eq!(
            post_json(
                &app.router,
                endpoint.path,
                with_proof(endpoint.body, invitation)
            )
            .await?,
            StatusCode::OK,
            "{} should accept fresh invitation",
            endpoint.path
        );
    }

    let endpoint = endpoint_requests(&app.public_issuer)?.remove(0);
    let registered = SybilProof::RegisteredUser {
        user_id: "admin".to_string(),
    };
    assert_eq!(
        post_json(
            &app.router,
            endpoint.path,
            with_proof(endpoint.body, registered)
        )
        .await?,
        StatusCode::FORBIDDEN
    );
    let _ = std::fs::remove_file(config.persistence_path);
    Ok(())
}

#[tokio::test]
async fn http_progressive_trust_accepts_current_state_and_rejects_stale_proof() -> Result<()> {
    let config = ProgressiveTrustConfig {
        levels: vec![TrustLevel {
            min_age_secs: 0,
            max_tokens_per_period: 100,
            cooldown_secs: 0,
        }],
        persistence_path: temp_path("progressive", "state.json"),
        autosave_interval_secs: 3600,
        hmac_secret: Some("progressive-test-secret".to_string()),
        hmac_secret_path: temp_path("progressive", "secret.bin"),
        user_id_salt: "progressive-test-salt".to_string(),
        allow_insecure_deterministic: false,
    };
    let system = ProgressiveTrustSystem::new(config.clone()).await?;
    let checker: Arc<dyn SybilResistance> = system.clone();
    let app = build_app(Some(checker)).await?;

    for (idx, endpoint) in endpoint_requests(&app.public_issuer)?
        .into_iter()
        .enumerate()
    {
        let proof = system.generate_proof(&format!("user-{idx}")).await?;
        assert_eq!(
            post_json(&app.router, endpoint.path, with_proof(endpoint.body, proof)).await?,
            StatusCode::OK,
            "{} should accept current progressive-trust proof",
            endpoint.path
        );
    }

    let endpoint = endpoint_requests(&app.public_issuer)?.remove(0);
    let stale = system.generate_proof("stale-user").await?;
    assert_eq!(
        post_json(
            &app.router,
            endpoint.path,
            with_proof(endpoint.body.clone(), stale.clone())
        )
        .await?,
        StatusCode::OK
    );
    assert_eq!(
        post_json(&app.router, endpoint.path, with_proof(endpoint.body, stale)).await?,
        StatusCode::FORBIDDEN
    );
    cleanup_paths(&[config.persistence_path, config.hmac_secret_path]);
    Ok(())
}

#[tokio::test]
async fn http_proof_of_diversity_accepts_server_state_and_rejects_tampering() -> Result<()> {
    let config = ProofOfDiversityConfig {
        min_score: 0,
        persistence_path: temp_path("diversity", "state.json"),
        autosave_interval_secs: 3600,
        hmac_secret: Some("diversity-test-secret".to_string()),
        hmac_secret_path: temp_path("diversity", "secret.bin"),
        fingerprint_salt: "diversity-test-salt".to_string(),
        allow_insecure_deterministic: false,
    };
    let system = ProofOfDiversitySystem::new(config.clone()).await?;
    let checker: Arc<dyn SybilResistance> = system.clone();
    let app = build_app(Some(checker)).await?;

    for (idx, endpoint) in endpoint_requests(&app.public_issuer)?
        .into_iter()
        .enumerate()
    {
        let user = format!("diverse-user-{idx}");
        system.observe_access(&user, "net-a", "device-a").await?;
        let proof = system.generate_proof(&user).await?;
        assert_eq!(
            post_json(&app.router, endpoint.path, with_proof(endpoint.body, proof)).await?,
            StatusCode::OK,
            "{} should accept diversity proof matching server state",
            endpoint.path
        );
    }

    let endpoint = endpoint_requests(&app.public_issuer)?.remove(0);
    system
        .observe_access("tampered-user", "net-a", "device-a")
        .await?;
    let mut proof = system.generate_proof("tampered-user").await?;
    if let SybilProof::ProofOfDiversity {
        diversity_score, ..
    } = &mut proof
    {
        *diversity_score = diversity_score.saturating_add(1);
    }
    assert_eq!(
        post_json(&app.router, endpoint.path, with_proof(endpoint.body, proof)).await?,
        StatusCode::FORBIDDEN
    );
    cleanup_paths(&[config.persistence_path, config.hmac_secret_path]);
    Ok(())
}

#[tokio::test]
async fn http_multi_party_vouching_accepts_valid_vouches_and_rejects_replay() -> Result<()> {
    let config = MultiPartyVouchingConfig {
        required_vouchers: 1,
        voucher_cooldown_secs: 0,
        vouch_expires_secs: 3600,
        new_user_can_vouch_after_secs: 0,
        persistence_path: temp_path("vouching", "state.json"),
        autosave_interval_secs: 3600,
        hmac_secret: Some("vouching-test-secret".to_string()),
        hmac_secret_path: temp_path("vouching", "secret.bin"),
        user_id_salt: "vouching-test-salt".to_string(),
        allow_insecure_deterministic: false,
    };
    let system = MultiPartyVouchingSystem::new(config.clone()).await?;
    let voucher_sk = SigningKey::random(&mut OsRng);
    system
        .add_voucher("alice".to_string(), VerifyingKey::from(&voucher_sk))
        .await?;
    let checker: Arc<dyn SybilResistance> = system.clone();
    let app = build_app(Some(checker)).await?;

    for (idx, endpoint) in endpoint_requests(&app.public_issuer)?
        .into_iter()
        .enumerate()
    {
        let user = format!("vouched-user-{idx}");
        let proof = vouching_proof(&system, &voucher_sk, &user).await?;
        assert_eq!(
            post_json(&app.router, endpoint.path, with_proof(endpoint.body, proof)).await?,
            StatusCode::OK,
            "{} should accept valid vouching proof",
            endpoint.path
        );
    }

    let endpoint = endpoint_requests(&app.public_issuer)?.remove(0);
    let proof = vouching_proof(&system, &voucher_sk, "replay-user").await?;
    assert_eq!(
        post_json(
            &app.router,
            endpoint.path,
            with_proof(endpoint.body.clone(), proof.clone())
        )
        .await?,
        StatusCode::OK
    );
    assert_eq!(
        post_json(&app.router, endpoint.path, with_proof(endpoint.body, proof)).await?,
        StatusCode::FORBIDDEN
    );
    cleanup_paths(&[config.persistence_path, config.hmac_secret_path]);
    Ok(())
}

async fn vouching_proof(
    system: &MultiPartyVouchingSystem,
    voucher_sk: &SigningKey,
    user: &str,
) -> Result<SybilProof> {
    let ts = current_timestamp_u64() as i64;
    let message = format!("vouch:{}:{}", system.hash_user_id(user), ts);
    system
        .submit_vouch("alice", user, voucher_sk.sign(message.as_bytes()), ts)
        .await?;
    let (id, vouches, hmac, proof_ts) = system.generate_proof_with_timestamp(user).await?;
    Ok(SybilProof::MultiPartyVouching {
        vouchee_id_hash: id,
        vouches,
        hmac_proof: hmac,
        timestamp: proof_ts,
    })
}

#[derive(Clone, Copy)]
enum MockKind {
    None,
    RateLimit,
    WebAuthn,
}

struct MockSybil {
    kind: MockKind,
    allow: bool,
}

impl SybilResistance for MockSybil {
    fn verify(&self, proof: &SybilProof) -> anyhow::Result<()> {
        if !self.supports(proof) {
            anyhow::bail!("unsupported mock proof");
        }
        if self.allow {
            Ok(())
        } else {
            anyhow::bail!("mock failure")
        }
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(
            (self.kind, proof),
            (MockKind::None, SybilProof::None)
                | (MockKind::RateLimit, SybilProof::RateLimit { .. })
                | (MockKind::WebAuthn, SybilProof::WebAuthn { .. })
        )
    }

    fn cost(&self) -> u64 {
        1
    }
}

#[tokio::test]
async fn http_webauthn_proof_shape_reaches_sybil_gate_on_all_issuance_routes() -> Result<()> {
    let checker: Arc<dyn SybilResistance> = Arc::new(MockSybil {
        kind: MockKind::WebAuthn,
        allow: true,
    });
    let app = build_app(Some(checker)).await?;

    for endpoint in endpoint_requests(&app.public_issuer)? {
        let proof = SybilProof::WebAuthn {
            subject_hash: "subject-hash".to_string(),
            auth_proof: Base64UrlUnpadded::encode_string(&[7u8; 32]),
            timestamp: current_timestamp_u64() as i64,
        };
        assert_eq!(
            post_json(&app.router, endpoint.path, with_proof(endpoint.body, proof)).await?,
            StatusCode::OK,
            "{} should pass WebAuthn-shaped proof to configured checker",
            endpoint.path
        );
    }

    let endpoint = endpoint_requests(&app.public_issuer)?.remove(0);
    assert_eq!(
        post_json(
            &app.router,
            endpoint.path,
            with_proof(endpoint.body, SybilProof::None)
        )
        .await?,
        StatusCode::FORBIDDEN
    );

    Ok(())
}

#[tokio::test]
async fn http_combined_modes_enforce_or_and_threshold_policies() -> Result<()> {
    let single = endpoint_requests(&build_app(None).await?.public_issuer)?.remove(0);

    let or_checker: Arc<dyn SybilResistance> = Arc::new(CombinedOr::new(vec![
        Arc::new(MockSybil {
            kind: MockKind::None,
            allow: true,
        }),
        Arc::new(MockSybil {
            kind: MockKind::RateLimit,
            allow: false,
        }),
    ]));
    let app = build_app(Some(or_checker)).await?;
    assert_eq!(
        post_json(
            &app.router,
            single.path,
            with_proof(single.body.clone(), SybilProof::None)
        )
        .await?,
        StatusCode::OK
    );

    let and_checker: Arc<dyn SybilResistance> = Arc::new(CombinedAnd::new(vec![
        Arc::new(MockSybil {
            kind: MockKind::None,
            allow: true,
        }),
        Arc::new(MockSybil {
            kind: MockKind::RateLimit,
            allow: true,
        }),
    ]));
    let app = build_app(Some(and_checker)).await?;
    let both = SybilProof::Multi {
        proofs: vec![
            SybilProof::None,
            SybilProof::RateLimit {
                client_id: String::new(),
                timestamp: current_timestamp_u64(),
            },
        ],
    };
    assert_eq!(
        post_json(
            &app.router,
            single.path,
            with_proof(single.body.clone(), both)
        )
        .await?,
        StatusCode::OK
    );
    assert_eq!(
        post_json(
            &app.router,
            single.path,
            with_proof(single.body.clone(), SybilProof::None)
        )
        .await?,
        StatusCode::FORBIDDEN
    );

    let threshold_checker: Arc<dyn SybilResistance> = Arc::new(CombinedThreshold::new(
        vec![
            Arc::new(MockSybil {
                kind: MockKind::None,
                allow: true,
            }),
            Arc::new(MockSybil {
                kind: MockKind::RateLimit,
                allow: true,
            }),
        ],
        2,
    )?);
    let app = build_app(Some(threshold_checker)).await?;
    let one = SybilProof::Multi {
        proofs: vec![SybilProof::None],
    };
    assert_eq!(
        post_json(
            &app.router,
            single.path,
            with_proof(single.body.clone(), one)
        )
        .await?,
        StatusCode::FORBIDDEN
    );
    let two = SybilProof::Multi {
        proofs: vec![
            SybilProof::None,
            SybilProof::RateLimit {
                client_id: String::new(),
                timestamp: current_timestamp_u64(),
            },
        ],
    };
    assert_eq!(
        post_json(&app.router, single.path, with_proof(single.body, two)).await?,
        StatusCode::OK
    );
    Ok(())
}

fn cleanup_paths(paths: &[PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}
