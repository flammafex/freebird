// SPDX-License-Identifier: Apache-2.0 OR MIT
// HTTP integration tests for issuer operator/admin workflows.

use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_crypto::{Server, VOPRF_CONTEXT_V4};
use freebird_issuer::{
    audit::{AuditConfig, AuditLog},
    multi_key_voprf::MultiKeyVoprfCore,
    routes::{
        admin::{ConfigSummary, SybilConfigSummary, SybilModeSettings},
        admin_router,
    },
    sybil_resistance::{
        invitation::{InvitationConfig, InvitationSystem},
        multi_party_vouching::{MultiPartyVouchingConfig, MultiPartyVouchingSystem},
    },
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const ADMIN_KEY: &str = "admin-key-for-integration-tests-0001";

struct AdminHarness {
    router: Router,
    _tmp: TempDir,
}

async fn build_admin_router(
    vouching: Option<Arc<MultiPartyVouchingSystem>>,
) -> Result<AdminHarness> {
    let tmp = tempfile::tempdir()?;

    let invitation_config = InvitationConfig {
        invites_per_user: 2,
        invite_cooldown_secs: 0,
        invite_expires_secs: 3600,
        new_user_can_invite_after_secs: 0,
        persistence_path: tmp.path().join("invitations.json"),
        autosave_interval_secs: 3600,
    };
    let invitation_system = Arc::new(
        InvitationSystem::load_or_create(SigningKey::random(&mut OsRng), invitation_config).await?,
    );

    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, VOPRF_CONTEXT_V4)
        .map_err(|e| anyhow::anyhow!("server init failed: {:?}", e))?;
    let pubkey_b64 = Base64UrlUnpadded::encode_string(&server.public_key_sec1_compressed());
    let voprf = Arc::new(MultiKeyVoprfCore::new(
        sk,
        pubkey_b64,
        "kid-admin-test".to_string(),
        VOPRF_CONTEXT_V4,
    )?);

    let audit_log = Arc::new(
        AuditLog::load_or_create(AuditConfig {
            persistence_path: tmp.path().join("audit.json"),
            max_entries: 100,
            autosave_interval_secs: 3600,
        })
        .await?,
    );

    let config_summary = ConfigSummary {
        issuer_id: "issuer:test:admin".to_string(),
        sybil_config: SybilConfigSummary {
            mode: "multi_party_vouching".to_string(),
            mode_description: "test configuration".to_string(),
            settings: SybilModeSettings::MultiPartyVouching {
                required_vouchers: 1,
                cooldown: "0s".to_string(),
                cooldown_secs: 0,
                expires: "1h".to_string(),
                expires_secs: 3600,
                new_user_wait: "0s".to_string(),
                new_user_wait_secs: 0,
                persistence_path: "test".to_string(),
            },
            combined_mechanisms: None,
            combined_mode_type: None,
            combined_threshold: None,
        },
        epoch_duration_secs: 86400,
        epoch_retention: 2,
        require_tls: false,
        behind_proxy: false,
        webauthn_enabled: false,
    };

    let router = admin_router(
        invitation_system,
        vouching,
        voprf,
        audit_log,
        ADMIN_KEY.to_string(),
        false,
        false,
        config_summary,
    );

    Ok(AdminHarness { router, _tmp: tmp })
}

async fn admin_request(
    router: &Router,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value)> {
    let body = body.unwrap_or_else(|| json!({}));
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-admin-key", ADMIN_KEY)
        .body(Body::from(serde_json::to_vec(&body)?))?;

    let resp = router.clone().oneshot(req).await?;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };

    Ok((status, value))
}

#[tokio::test]
async fn admin_can_manage_invitations_and_user_bans() -> Result<()> {
    let harness = build_admin_router(None).await?;

    let (status, _) = admin_request(
        &harness.router,
        Method::POST,
        "/bootstrap/add",
        Some(json!({ "user_id": "operator", "invite_count": 2 })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = admin_request(
        &harness.router,
        Method::POST,
        "/invitations/create",
        Some(json!({ "inviter_id": "operator", "count": 1 })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let code = body["invitations"][0]["code"]
        .as_str()
        .context("missing invitation code")?;

    let (status, _) = admin_request(
        &harness.router,
        Method::GET,
        &format!("/invitations/{code}"),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = admin_request(
        &harness.router,
        Method::DELETE,
        &format!("/invitations/{code}"),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["inviter_id"], "operator");

    let (status, _) = admin_request(
        &harness.router,
        Method::GET,
        &format!("/invitations/{code}"),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = admin_request(
        &harness.router,
        Method::POST,
        "/users/ban",
        Some(json!({ "user_id": "operator", "ban_tree": false })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);

    let (status, body) =
        admin_request(&harness.router, Method::GET, "/users/operator", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["banned"], true);

    let (status, body) = admin_request(
        &harness.router,
        Method::POST,
        "/users/unban",
        Some(json!({ "user_id": "operator" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);

    let (status, body) =
        admin_request(&harness.router, Method::GET, "/users/operator", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["banned"], false);

    let (status, body) =
        admin_request(&harness.router, Method::GET, "/webauthn/policy", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["enabled"], false);

    Ok(())
}

#[tokio::test]
async fn admin_can_manage_multi_party_vouching() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vouching = MultiPartyVouchingSystem::new(MultiPartyVouchingConfig {
        required_vouchers: 1,
        voucher_cooldown_secs: 0,
        vouch_expires_secs: 3600,
        new_user_can_vouch_after_secs: 0,
        persistence_path: tmp.path().join("vouching.json"),
        autosave_interval_secs: 3600,
        hmac_secret: Some("integration-test-secret".to_string()),
        hmac_secret_path: tmp.path().join("vouching-secret.bin"),
        user_id_salt: "integration-test-salt".to_string(),
        allow_insecure_deterministic: false,
    })
    .await?;
    let harness = build_admin_router(Some(vouching.clone())).await?;

    let voucher_key = SigningKey::random(&mut OsRng);
    let voucher_public_key = VerifyingKey::from(&voucher_key);
    let voucher_public_key_b64 =
        Base64UrlUnpadded::encode_string(voucher_public_key.to_encoded_point(true).as_bytes());

    let (status, body) = admin_request(
        &harness.router,
        Method::POST,
        "/vouching/vouchers",
        Some(json!({
            "user_id": "voucher-1",
            "public_key_b64": voucher_public_key_b64,
        })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);

    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let vouchee_hash = vouching.hash_user_id("candidate-1");
    let message = format!("vouch:{vouchee_hash}:{timestamp}");
    let signature: Signature = voucher_key.sign(message.as_bytes());
    let signature_b64 = Base64UrlUnpadded::encode_string(&signature.to_bytes());

    let (status, body) = admin_request(
        &harness.router,
        Method::POST,
        "/vouching/vouches",
        Some(json!({
            "voucher_id": "voucher-1",
            "vouchee_id": "candidate-1",
            "signature_b64": signature_b64,
            "timestamp": timestamp,
        })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["vouchee_id_hash"], vouchee_hash);

    let (status, body) =
        admin_request(&harness.router, Method::GET, "/vouching/pending", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);

    let (status, _) = admin_request(
        &harness.router,
        Method::POST,
        "/vouching/mark-successful",
        Some(json!({ "vouchee_id": "candidate-1" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);

    let (status, body) =
        admin_request(&harness.router, Method::GET, "/vouching/vouchers", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["vouchers"][0]["successful_vouches"], 1);

    let (status, body) = admin_request(
        &harness.router,
        Method::DELETE,
        "/vouching/pending",
        Some(json!({ "vouchee_id": "candidate-1" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["removed_count"], 1);

    let (status, body) = admin_request(
        &harness.router,
        Method::DELETE,
        "/vouching/vouchers/voucher-1",
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);

    let (status, body) =
        admin_request(&harness.router, Method::GET, "/vouching/vouchers", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 0);

    Ok(())
}
