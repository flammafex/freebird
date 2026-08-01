// SPDX-License-Identifier: Apache-2.0 OR MIT
// HTTP integration tests for issuer operator/admin workflows.

use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::tls_enforcement::ValidatedClientIp;
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
use std::net::{IpAddr, Ipv4Addr};
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
    build_admin_router_with_rotation(vouching, true).await
}

async fn build_admin_router_with_rotation(
    vouching: Option<Arc<MultiPartyVouchingSystem>>,
    allow_unsafe_v4_rotation: bool,
) -> Result<AdminHarness> {
    build_admin_router_with_options(vouching, allow_unsafe_v4_rotation, false, false).await
}

async fn build_admin_router_with_options(
    vouching: Option<Arc<MultiPartyVouchingSystem>>,
    allow_unsafe_v4_rotation: bool,
    behind_proxy: bool,
    require_tls: bool,
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
        require_tls,
        behind_proxy,
        webauthn_enabled: false,
        allow_unsafe_v4_rotation,
    };

    let router = admin_router(
        invitation_system,
        vouching,
        voprf,
        audit_log,
        ADMIN_KEY.to_string(),
        behind_proxy,
        require_tls,
        allow_unsafe_v4_rotation,
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

async fn dispatch_admin_request(
    router: &Router,
    method: Method,
    path: &str,
    body: Value,
    api_key: Option<&str>,
    cookie: Option<&str>,
    client_ip: Option<IpAddr>,
) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(api_key) = api_key {
        builder = builder.header("x-admin-key", api_key);
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }

    let mut request = builder.body(Body::from(serde_json::to_vec(&body)?))?;
    if let Some(client_ip) = client_ip {
        request
            .extensions_mut()
            .insert(ValidatedClientIp(client_ip));
    }

    let response = router.clone().oneshot(request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, headers, bytes.to_vec()))
}

async fn dispatch_admin_json_request(
    router: &Router,
    method: Method,
    path: &str,
    body: Value,
    api_key: Option<&str>,
    cookie: Option<&str>,
    client_ip: Option<IpAddr>,
) -> Result<(StatusCode, HeaderMap, Value)> {
    let (status, headers, bytes) =
        dispatch_admin_request(router, method, path, body, api_key, cookie, client_ip).await?;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).context("admin response was not JSON")?
    };
    Ok((status, headers, value))
}

#[tokio::test]
async fn v4_rotation_is_contained_when_disabled() -> Result<()> {
    let harness = build_admin_router_with_rotation(None, false).await?;
    let (status, before) = admin_request(&harness.router, Method::GET, "/keys", None).await?;
    assert_eq!(status, StatusCode::OK);
    let before_kid = before["keys"][0]["kid"].clone();
    let before_count = before["keys"].as_array().context("missing keys")?.len();

    let (status, body) = admin_request(
        &harness.router,
        Method::POST,
        "/keys/rotate",
        Some(json!({ "new_kid": "should-not-rotate" })),
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "V4 key rotation is disabled");

    let (status, after) = admin_request(&harness.router, Method::GET, "/keys", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after["keys"][0]["kid"], before_kid);
    assert_eq!(
        after["keys"].as_array().context("missing keys")?.len(),
        before_count
    );
    let (_, audit) = admin_request(&harness.router, Method::GET, "/audit", None).await?;
    assert!(!audit["entries"]
        .as_array()
        .context("missing audit entries")?
        .iter()
        .any(|entry| entry["action"] == "key_rotated"));
    Ok(())
}

#[tokio::test]
async fn development_rotation_override_permits_rotation() -> Result<()> {
    let harness = build_admin_router_with_rotation(None, true).await?;
    let (status, before) = admin_request(&harness.router, Method::GET, "/keys", None).await?;
    assert_eq!(status, StatusCode::OK);
    let old_kid = before["keys"][0]["kid"]
        .as_str()
        .context("missing active kid")?;

    let (status, body) = admin_request(
        &harness.router,
        Method::POST,
        "/keys/rotate",
        Some(json!({ "new_kid": "development-rotated", "grace_period_secs": 3600 })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["old_kid"], old_kid);
    assert_eq!(body["new_kid"], "development-rotated");

    let (_, keys) = admin_request(&harness.router, Method::GET, "/keys", None).await?;
    assert_eq!(keys["stats"]["total_keys"], 2);
    assert_eq!(keys["stats"]["active_keys"], 1);
    let (_, audit) = admin_request(&harness.router, Method::GET, "/audit", None).await?;
    assert!(audit["entries"]
        .as_array()
        .context("missing audit entries")?
        .iter()
        .any(|entry| entry["action"] == "key_rotated"));
    Ok(())
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

#[tokio::test]
async fn admin_auth_rejects_missing_and_invalid_keys_with_same_body() -> Result<()> {
    let harness = build_admin_router(None).await?;
    let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41));

    let (status, _, missing_body) = dispatch_admin_json_request(
        &harness.router,
        Method::GET,
        "/health",
        json!({}),
        None,
        None,
        Some(client_ip),
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing_body, json!({ "error": "unauthorized" }));

    let (status, _, invalid_body) = dispatch_admin_json_request(
        &harness.router,
        Method::GET,
        "/health",
        json!({}),
        Some("not-the-admin-key"),
        None,
        Some(client_ip),
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(invalid_body, json!({ "error": "unauthorized" }));
    assert_eq!(missing_body, invalid_body);

    let (status, _, invalid_cookie_body) = dispatch_admin_json_request(
        &harness.router,
        Method::GET,
        "/health",
        json!({}),
        None,
        Some("freebird_session=not-a-session-token"),
        Some(client_ip),
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(invalid_cookie_body, json!({ "error": "unauthorized" }));

    Ok(())
}

#[tokio::test]
async fn admin_login_session_and_logout_cookie_attributes_are_stable() -> Result<()> {
    for (require_tls, secure_suffix) in [(false, ""), (true, "; Secure")] {
        let harness = build_admin_router_with_options(None, true, false, require_tls).await?;
        let (status, headers, body) = dispatch_admin_json_request(
            &harness.router,
            Method::POST,
            "/login",
            json!({ "api_key": ADMIN_KEY }),
            None,
            None,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({ "status": "ok" }));

        let set_cookie = headers
            .get(header::SET_COOKIE)
            .context("login did not set a session cookie")?
            .to_str()?;
        let cookie_value = set_cookie
            .strip_prefix("freebird_session=")
            .and_then(|value| value.split(';').next())
            .context("login cookie did not contain a session value")?;
        assert!(!cookie_value.is_empty());
        assert_eq!(
            set_cookie,
            format!(
                "freebird_session={}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=86400{}",
                cookie_value, secure_suffix
            )
        );

        let session_cookie = format!("freebird_session={cookie_value}");
        let (status, _, health_body) = dispatch_admin_json_request(
            &harness.router,
            Method::GET,
            "/health",
            json!({}),
            None,
            Some(&session_cookie),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))),
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(health_body["status"], "ok");

        let (status, headers, logout_body) = dispatch_admin_json_request(
            &harness.router,
            Method::POST,
            "/logout",
            json!({}),
            None,
            None,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(logout_body, json!({ "status": "ok" }));
        assert_eq!(
            headers
                .get(header::SET_COOKIE)
                .context("logout did not set a clearing cookie")?
                .to_str()?,
            "freebird_session=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0"
        );
    }

    Ok(())
}

#[tokio::test]
async fn admin_auth_rate_limit_returns_status_and_generic_body() -> Result<()> {
    let harness = build_admin_router(None).await?;
    let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 43));

    for _ in 0..5 {
        let (status, _, body) = dispatch_admin_json_request(
            &harness.router,
            Method::GET,
            "/health",
            json!({}),
            Some("wrong-admin-key"),
            None,
            Some(client_ip),
        )
        .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, json!({ "error": "unauthorized" }));
    }

    let (status, _, body) = dispatch_admin_json_request(
        &harness.router,
        Method::GET,
        "/health",
        json!({}),
        Some("wrong-admin-key"),
        None,
        Some(client_ip),
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let error = body["error"].as_str().context("missing rate-limit error")?;
    assert!(error.starts_with("too many failed attempts, try again in "));
    assert!(error.ends_with(" seconds"));
    assert!(!error.contains(ADMIN_KEY));
    assert!(!error.contains("192.0.2.43"));

    Ok(())
}

#[tokio::test]
async fn admin_representative_error_bodies_are_stable() -> Result<()> {
    let harness = build_admin_router(None).await?;

    let cases = [
        (
            Method::POST,
            "/invitations/create",
            json!({ "inviter_id": "operator", "count": 0 }),
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid request: count must be greater than 0" }),
        ),
        (
            Method::GET,
            "/users/missing-user",
            json!({}),
            StatusCode::NOT_FOUND,
            json!({ "error": "user not found: missing-user" }),
        ),
        (
            Method::GET,
            "/readiness",
            json!({}),
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": "internal server error" }),
        ),
    ];

    for (method, path, request_body, expected_status, expected_body) in cases {
        let (status, _, body) = dispatch_admin_json_request(
            &harness.router,
            method,
            path,
            request_body,
            Some(ADMIN_KEY),
            None,
            None,
        )
        .await?;
        assert_eq!(status, expected_status, "unexpected status for {path}");
        assert_eq!(body, expected_body, "unexpected body for {path}");
    }

    Ok(())
}

#[tokio::test]
async fn admin_public_route_and_method_inventory_is_stable() -> Result<()> {
    let harness = build_admin_router(None).await?;
    let inventory = vec![
        ("/", vec![Method::GET, Method::HEAD]),
        ("/login", vec![Method::POST]),
        ("/logout", vec![Method::POST]),
        ("/health", vec![Method::GET, Method::HEAD]),
        ("/readiness", vec![Method::GET, Method::HEAD]),
        ("/stats", vec![Method::GET, Method::HEAD]),
        ("/config", vec![Method::GET, Method::HEAD]),
        ("/metrics", vec![Method::GET, Method::HEAD]),
        ("/users", vec![Method::GET, Method::HEAD]),
        ("/users/operator", vec![Method::GET, Method::HEAD]),
        ("/invites/grant", vec![Method::POST]),
        ("/invitations", vec![Method::GET, Method::HEAD]),
        ("/invitations/create", vec![Method::POST]),
        (
            "/invitations/not-found",
            vec![Method::GET, Method::HEAD, Method::DELETE],
        ),
        ("/users/ban", vec![Method::POST]),
        ("/users/unban", vec![Method::POST]),
        ("/bootstrap/add", vec![Method::POST]),
        ("/register-owner", vec![Method::POST]),
        ("/save", vec![Method::POST]),
        ("/keys", vec![Method::GET, Method::HEAD]),
        ("/keys/rotate", vec![Method::POST]),
        ("/keys/cleanup", vec![Method::POST]),
        ("/keys/not-found", vec![Method::DELETE]),
        (
            "/vouching/vouchers",
            vec![Method::GET, Method::HEAD, Method::POST],
        ),
        ("/vouching/vouchers/not-found", vec![Method::DELETE]),
        ("/vouching/vouches", vec![Method::POST]),
        (
            "/vouching/pending",
            vec![Method::GET, Method::HEAD, Method::DELETE],
        ),
        ("/vouching/mark-successful", vec![Method::POST]),
        ("/vouching/mark-problematic", vec![Method::POST]),
        ("/audit", vec![Method::GET, Method::HEAD]),
        ("/export/invitations", vec![Method::GET, Method::HEAD]),
        ("/export/users", vec![Method::GET, Method::HEAD]),
        ("/export/audit", vec![Method::GET, Method::HEAD]),
        ("/webauthn/credentials", vec![Method::GET, Method::HEAD]),
        ("/webauthn/credentials/not-found", vec![Method::DELETE]),
        ("/webauthn/stats", vec![Method::GET, Method::HEAD]),
        ("/webauthn/policy", vec![Method::GET, Method::HEAD]),
    ];
    assert_eq!(inventory.len(), 37);

    let all_methods = [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
        Method::HEAD,
    ];

    for (path, methods) in &inventory {
        for method in methods {
            let request_body = if path == &"/login" && method == Method::POST {
                json!({ "api_key": ADMIN_KEY })
            } else {
                json!({})
            };
            let (status, _, _) = dispatch_admin_request(
                &harness.router,
                method.clone(),
                path,
                request_body,
                Some(ADMIN_KEY),
                None,
                None,
            )
            .await?;
            assert_ne!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "declared route method was rejected: {method} {path}"
            );
        }

        for method in &all_methods {
            if methods.contains(method) {
                continue;
            }
            let (status, _, _) = dispatch_admin_request(
                &harness.router,
                method.clone(),
                path,
                json!({}),
                Some(ADMIN_KEY),
                None,
                None,
            )
            .await?;
            assert_eq!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "undeclared route method was accepted: {method} {path}"
            );
        }
    }

    for method in [Method::GET, Method::POST] {
        let (status, _, _) = dispatch_admin_request(
            &harness.router,
            method,
            "/not-a-public-admin-route",
            json!({}),
            Some(ADMIN_KEY),
            None,
            None,
        )
        .await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    Ok(())
}

#[test]
fn downstream_public_admin_dto_paths_compile() {
    fn assert_public_type<T>() {}

    use freebird_issuer::routes::admin;

    assert_public_type::<admin::ConfigSummary>();
    assert_public_type::<admin::GrantInvitesRequest>();
    assert_public_type::<admin::GrantInvitesResponse>();
    assert_public_type::<admin::BanUserRequest>();
    assert_public_type::<admin::BanUserResponse>();
    assert_public_type::<admin::UnbanUserRequest>();
    assert_public_type::<admin::UnbanUserResponse>();
    assert_public_type::<admin::AddBootstrapUserRequest>();
    assert_public_type::<admin::AddBootstrapUserResponse>();
    assert_public_type::<admin::RegisterOwnerRequest>();
    assert_public_type::<admin::RegisterOwnerResponse>();
    assert_public_type::<admin::CreateInvitationsRequest>();
    assert_public_type::<admin::InvitationCode>();
    assert_public_type::<admin::CreateInvitationsResponse>();
    assert_public_type::<admin::StatsResponse>();
    assert_public_type::<admin::HealthResponse>();
    assert_public_type::<admin::SybilConfigSummary>();
    assert_public_type::<admin::SybilModeSettings>();
    assert_public_type::<admin::TrustLevelSummary>();
    assert_public_type::<admin::ConfigResponse>();
    assert_public_type::<admin::RotateKeyRequest>();
    assert_public_type::<admin::RotateKeyResponse>();
    assert_public_type::<admin::ListKeysResponse>();
    assert_public_type::<admin::CleanupKeysResponse>();
    assert_public_type::<admin::ForceRemoveKeyResponse>();
    assert_public_type::<admin::UserSummary>();
    assert_public_type::<admin::UserDetailsResponse>();
    assert_public_type::<admin::ListInvitationsParams>();
    assert_public_type::<admin::ListInvitationsResponse>();
    assert_public_type::<admin::GetInvitationResponse>();
    assert_public_type::<admin::RevokeInvitationResponse>();
    assert_public_type::<admin::AddVoucherRequest>();
    assert_public_type::<admin::VoucherMutationResponse>();
    assert_public_type::<admin::ListVouchersResponse>();
    assert_public_type::<admin::ListPendingVouchesResponse>();
    assert_public_type::<admin::SubmitVouchRequest>();
    assert_public_type::<admin::SubmitVouchResponse>();
    assert_public_type::<admin::VoucheeRequest>();
    assert_public_type::<admin::ClearPendingVouchesResponse>();
    assert_public_type::<admin::ListUsersParams>();
    assert_public_type::<admin::ListUsersResponse>();
    assert_public_type::<admin::ListAuditParams>();
    assert_public_type::<admin::ListAuditResponse>();
    assert_public_type::<admin::ExportParams>();
    assert_public_type::<admin::UserExport>();
    assert_public_type::<admin::InvitationExport>();
    assert_public_type::<admin::AuditExport>();
    assert_public_type::<admin::WebAuthnCredentialSummary>();
    assert_public_type::<admin::ListWebAuthnCredentialsResponse>();
    assert_public_type::<admin::DeleteWebAuthnCredentialResponse>();
    assert_public_type::<admin::WebAuthnPolicyResponse>();
}
