// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.
mod keys;
mod voprf_core;
mod multi_key_voprf;
mod routes;
mod sybil_resistance;

use axum::{
    extract::{DefaultBodyLimit, State},
    routing::{get, post},
    Json, Router,
};
use axum::http::HeaderMap;
use axum::extract::ConnectInfo;
use common::logging;
use serde::Serialize;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tracing::{info, warn};
use sybil_resistance::{
    ProofOfWork, 
    RateLimit, 
    CombinedSybilResistance, 
    SybilResistance,
    invitation::InvitationSystem,
};
// Single unified state structure
#[derive(Clone)]
pub struct AppStateWithSybil {
    pub issuer_id: String,
    pub kid: String,
    pub exp_sec: u64,
    pub pubkey_b64: String,
    pub require_tls: bool,
    pub behind_proxy: bool,
    pub sybil_checker: Option<Arc<dyn SybilResistance>>,
    pub invitation_system: Option<Arc<InvitationSystem>>, // Add this field
}

#[derive(Serialize)]
struct WellKnown {
    issuer_id: String,
    voprf: VoprfInfo,
}

#[derive(Serialize)]
struct VoprfInfo {
    suite: String,
    kid: String,
    pubkey: String,
    exp_sec: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ---------- Logging ----------
    logging::init("info,axum=info,tower_http=info");

    // ---------- Config ----------
    let issuer_id = env::var("ISSUER_ID").unwrap_or_else(|_| "issuer:freebird:v1".to_string());
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".to_string());
    let token_ttl_min: u64 = env::var("TOKEN_TTL_MIN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
        .clamp(1, 24 * 60);
    let exp_sec = token_ttl_min * 60;

    let require_tls = env::var("REQUIRE_TLS")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let behind_proxy = env::var("BEHIND_PROXY")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // ---------- Keys ----------
    let (sk_bytes, pubkey_b64, kid_from_key) = keys::load_or_generate_keypair_b64()?;
    let kid = match env::var("KID") {
        Ok(k) => {
            if !k.starts_with(&kid_from_key) {
                warn!(provided=%k, derived=%kid_from_key, "KID mismatch; using derived prefix");
                format!("{}-{}", kid_from_key, OffsetDateTime::now_utc().date())
            } else {
                k
            }
        }
        Err(_) => format!("{}-{}", kid_from_key, OffsetDateTime::now_utc().date()),
    };

    // ---------- Sybil Resistance Configuration ----------
    let mut invitation_system: Option<Arc<InvitationSystem>> = None;
    
    let sybil_checker: Option<Arc<dyn SybilResistance>> = 
        match env::var("SYBIL_RESISTANCE").as_deref() {
            Ok("proof_of_work") | Ok("pow") => {
                let difficulty = env::var("SYBIL_POW_DIFFICULTY")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(20);
                
                info!("🛡️  Sybil resistance: Proof-of-Work (difficulty={})", difficulty);
                Some(Arc::new(ProofOfWork::new(difficulty)))
            }
            Ok("rate_limit") => {
                let interval_secs = env::var("SYBIL_RATE_LIMIT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3600);
                
                info!("🛡️  Sybil resistance: Rate Limiting (interval={}s)", interval_secs);
                Some(Arc::new(RateLimit::new(Duration::from_secs(interval_secs))))
            }
            Ok("invitation") => {
                // Invitation system setup (simplified - see full implementation in invitation.rs)
                use p256::ecdsa::SigningKey;
                use rand::rngs::OsRng;
                use sybil_resistance::invitation::InvitationConfig;
                use std::path::PathBuf;
                
                let signing_key = SigningKey::random(&mut OsRng);
                
                let config = InvitationConfig {
                    invites_per_user: env::var("SYBIL_INVITE_PER_USER")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(5),
                    invite_cooldown_secs: env::var("SYBIL_INVITE_COOLDOWN_SECS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(3600),
                    invite_expires_secs: env::var("SYBIL_INVITE_EXPIRES_SECS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(30 * 24 * 3600),
                    new_user_can_invite_after_secs: env::var("SYBIL_INVITE_NEW_USER_WAIT_SECS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(30 * 24 * 3600),
                    persistence_path: env::var("SYBIL_INVITE_PERSISTENCE_PATH")
                        .map(PathBuf::from)
                        .unwrap_or_else(|_| PathBuf::from("invitations.json")),
                    autosave_interval_secs: env::var("SYBIL_INVITE_AUTOSAVE_INTERVAL_SECS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(300),
                };
                
                let inv_sys = InvitationSystem::load_or_create(signing_key, config)
                    .await?;
                
                // Bootstrap users
                if let Ok(bootstrap_users) = env::var("SYBIL_INVITE_BOOTSTRAP_USERS") {
                    for entry in bootstrap_users.split(',') {
                        if let Some((user_id, count_str)) = entry.split_once(':') {
                            if let Ok(count) = count_str.parse::<u32>() {
                                inv_sys.add_bootstrap_user(user_id.to_string(), count).await;
                                info!("Added bootstrap user: {} with {} invites", user_id, count);
                            }
                        }
                    }
                }
                
                info!("🛡️  Sybil resistance: Invitation System");
                let inv_sys = Arc::new(inv_sys);
                invitation_system = Some(Arc::clone(&inv_sys));
                Some(inv_sys)
            }
            Ok("combined") => {
                let pow_difficulty = env::var("SYBIL_POW_DIFFICULTY")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(20);
                let rate_limit_secs = env::var("SYBIL_RATE_LIMIT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3600);
                
                info!(
                    "🛡️  Sybil resistance: Combined (PoW difficulty={}, rate limit={}s)",
                    pow_difficulty, rate_limit_secs
                );
                Some(Arc::new(CombinedSybilResistance::new(vec![
                    Box::new(ProofOfWork::new(pow_difficulty)),
                    Box::new(RateLimit::new(Duration::from_secs(rate_limit_secs))),
                ])))
            }
            Ok("none") | Err(_) => {
                info!("ℹ️  No Sybil resistance configured - tokens issued freely");
                None
            }
            Ok(other) => {
                warn!("⚠️  Unknown SYBIL_RESISTANCE value: '{}', disabling", other);
                None
            }
        };

    // ---------- Core ----------
    let ctx = b"freebird:v1";
    
    let voprf = Arc::new(multi_key_voprf::MultiKeyVoprfCore::load_or_create(
		sk_bytes, pubkey_b64.clone(), kid.clone(), ctx,
		Some(std::path::PathBuf::from("key_rotation_state.json")),
	).await?);

    // Single unified state
    let state = Arc::new(AppStateWithSybil {
        issuer_id,
        kid,
        exp_sec,
        pubkey_b64,
        require_tls,
        behind_proxy,
        sybil_checker,
        invitation_system, // Include the invitation system reference
    });

    // ---------- Router ----------
    // Both endpoints use the same unified handler
    // The handler adapts based on:
    // - Whether Sybil resistance is configured in state
    // - Whether a Sybil proof is provided in the request
    let mut app = Router::new()
        .route("/.well-known/issuer", get(well_known_handler))
        .route("/v1/oprf/issue", post(issue_handler))
        .route("/v1/oprf/issue/batch", post(batch_handler))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state((state.clone(), voprf.clone()));
        
    // Background task: Clean up expired keys daily
	let cleanup_voprf = Arc::clone(&voprf);
	tokio::spawn(async move {
		loop {
			tokio::time::sleep(tokio::time::Duration::from_secs(24 * 3600)).await;
			
			match cleanup_voprf.cleanup_expired_keys().await {
				Ok(removed) => {
					if removed > 0 {
						info!("Automatic cleanup removed {} expired keys", removed);
					}
				}
				Err(e) => {
					warn!("Automatic key cleanup failed: {}", e);
				}
			}
		}
	});
			
    // ---------- Admin API (optional) ----------
    if let Ok(admin_key) = env::var("ADMIN_API_KEY") {
        if admin_key.len() < 32 {
            warn!("⚠️  ADMIN_API_KEY is too short (< 32 chars), admin API disabled");
        } else if let Some(ref inv_sys) = state.invitation_system {
            info!("✅ Admin API enabled at /admin/*");
            info!("   Endpoints:");
            info!("   GET  /admin/health");
            info!("   GET  /admin/stats");
            info!("   POST /admin/invites/grant");
            info!("   POST /admin/users/ban");
            info!("   POST /admin/bootstrap/add");
            info!("   GET  /admin/users/:user_id");
            info!("   GET  /admin/invitations/:code");
            info!("   POST /admin/save");
            
            let admin_router = routes::admin_router(
                Arc::clone(inv_sys),
                Arc::clone(&voprf),
                admin_key
            );
            
            app = app.nest("/admin", admin_router);
        } else {
            warn!("⚠️  Admin API requires invitation-based Sybil resistance");
        }
    } else {
        info!("ℹ️  Admin API disabled (set ADMIN_API_KEY to enable)");
    }

    // ---------- Serve ----------
    let addr: SocketAddr = bind_addr.parse().expect("BIND_ADDR parse");
    let listener = TcpListener::bind(addr).await.expect("bind");

    if state.require_tls {
        info!("🕊️ Freebird issuer listening (TLS required) on {}", listener.local_addr()?);
    } else {
        info!("🕊️ Freebird issuer listening on {}", listener.local_addr()?);
    }
    
    info!("✅ Router configured. Endpoints:");
    info!("   GET  /.well-known/issuer");
    info!("   POST /v1/oprf/issue              (adaptive: checks for Sybil proof)");
    info!("   POST /v1/oprf/issue/batch    (same handler, clearer intent)");
    
    if state.sybil_checker.is_some() {
        info!("🛡️  Sybil resistance enabled - proofs will be verified when provided");
    } else {
        info!("ℹ️  Sybil resistance disabled - tokens issued without verification");
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| e.into())
}

// ---------- Handlers ----------

// Type alias for shared state
type SharedState = (Arc<AppStateWithSybil>, Arc<multi_key_voprf::MultiKeyVoprfCore>);

#[derive(Serialize)]
struct WellKnownMultiKey {
    issuer_id: String,
    voprf: VoprfInfoMultiKey,
}

#[derive(Serialize)]
struct VoprfInfoMultiKey {
    suite: String,
    keys: Vec<VoprfKeyInfo>,
    exp_sec: u64,
}

#[derive(Serialize)]
struct VoprfKeyInfo {
    kid: String,
    pubkey: String,
    status: String,
}

async fn well_known_handler(
    State((state, voprf)): State<SharedState>,  // Use voprf, not _
) -> Json<WellKnown> {
    let active_kid = voprf.active_kid().await;
    let active_pubkey = voprf.active_pubkey_b64().await;
    
    Json(WellKnown {
        issuer_id: state.issuer_id.clone(),
        voprf: VoprfInfo {
            suite: "OPRF(P-256, SHA-256)-verifiable".into(),
            kid: active_kid,      // NEW
            pubkey: active_pubkey, // NEW
            exp_sec: state.exp_sec,
        },
    })
}

async fn issue_handler(
    State((state, voprf)): State<SharedState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<routes::IssueReq>,
) -> Result<Json<routes::IssueResp>, (axum::http::StatusCode, String)> {
    routes::handle(State(state), voprf, connect_info, headers, Json(req)).await
}
async fn batch_handler(
    State((state, voprf)): State<SharedState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<routes::BatchIssueReq>,
) -> Result<Json<routes::BatchIssueResp>, (axum::http::StatusCode, String)> {
    routes::handle_batch(State(state), voprf, connect_info, headers, Json(req)).await
}
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        sigterm.recv().await;
    };
    
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    
    info!("shutdown signal received");
}