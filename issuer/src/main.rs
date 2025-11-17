// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
mod keys;
mod voprf_core;
mod routes;
#[cfg(feature = "human-gate-webauthn")]
mod proof;
mod sybil_resistance;

use axum::{
    extract::{DefaultBodyLimit, State},
    routing::{get, post},
    Json, Router,
};
use common::logging;
use serde::Serialize;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tracing::{info, warn};

use sybil_resistance::{ProofOfWork, RateLimit, CombinedSybilResistance, SybilResistance};

#[derive(Clone)]
pub struct AppState {
    pub issuer_id: String,
    pub kid: String,
    pub exp_sec: u64,
    pub pubkey_b64: String,
    pub require_tls: bool,
    pub behind_proxy: bool,
}

// App state with Sybil resistance
#[derive(Clone)]
pub struct AppStateWithSybil {
    pub issuer_id: String,
    pub kid: String,
    pub exp_sec: u64,
    pub pubkey_b64: String,
    pub require_tls: bool,
    pub behind_proxy: bool,
    pub sybil_checker: Option<Arc<dyn SybilResistance>>,
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
    let sybil_checker: Option<Arc<dyn SybilResistance>> = 
        match env::var("SYBIL_RESISTANCE").as_deref() {
            Ok("proof_of_work") | Ok("pow") => {
                let difficulty = env::var("SYBIL_POW_DIFFICULTY")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(20); // Default: ~1 second
                
                info!("🛡️  Sybil resistance: Proof-of-Work (difficulty={})", difficulty);
                Some(Arc::new(ProofOfWork::new(difficulty)))
            }
            Ok("rate_limit") => {
                let interval_secs = env::var("SYBIL_RATE_LIMIT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(3600); // Default: 1 hour
                
                info!("🛡️  Sybil resistance: Rate Limiting (interval={}s)", interval_secs);
                Some(Arc::new(RateLimit::new(Duration::from_secs(interval_secs))))
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
                warn!("⚠️  No Sybil resistance configured - tokens can be issued freely");
                None
            }
            Ok(other) => {
                warn!("⚠️  Unknown SYBIL_RESISTANCE value: '{}', disabling", other);
                None
            }
        };

    // ---------- Core ----------
    let ctx = b"freebird:v1";
    let voprf = Arc::new(voprf_core::VoprfCore::new(
        sk_bytes,
        pubkey_b64.clone(),
        kid.clone(),
        ctx,
    )?);

    // Standard state (for backward-compatible endpoint)
    let state = Arc::new(AppState {
        issuer_id: issuer_id.clone(),
        kid: kid.clone(),
        exp_sec,
        pubkey_b64: pubkey_b64.clone(),
        require_tls,
        behind_proxy,
    });

    // State with Sybil resistance (for protected endpoint)
    let state_with_sybil = Arc::new(AppStateWithSybil {
        issuer_id,
        kid,
        exp_sec,
        pubkey_b64,
        require_tls,
        behind_proxy,
        sybil_checker: sybil_checker.clone(),
    });

    // ---------- Router ----------
    // Use with_state() to provide state to handlers
    let app = Router::new()
        .route("/.well-known/issuer", get(well_known_handler))
        .route("/v1/oprf/issue", post(issue_handler))
        .route("/v1/oprf/issue-protected", post(issue_protected_handler))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state((state.clone(), state_with_sybil, voprf));

    // ---------- Serve ----------
    let addr: SocketAddr = bind_addr.parse().expect("BIND_ADDR parse");
    let listener = TcpListener::bind(addr).await.expect("bind");

    if state.require_tls {
        info!("🕊️ Freebird issuer listening (TLS required) on {}", listener.local_addr()?);
    } else {
        info!("🕊️ Freebird issuer listening on {}", listener.local_addr()?);
    }
    info!("✅ Router built successfully. Endpoints:");
    info!("   GET  /.well-known/issuer");
    info!("   POST /v1/oprf/issue (no Sybil resistance)");
    info!("   POST /v1/oprf/issue-protected (with Sybil resistance)");
    
    if sybil_checker.is_some() {
        info!("🛡️  Sybil resistance enabled on /v1/oprf/issue-protected");
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| e.into())
}

// ---------- Handlers ----------

// Type alias for our shared state
type SharedState = (Arc<AppState>, Arc<AppStateWithSybil>, Arc<voprf_core::VoprfCore>);

async fn well_known_handler(
    State((st, _, _)): State<SharedState>,
) -> Json<WellKnown> {
    Json(WellKnown {
        issuer_id: st.issuer_id.clone(),
        voprf: VoprfInfo {
            suite: "OPRF(P-256, SHA-256)-verifiable".into(),
            kid: st.kid.clone(),
            pubkey: st.pubkey_b64.clone(),
            exp_sec: st.exp_sec,
        },
    })
}

async fn issue_handler(
    State((st, _, voprf)): State<SharedState>,
    Json(req): Json<crate::routes::issue::IssueReq>,
) -> Result<Json<crate::routes::issue::IssueResp>, (axum::http::StatusCode, String)> {
    crate::routes::issue::handle(State(st), voprf, Json(req)).await
}

async fn issue_protected_handler(
    State((_, st_sybil, voprf)): State<SharedState>,
    Json(req): Json<crate::routes::issue_with_sybil::IssueReqWithSybil>,
) -> Result<Json<crate::routes::issue_with_sybil::IssueRespWithSybil>, (axum::http::StatusCode, String)> {
    crate::routes::issue_with_sybil::handle_with_sybil(State(st_sybil), voprf, Json(req)).await
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