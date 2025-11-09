// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
mod keys;
mod voprf_core;
mod routes;
#[cfg(feature = "human-gate-webauthn")]
mod proof;

use axum::{
    extract::{DefaultBodyLimit, State},
    routing::{get, post},
    Json, Router,
};
use common::logging;
use serde::Serialize;
use std::{env, net::SocketAddr, sync::Arc};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Clone)]
pub struct AppState {
    pub issuer_id: String,
    pub kid: String,
    pub exp_sec: u64,
    pub pubkey_b64: String,
    pub require_tls: bool,
    pub behind_proxy: bool,
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

    // ---------- Core ----------
    let ctx = b"freebird:v1";
    let voprf = Arc::new(voprf_core::VoprfCore::new(
        sk_bytes,
        pubkey_b64.clone(),
        kid.clone(),
        ctx,
    )?);

    let state = Arc::new(AppState {
        issuer_id,
        kid,
        exp_sec,
        pubkey_b64,
        require_tls,
        behind_proxy,
    });

    // ---------- Router ----------
    let shared_state = (state.clone(), voprf.clone());

    let app = Router::new()
        .route(
            "/.well-known/issuer",
            get(|State((app_state, _)): State<(Arc<AppState>, Arc<voprf_core::VoprfCore>)>| async move {
                well_known(State(app_state)).await
            }),
        )
        .route(
            "/v1/oprf/issue",
            post(
                |State((app_state, voprf)): State<(Arc<AppState>, Arc<voprf_core::VoprfCore>)>,
                 Json(req): Json<crate::routes::issue::IssueReq>| async move {
                    // Forward to handler properly
                    crate::routes::issue::handle(State(app_state), voprf, Json(req)).await
                },
            ),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(shared_state);

    // ---------- Serve ----------
    let addr: SocketAddr = bind_addr.parse().expect("BIND_ADDR parse");
    let listener = TcpListener::bind(addr).await.expect("bind");

    if state.require_tls {
        info!("🕊️ Freebird issuer listening (TLS required) on {}", listener.local_addr()?);
    } else {
        info!("🕊️ Freebird issuer listening on {}", listener.local_addr()?);
    }
    println!("✅ Router built successfully. Expected endpoints:");
    println!("   GET  /.well-known/issuer");
    println!("   POST /v1/oprf/issue");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| e.into())
}

// ---------- Handlers ----------
async fn well_known(State(st): State<Arc<AppState>>) -> Json<WellKnown> {
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
