use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::RwLock, time::sleep};
use tracing::{error, info, warn, debug};
use anyhow::Context;
use common::logging;

mod store;
use store::{SpendStore, StoreBackend};

#[derive(Clone)]
struct AppState {
    issuers: Arc<RwLock<HashMap<String, IssuerInfo>>>,
    store: Arc<dyn SpendStore>,
}

#[derive(Clone, Debug, Deserialize)]
struct WellKnown {
    issuer_id: String,
    voprf: VoprfInfo,
}

#[derive(Clone, Debug, Deserialize)]
struct VoprfInfo {
    suite: String,
    kid: String,
    pubkey: String,
    exp_sec: u64,
}

#[derive(Clone)]
struct IssuerInfo {
    pubkey_bytes: Vec<u8>,
    kid: String,
    ctx: Vec<u8>,
    exp_sec: u64,
}

// ✅ CLEANED: Removed HPS field
#[derive(Deserialize, Debug)]
struct VerifyRequest {
    token_b64: String,
    issuer_id: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    ok: bool,
    verified_at: i64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init("debug");

    // ---------- Backend selection ----------
    let backend = if let Ok(url) = std::env::var("REDIS_URL") {
        StoreBackend::Redis(url)
    } else {
        StoreBackend::InMemory
    };
    let store = backend.build().await;

    // ---------- Issuer metadata refresh ----------
    let issuer_url = std::env::var("ISSUER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8081/.well-known/issuer".into());
    let refresh_interval_min: u64 = std::env::var("REFRESH_INTERVAL_MIN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let state = Arc::new(AppState {
        issuers: Arc::new(RwLock::new(HashMap::new())),
        store,
    });

    // background refresh loop
    let refresh_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut failures = 0u32;
        loop {
            match refresh_issuer_metadata(&refresh_state, &issuer_url).await {
                Ok(_) => failures = 0,
                Err(e) => {
                    failures += 1;
                    warn!(?e, failures, "issuer refresh failed");
                }
            }
            let delay = refresh_interval_min
                .saturating_mul(60)
                .saturating_mul(u64::from((failures + 1).min(5)));

            sleep(Duration::from_secs(delay)).await;
        }
    });

    // ---------- Router ----------
    let app = Router::new()
        .route("/v1/verify", post(verify_with_logging))
        .with_state(state);

    // ---------- Serve ----------
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8082".into());
    let addr: SocketAddr = bind_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("🕊️ Freebird verifier listening on http://{}", listener.local_addr()?);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

// ---------- Background metadata refresh ----------
async fn refresh_issuer_metadata(state: &Arc<AppState>, issuer_url: &str) -> anyhow::Result<()> {
    info!(%issuer_url, "fetching issuer metadata");
    let res = reqwest::get(issuer_url)
        .await?
        .error_for_status()
        .context("issuer metadata request failed")?;
    let wk: WellKnown = res.json().await?;
    let pubkey_bytes =
        Base64UrlUnpadded::decode_vec(&wk.voprf.pubkey).context("base64 decode pubkey")?;

    let kid_for_log = wk.voprf.kid.clone();
    let ctx_len = b"freebird:v1".len();
    let info = IssuerInfo {
        pubkey_bytes,
        kid: wk.voprf.kid,
        ctx: b"freebird:v1".to_vec(),
        exp_sec: wk.voprf.exp_sec,
    };

    let mut issuers = state.issuers.write().await;
    issuers.insert(wk.issuer_id.clone(), info);
    info!(issuer = %wk.issuer_id, kid = %kid_for_log, ctx_len, "updated issuer metadata");
    Ok(())
}

// Wrapper to catch and log JSON deserialization errors
async fn verify_with_logging(
    state: State<Arc<AppState>>,
    result: Result<Json<VerifyRequest>, JsonRejection>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    info!("📥 /v1/verify request received");
    
    match result {
        Ok(Json(req)) => {
            info!("✅ Request parsed successfully: issuer_id={}", req.issuer_id);
            debug!("Full request: {:?}", req);
            verify(state, Json(req)).await
        }
        Err(rejection) => {
            error!("❌ JSON deserialization failed!");
            error!("Rejection type: {:?}", rejection);
            error!("Error message: {}", rejection);
            Err((StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", rejection)))
        }
    }
}

// ---------- Verification handler ----------
async fn verify(
    State(st): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    info!("🔍 Starting verification for issuer={}", req.issuer_id);
    
    // 1) Lookup issuer
    let issuers = st.issuers.read().await;
    debug!("Loaded issuers map, contains {} entries", issuers.len());
    
    let issuer = issuers
        .get(&req.issuer_id)
        .ok_or_else(|| {
            error!("Issuer not found: {}", req.issuer_id);
            (StatusCode::UNAUTHORIZED, "verification failed".to_string())
        })?;
    
    debug!("Found issuer: kid={}", issuer.kid);

    // 2) Verify DLEQ token and derive PRF output
    debug!("Verifying DLEQ token with context len={}", issuer.ctx.len());
    let verifier = crypto::Verifier::new(&issuer.ctx);
    let out_b64 = verifier
        .verify(&req.token_b64, &issuer.pubkey_bytes)
        .map_err(|e| {
            error!("Token verification failed: {:?}", e);
            (StatusCode::UNAUTHORIZED, "verification failed".into())
        })?;
    
    debug!("Token verified, PRF output derived");

    // 3) Replay / spend tracking
    let null_key = crypto::nullifier_key(&req.issuer_id, &out_b64);
    let spend_key = format!("freebird:spent:{}:{}", req.issuer_id, null_key);
    debug!("Checking spend status for key: {}", spend_key);
    
    let spent = st
        .store
        .mark_spent(&spend_key, Duration::from_secs(issuer.exp_sec))
        .await
        .map_err(|e| {
            error!(%spend_key, "store error: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error".into())
        })?;

    if !spent {
        warn!(%spend_key, "replay detected");
        return Err((StatusCode::UNAUTHORIZED, "verification failed".into()));
    }

    // 4) Success
    info!("✅ Token verified successfully: issuer={}, kid={}", req.issuer_id, issuer.kid);
    Ok(Json(VerifyResponse {
        ok: true,
        verified_at: time::OffsetDateTime::now_utc().unix_timestamp(),
    }))
}

// ---------- Graceful shutdown ----------
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