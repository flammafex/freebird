// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use axum::Router;
use freebird_common::metrics::MetricsMiddleware;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::RwLock, time::sleep};
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::metadata::refresh_issuer_metadata;
use crate::readiness::{StoreHealth, TokenFamily};
use crate::replay_authority::ReplayAuthorityHealth;
use crate::routes::admin::{self, AdminState, VerifierConfig};
use crate::routes::admin_rate_limit::AdminRateLimiter;
use crate::routes::public;
use crate::settings::Settings;
use crate::state::AppState;

pub struct Application {
    router: Router,
}

impl Application {
    pub async fn build(mut settings: Settings) -> anyhow::Result<Self> {
        let backend = settings.take_backend()?;
        let store_backend_name = settings.store_backend_name.clone();
        let store = backend.build().await?;
        let store_health = StoreHealth::new(Arc::clone(&store));
        let loaded = settings.complete_after_store()?;

        let replay_authority_config = loaded.replay_authority_config.clone();
        let replay_authority = Arc::new(ReplayAuthorityHealth::new(
            Arc::clone(&store),
            replay_authority_config.clone(),
            loaded.scope_digest,
        )?);

        let refresh_interval = Duration::from_secs(loaded.refresh_interval_min.saturating_mul(60));
        let issuer_urls = loaded.issuer_urls;
        info!(
            verifier_id = %loaded.verifier_id,
            audience = %loaded.audience,
            "Configured verifier scope"
        );
        let admin_settings = settings.complete_admin()?;

        let tls_layer = freebird_common::tls_enforcement::TlsEnforcementLayer::from_env()
            .map_err(|e| anyhow::anyhow!(e))?;
        let start_time = Instant::now();
        let issuers = Arc::new(RwLock::new(HashMap::new()));
        let metadata = Arc::new(RwLock::new(HashMap::new()));
        let state = Arc::new(AppState {
            issuers: Arc::clone(&issuers),
            store: Arc::clone(&store),
            verifier_id: loaded.verifier_id.clone(),
            audience: loaded.audience.clone(),
            scope_digest: loaded.scope_digest,
            epoch_duration_sec: loaded.epoch_duration_sec,
            epoch_retention: loaded.epoch_retention,
            issuer_urls: issuer_urls.clone(),
            metadata: Arc::clone(&metadata),
            accepted_token_families: loaded.accepted_token_families.clone(),
            refresh_interval,
            store_health: store_health.clone(),
            replay_authority: Arc::clone(&replay_authority),
            store_is_memory: store_backend_name == "memory",
        });

        // Background refresh loop for all issuer URLs. The task is spawned
        // before the router is assembled and performs its first refresh
        // immediately; startup deliberately does not await it.
        let refresh_state = Arc::clone(&state);
        let refresh_issuer_urls = issuer_urls.clone();
        let refresh_interval_min = loaded.refresh_interval_min;
        tokio::spawn(async move {
            // Track failures per-URL for independent backoff
            let mut failures: HashMap<String, u32> = HashMap::new();
            loop {
                for url in &refresh_issuer_urls {
                    match refresh_issuer_metadata(&refresh_state, url).await {
                        Ok(_) => {
                            failures.insert(url.clone(), 0);
                        }
                        Err(e) => {
                            let count = failures.entry(url.clone()).or_insert(0);
                            *count += 1;
                            warn!(?e, %url, failures = *count, "issuer refresh failed");
                        }
                    }
                }
                // Use max failure count across all URLs for backoff calculation
                let max_failures = failures.values().copied().max().unwrap_or(0);
                let delay = refresh_interval_min
                    .saturating_mul(60)
                    .saturating_mul(u64::from((max_failures + 1).min(5)));

                sleep(Duration::from_secs(delay)).await;
            }
        });

        if replay_authority.configured() {
            let replay_authority_task = Arc::clone(&replay_authority);
            tokio::spawn(async move {
                replay_authority_task.run().await;
            });
        }

        // ---------- Router ----------
        let mut app = public::router(Arc::clone(&state));

        // REQUIRE_TLS is intentionally read here for the admin cookie policy,
        // matching the previous startup stage. Metadata and replay-authority
        // refreshes continue to reread it in their own refresh paths.
        let require_tls = std::env::var("REQUIRE_TLS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let session_key = admin::derive_session_key(&admin_settings.admin_api_key);
        let admin_state = Arc::new(AdminState {
            issuers: Arc::clone(&issuers),
            store: Arc::clone(&store),
            api_key: admin_settings.admin_api_key,
            session_key,
            rate_limiter: AdminRateLimiter::new(),
            behind_proxy: admin_settings.behind_proxy,
            require_tls,
            start_time,
            config: VerifierConfig {
                epoch_duration_sec: loaded.epoch_duration_sec,
                epoch_retention: loaded.epoch_retention,
                refresh_interval_min: loaded.refresh_interval_min,
                store_backend: store_backend_name,
                issuer_urls: issuer_urls.clone(),
                verifier_id: loaded.verifier_id.clone(),
                audience: loaded.audience.clone(),
                accepted_token_versions: loaded
                    .accepted_token_families
                    .iter()
                    .map(|f| match f {
                        TokenFamily::V4 => "v4",
                        TokenFamily::V5 => "v5",
                    })
                    .map(str::to_string)
                    .collect(),
                graph_issuer_urls: replay_authority_config.graph_issuer_urls.clone(),
                replay_authority_probe_interval_secs: replay_authority_config
                    .probe_interval
                    .as_secs(),
                replay_authority_max_staleness_secs: replay_authority_config
                    .max_staleness
                    .as_secs(),
            },
            metadata,
            accepted_token_families: loaded.accepted_token_families,
            store_health,
            replay_authority,
        });

        let rate_limiter_clone = Arc::clone(&admin_state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                rate_limiter_clone.rate_limiter.cleanup_expired().await;
            }
        });

        let admin_router = admin::admin_router(admin_state);
        app = app.nest("/admin", admin_router);
        info!("Admin API enabled at /admin");
        let app = apply_outer_layers(app, tls_layer);

        Ok(Self { router: app })
    }

    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> anyhow::Result<()> {
        axum::serve(
            listener,
            self.router
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await?;
        Ok(())
    }
}

fn apply_outer_layers(
    app: Router,
    tls_layer: freebird_common::tls_enforcement::TlsEnforcementLayer,
) -> Router {
    // Outermost layers: catch panics before they escape handlers, then emit
    // HTTP tracing spans for every inbound request.
    app.layer(
        ServiceBuilder::new()
            .layer(CatchPanicLayer::custom(handle_panic))
            .layer(TraceLayer::new_for_http())
            .layer(MetricsMiddleware)
            .layer(tls_layer),
    )
}

/// Convert a handler panic into a structured JSON 500 so that internal
/// details (stack traces, key material) are never forwarded to clients.
fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    use axum::response::IntoResponse;

    let msg = if let Some(s) = err.downcast_ref::<&'static str>() {
        *s
    } else if let Some(s) = err.downcast_ref::<String>() {
        s.as_str()
    } else {
        "unknown panic"
    };

    tracing::error!(panic.message = %msg, "handler panic caught; suppressing details from client");

    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "error": "internal_error",
            "code": "INTERNAL_ERROR"
        })),
    )
        .into_response()
}

pub async fn shutdown_signal() {
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

    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::{apply_outer_layers, handle_panic};
    use axum::{
        body::Body, extract::ConnectInfo, http::Request, response::IntoResponse, routing::get,
        Router,
    };
    use std::net::SocketAddr;
    use tower::ServiceExt;

    #[test]
    fn panic_layer_response_remains_generic() {
        let response = handle_panic(Box::new("secret panic details")).into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn composed_router_keeps_admin_nesting_and_connect_info_boundary() {
        let public = Router::new().route("/health", get(|| async { "public" }));
        let admin = Router::new().route("/ping", get(|| async { "admin" }));
        let tls_layer = freebird_common::tls_enforcement::TlsEnforcementLayer::from_env().unwrap();
        let app = apply_outer_layers(public.nest("/admin", admin), tls_layer);

        let mut request = Request::builder()
            .uri("/admin/ping")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8082))));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
