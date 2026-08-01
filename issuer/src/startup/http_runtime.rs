// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::readiness::ReadinessState;
use crate::routes;
use crate::sybil_resistance::{invitation::InvitationSystem, ReplayStore, SybilResistance};
#[cfg(feature = "human-gate-webauthn")]
use crate::webauthn;
use crate::AppStateWithSybil;
use anyhow::Result;
use axum::extract::DefaultBodyLimit;
use axum::{
    routing::{get, post},
    Router,
};
use freebird_common::metrics::MetricsMiddleware;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub(super) struct HttpRuntimeInputs {
    pub(super) config: crate::config::Config,
    pub(super) kid: String,
    pub(super) pubkey_b64: String,
    pub(super) voprf: Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
    pub(super) audit_log: Arc<crate::audit::AuditLog>,
    pub(super) sybil_checker: Option<Arc<dyn SybilResistance>>,
    pub(super) invitation_system: Option<Arc<InvitationSystem>>,
    pub(super) multi_party_vouching_system:
        Option<Arc<crate::sybil_resistance::MultiPartyVouchingSystem>>,
    pub(super) public_issuer: Option<Arc<crate::public_tokens::PublicTokenIssuer>>,
    pub(super) exchange_engine: Option<Arc<crate::exchange::ExchangeEngine>>,
    pub(super) exchange_metadata: Option<freebird_common::api::ExchangeDiscoveryV2>,
    pub(super) graph_issuance_engine: Option<Arc<crate::graph_issuance::GraphIssuanceEngine>>,
    pub(super) admin_api_key: String,
    pub(super) sybil_replay_store: Arc<dyn ReplayStore>,
    pub(super) storage_paths: Vec<(String, PathBuf)>,
    pub(super) exchange_readiness: Option<crate::readiness::ExchangeReadinessState>,
    pub(super) graph_issuance_readiness: Option<crate::readiness::GraphIssuanceReadinessState>,
    #[cfg(feature = "human-gate-webauthn")]
    pub(super) webauthn_state: Option<Arc<crate::webauthn::WebAuthnState>>,
}

pub(super) struct HttpRuntime {
    pub(super) app: Router,
    pub(super) readiness: ReadinessState,
    pub(super) sybil_replay_store: Arc<dyn ReplayStore>,
    pub(super) storage_paths: Vec<(String, PathBuf)>,
    pub(super) exchange_readiness: Option<crate::readiness::ExchangeReadinessState>,
    pub(super) graph_issuance_readiness: Option<crate::readiness::GraphIssuanceReadinessState>,
}

fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    drop(err);
    tracing::error!("handler panic caught; suppressing all details");

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        )],
        axum::Json(serde_json::json!({
            "error": "internal_error",
            "code": "INTERNAL_ERROR"
        })),
    )
        .into_response()
}

pub type PublicState = (
    Arc<crate::AppStateWithSybil>,
    Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
);

pub fn exchange_router(body_limit: usize, timeout_secs: u64) -> Router<PublicState> {
    Router::new()
        .route(
            "/v2/public/exchange",
            post(routes::public_exchange::post_exchange),
        )
        .route(
            "/v2/public/exchange/status",
            get(routes::public_exchange::get_exchange_status),
        )
        .layer(TimeoutLayer::new(Duration::from_secs(timeout_secs)))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    routes::public_exchange::IDEMPOTENCY_KEY,
                ]),
        )
        .layer(freebird_common::rate_limit::PublicRateLimitLayer::default())
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        ))
}

pub fn graph_issuance_router(body_limit: usize, timeout_secs: u64) -> Router<PublicState> {
    Router::new()
        .route(
            "/v1/public/graph/issue",
            post(routes::public_graph_issuance::post),
        )
        .route(
            "/v1/public/graph/issue/status",
            get(routes::public_graph_issuance::status),
        )
        .route(
            "/v1/public/graph/replay-authority/probe",
            post(routes::public_graph_issuance::replay_authority_probe),
        )
        .layer(TimeoutLayer::new(Duration::from_secs(timeout_secs)))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    routes::public_graph_issuance::STATUS_CAPABILITY,
                ]),
        )
        .layer(freebird_common::rate_limit::PublicRateLimitLayer::default())
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        ))
}

pub fn apply_public_layers(app: Router) -> Result<Router> {
    Ok(app.layer(
        ServiceBuilder::new()
            .layer(CatchPanicLayer::custom(handle_panic))
            .layer(TraceLayer::new_for_http())
            .layer(MetricsMiddleware)
            .layer(
                freebird_common::tls_enforcement::TlsEnforcementLayer::from_env()
                    .map_err(|e| anyhow::anyhow!(e))?,
            ),
    ))
}

impl HttpRuntime {
    pub(super) fn build(inputs: HttpRuntimeInputs) -> Result<Self> {
        let HttpRuntimeInputs {
            config,
            kid,
            pubkey_b64,
            voprf,
            audit_log,
            sybil_checker,
            invitation_system,
            multi_party_vouching_system,
            public_issuer,
            exchange_engine,
            exchange_metadata,
            graph_issuance_engine,
            admin_api_key,
            sybil_replay_store,
            storage_paths,
            exchange_readiness,
            graph_issuance_readiness,
            #[cfg(feature = "human-gate-webauthn")]
            webauthn_state,
        } = inputs;

        // 6. App State & Router
        let state = Arc::new(AppStateWithSybil {
            issuer_id: config.issuer_id.clone(),
            kid: kid.clone(),
            pubkey_b64: pubkey_b64.clone(),
            require_tls: config.require_tls,
            behind_proxy: config.behind_proxy,
            sybil_checker: sybil_checker.clone(),
            invitation_system: invitation_system.clone(),
            public_issuer: public_issuer.clone(),
            exchange_engine: exchange_engine.clone(),
            exchange_metadata,
            graph_issuance_engine,
            graph_issuance_metadata: None,
            epoch_duration_sec: config.epoch_duration_sec,
            epoch_retention: config.epoch_retention,
            admin_api_key: Some(admin_api_key.clone()),
        });

        let app_state = (state.clone(), voprf.clone());
        let readiness = ReadinessState::new(config.unsafe_development_mode);
        // Initialize router
        // Note: routes::metadata::well_known_handler must exist!
        let app = Router::new()
            .route("/healthz", get(routes::liveness))
            .route(
                "/readyz",
                get({
                    let readiness = readiness.clone();
                    move || crate::readiness::public_readiness(readiness.clone())
                }),
            )
            .route(
                "/.well-known/issuer",
                get(routes::metadata::well_known_handler),
            )
            .route("/.well-known/keys", get(routes::metadata::keys_handler))
            .route("/v1/oprf/issue", post(routes::issue::handle))
            .route("/v1/oprf/renew", post(routes::issue::renew))
            .route(
                "/v1/oprf/issue/batch",
                post(routes::batch_issue::handle_batch),
            )
            .route("/v1/public/issue", post(routes::public_issue::handle))
            .route(
                "/v1/public/issue/batch",
                post(routes::public_issue::handle_batch),
            )
            .layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods([
                        axum::http::Method::GET,
                        axum::http::Method::POST,
                        axum::http::Method::OPTIONS,
                    ])
                    .allow_headers([axum::http::header::CONTENT_TYPE])
                    .max_age(Duration::from_secs(86400)),
            )
            .layer(DefaultBodyLimit::max(64 * 1024))
            .layer(freebird_common::rate_limit::PublicRateLimitLayer::default());

        let exchange_routes = exchange_router(
            config.exchange_config.request_body_limit,
            config.exchange_config.request_timeout_secs,
        );
        let graph_issuance_routes = graph_issuance_router(
            config.exchange_config.request_body_limit,
            config.exchange_config.request_timeout_secs,
        );
        let app = app.merge(exchange_routes).merge(graph_issuance_routes);

        // --- CRITICAL FIX: SHADOWING ---
        // Use `let app` to shadow the variable, allowing the type change from Router<S> to Router<()>
        let mut app = app.with_state(app_state);

        #[cfg(feature = "human-gate-webauthn")]
        if let Some(wa) = &webauthn_state {
            // Redirect /webauthn/ (trailing slash) to /webauthn.
            // axum 0.7's nest("/webauthn", ...) + inner route("/") registers
            // "/webauthn" (no slash), so /webauthn/ 404s without this.
            app = app.route(
                "/webauthn/",
                get(|| async { axum::response::Redirect::permanent("/webauthn") }),
            );
            app = app.nest("/webauthn", webauthn::router(wa.clone()));
        }

        if let Some(inv_sys) = invitation_system.clone() {
            #[cfg(feature = "human-gate-webauthn")]
            let webauthn_enabled = webauthn_state.is_some();
            #[cfg(not(feature = "human-gate-webauthn"))]
            let webauthn_enabled = false;

            let config_summary = routes::admin::ConfigSummary {
                issuer_id: config.issuer_id.clone(),
                sybil_config: routes::admin::SybilConfigSummary::from_config(&config.sybil_config),
                epoch_duration_secs: config.epoch_duration_sec,
                epoch_retention: config.epoch_retention,
                require_tls: config.require_tls,
                behind_proxy: config.behind_proxy,
                webauthn_enabled,
                allow_unsafe_v4_rotation: config.allow_unsafe_v4_rotation,
            };

            #[cfg(feature = "human-gate-webauthn")]
            let admin = routes::admin_router(
                inv_sys,
                multi_party_vouching_system.clone(),
                voprf.clone(),
                audit_log.clone(),
                admin_api_key,
                config.behind_proxy,
                config.require_tls,
                config.allow_unsafe_v4_rotation,
                webauthn_state.as_ref().map(|ws| ws.cred_store.clone()),
                config_summary,
            );
            #[cfg(not(feature = "human-gate-webauthn"))]
            let admin = routes::admin_router(
                inv_sys,
                multi_party_vouching_system.clone(),
                voprf.clone(),
                audit_log.clone(),
                admin_api_key,
                config.behind_proxy,
                config.require_tls,
                config.allow_unsafe_v4_rotation,
                config_summary,
            );
            app = app.nest("/admin", admin.layer(axum::Extension(readiness.clone())));
        }

        // Outermost layers: catch panics before they escape handlers, then
        // emit HTTP tracing spans for every inbound request.
        let app = apply_public_layers(app)?;

        Ok(Self {
            app,
            readiness,
            sybil_replay_store,
            storage_paths,
            exchange_readiness,
            graph_issuance_readiness,
        })
    }
}
