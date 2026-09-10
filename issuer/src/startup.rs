// issuer/src/startup.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::config::Config;
use crate::shutdown::{drain_admission_and_flush, wait_for_signal, ShutdownCoordinator};
use crate::sybil_resistance::admission::AdmissionExecutor;

use anyhow::{Context, Result};
use axum::Router;
use freebird_common::metrics;
use std::{
    future::IntoFuture,
    time::{Duration, Instant},
};
use tokio::net::TcpListener;
use tracing::info;

mod exchange_runtime;
mod http_runtime;
mod key_material;
mod preflight;
mod sybil_audit_runtime;
mod webauthn_runtime;
pub(crate) use exchange_runtime::validate_v7_exchange_inventory;
pub use exchange_runtime::validate_v7_runtime_config;
use exchange_runtime::ExchangeRuntime;
pub use http_runtime::{apply_public_layers, exchange_router, graph_issuance_router, PublicState};
use http_runtime::{HttpRuntime, HttpRuntimeInputs};
use sybil_audit_runtime::SybilAuditRuntime;

/// Convert a handler panic into a structured JSON 500 so that raw panic
/// messages (which may include key material or internal paths) are never
/// forwarded to the client.
pub struct Application {
    /// Bound port, captured at construction for logging/testing. Not read after bind.
    #[allow(dead_code)]
    port: u16,
    listener: TcpListener,
    app: Router,
    shutdown: ShutdownCoordinator,
    admission: AdmissionExecutor,
}

impl Application {
    pub async fn build(mut config: Config) -> Result<Self> {
        let admin_api_key = preflight::run(&mut config)?;
        metrics::register_metrics();
        // ... [Keys, VOPRF, WebAuthn setup code remains the same] ...
        // ... [Sybil setup code remains the same] ...

        // 1. Keys & VOPRF Setup
        let key_material::KeyMaterial {
            secret_guard: _issuer_secret,
            kid,
            pubkey_b64,
            voprf,
            native_bearer_v7,
            native_bearer_v7_retained,
            v7_signer_inventory,
        } = key_material::KeyMaterial::build(&config).await?;

        // The exchange subsystem remains separately staged and receives only
        // the native V7 signer inventory from startup.
        let exchange_runtime = ExchangeRuntime::build(&config, v7_signer_inventory).await?;
        let ExchangeRuntime {
            native_exchange_v7,
            native_exchange_v7_discovery,
            native_graph_issuance_v7,
            native_graph_issuance_v7_discovery,
            native_exchange_v7_readiness,
            native_graph_issuance_v7_readiness,
            replay_authority,
        } = exchange_runtime;

        // 2. WebAuthn Setup
        let webauthn_state =
            webauthn_runtime::build(config.webauthn_config.as_ref(), config.behind_proxy)?;

        let sybil_audit_runtime =
            SybilAuditRuntime::build(&config, voprf.clone(), &webauthn_state).await?;
        let SybilAuditRuntime {
            audit_log,
            sybil_replay_store,
            sybil_checker,
            invitation_system,
            multi_party_vouching_system,
            storage_paths,
            shutdown,
        } = sybil_audit_runtime;

        let http_runtime = HttpRuntime::build(HttpRuntimeInputs {
            config: config.clone(),
            kid,
            pubkey_b64,
            voprf: voprf.clone(),
            audit_log,
            sybil_checker,
            invitation_system,
            multi_party_vouching_system,
            native_bearer_v7,
            native_bearer_v7_retained,
            admin_api_key,
            sybil_replay_store,
            storage_paths,
            native_exchange_v7,
            native_exchange_v7_discovery,
            native_graph_issuance_v7,
            native_graph_issuance_v7_discovery,
            native_exchange_v7_readiness,
            native_graph_issuance_v7_readiness,
            replay_authority,
            webauthn_state: webauthn_state.clone(),
        })?;
        let HttpRuntime {
            admission,
            app,
            readiness,
            sybil_replay_store,
            storage_paths,
            native_exchange_v7_readiness,
            native_graph_issuance_v7_readiness,
            replay_authority,
        } = http_runtime;

        let listener = TcpListener::bind(config.bind_addr)
            .await
            .context("Failed to bind TCP listener")?;
        let port = listener.local_addr()?.port();

        readiness.spawn_checks(
            admission.clone(),
            sybil_replay_store.clone(),
            storage_paths,
            voprf.clone(),
            native_exchange_v7_readiness,
            native_graph_issuance_v7_readiness,
            replay_authority,
        );

        info!("🚀 Server ready at {}", config.bind_addr);

        Ok(Self {
            port,
            listener,
            app,
            shutdown,
            admission,
        })
    }

    pub async fn run(self) -> Result<()> {
        self.run_with_signal_timeout(wait_for_signal(), Duration::from_secs(30))
            .await
    }

    async fn run_with_signal_timeout<F>(self, signal: F, shutdown_timeout: Duration) -> Result<()>
    where
        F: std::future::Future<Output = ()> + Send,
    {
        let shutdown = self.shutdown;
        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
        let mut server = Box::pin(
            axum::serve(
                self.listener,
                self.app
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = signal_rx.await;
            })
            .into_future(),
        );
        tokio::pin!(signal);
        let drain_result = tokio::select! {
            result = &mut server => {
                self.admission.close();
                (Ok(result), Instant::now() + shutdown_timeout)
            },
            _ = &mut signal => {
                let deadline = Instant::now() + shutdown_timeout;
                self.admission.close();
                let _ = signal_tx.send(());
                let result = tokio::time::timeout_at(deadline.into(), &mut server).await;
                (result, deadline)
            }
        };
        let (drain_result, deadline) = drain_result;
        let drain_error = match drain_result {
            Err(_) => {
                tracing::error!(
                    critical_state = "in-flight requests",
                    "CRITICAL: issuer drain timed out"
                );
                Some(anyhow::anyhow!(
                    "drain timeout: in-flight requests did not complete"
                ))
            }
            Ok(Err(error)) => Some(anyhow::anyhow!("server drain error: {error}")),
            Ok(Ok(())) => None,
        };
        // Stop the server, then account for blocking jobs independently of
        // their request futures before entering any final persistence writer.
        drop(server);
        let flush_result = drain_admission_and_flush(&self.admission, shutdown, deadline).await;
        match (drain_error, flush_result) {
            (Some(error), Ok(())) => Err(error).context("Server error"),
            (Some(error), Err(flush_error)) => Err(anyhow::anyhow!(
                "server drain: {error:#}; persistence: {flush_error:#}"
            )),
            (None, result) => result,
        }
    }
}
