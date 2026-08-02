// issuer/src/startup.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::config::Config;
use crate::shutdown::{flush_or_report, wait_for_signal, ShutdownCoordinator};

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
pub use exchange_runtime::exchange_discovery_v2;
pub(crate) use exchange_runtime::validate_disabled_publication_acknowledgements_v2;
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
            public_issuer,
        } = key_material::KeyMaterial::build(&config).await?;

        let exchange_runtime = ExchangeRuntime::build(&config, public_issuer.as_deref()).await?;
        let ExchangeRuntime {
            exchange_engine,
            exchange_metadata,
            exchange_readiness,
            graph_issuance_engine,
            graph_issuance_readiness,
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
            public_issuer,
            exchange_engine,
            exchange_metadata,
            graph_issuance_engine,
            admin_api_key,
            sybil_replay_store,
            storage_paths,
            exchange_readiness,
            graph_issuance_readiness,
            webauthn_state: webauthn_state.clone(),
        })?;
        let HttpRuntime {
            app,
            readiness,
            sybil_replay_store,
            storage_paths,
            exchange_readiness,
            graph_issuance_readiness,
        } = http_runtime;

        let listener = TcpListener::bind(config.bind_addr)
            .await
            .context("Failed to bind TCP listener")?;
        let port = listener.local_addr()?.port();

        readiness.spawn_checks(
            sybil_replay_store.clone(),
            storage_paths,
            voprf.clone(),
            exchange_readiness,
            graph_issuance_readiness,
        );

        info!("🚀 Server ready at {}", config.bind_addr);

        Ok(Self {
            port,
            listener,
            app,
            shutdown,
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
            result = &mut server => return result.context("Server error"),
            _ = &mut signal => {
                let _ = signal_tx.send(());
                let deadline = Instant::now() + shutdown_timeout;
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
        // Ensure the listener/server future and all request resources are
        // terminated before any persistence writer is entered.
        drop(server);
        let flush_result = flush_or_report(shutdown, deadline).await;
        match (drain_error, flush_result) {
            (Some(error), Ok(())) => Err(error).context("Server error"),
            (Some(error), Err(flush_error)) => Err(anyhow::anyhow!(
                "server drain: {error:#}; persistence: {flush_error:#}"
            )),
            (None, result) => result,
        }
    }
}

#[cfg(test)]
impl Application {
    pub(crate) fn test_local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub(crate) fn test_shutdown_names(&self) -> Vec<&'static str> {
        self.shutdown.registration_names()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        exchange_discovery_v2, sybil_audit_runtime::parse_progressive_trust_levels,
        validate_disabled_publication_acknowledgements_v2, Application,
    };
    use crate::config::{
        ExchangeDisabledPublicationAcknowledgementV1, EXCHANGE_DISABLED_PUBLICATION_ACK_VERSION,
    };
    use crate::exchange::profiles::{
        ExchangeAdmissionStateV2, ExchangeDescriptorV2, ExchangeKeyV2, ExchangeKeysetV2,
        ExchangeProfileV2, ExchangeTransitionSlotV2, ExchangeTransitionV2,
    };
    use crate::shutdown::ShutdownCoordinator;
    use axum::{routing::get, Router};
    use freebird_common::api::ExchangeReceiptKeyInfo;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn publication_discovery(
        admission_state: freebird_common::api::ExchangeAdmissionStateV2,
    ) -> freebird_common::api::ExchangeDiscoveryV2 {
        use freebird_common::api::{ExchangeGraphDiscoveryV2, ExchangeTransitionDiscoveryV2};

        freebird_common::api::ExchangeDiscoveryV2 {
            active_graph: ExchangeGraphDiscoveryV2 {
                profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V2.into(),
                graph_id: "a".repeat(64),
                descriptors: vec![],
                keysets: vec![],
                transitions: vec![ExchangeTransitionDiscoveryV2 {
                    transition_id: "b".repeat(64),
                    source_keyset_id: "c".repeat(64),
                    target_keyset_id: "d".repeat(64),
                    source_slots: vec![],
                    output_slots: vec![],
                    budget_id: "budget".into(),
                    budget_limit: 1,
                    admission_state,
                }],
            },
            retained_graphs: vec![],
            active_receipt_key: ExchangeReceiptKeyInfo {
                key_id: "e".repeat(64),
                algorithm: "Ed25519".into(),
                purpose: "exchange_receipt_active".into(),
                public_key_b64: "AQ".into(),
                valid_from: 1,
                valid_until: 2,
            },
            retained_receipt_keys: vec![],
        }
    }

    fn publication_acknowledgement() -> ExchangeDisabledPublicationAcknowledgementV1 {
        ExchangeDisabledPublicationAcknowledgementV1 {
            version: EXCHANGE_DISABLED_PUBLICATION_ACK_VERSION.into(),
            issuer_id: "issuer:test".into(),
            graph_id: "a".repeat(64),
            disabled_transition_ids: vec!["b".repeat(64)],
            acknowledged_admission_state: "disabled".into(),
            operator: "operator@example.test".into(),
            acknowledged_at_unix: 1,
        }
    }

    #[test]
    fn parses_human_readable_progressive_trust_levels() {
        let levels = vec![
            "0:1:1d".to_string(),
            "30d:10:1h".to_string(),
            "90d:100:1m".to_string(),
        ];
        let parsed = parse_progressive_trust_levels(&levels).expect("levels should parse");

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].min_age_secs, 0);
        assert_eq!(parsed[1].min_age_secs, 30 * 24 * 3600);
        assert_eq!(parsed[2].cooldown_secs, 60);
    }

    #[test]
    fn rejects_invalid_or_empty_progressive_trust_levels() {
        assert!(parse_progressive_trust_levels(&[]).is_err());
        assert!(parse_progressive_trust_levels(&["bad".to_string()]).is_err());
        assert!(parse_progressive_trust_levels(&["10x:1:1m".to_string()]).is_err());
    }

    #[test]
    fn v2_discovery_projection_excludes_private_signer_paths_and_preserves_history() {
        let descriptor = ExchangeDescriptorV2 {
            id: "a".repeat(64),
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V2.into(),
            issuer_id: "issuer:test".into(),
            kid: "b".repeat(64),
            audience: Some("audience".into()),
            spki_b64: "AQ".into(),
            suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
            valid_from: 1,
            valid_until: 2,
        };
        let keyset = ExchangeKeysetV2 {
            id: "c".repeat(64),
            keys: vec![ExchangeKeyV2 {
                descriptor: descriptor.clone(),
                private_key_path: Some("/private/target.der".into()),
            }],
        };
        let transition = ExchangeTransitionV2 {
            id: "d".repeat(64),
            source_keyset_id: keyset.id.clone(),
            target_keyset_id: "e".repeat(64),
            sources: vec![ExchangeTransitionSlotV2 {
                descriptor_id: descriptor.id.clone(),
                slot_id: "in".into(),
                class: "bearer".into(),
                quantity: 1,
            }],
            outputs: vec![ExchangeTransitionSlotV2 {
                descriptor_id: descriptor.id.clone(),
                slot_id: "out".into(),
                class: "bearer".into(),
                quantity: 1,
            }],
            budget_id: "budget".into(),
            budget_limit: 1,
            admission_state: ExchangeAdmissionStateV2::RecoveryOnly,
        };
        let active = ExchangeProfileV2 {
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V2.into(),
            graph_id: "f".repeat(64),
            keysets: vec![keyset],
            transitions: vec![transition],
        };
        let mut retained = active.clone();
        retained.graph_id = "0".repeat(64);
        let receipt = ExchangeReceiptKeyInfo {
            key_id: "1".repeat(64),
            algorithm: "Ed25519".into(),
            purpose: "exchange_receipt_active".into(),
            public_key_b64: "AQ".into(),
            valid_from: 1,
            valid_until: 2,
        };

        let discovery = exchange_discovery_v2(&active, &[retained], &[receipt]).unwrap();
        assert_eq!(discovery.retained_graphs.len(), 1);
        assert_eq!(discovery.active_graph.transitions.len(), 1);
        let json = serde_json::to_string(&discovery).unwrap();
        assert!(!json.contains("private_key"));
        assert!(!json.contains("/private/target.der"));
        assert!(!json.contains("freebird/public-bearer-exchange/v1"));
    }

    #[tokio::test]
    async fn failed_or_bound_but_unserved_disabled_startup_cannot_unlock_acceptance() {
        let disabled =
            publication_discovery(freebird_common::api::ExchangeAdmissionStateV2::Disabled);
        validate_disabled_publication_acknowledgements_v2("issuer:test", &disabled, &[])
            .expect("disabled graph does not require an acknowledgement");

        // Merely binding and then abandoning a listener is not an operator
        // acknowledgement and must have no admission side effect.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        drop(listener);

        let accepting =
            publication_discovery(freebird_common::api::ExchangeAdmissionStateV2::AcceptingNew);
        assert!(
            validate_disabled_publication_acknowledgements_v2("issuer:test", &accepting, &[],)
                .is_err()
        );
    }

    #[test]
    fn disabled_publication_acknowledgement_rejects_graph_mismatch() {
        let accepting =
            publication_discovery(freebird_common::api::ExchangeAdmissionStateV2::AcceptingNew);
        let mut acknowledgement = publication_acknowledgement();
        acknowledgement.graph_id = "f".repeat(64);
        let error = validate_disabled_publication_acknowledgements_v2(
            "issuer:test",
            &accepting,
            &[acknowledgement],
        )
        .unwrap_err();
        assert!(error.to_string().contains("graph mismatch"));
    }

    #[test]
    fn accepting_transition_allows_exact_operator_acknowledgement() {
        let accepting =
            publication_discovery(freebird_common::api::ExchangeAdmissionStateV2::AcceptingNew);
        validate_disabled_publication_acknowledgements_v2(
            "issuer:test",
            &accepting,
            &[publication_acknowledgement()],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn application_run_accepts_injected_shutdown_signal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let application = Application {
            port: listener.local_addr().unwrap().port(),
            listener,
            app: Router::new(),
            shutdown: ShutdownCoordinator::new(),
        };
        application
            .run_with_signal_timeout(async {}, Duration::from_secs(1))
            .await
            .expect("injected signal should gracefully stop the server");
    }

    #[tokio::test]
    async fn application_reports_drain_timeout_and_drops_server_before_flush() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let application = Application {
            port,
            listener,
            app: Router::new().route(
                "/",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    "ok"
                }),
            ),
            shutdown: ShutdownCoordinator::new(),
        };
        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            application
                .run_with_signal_timeout(
                    async {
                        let _ = signal_rx.await;
                    },
                    Duration::from_millis(50),
                )
                .await
        });
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let _ = signal_tx.send(());
        let error = task
            .await
            .unwrap()
            .expect_err("drain timeout must fail shutdown");
        assert!(format!("{error:#}").contains("drain timeout"));
    }

    #[tokio::test]
    async fn application_returns_persistence_failure_after_server_lifecycle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut shutdown = ShutdownCoordinator::new();
        shutdown.add("injected_store", || async {
            Err(anyhow::anyhow!("disk full"))
        });
        shutdown.add("second_store", || async {
            Err(anyhow::anyhow!("permission denied"))
        });
        let application = Application {
            port: listener.local_addr().unwrap().port(),
            listener,
            app: Router::new(),
            shutdown,
        };
        let error = application
            .run_with_signal_timeout(async {}, Duration::from_secs(1))
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("injected_store"));
        assert!(message.contains("second_store"));
    }
}

#[cfg(test)]
mod characterization_tests;
