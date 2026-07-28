// issuer/src/startup.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::readiness::ReadinessState;
use crate::shutdown::{flush_or_report, wait_for_signal, ShutdownCoordinator};
#[cfg(feature = "human-gate-webauthn")]
use crate::webauthn;
use crate::{
    audit::{AuditConfig, AuditLog},
    config::Config,
    keys, multi_key_voprf, routes,
    sybil_resistance::{
        self,
        invitation::{InvitationConfig, InvitationSystem},
        replay_store_from_env, CombinedAnd, CombinedOr, CombinedThreshold, ProofOfWork, RateLimit,
        SybilResistance,
    },
    AppStateWithSybil,
};

use anyhow::{bail, Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::{
    routing::{get, post},
    Router,
};
use base64ct::Encoding;
use freebird_common::metrics::{self, MetricsMiddleware};
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs,
    future::IntoFuture,
    io::Write,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

/// Convert a handler panic into a structured JSON 500 so that raw panic
/// messages (which may include key material or internal paths) are never
/// forwarded to the client.
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

pub struct Application {
    /// Bound port, captured at construction for logging/testing. Not read after bind.
    #[allow(dead_code)]
    port: u16,
    listener: TcpListener,
    app: Router,
    shutdown: ShutdownCoordinator,
}

fn load_or_generate_invitation_signing_key(path: &Path) -> Result<SigningKey> {
    if let Ok(bytes) = fs::read(path) {
        if bytes.len() != 32 {
            anyhow::bail!(
                "invalid invitation signing key size: got {} bytes, expected 32",
                bytes.len()
            );
        }

        let key_bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .context("failed to parse invitation signing key bytes")?;
        return SigningKey::from_bytes(&key_bytes.into())
            .context("invalid invitation signing key material");
    }

    let signing_key = SigningKey::random(&mut OsRng);
    let raw = signing_key.to_bytes();
    let tmp_path = path.with_extension("tmp");

    #[cfg(unix)]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(raw.as_ref())?;
        f.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(raw.as_ref())?;
        f.sync_all()?;
    }

    fs::rename(&tmp_path, path).context("failed to persist invitation signing key")?;
    #[cfg(unix)]
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        let directory = std::fs::File::open(parent)
            .context("failed to open invitation key directory for sync")?;
        directory
            .sync_all()
            .context("failed to sync invitation key directory")?;
    }
    Ok(signing_key)
}

fn parse_progressive_trust_levels(levels: &[String]) -> Result<Vec<sybil_resistance::TrustLevel>> {
    let mut parsed = Vec::with_capacity(levels.len());

    for level_str in levels {
        let parts: Vec<&str> = level_str.split(':').collect();
        if parts.len() != 3 {
            bail!(
                "invalid progressive trust level '{}': expected format age:tokens:cooldown",
                level_str
            );
        }

        let min_age_secs =
            freebird_common::duration::parse_duration(parts[0]).with_context(|| {
                format!(
                    "invalid progressive trust min age '{}' in '{}'",
                    parts[0], level_str
                )
            })?;
        let max_tokens_per_period = parts[1].parse::<u32>().with_context(|| {
            format!(
                "invalid progressive trust max token count '{}' in '{}'",
                parts[1], level_str
            )
        })?;
        let cooldown_secs =
            freebird_common::duration::parse_duration(parts[2]).with_context(|| {
                format!(
                    "invalid progressive trust cooldown '{}' in '{}'",
                    parts[2], level_str
                )
            })?;

        parsed.push(sybil_resistance::TrustLevel {
            min_age_secs,
            max_tokens_per_period,
            cooldown_secs,
        });
    }

    if parsed.is_empty() {
        bail!("progressive trust requires at least one configured level");
    }

    for window in parsed.windows(2) {
        if window[0].min_age_secs > window[1].min_age_secs {
            bail!(
                "progressive trust levels must be sorted by min age ascending (got {} before {})",
                window[0].min_age_secs,
                window[1].min_age_secs
            );
        }
    }

    Ok(parsed)
}

fn graph_discovery_v2(
    graph: &crate::exchange::profiles::ExchangeProfileV2,
) -> freebird_common::api::ExchangeGraphDiscoveryV2 {
    use freebird_common::api::{
        ExchangeAdmissionStateV2, ExchangeDescriptorDiscoveryV2, ExchangeKeysetDiscoveryV2,
        ExchangeTransitionDiscoveryV2, ExchangeTransitionSlotDiscoveryV2,
    };

    let slots = |slots: &[crate::exchange::profiles::ExchangeTransitionSlotV2]| {
        slots
            .iter()
            .map(|slot| ExchangeTransitionSlotDiscoveryV2 {
                descriptor_id: slot.descriptor_id.clone(),
                slot_id: slot.slot_id.clone(),
                class: slot.class.clone(),
                quantity: slot.quantity,
            })
            .collect()
    };
    freebird_common::api::ExchangeGraphDiscoveryV2 {
        profile_id: graph.profile_id.clone(),
        graph_id: graph.graph_id.clone(),
        descriptors: graph
            .keysets
            .iter()
            .flat_map(|keyset| &keyset.keys)
            .map(|key| ExchangeDescriptorDiscoveryV2 {
                descriptor_id: key.descriptor.id.clone(),
                profile_id: key.descriptor.profile_id.clone(),
                issuer_id: key.descriptor.issuer_id.clone(),
                token_key_id: key.descriptor.kid.clone(),
                audience: key.descriptor.audience.clone(),
                pubkey_spki_b64: key.descriptor.spki_b64.clone(),
                suite: key.descriptor.suite.clone(),
                valid_from: key.descriptor.valid_from,
                valid_until: key.descriptor.valid_until,
            })
            .collect(),
        keysets: graph
            .keysets
            .iter()
            .map(|keyset| ExchangeKeysetDiscoveryV2 {
                keyset_id: keyset.id.clone(),
                descriptor_ids: keyset
                    .keys
                    .iter()
                    .map(|key| key.descriptor.id.clone())
                    .collect(),
            })
            .collect(),
        transitions: graph
            .transitions
            .iter()
            .map(|transition| ExchangeTransitionDiscoveryV2 {
                transition_id: transition.id.clone(),
                source_keyset_id: transition.source_keyset_id.clone(),
                target_keyset_id: transition.target_keyset_id.clone(),
                source_slots: slots(&transition.sources),
                output_slots: slots(&transition.outputs),
                budget_id: transition.budget_id.clone(),
                budget_limit: transition.budget_limit,
                admission_state: match transition.admission_state {
                    crate::exchange::profiles::ExchangeAdmissionStateV2::AcceptingNew => {
                        ExchangeAdmissionStateV2::AcceptingNew
                    }
                    crate::exchange::profiles::ExchangeAdmissionStateV2::RecoveryOnly => {
                        ExchangeAdmissionStateV2::RecoveryOnly
                    }
                    crate::exchange::profiles::ExchangeAdmissionStateV2::Disabled => {
                        ExchangeAdmissionStateV2::Disabled
                    }
                },
            })
            .collect(),
    }
}

pub fn exchange_discovery_v2(
    active: &crate::exchange::profiles::ExchangeProfileV2,
    retained: &[crate::exchange::profiles::ExchangeProfileV2],
    receipt_keys: &[freebird_common::api::ExchangeReceiptKeyInfo],
) -> Result<freebird_common::api::ExchangeDiscoveryV2> {
    let active_receipt_key = receipt_keys
        .iter()
        .find(|key| key.purpose == "exchange_receipt_active")
        .cloned()
        .context("active V2 receipt discovery metadata is unavailable")?;
    let retained_receipt_keys = receipt_keys
        .iter()
        .filter(|key| key.purpose == "exchange_receipt_retained")
        .cloned()
        .collect();
    Ok(freebird_common::api::ExchangeDiscoveryV2 {
        active_graph: graph_discovery_v2(active),
        retained_graphs: retained.iter().map(graph_discovery_v2).collect(),
        active_receipt_key,
        retained_receipt_keys,
    })
}

fn exchange_registry_entries_v2(
    identities: &std::collections::BTreeMap<String, crate::exchange::history::GlobalV5KeyIdentity>,
) -> Vec<crate::exchange::store::KeyRegistryEntry> {
    identities
        .values()
        .map(|identity| crate::exchange::store::KeyRegistryEntry {
            key_id: identity.key_id.clone(),
            canonical_metadata: identity.canonical_bytes(),
        })
        .collect()
}

pub(crate) fn validate_disabled_publication_acknowledgements_v2(
    issuer_id: &str,
    discovery: &freebird_common::api::ExchangeDiscoveryV2,
    acknowledgements: &[crate::config::ExchangeDisabledPublicationAcknowledgementV1],
) -> Result<()> {
    let graphs = std::iter::once(&discovery.active_graph)
        .chain(&discovery.retained_graphs)
        .collect::<Vec<_>>();
    let mut acknowledged = std::collections::HashSet::new();
    for acknowledgement in acknowledgements {
        if acknowledgement.issuer_id != issuer_id {
            bail!("disabled-publication acknowledgement issuer mismatch")
        }
        let graph = graphs
            .iter()
            .find(|graph| graph.graph_id == acknowledgement.graph_id)
            .context("disabled-publication acknowledgement graph mismatch")?;
        for transition_id in &acknowledgement.disabled_transition_ids {
            if !graph
                .transitions
                .iter()
                .any(|transition| transition.transition_id == *transition_id)
            {
                bail!("disabled-publication acknowledgement transition mismatch")
            }
            if !acknowledged.insert((graph.graph_id.as_str(), transition_id.as_str())) {
                bail!("duplicate disabled-publication acknowledgement")
            }
        }
    }
    for graph in graphs {
        for transition in &graph.transitions {
            if transition.admission_state
                == freebird_common::api::ExchangeAdmissionStateV2::AcceptingNew
                && !acknowledged
                    .contains(&(graph.graph_id.as_str(), transition.transition_id.as_str()))
            {
                bail!(
                    "accepting V2 transition lacks an explicit disabled-publication acknowledgement for this graph"
                )
            }
        }
    }
    Ok(())
}

async fn validate_pending_graph_references_v2(
    store: &crate::exchange::store::ExchangeStore,
    active: &crate::exchange::profiles::ExchangeProfileV2,
    retained: &[crate::exchange::profiles::ExchangeProfileV2],
) -> Result<()> {
    for record in store.pending_records_v2().await? {
        let graph = std::iter::once(active)
            .chain(retained)
            .find(|graph| graph.graph_id == record.graph_id)
            .context("pending V2 exchange references an unavailable graph")?;
        let transition = graph
            .transitions
            .iter()
            .find(|transition| {
                transition.id == record.transition_id
                    && transition.source_keyset_id == record.source_keyset_id
                    && transition.target_keyset_id == record.target_keyset_id
            })
            .context("pending V2 exchange references an unavailable transition")?;
        if !transition.allows_recovery() {
            bail!("disabled V2 exchange transition still has pending references")
        }
    }
    Ok(())
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

impl Application {
    pub async fn build(config: Config) -> Result<Self> {
        if config.sybil_config.progressive_trust_salt == "default-salt-change-in-production" {
            bail!("Insecure default salt detected for SYBIL_PROGRESSIVE_TRUST_SALT");
        }
        if config.sybil_config.proof_of_diversity_fingerprint_salt
            == "default-salt-change-in-production"
        {
            bail!("Insecure default salt detected for SYBIL_PROOF_OF_DIVERSITY_SALT");
        }
        if config.sybil_config.multi_party_vouching_salt == "default-salt-change-in-production" {
            bail!("Insecure default salt detected for SYBIL_MULTI_PARTY_VOUCHING_SALT");
        }
        if config.allow_unsafe_v4_rotation {
            warn!("UNSAFE V4 admin key rotation is enabled; development only");
        } else {
            warn!("V4 admin key rotation is disabled (development override required)");
        }

        let admin_api_key = match config.admin_api_key {
            Some(key) if key.len() >= 32 => key,
            Some(key) => bail!(
                "ADMIN_API_KEY must be at least 32 characters, got {}",
                key.len()
            ),
            None => bail!("ADMIN_API_KEY must be set (minimum 32 characters)"),
        };

        metrics::register_metrics();
        // ... [Keys, VOPRF, WebAuthn setup code remains the same] ...
        // ... [Sybil setup code remains the same] ...

        // 1. Keys & VOPRF Setup
        let (sk_bytes, pubkey_b64, kid_from_key) =
            keys::load_or_generate_keypair_b64_at(&config.key_config.sk_path)
                .context("Failed to load or generate issuer keypair")?;

        let kid = config
            .key_config
            .kid_override
            .as_ref()
            .map(|k| {
                if !k.starts_with(&kid_from_key) {
                    warn!(provided=%k, derived=%kid_from_key, "KID mismatch; using derived prefix");
                    format!("{}-{}", kid_from_key, OffsetDateTime::now_utc().date())
                } else {
                    k.clone()
                }
            })
            .unwrap_or_else(|| format!("{}-{}", kid_from_key, OffsetDateTime::now_utc().date()));

        let ctx = freebird_crypto::VOPRF_CONTEXT_V4;
        let voprf = Arc::new(
            multi_key_voprf::MultiKeyVoprfCore::load_or_create(
                *sk_bytes,
                pubkey_b64.clone(),
                kid.clone(),
                ctx,
                Some(config.key_config.rotation_state_path.clone()),
            )
            .await
            .context("Failed to initialize VOPRF core")?,
        );

        let cleanup_voprf = Arc::clone(&voprf);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                if let Err(e) = cleanup_voprf.cleanup_expired_keys().await {
                    warn!("Automatic key cleanup failed: {}", e);
                }
            }
        });

        let public_issuer = crate::public_tokens::PublicTokenIssuer::load_or_generate(
            &config.public_key_config,
            &config.issuer_id,
        )
        .context("Failed to initialize V5 public bearer issuer")?
        .map(Arc::new);
        if let Some(public_issuer) = &public_issuer {
            info!(
                token_key_id = %public_issuer.token_key_id_hex(),
                "✅ V5 public bearer issuer initialized"
            );
        }

        let (
            exchange_engine,
            exchange_metadata,
            exchange_readiness,
            graph_issuance_engine,
            graph_issuance_readiness,
        ) = if config.exchange_config.enabled {
            let direct_v5_metadata = public_issuer.as_ref().map(|issuer| issuer.metadata());
            let direct_v5_spki = direct_v5_metadata
                .as_ref()
                .map(|metadata| base64ct::Base64UrlUnpadded::decode_vec(&metadata.pubkey_spki_b64))
                .transpose()
                .context("invalid authoritative direct V5 public key metadata")?;
            let loaded = config
                .exchange_config
                .load_v2(&config.issuer_id, direct_v5_spki.as_deref())
                .context("Failed to load V2 exchange graph and signer configuration")?;
            let store = crate::exchange::store::ExchangeStore::new(
                config
                    .exchange_config
                    .redis_url
                    .as_deref()
                    .context("exchange Redis URL missing")?,
            )?;
            store
                .validate_durable_standalone()
                .await
                .context("exchange Redis durability check failed")?;
            validate_pending_graph_references_v2(
                &store,
                &loaded.active_graph,
                &loaded.retained_graphs,
            )
            .await
            .context("invalid pending V2 exchange graph references")?;
            let mut metadata = exchange_discovery_v2(
                &loaded.active_graph,
                &loaded.retained_graphs,
                &loaded.receipt_keys.discovery_metadata(),
            )?;
            if let Some(history) = loaded.public_history.clone() {
                crate::exchange::history::merge_public_history_v2(&mut metadata, history)?;
            }
            freebird_common::api::validate_exchange_discovery_v2(&config.issuer_id, &metadata)
                .map_err(anyhow::Error::msg)?;
            let global_identities = crate::exchange::history::global_key_identities_v2(
                &config.issuer_id,
                direct_v5_metadata,
                &metadata,
            )?;
            let registry_entries = exchange_registry_entries_v2(&global_identities);
            match store.initialize_key_registry_v2(&registry_entries).await? {
                crate::exchange::store::KeyRegistryOutcome::Initialized
                | crate::exchange::store::KeyRegistryOutcome::Equal => {}
                crate::exchange::store::KeyRegistryOutcome::Conflict
                | crate::exchange::store::KeyRegistryOutcome::Missing => {
                    bail!("V2 durable key registry conflicts with configured graph history")
                }
            }
            let publication_acknowledgements = config
                .exchange_config
                .load_disabled_publication_acknowledgements()?;
            validate_disabled_publication_acknowledgements_v2(
                &config.issuer_id,
                &metadata,
                &publication_acknowledgements,
            )?;
            let source_valid_until = global_identities
                .into_iter()
                .map(|(key_id, identity)| (key_id, identity.longest_valid_until))
                .collect();
            let graph_issuance_enabled = config.exchange_config.graph_issuance.enabled;
            let (document, authorizer): (
                crate::graph_issuance::GraphIssuancePolicyDocument,
                Arc<dyn crate::graph_issuance::GraphIssuanceAuthorizer>,
            ) = if graph_issuance_enabled {
                let document = crate::graph_issuance::GraphIssuancePolicyDocument::load(
                    &config.exchange_config.graph_issuance.policy_path,
                    &loaded.active_graph,
                    &loaded.retained_graphs,
                )?;
                let configured_scheme = match &config.exchange_config.graph_issuance.authorization {
                    crate::config::GraphIssuanceAuthorizationConfig::HmacSha256(_) => "hmac_sha256",
                    crate::config::GraphIssuanceAuthorizationConfig::V4Local { .. } => "v4_local",
                    crate::config::GraphIssuanceAuthorizationConfig::DevelopmentMock => {
                        "development_mock"
                    }
                    crate::config::GraphIssuanceAuthorizationConfig::Disabled => {
                        bail!("graph issuance authorization verifier is disabled")
                    }
                };
                if document.policies.iter().any(|policy| {
                    policy.admission_state
                        == crate::graph_issuance::GraphIssuanceAdmissionState::AcceptingNew
                        && policy.authorization_scheme != configured_scheme
                }) {
                    bail!("accepting graph issuance policy authorization scheme mismatch")
                }
                let authorizer: Arc<dyn crate::graph_issuance::GraphIssuanceAuthorizer> =
                    match &config.exchange_config.graph_issuance.authorization {
                        crate::config::GraphIssuanceAuthorizationConfig::HmacSha256(secret) => {
                            Arc::new(crate::graph_issuance::HmacGraphIssuanceAuthorizer::new(
                                secret.clone(),
                            )?)
                        }
                        crate::config::GraphIssuanceAuthorizationConfig::V4Local { keys } => {
                            Arc::new(crate::graph_issuance::V4LocalGraphIssuanceAuthorizer::new(
                                keys.clone(),
                            )?)
                        }
                        crate::config::GraphIssuanceAuthorizationConfig::DevelopmentMock
                            if config.unsafe_development_mode =>
                        {
                            warn!("UNSAFE development-only graph issuance authorization enabled");
                            Arc::new(crate::graph_issuance::DevelopmentMockAuthorizer)
                        }
                        _ => bail!("graph issuance authorization verifier is unavailable"),
                    };
                (document, authorizer)
            } else {
                (
                    crate::graph_issuance::GraphIssuancePolicyDocument {
                        version: crate::graph_issuance::POLICY_DOCUMENT_VERSION.into(),
                        policies: Vec::new(),
                    },
                    Arc::new(crate::graph_issuance::DisabledGraphIssuanceAuthorizer),
                )
            };
            let mut graph_engine = crate::graph_issuance::GraphIssuanceEngine::new_with_enabled(
                &loaded.active_graph,
                &loaded.retained_graphs,
                document,
                config
                    .exchange_config
                    .redis_url
                    .as_deref()
                    .context("exchange Redis URL missing")?,
                authorizer,
                graph_issuance_enabled,
            )?;
            let issuance_metadata = graph_engine.initialize().await?;
            freebird_common::api::validate_graph_issuance_discovery_v2(
                &metadata,
                &issuance_metadata,
            )
            .map_err(anyhow::Error::msg)?;
            let graph_engine = Arc::new(graph_engine);
            let graph_readiness =
                crate::readiness::GraphIssuanceReadinessState::new(graph_engine.clone());
            let graph_issuance_engine = Some(graph_engine);
            let graph_issuance_readiness = Some(graph_readiness);
            let engine = crate::exchange::ExchangeEngine::new_v2_with_source_validity(
                loaded.active_graph,
                loaded.retained_graphs,
                store.clone(),
                config.issuer_id.clone(),
                loaded.receipt_keys,
                config.exchange_config.receipt_lifetime_secs,
                source_valid_until,
            )
            .await?;
            let engine = Arc::new(engine);
            let readiness = crate::readiness::ExchangeReadinessState::new(
                engine.clone(),
                store,
                registry_entries,
                config.issuer_id.clone(),
                metadata.clone(),
                config
                    .exchange_config
                    .disabled_publication_ack_paths
                    .clone(),
            );
            (
                Some(engine),
                Some(metadata),
                Some(readiness),
                graph_issuance_engine,
                graph_issuance_readiness,
            )
        } else {
            (None, None, None, None, None)
        };

        // 2. WebAuthn Setup
        #[cfg(feature = "human-gate-webauthn")]
        let webauthn_state = if let Some(wa_conf) = &config.webauthn_config {
            info!(
                "🔐 Initializing WebAuthn subsystem for RP: {}",
                wa_conf.rp_id
            );

            // Security: Enforce WEBAUTHN_PROOF_SECRET when WebAuthn is enabled
            if std::env::var("WEBAUTHN_PROOF_SECRET").is_err() {
                bail!("WEBAUTHN_PROOF_SECRET must be set when WebAuthn is enabled");
            }

            let ctx = webauthn::WebAuthnCtx::new(
                wa_conf.rp_id.clone(),
                wa_conf.rp_name.clone(),
                wa_conf.rp_origin.clone(),
            )
            .context("Failed to create WebAuthn context")?;

            let store = if let Some(url) = &wa_conf.redis_url {
                info!("Using Redis for WebAuthn credentials");
                webauthn::CredentialStore::Redis(
                    webauthn::RedisCredStore::new(url, wa_conf.cred_ttl)
                        .context("Failed to connect to WebAuthn Redis")?,
                )
            } else {
                warn!("⚠️  Using in-memory WebAuthn credential storage");
                webauthn::CredentialStore::InMemory(webauthn::InMemoryCredStore::new())
            };

            Some(webauthn::WebAuthnState::new(
                ctx,
                store,
                config.behind_proxy,
            ))
        } else {
            None
        };

        // 3. Audit Log Setup
        let audit_config = AuditConfig {
            persistence_path: config.audit_log_path.clone(),
            max_entries: 10000,
            autosave_interval_secs: 60,
        };
        let audit_log = Arc::new(
            AuditLog::load_or_create(audit_config)
                .await
                .context("Failed to initialize audit log")?,
        );
        info!("✅ Audit log initialized");

        let sybil_replay_store =
            replay_store_from_env().context("Failed to initialize Sybil replay store")?;
        let replay_backend =
            std::env::var("SYBIL_REPLAY_STORE").unwrap_or_else(|_| "memory".into());
        if replay_backend.eq_ignore_ascii_case("memory") && !config.unsafe_development_mode {
            bail!("persistent Redis replay storage is required outside development");
        }

        // 4. Sybil Resistance Setup
        let mut invitation_system: Option<Arc<InvitationSystem>> = None;
        let mut progressive_trust_system = None;
        let mut proof_of_diversity_system = None;
        let mut multi_party_vouching_system: Option<
            Arc<sybil_resistance::MultiPartyVouchingSystem>,
        > = None;
        let sybil_checker: Option<Arc<dyn SybilResistance>> = match config
            .sybil_config
            .mode
            .as_str()
        {
            "pow" | "proof_of_work" => Some(Arc::new(ProofOfWork::with_replay_store(
                config.sybil_config.pow_difficulty,
                sybil_replay_store.clone(),
            ))),
            "rate_limit" => Some(Arc::new(RateLimit::new(Duration::from_secs(
                config.sybil_config.rate_limit_secs,
            )))),
            "invitation" => {
                let inv_conf = InvitationConfig {
                    invites_per_user: config.sybil_config.invite_per_user,
                    invite_cooldown_secs: config.sybil_config.invite_cooldown_secs,
                    invite_expires_secs: config.sybil_config.invite_expires_secs,
                    new_user_can_invite_after_secs: config.sybil_config.invite_new_user_wait_secs,
                    persistence_path: config.sybil_config.invite_persistence_path.clone(),
                    autosave_interval_secs: config.sybil_config.invite_autosave_interval_secs,
                };
                let signing_key = load_or_generate_invitation_signing_key(
                    &config.sybil_config.invite_signing_key_path,
                )
                .context("Failed to load invitation signing key")?;
                let sys = InvitationSystem::load_or_create(signing_key, inv_conf)
                    .await
                    .context("Failed to load invitation system")?;

                if let Some(bootstrap) = &config.sybil_config.bootstrap_users {
                    for entry in bootstrap.split(',') {
                        if let Some((uid, count_str)) = entry.split_once(':') {
                            if let Ok(count) = count_str.parse::<u32>() {
                                sys.add_bootstrap_user(uid.to_string(), count).await;
                            }
                        }
                    }
                }
                let sys_arc = Arc::new(sys);
                invitation_system = Some(sys_arc.clone());
                Some(sys_arc)
            }
            #[cfg(feature = "human-gate-webauthn")]
            "webauthn" => {
                if let Some(wa) = &webauthn_state {
                    info!("✅ Sybil resistance: WebAuthn");
                    // Use the new path
                    Some(Arc::new(webauthn::WebAuthnGate::with_replay_store(
                        wa.clone(),
                        config.sybil_config.webauthn_max_proof_age,
                        sybil_replay_store.clone(),
                    )))
                } else {
                    warn!("⚠️  WebAuthn Sybil resistance selected but not configured");
                    None
                }
            }
            "progressive_trust" => {
                let levels =
                    parse_progressive_trust_levels(&config.sybil_config.progressive_trust_levels)
                        .context("Invalid progressive trust level configuration")?;

                let pt_config = sybil_resistance::ProgressiveTrustConfig {
                    levels,
                    persistence_path: config
                        .sybil_config
                        .progressive_trust_persistence_path
                        .clone(),
                    autosave_interval_secs: config.sybil_config.progressive_trust_autosave_interval,
                    hmac_secret: config.sybil_config.progressive_trust_hmac_secret.clone(),
                    hmac_secret_path: config
                        .sybil_config
                        .progressive_trust_hmac_secret_path
                        .clone(),
                    user_id_salt: config.sybil_config.progressive_trust_salt.clone(),
                    allow_insecure_deterministic: config
                        .sybil_config
                        .progressive_trust_allow_insecure,
                };

                let sys = sybil_resistance::ProgressiveTrustSystem::new(pt_config)
                    .await
                    .context("Failed to initialize Progressive Trust system")?;

                progressive_trust_system = Some(sys.clone());
                info!("✅ Sybil resistance: Progressive Trust");
                Some(sys)
            }
            "social_graph" => {
                let sg_config = sybil_resistance::SocialGraphConfig {
                    attesters_path: config.sybil_config.social_graph_attesters_path.clone(),
                    jwks_url: config.sybil_config.social_graph_jwks_url.clone(),
                    key_refresh_interval: Duration::from_secs(
                        config.sybil_config.social_graph_key_refresh_interval_secs,
                    ),
                    min_level: config.sybil_config.social_graph_min_level,
                    accepted_policy_ids: config
                        .sybil_config
                        .social_graph_accepted_policy_ids
                        .clone(),
                    attestation_max_age: Duration::from_secs(
                        config.sybil_config.social_graph_attestation_max_age_secs,
                    ),
                    clock_skew_secs: config.sybil_config.social_graph_clock_skew_secs,
                    require_request_binding: config
                        .sybil_config
                        .social_graph_require_request_binding,
                    require_quota_nullifier: config
                        .sybil_config
                        .social_graph_require_quota_nullifier,
                    replay_ttl: Duration::from_secs(
                        config.sybil_config.social_graph_replay_ttl_secs,
                    ),
                    state_path: config.sybil_config.social_graph_state_path.clone(),
                    fail_closed: config.sybil_config.social_graph_fail_closed,
                };
                let gate =
                    sybil_resistance::SocialGraphGate::new(sg_config, sybil_replay_store.clone())
                        .context("Failed to initialize Social Graph gate")?;
                info!("✅ Sybil resistance: Social Graph");
                Some(gate)
            }
            "proof_of_diversity" => {
                let pod_config = sybil_resistance::ProofOfDiversityConfig {
                    min_score: config.sybil_config.proof_of_diversity_min_score,
                    persistence_path: config
                        .sybil_config
                        .proof_of_diversity_persistence_path
                        .clone(),
                    autosave_interval_secs: config
                        .sybil_config
                        .proof_of_diversity_autosave_interval,
                    hmac_secret: config.sybil_config.proof_of_diversity_hmac_secret.clone(),
                    hmac_secret_path: config
                        .sybil_config
                        .proof_of_diversity_hmac_secret_path
                        .clone(),
                    fingerprint_salt: config
                        .sybil_config
                        .proof_of_diversity_fingerprint_salt
                        .clone(),
                    allow_insecure_deterministic: config
                        .sybil_config
                        .proof_of_diversity_allow_insecure,
                };

                let sys = sybil_resistance::ProofOfDiversitySystem::new(pod_config)
                    .await
                    .context("Failed to initialize Proof of Diversity system")?;

                proof_of_diversity_system = Some(sys.clone());
                info!("✅ Sybil resistance: Proof of Diversity");
                Some(sys)
            }
            "multi_party_vouching" => {
                let mpv_config = sybil_resistance::MultiPartyVouchingConfig {
                    required_vouchers: config.sybil_config.multi_party_vouching_required_vouchers,
                    voucher_cooldown_secs: config.sybil_config.multi_party_vouching_cooldown_secs,
                    vouch_expires_secs: config.sybil_config.multi_party_vouching_expires_secs,
                    new_user_can_vouch_after_secs: config
                        .sybil_config
                        .multi_party_vouching_new_user_wait_secs,
                    persistence_path: config
                        .sybil_config
                        .multi_party_vouching_persistence_path
                        .clone(),
                    autosave_interval_secs: config
                        .sybil_config
                        .multi_party_vouching_autosave_interval,
                    hmac_secret: config.sybil_config.multi_party_vouching_hmac_secret.clone(),
                    hmac_secret_path: config
                        .sybil_config
                        .multi_party_vouching_hmac_secret_path
                        .clone(),
                    user_id_salt: config.sybil_config.multi_party_vouching_salt.clone(),
                    allow_insecure_deterministic: config
                        .sybil_config
                        .multi_party_vouching_allow_insecure,
                };

                let sys = sybil_resistance::MultiPartyVouchingSystem::new_with_replay_store(
                    mpv_config,
                    sybil_replay_store.clone(),
                )
                .await
                .context("Failed to initialize Multi-Party Vouching system")?;

                multi_party_vouching_system = Some(sys.clone());
                info!("✅ Sybil resistance: Multi-Party Vouching");
                Some(sys)
            }
            "combined" => {
                info!(
                    "🔧 Building combined Sybil resistance with {} mode",
                    config.sybil_config.combined_mode
                );

                // Build mechanisms from config list
                let mut mechanisms: Vec<Arc<dyn SybilResistance>> = Vec::new();

                for mechanism_name in &config.sybil_config.combined_mechanisms {
                    let mechanism_name = mechanism_name.trim();
                    info!("  Adding mechanism: {}", mechanism_name);

                    match mechanism_name {
                        "pow" | "proof_of_work" => {
                            mechanisms.push(Arc::new(ProofOfWork::with_replay_store(
                                config.sybil_config.pow_difficulty,
                                sybil_replay_store.clone(),
                            )));
                        }
                        "rate_limit" => {
                            mechanisms.push(Arc::new(RateLimit::new(Duration::from_secs(
                                config.sybil_config.rate_limit_secs,
                            ))));
                        }
                        "invitation" => {
                            let inv_conf = InvitationConfig {
                                invites_per_user: config.sybil_config.invite_per_user,
                                invite_cooldown_secs: config.sybil_config.invite_cooldown_secs,
                                invite_expires_secs: config.sybil_config.invite_expires_secs,
                                new_user_can_invite_after_secs: config
                                    .sybil_config
                                    .invite_new_user_wait_secs,
                                persistence_path: config
                                    .sybil_config
                                    .invite_persistence_path
                                    .clone(),
                                autosave_interval_secs: config
                                    .sybil_config
                                    .invite_autosave_interval_secs,
                            };
                            let signing_key = load_or_generate_invitation_signing_key(
                                &config.sybil_config.invite_signing_key_path,
                            )
                            .context("Failed to load invitation signing key for combined mode")?;
                            let sys = InvitationSystem::load_or_create(signing_key, inv_conf)
                                .await
                                .context("Failed to load invitation system for combined mode")?;
                            let sys_arc = Arc::new(sys);
                            invitation_system = Some(sys_arc.clone());
                            mechanisms.push(sys_arc);
                        }
                        #[cfg(feature = "human-gate-webauthn")]
                        "webauthn" => {
                            if let Some(wa) = &webauthn_state {
                                mechanisms.push(Arc::new(
                                    webauthn::WebAuthnGate::with_replay_store(
                                        wa.clone(),
                                        config.sybil_config.webauthn_max_proof_age,
                                        sybil_replay_store.clone(),
                                    ),
                                ));
                            } else {
                                warn!("⚠️  WebAuthn requested in combined mode but not configured, skipping");
                            }
                        }
                        "progressive_trust" => {
                            let levels = parse_progressive_trust_levels(
                                &config.sybil_config.progressive_trust_levels,
                            )
                            .context(
                                "Invalid progressive trust level configuration for combined mode",
                            )?;

                            let pt_config = sybil_resistance::ProgressiveTrustConfig {
                                levels,
                                persistence_path: config
                                    .sybil_config
                                    .progressive_trust_persistence_path
                                    .clone(),
                                autosave_interval_secs: config
                                    .sybil_config
                                    .progressive_trust_autosave_interval,
                                hmac_secret: config
                                    .sybil_config
                                    .progressive_trust_hmac_secret
                                    .clone(),
                                hmac_secret_path: config
                                    .sybil_config
                                    .progressive_trust_hmac_secret_path
                                    .clone(),
                                user_id_salt: config.sybil_config.progressive_trust_salt.clone(),
                                allow_insecure_deterministic: config
                                    .sybil_config
                                    .progressive_trust_allow_insecure,
                            };

                            let sys = sybil_resistance::ProgressiveTrustSystem::new(pt_config)
                                .await
                                .context(
                                    "Failed to initialize Progressive Trust for combined mode",
                                )?;
                            progressive_trust_system = Some(sys.clone());
                            mechanisms.push(sys);
                        }
                        "social_graph" => {
                            let sg_config = sybil_resistance::SocialGraphConfig {
                                attesters_path: config
                                    .sybil_config
                                    .social_graph_attesters_path
                                    .clone(),
                                jwks_url: config.sybil_config.social_graph_jwks_url.clone(),
                                key_refresh_interval: Duration::from_secs(
                                    config.sybil_config.social_graph_key_refresh_interval_secs,
                                ),
                                min_level: config.sybil_config.social_graph_min_level,
                                accepted_policy_ids: config
                                    .sybil_config
                                    .social_graph_accepted_policy_ids
                                    .clone(),
                                attestation_max_age: Duration::from_secs(
                                    config.sybil_config.social_graph_attestation_max_age_secs,
                                ),
                                clock_skew_secs: config.sybil_config.social_graph_clock_skew_secs,
                                require_request_binding: config
                                    .sybil_config
                                    .social_graph_require_request_binding,
                                require_quota_nullifier: config
                                    .sybil_config
                                    .social_graph_require_quota_nullifier,
                                replay_ttl: Duration::from_secs(
                                    config.sybil_config.social_graph_replay_ttl_secs,
                                ),
                                state_path: config.sybil_config.social_graph_state_path.clone(),
                                fail_closed: config.sybil_config.social_graph_fail_closed,
                            };
                            mechanisms.push(sybil_resistance::SocialGraphGate::new(
                                sg_config,
                                sybil_replay_store.clone(),
                            )?);
                        }
                        "proof_of_diversity" => {
                            let pod_config = sybil_resistance::ProofOfDiversityConfig {
                                min_score: config.sybil_config.proof_of_diversity_min_score,
                                persistence_path: config
                                    .sybil_config
                                    .proof_of_diversity_persistence_path
                                    .clone(),
                                autosave_interval_secs: config
                                    .sybil_config
                                    .proof_of_diversity_autosave_interval,
                                hmac_secret: config
                                    .sybil_config
                                    .proof_of_diversity_hmac_secret
                                    .clone(),
                                hmac_secret_path: config
                                    .sybil_config
                                    .proof_of_diversity_hmac_secret_path
                                    .clone(),
                                fingerprint_salt: config
                                    .sybil_config
                                    .proof_of_diversity_fingerprint_salt
                                    .clone(),
                                allow_insecure_deterministic: config
                                    .sybil_config
                                    .proof_of_diversity_allow_insecure,
                            };

                            let sys = sybil_resistance::ProofOfDiversitySystem::new(pod_config)
                                .await
                                .context(
                                    "Failed to initialize Proof of Diversity for combined mode",
                                )?;
                            proof_of_diversity_system = Some(sys.clone());
                            mechanisms.push(sys);
                        }
                        "multi_party_vouching" => {
                            let mpv_config = sybil_resistance::MultiPartyVouchingConfig {
                                required_vouchers: config
                                    .sybil_config
                                    .multi_party_vouching_required_vouchers,
                                voucher_cooldown_secs: config
                                    .sybil_config
                                    .multi_party_vouching_cooldown_secs,
                                vouch_expires_secs: config
                                    .sybil_config
                                    .multi_party_vouching_expires_secs,
                                new_user_can_vouch_after_secs: config
                                    .sybil_config
                                    .multi_party_vouching_new_user_wait_secs,
                                persistence_path: config
                                    .sybil_config
                                    .multi_party_vouching_persistence_path
                                    .clone(),
                                autosave_interval_secs: config
                                    .sybil_config
                                    .multi_party_vouching_autosave_interval,
                                hmac_secret: config
                                    .sybil_config
                                    .multi_party_vouching_hmac_secret
                                    .clone(),
                                hmac_secret_path: config
                                    .sybil_config
                                    .multi_party_vouching_hmac_secret_path
                                    .clone(),
                                user_id_salt: config.sybil_config.multi_party_vouching_salt.clone(),
                                allow_insecure_deterministic: config
                                    .sybil_config
                                    .multi_party_vouching_allow_insecure,
                            };

                            let sys =
                                sybil_resistance::MultiPartyVouchingSystem::new_with_replay_store(
                                    mpv_config,
                                    sybil_replay_store.clone(),
                                )
                                .await
                                .context(
                                    "Failed to initialize Multi-Party Vouching for combined mode",
                                )?;
                            multi_party_vouching_system = Some(sys.clone());
                            mechanisms.push(sys);
                        }
                        unknown => {
                            warn!(
                                "⚠️  Unknown mechanism '{}' in SYBIL_COMBINED_MECHANISMS, skipping",
                                unknown
                            );
                        }
                    }
                }

                if mechanisms.is_empty() {
                    warn!("⚠️  No valid mechanisms configured for combined mode");
                    None
                } else {
                    // Create the appropriate combiner based on mode
                    let combiner: Arc<dyn SybilResistance> =
                        match config.sybil_config.combined_mode.to_lowercase().as_str() {
                            "or" => {
                                info!(
                                    "✅ Sybil resistance: Combined OR mode with {} mechanisms",
                                    mechanisms.len()
                                );
                                Arc::new(CombinedOr::new(mechanisms))
                            }
                            "and" => {
                                info!(
                                    "✅ Sybil resistance: Combined AND mode with {} mechanisms",
                                    mechanisms.len()
                                );
                                Arc::new(CombinedAnd::new(mechanisms))
                            }
                            "threshold" => {
                                let threshold = config.sybil_config.combined_threshold as usize;
                                info!(
                                "✅ Sybil resistance: Combined Threshold mode ({}/{} mechanisms)",
                                threshold,
                                mechanisms.len()
                            );
                                Arc::new(
                                    CombinedThreshold::new(mechanisms, threshold)
                                        .context("Failed to create threshold combiner")?,
                                )
                            }
                            unknown => {
                                warn!("⚠️  Unknown combined mode '{}', defaulting to OR", unknown);
                                Arc::new(CombinedOr::new(mechanisms))
                            }
                        };
                    Some(combiner)
                }
            }
            _ => None,
        };

        if invitation_system.is_none() {
            let inv_conf = InvitationConfig {
                invites_per_user: config.sybil_config.invite_per_user,
                invite_cooldown_secs: config.sybil_config.invite_cooldown_secs,
                invite_expires_secs: config.sybil_config.invite_expires_secs,
                new_user_can_invite_after_secs: config.sybil_config.invite_new_user_wait_secs,
                persistence_path: config.sybil_config.invite_persistence_path.clone(),
                autosave_interval_secs: config.sybil_config.invite_autosave_interval_secs,
            };
            let signing_key = load_or_generate_invitation_signing_key(
                &config.sybil_config.invite_signing_key_path,
            )
            .context("Failed to load invitation signing key for admin")?;
            let sys = InvitationSystem::load_or_create(signing_key, inv_conf)
                .await
                .context("Failed to load invitation system for admin")?;

            if let Some(bootstrap) = &config.sybil_config.bootstrap_users {
                for entry in bootstrap.split(',') {
                    if let Some((uid, count_str)) = entry.split_once(':') {
                        if let Ok(count) = count_str.parse::<u32>() {
                            sys.add_bootstrap_user(uid.to_string(), count).await;
                        }
                    }
                }
            }

            invitation_system = Some(Arc::new(sys));
        }

        // 5. Shutdown persistence registry.  These are the authoritative
        // stores created above; stores not constructed by this configuration
        // are intentionally not flushed.
        let mut shutdown = ShutdownCoordinator::new();
        {
            let audit = Arc::clone(&audit_log);
            shutdown.add("audit", move || {
                let audit = Arc::clone(&audit);
                async move { audit.save().await }
            });
        }
        if let Some(store) = invitation_system.clone() {
            shutdown.add("invitations", move || {
                let store = Arc::clone(&store);
                async move { store.save().await }
            });
        }
        if let Some(store) = progressive_trust_system.clone() {
            shutdown.add("progressive_trust", move || {
                let store = Arc::clone(&store);
                async move { store.save_state().await }
            });
        }
        if let Some(store) = proof_of_diversity_system.clone() {
            shutdown.add("proof_of_diversity", move || {
                let store = Arc::clone(&store);
                async move { store.save_state().await }
            });
        }
        if let Some(store) = multi_party_vouching_system.clone() {
            shutdown.add("multi_party_vouching", move || {
                let store = Arc::clone(&store);
                async move { store.save_state().await }
            });
        }
        let rotation = Arc::clone(&voprf);
        shutdown.add("rotation_metadata", move || {
            let rotation = Arc::clone(&rotation);
            async move { rotation.save_state().await }
        });

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
        let mut storage_paths = vec![
            ("audit".to_string(), config.audit_log_path.clone()),
            (
                "rotation".to_string(),
                config.key_config.rotation_state_path.clone(),
            ),
            (
                "invitation".to_string(),
                config.sybil_config.invite_persistence_path.clone(),
            ),
        ];
        if progressive_trust_system.is_some() {
            storage_paths.push((
                "progressive_trust".to_string(),
                config
                    .sybil_config
                    .progressive_trust_persistence_path
                    .clone(),
            ));
        }
        if proof_of_diversity_system.is_some() {
            storage_paths.push((
                "proof_of_diversity".to_string(),
                config
                    .sybil_config
                    .proof_of_diversity_persistence_path
                    .clone(),
            ));
        }
        if multi_party_vouching_system.is_some() {
            storage_paths.push((
                "vouching".to_string(),
                config
                    .sybil_config
                    .multi_party_vouching_persistence_path
                    .clone(),
            ));
        }
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
mod tests {
    use super::{
        exchange_discovery_v2, parse_progressive_trust_levels,
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
