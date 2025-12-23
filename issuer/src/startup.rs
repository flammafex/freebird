// issuer/src/startup.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::{
    audit::{AuditConfig, AuditLog},
    config::Config,
    keys, multi_key_voprf, routes,
    sybil_resistance::{
        self, invitation::{InvitationConfig, InvitationSystem},
        CombinedOr, CombinedAnd, CombinedThreshold,
        ProofOfWork, RateLimit, SybilResistance,
    },
    AppStateWithSybil,
};
#[cfg(feature = "human-gate-webauthn")]
use crate::webauthn;

use anyhow::{Context, Result};
use axum::{routing::{get, post}, Router};
use axum::extract::DefaultBodyLimit;
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use std::{sync::Arc, time::Duration};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tracing::{info, warn};

pub struct Application {
    port: u16,
    server: axum::serve::Serve<Router, Router>,
}

impl Application {
    pub async fn build(config: Config) -> Result<Self> {
        // ... [Keys, VOPRF, WebAuthn setup code remains the same] ...
        // ... [Sybil setup code remains the same] ...

        // 1. Keys & VOPRF Setup
        if config.key_config.sk_path.to_str().unwrap() != "issuer_sk.bin" {
             std::env::set_var("ISSUER_SK_PATH", &config.key_config.sk_path);
        }

        let (sk_bytes, pubkey_b64, kid_from_key) = keys::load_or_generate_keypair_b64()
            .context("Failed to load or generate issuer keypair")?;

        let kid = config.key_config.kid_override.as_ref().map(|k| {
            if !k.starts_with(&kid_from_key) {
                warn!(provided=%k, derived=%kid_from_key, "KID mismatch; using derived prefix");
                format!("{}-{}", kid_from_key, OffsetDateTime::now_utc().date())
            } else {
                k.clone()
            }
        }).unwrap_or_else(|| format!("{}-{}", kid_from_key, OffsetDateTime::now_utc().date()));

        let ctx = b"freebird:v1";
        let voprf = Arc::new(
            multi_key_voprf::MultiKeyVoprfCore::load_or_create(
                sk_bytes,
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
        
        

        // 2. WebAuthn Setup
        #[cfg(feature = "human-gate-webauthn")]
        let webauthn_state = if let Some(wa_conf) = &config.webauthn_config {
             info!("🔐 Initializing WebAuthn subsystem for RP: {}", wa_conf.rp_id);
             
             let ctx = webauthn::WebAuthnCtx::new(
                 wa_conf.rp_id.clone(), 
                 wa_conf.rp_name.clone(), 
                 wa_conf.rp_origin.clone()
             ).context("Failed to create WebAuthn context")?;

             let store = if let Some(url) = &wa_conf.redis_url {
                 info!("Using Redis for WebAuthn credentials");
                 webauthn::CredentialStore::Redis(
                     webauthn::RedisCredStore::new(url, wa_conf.cred_ttl)
                         .context("Failed to connect to WebAuthn Redis")?
                 )
             } else {
                 warn!("⚠️  Using in-memory WebAuthn credential storage");
                 webauthn::CredentialStore::InMemory(webauthn::InMemoryCredStore::new())
             };

             Some(webauthn::WebAuthnState::new(ctx, store, config.behind_proxy))
        } else {
            None
        };

        // 3. Federation Store (needed before Sybil setup for Federated Trust)
        let federation_store = crate::federation_store::FederationStore::new(&config.federation_data_path)
            .await
            .context("Failed to initialize federation store")?;
        info!("✅ Federation store initialized at {:?}", config.federation_data_path);

        // 3.5 Audit Log Setup
        let audit_config = AuditConfig {
            persistence_path: std::path::PathBuf::from("audit_log.json"),
            max_entries: 10000,
            autosave_interval_secs: 60,
        };
        let audit_log = Arc::new(
            AuditLog::load_or_create(audit_config)
                .await
                .context("Failed to initialize audit log")?
        );
        info!("✅ Audit log initialized");

        // 4. Sybil Resistance Setup
        let mut invitation_system: Option<Arc<InvitationSystem>> = None;
        let sybil_checker: Option<Arc<dyn SybilResistance>> = match config.sybil_config.mode.as_str() {
            "pow" | "proof_of_work" => Some(Arc::new(ProofOfWork::new(config.sybil_config.pow_difficulty))),
            "rate_limit" => Some(Arc::new(RateLimit::new(Duration::from_secs(config.sybil_config.rate_limit_secs)))),
            "invitation" => {
                let inv_conf = InvitationConfig {
                    invites_per_user: config.sybil_config.invite_per_user,
                    invite_cooldown_secs: config.sybil_config.invite_cooldown_secs,
                    invite_expires_secs: config.sybil_config.invite_expires_secs,
                    new_user_can_invite_after_secs: config.sybil_config.invite_new_user_wait_secs,
                    persistence_path: config.sybil_config.invite_persistence_path.clone(),
                    autosave_interval_secs: config.sybil_config.invite_autosave_interval_secs,
                };
                let signing_key = SigningKey::random(&mut OsRng);
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
                    Some(Arc::new(webauthn::WebAuthnGate::new(
                        wa.clone(),
                        config.sybil_config.webauthn_max_proof_age
                    )))
                 } else {
                    warn!("⚠️  WebAuthn Sybil resistance selected but not configured");
                    None
                }
            }
            "progressive_trust" => {
                // Parse trust levels from config
                let levels: Vec<sybil_resistance::TrustLevel> = config.sybil_config.progressive_trust_levels
                    .iter()
                    .filter_map(|level_str| {
                        let parts: Vec<&str> = level_str.split(':').collect();
                        if parts.len() == 3 {
                            let min_age_secs = parts[0].parse().ok()?;
                            let max_tokens_per_period = parts[1].parse().ok()?;
                            let cooldown_secs = parts[2].parse().ok()?;
                            Some(sybil_resistance::TrustLevel {
                                min_age_secs,
                                max_tokens_per_period,
                                cooldown_secs,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();

                let pt_config = sybil_resistance::ProgressiveTrustConfig {
                    levels,
                    persistence_path: config.sybil_config.progressive_trust_persistence_path.clone(),
                    autosave_interval_secs: config.sybil_config.progressive_trust_autosave_interval,
                    hmac_secret: config.sybil_config.progressive_trust_hmac_secret.clone(),
                    hmac_secret_path: config.sybil_config.progressive_trust_hmac_secret_path.clone(),
                    user_id_salt: config.sybil_config.progressive_trust_salt.clone(),
                    allow_insecure_deterministic: config.sybil_config.progressive_trust_allow_insecure,
                };

                let sys = sybil_resistance::ProgressiveTrustSystem::new(pt_config)
                    .await
                    .context("Failed to initialize Progressive Trust system")?;

                info!("✅ Sybil resistance: Progressive Trust");
                Some(sys)
            }
            "proof_of_diversity" => {
                let pod_config = sybil_resistance::ProofOfDiversityConfig {
                    min_score: config.sybil_config.proof_of_diversity_min_score,
                    persistence_path: config.sybil_config.proof_of_diversity_persistence_path.clone(),
                    autosave_interval_secs: config.sybil_config.proof_of_diversity_autosave_interval,
                    hmac_secret: config.sybil_config.proof_of_diversity_hmac_secret.clone(),
                    fingerprint_salt: config.sybil_config.proof_of_diversity_fingerprint_salt.clone(),
                };

                let sys = sybil_resistance::ProofOfDiversitySystem::new(pod_config)
                    .await
                    .context("Failed to initialize Proof of Diversity system")?;

                info!("✅ Sybil resistance: Proof of Diversity");
                Some(sys)
            }
            "multi_party_vouching" => {
                let mpv_config = sybil_resistance::MultiPartyVouchingConfig {
                    required_vouchers: config.sybil_config.multi_party_vouching_required_vouchers,
                    voucher_cooldown_secs: config.sybil_config.multi_party_vouching_cooldown_secs,
                    vouch_expires_secs: config.sybil_config.multi_party_vouching_expires_secs,
                    new_user_can_vouch_after_secs: config.sybil_config.multi_party_vouching_new_user_wait_secs,
                    persistence_path: config.sybil_config.multi_party_vouching_persistence_path.clone(),
                    autosave_interval_secs: config.sybil_config.multi_party_vouching_autosave_interval,
                    hmac_secret: config.sybil_config.multi_party_vouching_hmac_secret.clone(),
                    user_id_salt: config.sybil_config.multi_party_vouching_salt.clone(),
                };

                let sys = sybil_resistance::MultiPartyVouchingSystem::new(mpv_config)
                    .await
                    .context("Failed to initialize Multi-Party Vouching system")?;

                info!("✅ Sybil resistance: Multi-Party Vouching");
                Some(sys)
            }
            "federated_trust" => {
                let trust_policy = freebird_common::federation::TrustPolicy {
                    enabled: config.sybil_config.federated_trust_enabled,
                    max_trust_depth: config.sybil_config.federated_trust_max_depth,
                    min_trust_paths: config.sybil_config.federated_trust_min_paths,
                    require_direct_trust: config.sybil_config.federated_trust_require_direct,
                    trusted_roots: config.sybil_config.federated_trust_trusted_roots.clone(),
                    blocked_issuers: config.sybil_config.federated_trust_blocked_issuers.clone(),
                    refresh_interval_secs: config.sybil_config.federated_trust_cache_ttl_secs,
                    min_trust_level: config.sybil_config.federated_trust_min_trust_level,
                };

                let ft_config = sybil_resistance::FederatedTrustConfig {
                    trust_policy,
                    federation_store: Arc::new(federation_store.clone()),
                    our_issuer_id: config.issuer_id.clone(),
                    cache_ttl_secs: config.sybil_config.federated_trust_cache_ttl_secs,
                    max_token_age_secs: config.sybil_config.federated_trust_max_token_age_secs,
                };

                let sys = sybil_resistance::FederatedTrustSystem::new(ft_config)
                    .await
                    .context("Failed to initialize Federated Trust system")?;

                info!("✅ Sybil resistance: Federated Trust");
                Some(sys)
            }
            "combined" => {
                info!("🔧 Building combined Sybil resistance with {} mode", config.sybil_config.combined_mode);

                // Build mechanisms from config list
                let mut mechanisms: Vec<Arc<dyn SybilResistance>> = Vec::new();

                for mechanism_name in &config.sybil_config.combined_mechanisms {
                    let mechanism_name = mechanism_name.trim();
                    info!("  Adding mechanism: {}", mechanism_name);

                    match mechanism_name {
                        "pow" | "proof_of_work" => {
                            mechanisms.push(Arc::new(ProofOfWork::new(config.sybil_config.pow_difficulty)));
                        }
                        "rate_limit" => {
                            mechanisms.push(Arc::new(RateLimit::new(Duration::from_secs(config.sybil_config.rate_limit_secs))));
                        }
                        "invitation" => {
                            let inv_conf = InvitationConfig {
                                invites_per_user: config.sybil_config.invite_per_user,
                                invite_cooldown_secs: config.sybil_config.invite_cooldown_secs,
                                invite_expires_secs: config.sybil_config.invite_expires_secs,
                                new_user_can_invite_after_secs: config.sybil_config.invite_new_user_wait_secs,
                                persistence_path: config.sybil_config.invite_persistence_path.clone(),
                                autosave_interval_secs: config.sybil_config.invite_autosave_interval_secs,
                            };
                            let signing_key = SigningKey::random(&mut OsRng);
                            let sys = InvitationSystem::load_or_create(signing_key, inv_conf)
                                .await
                                .context("Failed to load invitation system for combined mode")?;
                            mechanisms.push(Arc::new(sys));
                        }
                        #[cfg(feature = "human-gate-webauthn")]
                        "webauthn" => {
                            if let Some(wa) = &webauthn_state {
                                mechanisms.push(Arc::new(webauthn::WebAuthnGate::new(
                                    wa.clone(),
                                    config.sybil_config.webauthn_max_proof_age
                                )));
                            } else {
                                warn!("⚠️  WebAuthn requested in combined mode but not configured, skipping");
                            }
                        }
                        "progressive_trust" => {
                            let levels: Vec<sybil_resistance::TrustLevel> = config.sybil_config.progressive_trust_levels
                                .iter()
                                .filter_map(|level_str| {
                                    let parts: Vec<&str> = level_str.split(':').collect();
                                    if parts.len() == 3 {
                                        let min_age_secs = parts[0].parse().ok()?;
                                        let max_tokens_per_period = parts[1].parse().ok()?;
                                        let cooldown_secs = parts[2].parse().ok()?;
                                        Some(sybil_resistance::TrustLevel {
                                            min_age_secs,
                                            max_tokens_per_period,
                                            cooldown_secs,
                                        })
                                    } else {
                                        None
                                    }
                                })
                                .collect();

                            let pt_config = sybil_resistance::ProgressiveTrustConfig {
                                levels,
                                persistence_path: config.sybil_config.progressive_trust_persistence_path.clone(),
                                autosave_interval_secs: config.sybil_config.progressive_trust_autosave_interval,
                                hmac_secret: config.sybil_config.progressive_trust_hmac_secret.clone(),
                                hmac_secret_path: config.sybil_config.progressive_trust_hmac_secret_path.clone(),
                                user_id_salt: config.sybil_config.progressive_trust_salt.clone(),
                                allow_insecure_deterministic: config.sybil_config.progressive_trust_allow_insecure,
                            };

                            let sys = sybil_resistance::ProgressiveTrustSystem::new(pt_config)
                                .await
                                .context("Failed to initialize Progressive Trust for combined mode")?;
                            mechanisms.push(sys);
                        }
                        "proof_of_diversity" => {
                            let pod_config = sybil_resistance::ProofOfDiversityConfig {
                                min_score: config.sybil_config.proof_of_diversity_min_score,
                                persistence_path: config.sybil_config.proof_of_diversity_persistence_path.clone(),
                                autosave_interval_secs: config.sybil_config.proof_of_diversity_autosave_interval,
                                hmac_secret: config.sybil_config.proof_of_diversity_hmac_secret.clone(),
                                fingerprint_salt: config.sybil_config.proof_of_diversity_fingerprint_salt.clone(),
                            };

                            let sys = sybil_resistance::ProofOfDiversitySystem::new(pod_config)
                                .await
                                .context("Failed to initialize Proof of Diversity for combined mode")?;
                            mechanisms.push(sys);
                        }
                        "multi_party_vouching" => {
                            let mpv_config = sybil_resistance::MultiPartyVouchingConfig {
                                required_vouchers: config.sybil_config.multi_party_vouching_required_vouchers,
                                voucher_cooldown_secs: config.sybil_config.multi_party_vouching_cooldown_secs,
                                vouch_expires_secs: config.sybil_config.multi_party_vouching_expires_secs,
                                new_user_can_vouch_after_secs: config.sybil_config.multi_party_vouching_new_user_wait_secs,
                                persistence_path: config.sybil_config.multi_party_vouching_persistence_path.clone(),
                                autosave_interval_secs: config.sybil_config.multi_party_vouching_autosave_interval,
                                hmac_secret: config.sybil_config.multi_party_vouching_hmac_secret.clone(),
                                user_id_salt: config.sybil_config.multi_party_vouching_salt.clone(),
                            };

                            let sys = sybil_resistance::MultiPartyVouchingSystem::new(mpv_config)
                                .await
                                .context("Failed to initialize Multi-Party Vouching for combined mode")?;
                            mechanisms.push(sys);
                        }
                        "federated_trust" => {
                            let trust_policy = freebird_common::federation::TrustPolicy {
                                enabled: config.sybil_config.federated_trust_enabled,
                                max_trust_depth: config.sybil_config.federated_trust_max_depth,
                                min_trust_paths: config.sybil_config.federated_trust_min_paths,
                                require_direct_trust: config.sybil_config.federated_trust_require_direct,
                                trusted_roots: config.sybil_config.federated_trust_trusted_roots.clone(),
                                blocked_issuers: config.sybil_config.federated_trust_blocked_issuers.clone(),
                                refresh_interval_secs: config.sybil_config.federated_trust_cache_ttl_secs,
                                min_trust_level: config.sybil_config.federated_trust_min_trust_level,
                            };

                            let ft_config = sybil_resistance::FederatedTrustConfig {
                                trust_policy,
                                federation_store: Arc::new(federation_store.clone()),
                                our_issuer_id: config.issuer_id.clone(),
                                cache_ttl_secs: config.sybil_config.federated_trust_cache_ttl_secs,
                                max_token_age_secs: config.sybil_config.federated_trust_max_token_age_secs,
                            };

                            let sys = sybil_resistance::FederatedTrustSystem::new(ft_config)
                                .await
                                .context("Failed to initialize Federated Trust for combined mode")?;
                            mechanisms.push(sys);
                        }
                        unknown => {
                            warn!("⚠️  Unknown mechanism '{}' in SYBIL_COMBINED_MECHANISMS, skipping", unknown);
                        }
                    }
                }

                if mechanisms.is_empty() {
                    warn!("⚠️  No valid mechanisms configured for combined mode");
                    None
                } else {
                    // Create the appropriate combiner based on mode
                    let combiner: Arc<dyn SybilResistance> = match config.sybil_config.combined_mode.to_lowercase().as_str() {
                        "or" => {
                            info!("✅ Sybil resistance: Combined OR mode with {} mechanisms", mechanisms.len());
                            Arc::new(CombinedOr::new(mechanisms))
                        }
                        "and" => {
                            info!("✅ Sybil resistance: Combined AND mode with {} mechanisms", mechanisms.len());
                            Arc::new(CombinedAnd::new(mechanisms))
                        }
                        "threshold" => {
                            let threshold = config.sybil_config.combined_threshold as usize;
                            info!("✅ Sybil resistance: Combined Threshold mode ({}/{} mechanisms)", threshold, mechanisms.len());
                            Arc::new(CombinedThreshold::new(mechanisms, threshold)
                                .context("Failed to create threshold combiner")?)
                        }
                        unknown => {
                            warn!("⚠️  Unknown combined mode '{}', defaulting to OR", unknown);
                            Arc::new(CombinedOr::new(mechanisms))
                        }
                    };
                    Some(combiner)
                }
            }
            _ => None
        };

        // 5. App State & Router
        let state = Arc::new(AppStateWithSybil {
            issuer_id: config.issuer_id.clone(),
            kid: kid.clone(),
            exp_sec: config.token_ttl_min * 60,
            pubkey_b64: pubkey_b64.clone(),
            require_tls: config.require_tls,
            behind_proxy: config.behind_proxy,
            sybil_checker: sybil_checker.clone(),
            invitation_system: invitation_system.clone(),
            epoch_duration_sec: config.epoch_duration_sec,
            epoch_retention: config.epoch_retention,
            federation_store: federation_store.clone(),
        });

        let app_state = (state.clone(), voprf.clone());

        // Initialize router
        // Note: routes::metadata::well_known_handler must exist!
        let app = Router::new()
            .route("/.well-known/issuer", get(routes::metadata::well_known_handler))
            .route("/.well-known/keys", get(routes::metadata::keys_handler))
            .route("/.well-known/federation", get(routes::metadata::federation_handler))
            .route("/v1/oprf/issue", post(routes::issue::handle))
            .route("/v1/oprf/issue/batch", post(routes::batch_issue::handle_batch))
            .layer(DefaultBodyLimit::max(64 * 1024));
        
        // --- CRITICAL FIX: SHADOWING ---
        // Use `let app` to shadow the variable, allowing the type change from Router<S> to Router<()>
        let mut app = app.with_state(app_state);

       #[cfg(feature = "human-gate-webauthn")]
        if let Some(wa) = &webauthn_state {
            // Use the factory function we created in handlers.rs
            // Note: `webauthn::router` handles the attestation check logic internally now!
            app = app.nest("/webauthn", webauthn::router(wa.clone()));
        }

        if let Some(key) = config.admin_api_key {
            if key.len() >= 32 {
                if let Some(inv_sys) = invitation_system {
                    // Create config summary for admin API
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
                    };

                    #[cfg(feature = "human-gate-webauthn")]
                    let admin = routes::admin_router(
                        inv_sys,
                        voprf.clone(),
                        federation_store.clone(),
                        audit_log.clone(),
                        key,
                        config.behind_proxy,
                        webauthn_state.as_ref().map(|ws| ws.cred_store.clone()),
                        config_summary,
                    );
                    #[cfg(not(feature = "human-gate-webauthn"))]
                    let admin = routes::admin_router(
                        inv_sys,
                        voprf.clone(),
                        federation_store.clone(),
                        audit_log.clone(),
                        key,
                        config.behind_proxy,
                        config_summary,
                    );
                    app = app.nest("/admin", admin);
                }
            }
        }

        let listener = TcpListener::bind(config.bind_addr).await
            .context("Failed to bind TCP listener")?;
        
        info!("🚀 Server ready at {}", config.bind_addr);

        Ok(Self {
            port: listener.local_addr()?.port(),
            server: axum::serve(listener, app),
        })
    }

    pub async fn run(self) -> Result<()> {
        self.server.with_graceful_shutdown(shutdown_signal()).await.context("Server error")
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.expect("Failed to install CTRL+C handler");
}
