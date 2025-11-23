// issuer/src/startup.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::{
    config::Config,
    keys, multi_key_voprf, routes,
    sybil_resistance::{
        self, invitation::{InvitationConfig, InvitationSystem},
        CombinedSybilResistance, ProofOfWork, RateLimit, SybilResistance,
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
#[cfg(feature = "human-gate-webauthn")]
use tokio::sync::RwLock; // Only needed if webauthn is enabled
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

             Some(Arc::new(webauthn::WebAuthnState {
                 webauthn: ctx,
                 cred_store: store,
                 sessions: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
             }))
        } else {
            None
        };
        // 3. Sybil Resistance Setup (Simplified for brevity, logic matches previous step)
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
                    user_id_salt: config.sybil_config.progressive_trust_salt.clone(),
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
            "combined" => Some(Arc::new(CombinedSybilResistance::new(vec![
                Box::new(ProofOfWork::new(config.sybil_config.pow_difficulty)),
                Box::new(RateLimit::new(Duration::from_secs(config.sybil_config.rate_limit_secs))),
            ]))),
            _ => None
        };

        // 4. Federation Store
        let federation_data_dir = std::path::PathBuf::from("./data/federation");
        let federation_store = crate::federation_store::FederationStore::new(&federation_data_dir)
            .await
            .context("Failed to initialize federation store")?;
        info!("✅ Federation store initialized at {:?}", federation_data_dir);

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
        let mut app = Router::new()
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
                    let admin = routes::admin_router(inv_sys, voprf.clone(), federation_store.clone(), key);
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