// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::audit::{AuditConfig, AuditLog};
use crate::config::Config;
use crate::shutdown::ShutdownCoordinator;
use crate::sybil_resistance::{
    self,
    invitation::{InvitationConfig, InvitationSystem},
    replay_store_from_env, CombinedAnd, CombinedOr, CombinedThreshold, ProofOfWork, RateLimit,
    SybilResistance,
};
#[cfg(feature = "human-gate-webauthn")]
use crate::webauthn;
use anyhow::{bail, Context, Result};
use p256::ecdsa::SigningKey;
use rand::rngs::OsRng;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tracing::{info, warn};

pub(super) struct SybilAuditRuntime {
    pub(super) audit_log: Arc<AuditLog>,
    pub(super) sybil_replay_store: Arc<dyn sybil_resistance::ReplayStore>,
    pub(super) sybil_checker: Option<Arc<dyn SybilResistance>>,
    pub(super) invitation_system: Option<Arc<InvitationSystem>>,
    pub(super) multi_party_vouching_system: Option<Arc<sybil_resistance::MultiPartyVouchingSystem>>,
    pub(super) storage_paths: Vec<(String, PathBuf)>,
    pub(super) shutdown: ShutdownCoordinator,
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

pub(super) fn parse_progressive_trust_levels(
    levels: &[String],
) -> Result<Vec<sybil_resistance::TrustLevel>> {
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

impl SybilAuditRuntime {
    pub(super) async fn build(
        config: &Config,
        voprf: Arc<crate::multi_key_voprf::MultiKeyVoprfCore>,
        #[cfg(feature = "human-gate-webauthn")] webauthn_state: &Option<
            Arc<crate::webauthn::WebAuthnState>,
        >,
    ) -> Result<Self> {
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
                if let Some(wa) = webauthn_state {
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
                            if let Some(wa) = webauthn_state {
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

        Ok(Self {
            audit_log,
            sybil_replay_store,
            sybil_checker,
            invitation_system,
            multi_party_vouching_system,
            storage_paths,
            shutdown,
        })
    }
}
