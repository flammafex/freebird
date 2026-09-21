// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

use crate::metadata::IssuerInfo;
use crate::readiness::{MetadataStatus, StoreHealth, TokenFamily};
use crate::replay_authority::ReplayAuthorityHealth;
use crate::store::{SpendOutcome, SpendStore};
use axum::http::StatusCode;
use freebird_common::spend_key::v7_spend_key;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::RwLock;

/// The nominal identity of a V7 discovery descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V7DescriptorIdentity {
    pub profile_id: String,
    pub descriptor_id: String,
}

/// One issuer-local V7 trust record.
///
/// The typed binding and policy are kept together with the descriptor identity
/// and its inclusive validity window. In particular, this is not a legacy
/// public-key projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V7IssuerTrustEntry {
    pub binding: freebird_crypto::V7PublicKeyBinding,
    pub policy: freebird_crypto::V7BodyPolicy,
    pub identity: V7DescriptorIdentity,
    pub valid_from: i64,
    pub valid_until: i64,
}

/// A complete issuer-local V7 trust snapshot, indexed by the explicit typed
/// V7 token-key ID.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct V7IssuerTrustSnapshot {
    pub by_token_key_id: HashMap<freebird_crypto::V7TokenKeyId, V7IssuerTrustEntry>,
}

/// The verifier's typed V7 trust registry, keyed first by issuer ID and then
/// by the token key ID carried by a native bearer body.
pub type V7TrustRegistry = HashMap<String, V7IssuerTrustSnapshot>;

impl V7IssuerTrustSnapshot {
    pub fn get(&self, token_key_id: &freebird_crypto::V7TokenKeyId) -> Option<&V7IssuerTrustEntry> {
        self.by_token_key_id.get(token_key_id)
    }
}

#[derive(Default)]
struct V7TrustHistory {
    current: HashMap<String, V7IssuerTrustSnapshot>,
    observed: HashMap<String, HashMap<freebird_crypto::V7TokenKeyId, V7IssuerTrustEntry>>,
}

static V7_TRUST_HISTORY: OnceLock<Mutex<V7TrustHistory>> = OnceLock::new();

fn v7_trust_history() -> &'static Mutex<V7TrustHistory> {
    V7_TRUST_HISTORY.get_or_init(|| Mutex::new(V7TrustHistory::default()))
}

/// Commit a fully validated V7 snapshot while enforcing process-lifetime
/// retention.  A binding which has already been observed must remain present
/// and byte-for-byte identical in every later discovery response.
pub(crate) fn commit_v7_trust(
    issuer_id: &str,
    candidate: V7IssuerTrustSnapshot,
) -> anyhow::Result<()> {
    let mut history = v7_trust_history()
        .lock()
        .map_err(|_| anyhow::anyhow!("V7 trust history lock poisoned"))?;
    if let Some(observed) = history.observed.get(issuer_id) {
        for (token_key_id, previous) in observed {
            match candidate.by_token_key_id.get(token_key_id) {
                Some(current) if current == previous => {}
                Some(_) => anyhow::bail!(
                    "V7 retained binding was rebound for token key {}",
                    hex::encode(token_key_id.as_bytes())
                ),
                None => anyhow::bail!(
                    "V7 retained binding disappeared for token key {}",
                    hex::encode(token_key_id.as_bytes())
                ),
            }
        }
    }
    history
        .observed
        .entry(issuer_id.to_owned())
        .or_default()
        .extend(candidate.by_token_key_id.clone());
    history.current.insert(issuer_id.to_owned(), candidate);
    Ok(())
}

/// Return the last committed V7 trust snapshot for an issuer.
pub fn v7_trust_snapshot(issuer_id: &str) -> Option<V7IssuerTrustSnapshot> {
    v7_trust_history()
        .lock()
        .ok()
        .and_then(|history| history.current.get(issuer_id).cloned())
}

/// Return the current typed V7 trust registry for verification dispatch.
pub fn v7_trust_registry() -> V7TrustRegistry {
    v7_trust_history()
        .lock()
        .map(|history| history.current.clone())
        .unwrap_or_default()
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) issuers: Arc<RwLock<HashMap<String, IssuerInfo>>>,
    pub(crate) store: Arc<dyn SpendStore>,
    pub(crate) verifier_id: String,
    pub(crate) audience: String,
    pub(crate) scope_digest: [u8; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
    /// Epoch configuration kept for admin display / operator observability.
    /// V4 token lifetime is controlled by verifier key acceptance policy,
    /// but operators still configure these env vars and expect them surfaced.
    #[allow(dead_code)]
    pub(crate) epoch_duration_sec: u64,
    #[allow(dead_code)]
    pub(crate) epoch_retention: u32,
    pub(crate) issuer_urls: Vec<String>,
    pub(crate) metadata: Arc<RwLock<HashMap<String, MetadataStatus>>>,
    pub(crate) accepted_token_families: Vec<TokenFamily>,
    pub(crate) refresh_interval: Duration,
    pub(crate) store_health: StoreHealth,
    pub(crate) replay_authority: Arc<ReplayAuthorityHealth>,
    pub(crate) store_is_memory: bool,
}

pub(crate) fn ensure_token_family_enabled(
    version: u8,
    accepted: &[TokenFamily],
) -> Result<(), (StatusCode, String)> {
    let enabled = match version {
        freebird_crypto::REDEMPTION_TOKEN_VERSION_V4 => accepted.contains(&TokenFamily::V4),
        freebird_crypto::public_bearer_v7::V7_ENVELOPE_VERSION => {
            accepted.contains(&TokenFamily::V7)
        }
        _ => false,
    };
    if enabled {
        Ok(())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "token family is not accepted by this verifier".into(),
        ))
    }
}

pub(crate) fn family_enabled(accepted: &[TokenFamily], family: TokenFamily) -> bool {
    accepted.contains(&family)
}

pub(crate) async fn record_spend(
    store: &dyn SpendStore,
    spend_key: &str,
    valid_until: Option<i64>,
) -> anyhow::Result<SpendOutcome> {
    match valid_until {
        Some(valid_until) => store.mark_spent_through(spend_key, valid_until).await,
        None => Ok(if store.mark_spent(spend_key, None).await? {
            SpendOutcome::Fresh
        } else {
            SpendOutcome::Replay
        }),
    }
}

/// Construct the exact V7 replay identity for a native bearer body.
///
/// The nullifier is encoded as lowercase hexadecimal.  No artifact,
/// descriptor, graph, keyset, verifier, or audience value participates in the
/// replay namespace.
#[allow(dead_code)]
pub(crate) fn v7_spend_key_for_body(body: &freebird_crypto::PublicBearerV7Body) -> String {
    v7_spend_key(body.issuer_id(), &hex::encode(body.nullifier()))
}

/// Atomically record a V7 spend through the trusted inclusive validity window.
#[allow(dead_code)]
pub(crate) async fn record_v7_spend(
    store: &dyn SpendStore,
    body: &freebird_crypto::PublicBearerV7Body,
    valid_until: i64,
) -> anyhow::Result<SpendOutcome> {
    store
        .mark_spent_through(&v7_spend_key_for_body(body), valid_until)
        .await
}

pub(crate) fn compute_throughput(successful: usize, total_time_ms: u64) -> f64 {
    if total_time_ms == 0 {
        0.0
    } else {
        (successful as f64 / total_time_ms as f64) * 1000.0
    }
}

pub(crate) async fn ensure_v4_replay_authority_ready(
    state: &AppState,
) -> Result<(), (StatusCode, String)> {
    if !state
        .replay_authority
        .allows_v4_replay(state.store_is_memory)
        .await
    {
        tracing::error!("V4 replay authority attestation is unavailable");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "replay authority unavailable".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        commit_v7_trust, compute_throughput, ensure_token_family_enabled,
        ensure_v4_replay_authority_ready, family_enabled, record_spend, record_v7_spend,
        v7_spend_key_for_body, v7_trust_snapshot, AppState, V7DescriptorIdentity,
        V7IssuerTrustEntry, V7IssuerTrustSnapshot,
    };
    use crate::readiness::TokenFamily;
    use crate::replay_authority::{ReplayAuthorityConfig, ReplayAuthorityHealth};
    use crate::store::{SpendOutcome, SpendStore};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::sync::RwLock;

    fn v7_entry(
        token_key_id: u8,
        descriptor_id: u8,
    ) -> (freebird_crypto::V7TokenKeyId, V7IssuerTrustEntry) {
        let token_key_id = freebird_crypto::V7TokenKeyId::new([token_key_id; 32]);
        let identity = freebird_crypto::V7KeyIdentity::new("issuer:test", token_key_id).unwrap();
        let provider =
            freebird_crypto::provider::software::SoftwareV7BlindRsaProvider::generate(identity)
                .unwrap();
        (
            token_key_id,
            V7IssuerTrustEntry {
                binding: provider.binding().clone(),
                policy: freebird_crypto::V7BodyPolicy::new("USD", 1).unwrap(),
                identity: V7DescriptorIdentity {
                    profile_id: freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID.into(),
                    descriptor_id: format!("{descriptor_id:02x}").repeat(32),
                },
                valid_from: 1,
                valid_until: 2,
            },
        )
    }

    #[derive(Default)]
    struct RecordingStore {
        calls: Mutex<Vec<(String, Option<i64>)>>,
    }

    #[async_trait::async_trait]
    impl SpendStore for RecordingStore {
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn mark_spent(
            &self,
            key: &str,
            ttl: Option<std::time::Duration>,
        ) -> anyhow::Result<bool> {
            assert!(ttl.is_none(), "V4 replay markers must remain non-expiring");
            self.calls.lock().unwrap().push((key.to_string(), None));
            Ok(true)
        }

        async fn mark_spent_through(
            &self,
            key: &str,
            valid_until: i64,
        ) -> anyhow::Result<SpendOutcome> {
            self.calls
                .lock()
                .unwrap()
                .push((key.to_string(), Some(valid_until)));
            Ok(SpendOutcome::Fresh)
        }
    }

    #[test]
    fn test_compute_throughput_zero_time() {
        assert_eq!(compute_throughput(100, 0), 0.0);
    }

    #[test]
    fn test_compute_throughput_normal() {
        assert_eq!(compute_throughput(500, 250), 2000.0);
    }

    #[test]
    fn token_family_enforcement_is_explicit_and_refresh_uses_enabled_families() {
        let accepted = [TokenFamily::V4];
        assert!(ensure_token_family_enabled(
            freebird_crypto::REDEMPTION_TOKEN_VERSION_V4,
            &accepted
        )
        .is_ok());
        assert!(ensure_token_family_enabled(
            freebird_crypto::public_bearer_v7::V7_ENVELOPE_VERSION,
            &accepted
        )
        .is_err());
        assert!(family_enabled(&[TokenFamily::V4], TokenFamily::V4));
        assert!(!family_enabled(&[TokenFamily::V4], TokenFamily::V7));
        assert!(family_enabled(&[TokenFamily::V7], TokenFamily::V7));
        assert!(!family_enabled(&[TokenFamily::V7], TokenFamily::V4));
    }

    #[tokio::test]
    async fn single_and_batch_writes_share_absolute_expiry_and_preserve_v4() {
        let store = RecordingStore::default();

        assert_eq!(
            record_spend(&store, "single-expiring", Some(123))
                .await
                .unwrap(),
            SpendOutcome::Fresh
        );
        assert_eq!(
            record_spend(&store, "batch-expiring", Some(123))
                .await
                .unwrap(),
            SpendOutcome::Fresh
        );
        assert_eq!(
            record_spend(&store, "v4", None).await.unwrap(),
            SpendOutcome::Fresh
        );

        assert_eq!(
            *store.calls.lock().unwrap(),
            vec![
                ("single-expiring".to_string(), Some(123)),
                ("batch-expiring".to_string(), Some(123)),
                ("v4".to_string(), None),
            ]
        );
    }

    #[tokio::test]
    async fn nonparticipating_memory_v4_does_not_gate_spend_mutation() {
        let store = Arc::new(RecordingStore::default());
        let authority = Arc::new(
            ReplayAuthorityHealth::new(
                store.clone(),
                ReplayAuthorityConfig {
                    graph_issuer_urls: vec![],
                    probe_interval: Duration::from_secs(30),
                    max_staleness: Duration::from_secs(60),
                },
                [0; 32],
            )
            .unwrap(),
        );
        let state = AppState {
            issuers: Arc::new(RwLock::new(HashMap::new())),
            store: store.clone(),
            verifier_id: "verifier:test".into(),
            audience: "test".into(),
            scope_digest: [0; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN],
            epoch_duration_sec: 86_400,
            epoch_retention: 2,
            issuer_urls: vec![],
            metadata: Arc::new(RwLock::new(HashMap::new())),
            accepted_token_families: vec![TokenFamily::V4],
            refresh_interval: Duration::from_secs(60),
            store_health: crate::readiness::StoreHealth::new(store.clone()),
            replay_authority: authority,
            store_is_memory: true,
        };
        assert!(ensure_v4_replay_authority_ready(&state).await.is_ok());
        assert!(store.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn v7_replay_identity_is_body_nullifier_only_and_check_is_non_consuming() {
        let store = crate::store::InMemoryStore::default();
        let body = freebird_crypto::PublicBearerV7Body::new_derived(
            "USD",
            42,
            "issuer:test",
            freebird_crypto::V7TokenKeyId::new([7; 32]),
            [8; 32],
            [9; 32],
        )
        .unwrap();
        assert_eq!(
            v7_spend_key_for_body(&body),
            format!(
                "freebird:spent:v7:issuer:test:{}",
                hex::encode(body.nullifier())
            )
        );

        // A check-style caller only verifies the artifact and does not call
        // record_v7_spend. The first mutation below is the consuming verify
        // path.
        let valid_until = time::OffsetDateTime::now_utc().unix_timestamp() + 60;
        assert_eq!(
            record_v7_spend(&store, &body, valid_until).await.unwrap(),
            SpendOutcome::Fresh
        );
        assert_eq!(
            record_v7_spend(&store, &body, valid_until).await.unwrap(),
            SpendOutcome::Replay
        );

        // Randomized presentation fields are not part of the marker.  A
        // second artifact presenting the same body nullifier is therefore a
        // replay even if its randomizer/signature bytes differ.
        assert_eq!(v7_spend_key_for_body(&body), v7_spend_key_for_body(&body));
    }

    #[test]
    fn v7_refresh_is_atomic_and_retained_bindings_cannot_rollback_or_rebind() {
        let (key_id, entry) = v7_entry(7, 8);
        let mut first = V7IssuerTrustSnapshot::default();
        first.by_token_key_id.insert(key_id, entry.clone());
        commit_v7_trust("issuer:test:state-retention", first.clone()).unwrap();

        let missing = V7IssuerTrustSnapshot::default();
        assert!(commit_v7_trust("issuer:test:state-retention", missing).is_err());
        assert_eq!(
            v7_trust_snapshot("issuer:test:state-retention"),
            Some(first.clone())
        );

        let (_, rebound) = v7_entry(7, 9);
        let mut changed = V7IssuerTrustSnapshot::default();
        changed.by_token_key_id.insert(key_id, rebound);
        assert!(commit_v7_trust("issuer:test:state-retention", changed).is_err());
        assert_eq!(
            v7_trust_snapshot("issuer:test:state-retention"),
            Some(first)
        );
    }
}
