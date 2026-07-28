// SPDX-License-Identifier: Apache-2.0 OR MIT

//! V2 graph-issuance replay-authority discovery and attestation.
//!
//! The verifier deliberately performs the probe through its ordinary
//! [`SpendStore`].  A second Redis client, even when configured with the same
//! URL, would make the check meaningless for deployments which use pool-level
//! ACLs, failover, or a cloned database.

use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::{
    api::KeyDiscoveryResp,
    graph_issuance_api::{
        decode_digest, decode_proof, replay_authority_proof_v1, ReplayAuthorityProbeV1,
        ReplayAuthorityProofV1, REPLAY_AUTHORITY_VERSION_V1,
    },
};
use rand::{rngs::OsRng, RngCore};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::store::SpendStore;

pub const REPLAY_AUTHORITY_PROBE_ROUTE: &str = "/v1/public/graph/replay-authority/probe";
pub const REPLAY_AUTHORITY_PROBE_INTERVAL: Duration = Duration::from_secs(30);
pub const REPLAY_AUTHORITY_MAX_STALENESS: Duration = Duration::from_secs(60);
pub const REPLAY_AUTHORITY_PROBE_TTL: Duration = Duration::from_secs(30);
const PROBE_KEY_PREFIX: &str = "freebird:v4-replay-authority:v1:probe:";
const ACK_KEY_PREFIX: &str = "freebird:v4-replay-authority:v1:ack:";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayAuthorityConfig {
    pub graph_issuer_urls: Vec<String>,
    pub probe_interval: Duration,
    pub max_staleness: Duration,
}

impl ReplayAuthorityConfig {
    /// Read the verifier-owned graph authority settings.  The explicit
    /// prefixes avoid confusing graph issuer metadata with ordinary V4
    /// issuer metadata.
    pub fn from_env() -> Result<Self> {
        let graph_issuer_urls = std::env::var("VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS")
            .or_else(|_| std::env::var("VERIFIER_GRAPH_ISSUANCE_ISSUER_URL"))
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let probe_interval = parse_duration_env(
            "VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL",
            REPLAY_AUTHORITY_PROBE_INTERVAL,
        )?;
        let max_staleness = parse_duration_env(
            "VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS",
            REPLAY_AUTHORITY_MAX_STALENESS,
        )?;
        if probe_interval.is_zero() || max_staleness.is_zero() {
            anyhow::bail!("replay-authority probe interval and max staleness must be positive")
        }
        Ok(Self {
            graph_issuer_urls,
            probe_interval,
            max_staleness,
        })
    }
}

fn parse_duration_env(name: &str, default: Duration) -> Result<Duration> {
    let Some(value) = std::env::var(name).ok() else {
        return Ok(default);
    };
    let seconds = freebird_common::duration::parse_duration(&value)
        .map_err(|error| anyhow!("{name}: {error}"))?;
    Ok(Duration::from_secs(seconds))
}

#[derive(Clone, Default)]
struct AuthorityRecord {
    issuer_id: Option<String>,
    authority_id: Option<String>,
    /// Every scope which has ever appeared in valid discovery remains here.
    /// This is an in-process guard in addition to the issuer's append-only
    /// discovery contract.
    tombstones: BTreeSet<[u8; 32]>,
    last_success: BTreeMap<[u8; 32], Instant>,
    failed_scopes: BTreeSet<[u8; 32]>,
    metadata_valid: bool,
    last_error: Option<String>,
}

#[derive(Default)]
struct AuthorityState {
    records: HashMap<String, AuthorityRecord>,
    expected_authority_id: Option<String>,
    /// Once discovery has proved that this verifier participates in graph
    /// issuance, later discovery failures must never turn that participation
    /// off.  Configured authority URLs are pending/fail-closed before this is
    /// set.
    local_scope_matched_ever: bool,
}

/// Shared health state used by readiness and the V4 consuming handlers.
#[derive(Clone)]
pub struct ReplayAuthorityHealth {
    store: Arc<dyn SpendStore>,
    issuer_urls: Arc<Vec<String>>,
    local_scope_digest: [u8; 32],
    probe_interval: Duration,
    max_staleness: Duration,
    client: reqwest::Client,
    state: Arc<RwLock<AuthorityState>>,
}

impl ReplayAuthorityHealth {
    pub fn new(
        store: Arc<dyn SpendStore>,
        config: ReplayAuthorityConfig,
        local_scope_digest: [u8; 32],
    ) -> Result<Self> {
        let mut urls = config.graph_issuer_urls;
        urls.sort();
        urls.dedup();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("build replay-authority HTTP client")?;
        Ok(Self {
            store,
            issuer_urls: Arc::new(urls),
            local_scope_digest,
            probe_interval: config.probe_interval,
            max_staleness: config.max_staleness,
            client,
            state: Arc::new(RwLock::new(AuthorityState::default())),
        })
    }

    pub fn configured(&self) -> bool {
        !self.issuer_urls.is_empty()
    }

    pub fn issuer_urls(&self) -> &[String] {
        self.issuer_urls.as_slice()
    }

    pub fn probe_interval(&self) -> Duration {
        self.probe_interval
    }

    pub fn max_staleness(&self) -> Duration {
        self.max_staleness
    }

    /// Configured graph authority URLs represent a pending participant until
    /// discovery proves the local scope.  Pending is intentionally treated as
    /// participating for V4 gating: cold start and discovery failure must fail
    /// closed.  Once the local scope has matched, that state is sticky.
    pub async fn participating(&self) -> bool {
        self.configured()
    }

    pub async fn local_scope_matched_ever(&self) -> bool {
        self.state.read().await.local_scope_matched_ever
    }

    pub async fn allows_v4_replay(&self, memory_replay: bool) -> bool {
        if !self.participating().await {
            return true;
        }
        !memory_replay && self.healthy().await
    }

    /// A V4 authority is healthy only when every configured graph issuer has
    /// valid discovery, advertises this verifier's retained local scope, and
    /// has a recent successful bidirectional probe for that scope.
    pub async fn healthy(&self) -> bool {
        if !self.configured() {
            return true;
        }
        let state = self.state.read().await;
        let now = Instant::now();
        self.issuer_urls.iter().all(|url| {
            let Some(record) = state.records.get(url) else {
                return false;
            };
            if !record.metadata_valid
                || record.authority_id.is_none()
                || record.issuer_id.is_none()
                || record.last_error.is_some()
                || !record.failed_scopes.is_empty()
            {
                return false;
            }
            record.tombstones.contains(&self.local_scope_digest)
                && record.tombstones.iter().all(|scope| {
                    record
                        .last_success
                        .get(scope)
                        .is_some_and(|at| now.duration_since(*at) <= self.max_staleness)
                })
        })
    }

    pub async fn failure_reason(&self) -> Option<String> {
        if !self.configured() {
            return None;
        }
        if self.healthy().await {
            return None;
        }
        let state = self.state.read().await;
        state
            .records
            .values()
            .find_map(|record| record.last_error.clone())
            .or_else(|| Some("replay-authority probe is missing or stale".into()))
    }

    /// Install one issuer's discovery snapshot after validating the V2
    /// exchange/graph relationship and the permanent authority identity.
    pub async fn update_discovery(&self, url: &str, discovery: &KeyDiscoveryResp) -> Result<()> {
        match self.apply_discovery(url, discovery).await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.record_metadata_failure(url, &error.to_string()).await;
                Err(error)
            }
        }
    }

    async fn apply_discovery(&self, url: &str, discovery: &KeyDiscoveryResp) -> Result<()> {
        let graph = discovery
            .graph_issuance
            .as_ref()
            .ok_or_else(|| anyhow!("graph issuance replay-authority metadata is missing"))?;
        let exchange = discovery
            .exchange
            .as_ref()
            .ok_or_else(|| anyhow!("V2 exchange metadata is missing for graph issuance"))?;
        freebird_common::api::validate_graph_issuance_discovery_v2(exchange, graph)
            .map_err(anyhow::Error::msg)?;

        let authority = &graph.replay_authority.authority_id;
        let authority_raw = freebird_common::graph_issuance_api::decode_authority_id(authority)
            .map_err(|error| anyhow!(error.to_string()))?;
        if Base64UrlUnpadded::encode_string(&authority_raw) != *authority {
            anyhow::bail!("replay-authority identity is not canonical")
        }
        let tombstones = graph
            .replay_authority
            .v4_scope_digest_tombstones
            .iter()
            .map(|scope| decode_digest(scope).map_err(|error| anyhow!(error.to_string())))
            .collect::<Result<BTreeSet<_>>>()?;

        let mut state = self.state.write().await;
        let authority_was_unset = state.expected_authority_id.is_none();
        if let Some(expected) = &state.expected_authority_id {
            if expected != authority {
                let record = state.records.entry(url.to_owned()).or_default();
                record.metadata_valid = false;
                record.last_error = Some("replay-authority identity mismatch".into());
                anyhow::bail!("replay-authority identity mismatch")
            }
        }

        let local_scope_matched = tombstones.contains(&self.local_scope_digest);
        let was_metadata_valid;
        {
            let record = state.records.entry(url.to_owned()).or_default();
            was_metadata_valid = record.metadata_valid;
            if let Some(previous) = &record.authority_id {
                if previous != authority {
                    record.metadata_valid = false;
                    record.last_error = Some("replay-authority identity changed".into());
                    anyhow::bail!("replay-authority identity changed")
                }
            }
            if !record.tombstones.is_subset(&tombstones) {
                record.metadata_valid = false;
                record.last_error = Some("replay-authority tombstones moved backwards".into());
                anyhow::bail!("replay-authority tombstones moved backwards")
            }
        }

        if local_scope_matched {
            state.local_scope_matched_ever = true;
        }
        if authority_was_unset {
            state.expected_authority_id = Some(authority.clone());
        }
        let record = state.records.entry(url.to_owned()).or_default();
        record.issuer_id = Some(discovery.issuer_id.clone());
        record.authority_id = Some(authority.clone());
        record.tombstones = tombstones;
        record
            .last_success
            .retain(|scope, _| record.tombstones.contains(scope));
        record
            .failed_scopes
            .retain(|scope| record.tombstones.contains(scope));
        if !was_metadata_valid {
            // A discovery failure invalidates the previous attestation
            // generation.  Recovery must complete a fresh probe for every
            // durable tombstone; old timestamps cannot bridge the gap.
            record.last_success.clear();
            record.failed_scopes.clear();
        }
        record.metadata_valid = true;
        record.last_error = None;
        Ok(())
    }

    pub async fn record_refresh_failure(&self, url: &str, error: &str) {
        let mut state = self.state.write().await;
        let record = state.records.entry(url.to_owned()).or_default();
        record.metadata_valid = false;
        record.last_error = Some(error.to_owned());
    }

    /// Refresh all configured graph issuer discovery documents and run a
    /// fresh probe for every retained V4 scope.
    pub async fn refresh_and_probe(&self) {
        for url in self.issuer_urls.iter() {
            match self.fetch_discovery(url).await {
                Ok(discovery) => {
                    if let Err(error) = self.update_discovery(url, &discovery).await {
                        warn!(%url, ?error, "replay-authority discovery rejected");
                    }
                }
                Err(error) => {
                    self.record_refresh_failure(url, &error.to_string()).await;
                    warn!(%url, ?error, "replay-authority discovery refresh failed");
                }
            }
        }
        self.probe_all().await;
    }

    pub async fn probe_all(&self) {
        let snapshots = {
            let state = self.state.read().await;
            self.issuer_urls
                .iter()
                .filter_map(|url| {
                    let record = state.records.get(url)?;
                    if !record.metadata_valid
                        || !record.tombstones.contains(&self.local_scope_digest)
                    {
                        return None;
                    }
                    Some((
                        url.clone(),
                        record.issuer_id.clone()?,
                        record.authority_id.clone()?,
                        record.tombstones.iter().copied().collect::<Vec<_>>(),
                    ))
                })
                .collect::<Vec<_>>()
        };

        for (url, issuer_id, authority_id, scopes) in snapshots {
            for scope in scopes {
                match self
                    .probe_one(&url, &issuer_id, &authority_id, &scope)
                    .await
                {
                    Ok(()) => {
                        let mut state = self.state.write().await;
                        if let Some(record) = state.records.get_mut(&url) {
                            if record.metadata_valid
                                && record.authority_id.as_deref() == Some(authority_id.as_str())
                            {
                                record.last_success.insert(scope, Instant::now());
                                record.failed_scopes.remove(&scope);
                                if record.failed_scopes.is_empty() {
                                    record.last_error = None;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        self.record_probe_failure(&url, &scope, &error.to_string())
                            .await;
                        warn!(%url, ?error, "replay-authority probe failed");
                    }
                }
            }
        }
    }

    async fn fetch_discovery(&self, url: &str) -> Result<KeyDiscoveryResp> {
        let discovery_url = discovery_url(url)?;
        require_tls(&discovery_url)?;
        self.client
            .get(discovery_url.clone())
            .send()
            .await
            .with_context(|| format!("request graph issuer discovery {discovery_url}"))?
            .error_for_status()
            .with_context(|| format!("graph issuer discovery failed: {discovery_url}"))?
            .json()
            .await
            .context("decode graph issuer discovery")
    }

    async fn probe_one(
        &self,
        issuer_url: &str,
        issuer_id: &str,
        authority_id: &str,
        _scope: &[u8; 32],
    ) -> Result<()> {
        let mut challenge = [0u8; 32];
        let mut probe_id = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut challenge)
            .map_err(|error| anyhow!("generate replay-authority challenge: {error}"))?;
        OsRng
            .try_fill_bytes(&mut probe_id)
            .map_err(|error| anyhow!("generate replay-authority probe ID: {error}"))?;

        let probe_hex = hex::encode(probe_id);
        let probe_key = format!("{PROBE_KEY_PREFIX}{probe_hex}");
        if !self
            .store
            .put_replay_probe(&probe_key, &challenge, REPLAY_AUTHORITY_PROBE_TTL)
            .await?
        {
            anyhow::bail!("replay-authority probe key was not fresh")
        }

        let encoded_authority = Base64UrlUnpadded::encode_string(
            &freebird_common::graph_issuance_api::decode_authority_id(authority_id)
                .map_err(|error| anyhow!(error.to_string()))?,
        );
        let encoded_probe = Base64UrlUnpadded::encode_string(&probe_id);
        let request = ReplayAuthorityProbeV1 {
            version: REPLAY_AUTHORITY_VERSION_V1,
            authority_id: encoded_authority,
            probe_id: encoded_probe.clone(),
        };
        let response = self
            .client
            .post({
                let url = probe_url(issuer_url)?;
                require_tls(&url)?;
                url
            })
            .json(&request)
            .send()
            .await
            .context("replay-authority probe request failed")?
            .error_for_status()
            .context("replay-authority probe returned an error")?
            .json::<ReplayAuthorityProofV1>()
            .await
            .context("decode replay-authority proof")?;

        response
            .validate_against(&challenge, issuer_id, authority_id, &encoded_probe)
            .map_err(|error| anyhow!(error.to_string()))?;
        let http_proof =
            decode_proof(&response.proof).map_err(|error| anyhow!(error.to_string()))?;
        let authority_raw = freebird_common::graph_issuance_api::decode_authority_id(authority_id)
            .map_err(|error| anyhow!(error.to_string()))?;
        let local_proof =
            replay_authority_proof_v1(&challenge, &authority_raw, &probe_id, issuer_id)
                .map_err(|error| anyhow!(error.to_string()))?;
        if http_proof.ct_eq(&local_proof).unwrap_u8() != 1 {
            anyhow::bail!("replay-authority HTTP proof mismatch")
        }

        let ack_key = format!("{ACK_KEY_PREFIX}{probe_hex}");
        let ack = self
            .store
            .take_replay_ack(&ack_key)
            .await?
            .ok_or_else(|| anyhow!("replay-authority Redis acknowledgement is missing"))?;
        let ack: [u8; 32] = ack
            .try_into()
            .map_err(|_| anyhow!("replay-authority Redis acknowledgement has invalid length"))?;
        if http_proof.ct_eq(&ack).unwrap_u8() != 1 {
            anyhow::bail!("replay-authority Redis acknowledgement mismatch")
        }
        debug!(%issuer_url, "replay-authority probe succeeded");
        Ok(())
    }

    async fn record_probe_failure(&self, url: &str, scope: &[u8; 32], error: &str) {
        let mut state = self.state.write().await;
        if let Some(record) = state.records.get_mut(url) {
            record.failed_scopes.insert(*scope);
            record.last_error = Some(error.to_owned());
        }
    }

    async fn record_metadata_failure(&self, url: &str, error: &str) {
        let mut state = self.state.write().await;
        let record = state.records.entry(url.to_owned()).or_default();
        record.metadata_valid = false;
        record.last_error = Some(error.to_owned());
    }

    /// Background task entry point.  The first tick is immediate, so a
    /// newly-started verifier does not wait 30 seconds before discovering its
    /// authority.
    pub async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.probe_interval);
        loop {
            interval.tick().await;
            self.refresh_and_probe().await;
        }
    }
}

fn discovery_url(raw: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(raw).context("parse graph issuer URL")?;
    if !url.path().ends_with("/.well-known/keys") {
        url.set_path("/.well-known/keys");
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn probe_url(raw: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(raw).context("parse graph issuer URL")?;
    url.set_path(REPLAY_AUTHORITY_PROBE_ROUTE);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn require_tls(url: &reqwest::Url) -> Result<()> {
    let required = std::env::var("REQUIRE_TLS")
        .map(|value| value == "true" || value == "1")
        .unwrap_or(false);
    if required && url.scheme() != "https" {
        anyhow::bail!("graph issuer URL must use HTTPS")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{InMemoryStore, SpendStore};
    use async_trait::async_trait;
    use axum::{extract::State, routing::post, Json, Router};
    use freebird_common::api::{
        ExchangeDiscoveryV2, ExchangeGraphDiscoveryV2, ExchangeKeysetDiscoveryV2,
        ExchangeReceiptKeyInfo, GraphIssuanceDiscoveryV2, GraphIssuanceReplayAuthorityDiscoveryV1,
        KeyDiscoveryResp, VoprfKeyInfo,
    };
    use freebird_common::graph_issuance_api::{
        decode_authority_id, decode_probe_id, replay_authority_proof_v1, ReplayAuthorityProofV1,
        REPLAY_AUTHORITY_VERSION_V1,
    };
    use std::collections::HashMap;

    #[derive(Clone, Copy)]
    enum ResponseMode {
        Valid,
        MalformedProof,
        MismatchedAuthority,
    }

    struct ProbeStore {
        probes: tokio::sync::Mutex<HashMap<String, [u8; 32]>>,
        acknowledgements: tokio::sync::Mutex<HashMap<String, Vec<u8>>>,
    }

    impl ProbeStore {
        fn new() -> Self {
            Self {
                probes: tokio::sync::Mutex::new(HashMap::new()),
                acknowledgements: tokio::sync::Mutex::new(HashMap::new()),
            }
        }

        async fn take_probe(&self, key: &str) -> Option<[u8; 32]> {
            self.probes.lock().await.remove(key)
        }

        async fn put_ack(&self, key: String, value: Vec<u8>) {
            self.acknowledgements.lock().await.insert(key, value);
        }
    }

    #[async_trait]
    impl SpendStore for ProbeStore {
        async fn health_check(&self) -> Result<()> {
            Ok(())
        }

        async fn mark_spent(&self, _: &str, _: Option<Duration>) -> Result<bool> {
            Ok(true)
        }

        async fn put_replay_probe(
            &self,
            key: &str,
            challenge: &[u8; 32],
            _: Duration,
        ) -> Result<bool> {
            let mut probes = self.probes.lock().await;
            Ok(probes.insert(key.to_owned(), *challenge).is_none())
        }

        async fn take_replay_ack(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.acknowledgements.lock().await.remove(key))
        }
    }

    struct ProbeResponder {
        store: Arc<ProbeStore>,
        mode: ResponseMode,
    }

    async fn respond_to_probe(
        State(responder): State<Arc<ProbeResponder>>,
        Json(request): Json<ReplayAuthorityProbeV1>,
    ) -> Result<Json<ReplayAuthorityProofV1>, axum::http::StatusCode> {
        let authority = decode_authority_id(&request.authority_id)
            .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
        let probe =
            decode_probe_id(&request.probe_id).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
        let probe_hex = hex::encode(probe);
        let challenge = responder
            .store
            .take_probe(&format!("{PROBE_KEY_PREFIX}{probe_hex}"))
            .await
            .ok_or(axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
        let expected = replay_authority_proof_v1(&challenge, &authority, &probe, "issuer:test")
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        let mut response = ReplayAuthorityProofV1 {
            version: REPLAY_AUTHORITY_VERSION_V1,
            authority_id: request.authority_id,
            probe_id: request.probe_id,
            proof: Base64UrlUnpadded::encode_string(&expected),
        };
        match responder.mode {
            ResponseMode::Valid => {}
            ResponseMode::MalformedProof => response.proof = "not-base64".into(),
            ResponseMode::MismatchedAuthority => {
                response.authority_id = Base64UrlUnpadded::encode_string(&[8; 32]);
            }
        }
        responder
            .store
            .put_ack(format!("{ACK_KEY_PREFIX}{probe_hex}"), expected.to_vec())
            .await;
        Ok(Json(response))
    }

    fn discovery() -> KeyDiscoveryResp {
        let scope = Base64UrlUnpadded::encode_string(&[7; 32]);
        KeyDiscoveryResp {
            issuer_id: "issuer:test".into(),
            current_epoch: 1,
            valid_epochs: vec![1],
            epoch_duration_sec: 86_400,
            voprf: VoprfKeyInfo {
                suite: "suite".into(),
                kid: "kid".into(),
                pubkey: "pubkey".into(),
            },
            public: vec![],
            exchange: Some(ExchangeDiscoveryV2 {
                active_graph: ExchangeGraphDiscoveryV2 {
                    profile_id: String::new(),
                    graph_id: "1".repeat(64),
                    descriptors: vec![],
                    keysets: vec![ExchangeKeysetDiscoveryV2 {
                        keyset_id: "2".repeat(64),
                        descriptor_ids: vec![],
                    }],
                    transitions: vec![],
                },
                retained_graphs: vec![],
                active_receipt_key: ExchangeReceiptKeyInfo {
                    key_id: String::new(),
                    algorithm: String::new(),
                    purpose: String::new(),
                    public_key_b64: String::new(),
                    valid_from: 0,
                    valid_until: 0,
                },
                retained_receipt_keys: vec![],
            }),
            graph_issuance: Some(GraphIssuanceDiscoveryV2 {
                version: freebird_common::graph_issuance_api::GRAPH_ISSUANCE_VERSION_V2,
                policies: vec![],
                replay_authority: GraphIssuanceReplayAuthorityDiscoveryV1 {
                    authority_id: Base64UrlUnpadded::encode_string(&[9; 32]),
                    v4_scope_digest_tombstones: vec![scope],
                },
            }),
        }
    }

    fn discovery_with_scopes(scopes: &[[u8; 32]]) -> KeyDiscoveryResp {
        let mut discovery = discovery();
        discovery
            .graph_issuance
            .as_mut()
            .unwrap()
            .replay_authority
            .v4_scope_digest_tombstones = scopes
            .iter()
            .map(|scope| Base64UrlUnpadded::encode_string(scope))
            .collect();
        discovery
    }

    async fn server(
        store: Arc<ProbeStore>,
        mode: ResponseMode,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(REPLAY_AUTHORITY_PROBE_ROUTE, post(respond_to_probe))
            .with_state(Arc::new(ProbeResponder { store, mode }));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), handle)
    }

    #[test]
    fn config_has_frozen_defaults() {
        assert_eq!(REPLAY_AUTHORITY_PROBE_INTERVAL, Duration::from_secs(30));
        assert_eq!(REPLAY_AUTHORITY_MAX_STALENESS, Duration::from_secs(60));
        assert_eq!(REPLAY_AUTHORITY_PROBE_TTL, Duration::from_secs(30));
        assert_eq!(
            REPLAY_AUTHORITY_PROBE_ROUTE,
            "/v1/public/graph/replay-authority/probe"
        );
    }

    #[test]
    fn fixed_routes_replace_operator_supplied_paths() {
        assert_eq!(
            discovery_url("https://issuer.example/custom?x=1")
                .unwrap()
                .path(),
            "/.well-known/keys"
        );
        assert_eq!(
            probe_url("https://issuer.example/.well-known/issuer#fragment")
                .unwrap()
                .path(),
            REPLAY_AUTHORITY_PROBE_ROUTE
        );
    }

    #[tokio::test]
    async fn memory_store_cannot_attest_an_authority() {
        let health = ReplayAuthorityHealth::new(
            Arc::new(InMemoryStore::default()),
            ReplayAuthorityConfig {
                graph_issuer_urls: vec!["http://issuer".into()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [7; 32],
        )
        .unwrap();
        assert!(health.participating().await);
        assert!(!health.local_scope_matched_ever().await);
        assert!(!health.healthy().await);
        assert!(!health.allows_v4_replay(false).await);
    }

    #[tokio::test]
    async fn cold_start_and_removed_or_invalid_metadata_stay_fail_closed() {
        let store = Arc::new(ProbeStore::new());
        let url = "http://issuer";
        let health = ReplayAuthorityHealth::new(
            store,
            ReplayAuthorityConfig {
                graph_issuer_urls: vec![url.into()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [7; 32],
        )
        .unwrap();
        assert!(health.participating().await);
        assert!(!health.healthy().await);

        health.update_discovery(url, &discovery()).await.unwrap();
        assert!(health.local_scope_matched_ever().await);
        health.record_refresh_failure(url, "metadata removed").await;
        assert!(health.participating().await);
        assert!(!health.healthy().await);

        let mut missing = discovery();
        missing.graph_issuance = None;
        assert!(health.update_discovery(url, &missing).await.is_err());
        assert!(health.participating().await);
        assert!(!health.healthy().await);

        let mut invalid = discovery();
        invalid
            .graph_issuance
            .as_mut()
            .unwrap()
            .replay_authority
            .authority_id = Base64UrlUnpadded::encode_string(&[8; 32]);
        assert!(health.update_discovery(url, &invalid).await.is_err());
        assert!(health.participating().await);
        assert!(health.local_scope_matched_ever().await);
        assert!(!health.healthy().await);
    }

    #[tokio::test]
    async fn retained_tombstone_removal_is_sticky_and_fail_closed() {
        let health = ReplayAuthorityHealth::new(
            Arc::new(ProbeStore::new()),
            ReplayAuthorityConfig {
                graph_issuer_urls: vec!["http://issuer".into()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [7; 32],
        )
        .unwrap();
        let initial = discovery_with_scopes(&[[7; 32], [8; 32]]);
        health
            .update_discovery("http://issuer", &initial)
            .await
            .unwrap();
        let removed = discovery_with_scopes(&[[7; 32]]);
        assert!(health
            .update_discovery("http://issuer", &removed)
            .await
            .is_err());
        assert!(health.local_scope_matched_ever().await);
        assert!(!health.healthy().await);
    }

    #[tokio::test]
    async fn local_scope_mismatch_or_empty_tombstones_remain_pending_and_fail_closed() {
        let store = Arc::new(ProbeStore::new());
        let url = "http://issuer";
        let health = ReplayAuthorityHealth::new(
            store,
            ReplayAuthorityConfig {
                graph_issuer_urls: vec![url.into()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [8; 32],
        )
        .unwrap();
        let valid = discovery();
        health.update_discovery(url, &valid).await.unwrap();
        assert!(health.participating().await);
        assert!(!health.local_scope_matched_ever().await);
        assert!(!health.healthy().await);

        let mut empty = valid;
        empty
            .graph_issuance
            .as_mut()
            .unwrap()
            .replay_authority
            .v4_scope_digest_tombstones
            .clear();
        let empty_health = ReplayAuthorityHealth::new(
            Arc::new(ProbeStore::new()),
            ReplayAuthorityConfig {
                graph_issuer_urls: vec![url.into()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [8; 32],
        )
        .unwrap();
        empty_health.update_discovery(url, &empty).await.unwrap();
        assert!(empty_health.participating().await);
        assert!(!empty_health.local_scope_matched_ever().await);
        assert!(!empty_health.healthy().await);
    }

    #[tokio::test]
    async fn matching_configured_memory_v4_participates_but_fails_closed() {
        let url = "http://issuer";
        let health = ReplayAuthorityHealth::new(
            Arc::new(InMemoryStore::default()),
            ReplayAuthorityConfig {
                graph_issuer_urls: vec![url.into()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [7; 32],
        )
        .unwrap();
        health.update_discovery(url, &discovery()).await.unwrap();
        assert!(health.participating().await);
        assert!(health.local_scope_matched_ever().await);
        assert!(!health.healthy().await);
        assert!(!health.allows_v4_replay(true).await);
    }

    #[tokio::test]
    async fn same_redis_store_passes_and_different_or_cloned_store_fails() {
        let shared = Arc::new(ProbeStore::new());
        let (url, handle) = server(shared.clone(), ResponseMode::Valid).await;
        let health = ReplayAuthorityHealth::new(
            shared.clone(),
            ReplayAuthorityConfig {
                graph_issuer_urls: vec![url.clone()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [7; 32],
        )
        .unwrap();
        health.update_discovery(&url, &discovery()).await.unwrap();
        health.probe_all().await;
        assert!(health.healthy().await);
        handle.abort();

        let verifier_store = Arc::new(ProbeStore::new());
        let issuer_store = Arc::new(ProbeStore::new());
        let (url, handle) = server(issuer_store, ResponseMode::Valid).await;
        let different = ReplayAuthorityHealth::new(
            verifier_store,
            ReplayAuthorityConfig {
                graph_issuer_urls: vec![url.clone()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [7; 32],
        )
        .unwrap();
        different
            .update_discovery(&url, &discovery())
            .await
            .unwrap();
        different.probe_all().await;
        assert!(!different.healthy().await);
        handle.abort();
    }

    #[tokio::test]
    async fn stale_nonlocal_tombstone_blocks_authority_health() {
        let store = Arc::new(ProbeStore::new());
        let (url, handle) = server(store.clone(), ResponseMode::Valid).await;
        let health = ReplayAuthorityHealth::new(
            store,
            ReplayAuthorityConfig {
                graph_issuer_urls: vec![url.clone()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [7; 32],
        )
        .unwrap();
        health
            .update_discovery(&url, &discovery_with_scopes(&[[7; 32], [8; 32]]))
            .await
            .unwrap();
        health.probe_all().await;
        assert!(health.healthy().await);
        {
            let mut state = health.state.write().await;
            state
                .records
                .get_mut(&url)
                .unwrap()
                .last_success
                .insert([8; 32], Instant::now() - Duration::from_secs(61));
        }
        assert!(health.participating().await);
        assert!(!health.healthy().await);
        assert!(!health.allows_v4_replay(false).await);
        handle.abort();
    }

    #[tokio::test]
    async fn malformed_or_mismatched_proof_fails_closed() {
        for mode in [
            ResponseMode::MalformedProof,
            ResponseMode::MismatchedAuthority,
        ] {
            let store = Arc::new(ProbeStore::new());
            let (url, handle) = server(store.clone(), mode).await;
            let health = ReplayAuthorityHealth::new(
                store,
                ReplayAuthorityConfig {
                    graph_issuer_urls: vec![url.clone()],
                    probe_interval: Duration::from_secs(30),
                    max_staleness: Duration::from_secs(60),
                },
                [7; 32],
            )
            .unwrap();
            health.update_discovery(&url, &discovery()).await.unwrap();
            health.probe_all().await;
            assert!(!health.healthy().await);
            handle.abort();
        }
    }

    #[tokio::test]
    async fn retained_scope_is_probed_when_policy_list_is_empty() {
        let store = Arc::new(ProbeStore::new());
        let (url, handle) = server(store.clone(), ResponseMode::Valid).await;
        let health = ReplayAuthorityHealth::new(
            store,
            ReplayAuthorityConfig {
                graph_issuer_urls: vec![url.clone()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [7; 32],
        )
        .unwrap();
        let mut retired = discovery();
        retired.graph_issuance.as_mut().unwrap().policies.clear();
        health.update_discovery(&url, &retired).await.unwrap();
        health.probe_all().await;
        assert!(health.healthy().await);
        handle.abort();
    }

    #[tokio::test]
    async fn authority_identity_is_permanent_and_probe_staleness_gates() {
        let store = Arc::new(ProbeStore::new());
        let url = "http://issuer";
        let health = ReplayAuthorityHealth::new(
            store,
            ReplayAuthorityConfig {
                graph_issuer_urls: vec![url.into()],
                probe_interval: Duration::from_secs(30),
                max_staleness: Duration::from_secs(60),
            },
            [7; 32],
        )
        .unwrap();
        let good = discovery();
        health.update_discovery(url, &good).await.unwrap();
        let scope = decode_digest(
            good.graph_issuance
                .as_ref()
                .unwrap()
                .replay_authority
                .v4_scope_digest_tombstones
                .first()
                .unwrap(),
        )
        .unwrap();
        {
            let mut state = health.state.write().await;
            let record = state.records.get_mut(url).unwrap();
            record.last_success.insert(
                scope,
                Instant::now().checked_sub(Duration::from_secs(61)).unwrap(),
            );
        }
        assert!(!health.healthy().await);

        let mut changed = good;
        changed
            .graph_issuance
            .as_mut()
            .unwrap()
            .replay_authority
            .authority_id = Base64UrlUnpadded::encode_string(&[8; 32]);
        assert!(health.update_discovery(url, &changed).await.is_err());
        assert!(!health.healthy().await);
    }
}
