// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Private graph issuance unit and characterization tests.

use super::authorizer::*;
use super::engine::*;
use super::policy::*;
use super::store::*;
use super::test_support;
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::graph_issuance_api::{
    self, GraphIssuanceResultV2, ReplayAuthorityProbeV1, GRAPH_ISSUANCE_VERSION_V2,
};
use std::sync::Arc;

#[path = "../graph_issuance_characterization_tests.rs"]
mod characterization_tests;

use anyhow::{bail, Context};
use std::{
    collections::HashMap,
    io::Write,
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::Duration,
};

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

struct LogWriter(LogCapture);

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 .0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for LogCapture {
    type Writer = LogWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        LogWriter(self.clone())
    }
}

struct RedisHarness {
    child: Option<Child>,
    url: String,
    port: u16,
    dir: tempfile::TempDir,
}

impl RedisHarness {
    fn start_if_available() -> anyhow::Result<Option<Self>> {
        if !Command::new("redis-server")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(None);
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let dir = tempfile::tempdir()?;
        let mut harness = Self {
            child: None,
            url: format!("redis://127.0.0.1:{port}/"),
            port,
            dir,
        };
        harness.spawn()?;
        Ok(Some(harness))
    }

    fn spawn(&mut self) -> anyhow::Result<()> {
        self.child = Some(
            Command::new("redis-server")
                .args([
                    "--port",
                    &self.port.to_string(),
                    "--bind",
                    "127.0.0.1",
                    "--dir",
                    self.dir.path().to_str().context("non-UTF8 Redis path")?,
                    "--appendonly",
                    "yes",
                    "--appendfsync",
                    "always",
                    "--save",
                    "",
                    "--maxmemory-policy",
                    "noeviction",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        for _ in 0..250 {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return Ok(());
            }
            if self
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().ok().flatten().is_some())
            {
                bail!("Redis exited during graph issuance test startup")
            }
            thread::sleep(Duration::from_millis(20));
        }
        bail!("Redis did not become reachable")
    }

    fn restart(&mut self) -> anyhow::Result<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.spawn()
    }
}

impl Drop for RedisHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[tokio::test]
async fn replay_authority_identity_probe_and_tombstones_are_durable() {
    let Some(harness) = RedisHarness::start_if_available().unwrap() else {
        return;
    };
    let store = GraphIssuanceStore::new(&harness.url).unwrap();
    let first_scope = [7u8; 32];
    let (authority, tombstones) = store
        .initialize_replay_authority(&[first_scope])
        .await
        .unwrap();
    assert_eq!(authority.len(), 32);
    assert_eq!(tombstones, vec![first_scope]);
    let (same_authority, tombstones) = store
        .initialize_replay_authority(&[[8u8; 32]])
        .await
        .unwrap();
    assert_eq!(same_authority, authority);
    assert_eq!(tombstones.len(), 2);
    let (durable_authority, durable_tombstones) =
        store.read_replay_authority_state().await.unwrap();
    assert_eq!(durable_authority, authority);
    assert_eq!(durable_tombstones.len(), 2);

    let probe_id = [9u8; 32];
    let challenge = [10u8; 32];
    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: String = redis::cmd("SET")
        .arg(GraphIssuanceStore::probe_key(&probe_id))
        .arg(challenge.as_slice())
        .arg("NX")
        .arg("EX")
        .arg(REPLAY_AUTHORITY_PROBE_TTL_SECS)
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let probe = ReplayAuthorityProbeV1 {
        version: freebird_common::graph_issuance_api::REPLAY_AUTHORITY_VERSION_V1,
        authority_id: Base64UrlUnpadded::encode_string(&authority),
        probe_id: Base64UrlUnpadded::encode_string(&probe_id),
    };
    let proof = store
        .replay_authority_probe(&probe, "issuer:test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proof,
        graph_issuance_api::replay_authority_proof_v1(
            &challenge,
            &authority,
            &probe_id,
            "issuer:test"
        )
        .unwrap()
    );
    assert!(store
        .replay_authority_probe(&probe, "issuer:test")
        .await
        .unwrap()
        .is_none());
    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: i64 = redis::cmd("DEL")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(store.read_replay_authority_state().await.is_err());
    let _: String = redis::cmd("SET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .arg(authority.as_slice())
        .query_async(&mut connection)
        .await
        .unwrap();
    let ack: Vec<u8> = redis::cmd("GETDEL")
        .arg(GraphIssuanceStore::ack_key(&probe_id))
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(ack, proof);

    let replacement_challenge = [12u8; 32];
    let _: String = redis::cmd("SET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .arg([11u8; 32].as_slice())
        .query_async(&mut connection)
        .await
        .unwrap();
    let _: String = redis::cmd("SET")
        .arg(GraphIssuanceStore::probe_key(&probe_id))
        .arg(replacement_challenge.as_slice())
        .arg("EX")
        .arg(REPLAY_AUTHORITY_PROBE_TTL_SECS)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(store
        .replay_authority_probe(&probe, "issuer:test")
        .await
        .is_err());
    let retained_challenge: Vec<u8> = redis::cmd("GET")
        .arg(GraphIssuanceStore::probe_key(&probe_id))
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(retained_challenge, replacement_challenge);
}

fn redis_policy(budget_id: &str, budget_limit: u64) -> GraphIssuancePolicy {
    GraphIssuancePolicy {
        issuance_policy_id: "redis-v4-policy".into(),
        graph_id: "1".repeat(64),
        keyset_id: "2".repeat(64),
        descriptor_id: "3".repeat(64),
        budget_id: budget_id.into(),
        budget_limit,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::AcceptingNew,
        authorization_scheme: "v4_local".into(),
        v4_local: None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn reserve_for_test(
    store: &GraphIssuanceStore,
    operation: [u8; 16],
    request: [u8; 32],
    capability: [u8; 32],
    policy: &GraphIssuancePolicy,
    marker: &str,
) -> anyhow::Result<ReserveOutcome> {
    store
        .reserve(
            &operation,
            &request,
            &capability,
            policy,
            &[operation[0]; 32],
            Some(marker),
            "target-key",
            b"blind-signature",
            b"durable-response",
            1,
            i64::MAX,
        )
        .await
}

#[tokio::test]
async fn malformed_budget_charge_is_rejected_without_any_mutation() {
    let Some(harness) = RedisHarness::start_if_available().unwrap() else {
        return;
    };
    let store = GraphIssuanceStore::new(&harness.url).unwrap();
    let policy = redis_policy("malformed-budget", 10);
    let budget_key = format!("{PREFIX}budget:{}", policy.budget_id);
    let digest = policy_digest(&policy);
    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: i64 = redis::cmd("HSET")
        .arg(&budget_key)
        .arg("policy_id")
        .arg(&policy.issuance_policy_id)
        .arg("policy_digest")
        .arg(digest.as_slice())
        .arg("limit")
        .arg(policy.budget_limit)
        .arg("charge_kind")
        .arg("issuance_quantity")
        .arg("charged")
        .arg("0")
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);

    for (index, malformed) in ["1.5", "-1"].into_iter().enumerate() {
        let mut connection = redis::Client::open(harness.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let _: i64 = redis::cmd("HSET")
            .arg(&budget_key)
            .arg("charged")
            .arg(malformed)
            .query_async(&mut connection)
            .await
            .unwrap();
        drop(connection);

        let operation = [20 + index as u8; 16];
        let marker = format!("{PREFIX}malformed-marker-{index}");
        assert!(matches!(
            reserve_for_test(
                &store,
                operation,
                [30 + index as u8; 32],
                [40 + index as u8; 32],
                &policy,
                &marker,
            )
            .await
            .unwrap(),
            ReserveOutcome::PolicyConflict
        ));
        let mut connection = redis::Client::open(harness.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        let operation_value: i64 = redis::cmd("EXISTS")
            .arg(GraphIssuanceStore::operation_key(&operation))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(operation_value, 0);
        let marker_value: Option<Vec<u8>> = redis::cmd("GET")
            .arg(&marker)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(marker_value.is_none());
        let stored: Vec<u8> = redis::cmd("HGET")
            .arg(&budget_key)
            .arg("charged")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(stored, malformed.as_bytes());
    }
}

#[tokio::test]
async fn graph_issuance_redis_reservation_is_atomic_idempotent_and_aof_recoverable() {
    let Some(mut harness) = RedisHarness::start_if_available().unwrap() else {
        return;
    };
    let policy = redis_policy("redis-v4-budget", 2);
    let store = GraphIssuanceStore::new(&harness.url).unwrap();
    let marker = "freebird:spent:v4:redis-v4-marker";
    assert!(matches!(
        reserve_for_test(&store, [1; 16], [1; 32], [2; 32], &policy, marker,)
            .await
            .unwrap(),
        ReserveOutcome::Created
    ));

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let budget_key = "freebird:graph-issuance:v2:budget:redis-v4-budget";
    let budget: HashMap<Vec<u8>, Vec<u8>> = redis::cmd("HGETALL")
        .arg(budget_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        budget.get(b"charged".as_slice()).map(Vec::as_slice),
        Some(b"1".as_slice())
    );
    assert_eq!(
        redis::cmd("GET")
            .arg(marker)
            .query_async::<_, Option<Vec<u8>>>(&mut connection)
            .await
            .unwrap()
            .as_deref(),
        Some(b"1".as_slice())
    );
    drop(connection);

    // Exact retries recover the stored response and do not re-charge the
    // budget or attempt to consume the global V4 marker again.
    assert!(matches!(
        reserve_for_test(&store, [1; 16], [1; 32], [2; 32], &policy, marker,)
            .await
            .unwrap(),
        ReserveOutcome::Existing(_)
    ));
    assert!(matches!(
        reserve_for_test(&store, [1; 16], [9; 32], [2; 32], &policy, marker,)
            .await
            .unwrap(),
        ReserveOutcome::Conflict
    ));
    assert!(matches!(
        reserve_for_test(&store, [1; 16], [1; 32], [9; 32], &policy, marker,)
            .await
            .unwrap(),
        ReserveOutcome::Conflict
    ));

    // A duplicate V4 marker is rejected even under a different policy and
    // operation, while a concurrent race has exactly one winner.
    let other_policy = GraphIssuancePolicy {
        issuance_policy_id: "redis-v4-policy-two".into(),
        budget_id: "redis-v4-budget-two".into(),
        ..policy.clone()
    };
    assert!(matches!(
        reserve_for_test(&store, [3; 16], [3; 32], [4; 32], &other_policy, marker,)
            .await
            .unwrap(),
        ReserveOutcome::AuthorizationUsed
    ));

    let race_marker = "freebird:spent:v4:redis-v4-race";
    let (race_a, race_b) = tokio::join!(
        reserve_for_test(&store, [4; 16], [4; 32], [5; 32], &policy, race_marker,),
        reserve_for_test(&store, [5; 16], [5; 32], [6; 32], &policy, race_marker,),
    );
    let race_outcomes = [race_a.unwrap(), race_b.unwrap()];
    assert_eq!(
        race_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ReserveOutcome::Created))
            .count(),
        1
    );

    // The first reservation plus the race winner consume the entire
    // independent issuance budget; the losing request never charges it.
    assert!(matches!(
        reserve_for_test(
            &store,
            [6; 16],
            [6; 32],
            [7; 32],
            &policy,
            "freebird:spent:v4:redis-v4-exhausted",
        )
        .await
        .unwrap(),
        ReserveOutcome::BudgetExhausted
    ));

    harness.restart().unwrap();
    let recovered = GraphIssuanceStore::new(&harness.url).unwrap();
    assert!(matches!(
        reserve_for_test(&recovered, [1; 16], [1; 32], [2; 32], &policy, marker,)
            .await
            .unwrap(),
        ReserveOutcome::Existing(_)
    ));
    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let budget: HashMap<Vec<u8>, Vec<u8>> = redis::cmd("HGETALL")
        .arg(budget_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        budget.get(b"charged".as_slice()).map(Vec::as_slice),
        Some(b"2".as_slice())
    );
    assert!(redis::cmd("GET")
        .arg("freebird:spent:v4:redis-v4-exhausted")
        .query_async::<_, Option<Vec<u8>>>(&mut connection)
        .await
        .unwrap()
        .is_none());
}

#[test]
fn hmac_authorization_is_bound_and_nullified_without_persisting_secret() {
    let policy = GraphIssuancePolicy {
        issuance_policy_id: "bootstrap".into(),
        graph_id: "1".repeat(64),
        keyset_id: "2".repeat(64),
        descriptor_id: "3".repeat(64),
        budget_id: "budget".into(),
        budget_limit: 10,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::AcceptingNew,
        authorization_scheme: "hmac_sha256".into(),
        v4_local: None,
    };
    let secret = vec![7; 32];
    let authorizer = HmacGraphIssuanceAuthorizer::new(secret.clone()).unwrap();
    let binding = [8; 32];
    let nonce = [9; 32];
    let authorization = graph_issuance_api::build_hmac_authorization_v2(
        &secret,
        &nonce,
        &policy.issuance_policy_id,
        &binding,
    )
    .unwrap();
    let claim = authorizer
        .authorize(&policy, &binding, &authorization)
        .unwrap();
    assert_eq!(
        claim.nullifier_digest,
        domain_digest(NULLIFIER_DOMAIN, &nonce)
    );
    assert!(claim.global_spend_key.is_none());
    assert!(authorizer
        .authorize(&policy, &[0; 32], &authorization)
        .is_err());
    let mut tampered = Base64UrlUnpadded::decode_vec(&authorization).unwrap();
    tampered[0] ^= 1;
    assert!(authorizer
        .authorize(
            &policy,
            &binding,
            &Base64UrlUnpadded::encode_string(&tampered)
        )
        .is_err());
}

#[test]
fn issuer_rejects_quantity_and_digest_mutations_in_v2_results() {
    let request = graph_issuance_api::GraphIssuanceRequestV2 {
        version: GRAPH_ISSUANCE_VERSION_V2,
        public_operation_id: Base64UrlUnpadded::encode_string(&[1; 16]),
        issuance_policy_id: "policy".into(),
        graph_id: "1".repeat(64),
        keyset_id: "2".repeat(64),
        descriptor_id: "3".repeat(64),
        blinded_message: Base64UrlUnpadded::encode_string(&[4; 32]),
        authorization: Base64UrlUnpadded::encode_string(&[5; 32]),
    };
    let mut result = GraphIssuanceResultV2 {
        version: GRAPH_ISSUANCE_VERSION_V2,
        public_operation_id: request.public_operation_id.clone(),
        issuance_policy_id: request.issuance_policy_id.clone(),
        graph_id: request.graph_id.clone(),
        keyset_id: request.keyset_id.clone(),
        descriptor_id: request.descriptor_id.clone(),
        token_key_id: "a".repeat(64),
        quantity: 1,
        request_digest: Base64UrlUnpadded::encode_string(&request.request_digest().unwrap()),
        blind_signature: Base64UrlUnpadded::encode_string(&[6; 32]),
        result_digest: String::new(),
    };
    result.result_digest =
        Base64UrlUnpadded::encode_string(&result.calculated_result_digest().unwrap());
    assert!(result.validate_against(&request, &"a".repeat(64)).is_ok());
    result.quantity = 2;
    assert!(result.validate_against(&request, &"a".repeat(64)).is_err());
    result.quantity = 1;
    result.result_digest = Base64UrlUnpadded::encode_string(&[0; 32]);
    assert!(result.validate_against(&request, &"a".repeat(64)).is_err());
}

#[test]
fn v4_local_uses_shared_verification_and_never_logs_the_raw_credential() {
    let secret = [0x41; 32];
    let verifier_id = "verifier:test:v4-local";
    let audience = "graph";
    let issuer_id = "issuer:test:v4-local";
    let kid = "kid-v4-local";
    let scope = freebird_crypto::build_scope_digest(verifier_id, audience).unwrap();
    let input =
        freebird_crypto::build_private_token_input(issuer_id, kid, &[9; 32], &scope).unwrap();
    let server =
        freebird_crypto::Server::from_secret_key(secret, freebird_crypto::VOPRF_CONTEXT_V4)
            .unwrap();
    let token = freebird_crypto::RedemptionToken {
        nonce: [9; 32],
        scope_digest: scope,
        kid: kid.into(),
        issuer_id: issuer_id.into(),
        authenticator: server.evaluate_unblinded(&input).unwrap(),
    };
    let authorization =
        Base64UrlUnpadded::encode_string(&freebird_crypto::build_redemption_token(&token).unwrap());
    let policy = GraphIssuancePolicy {
        issuance_policy_id: "v4-policy".into(),
        graph_id: "1".repeat(64),
        keyset_id: "2".repeat(64),
        descriptor_id: "3".repeat(64),
        budget_id: "v4-budget".into(),
        budget_limit: 10,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::AcceptingNew,
        authorization_scheme: "v4_local".into(),
        v4_local: Some(GraphIssuanceV4LocalPolicy {
            verifier_id: verifier_id.into(),
            audience: audience.into(),
            trusted_issuers: vec![GraphIssuanceV4TrustedIssuer {
                issuer_id: issuer_id.into(),
                key_ids: vec![kid.into()],
            }],
        }),
    };
    let authorizer =
        V4LocalGraphIssuanceAuthorizer::new(vec![crate::config::GraphIssuanceV4VerificationKey {
            issuer_id: issuer_id.into(),
            kid: kid.into(),
            secret_key: secret,
        }])
        .unwrap();
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    let claim = tracing::subscriber::with_default(subscriber, || {
        authorizer.authorize(&policy, &[0; 32], &authorization)
    })
    .unwrap();
    assert_eq!(
        claim.global_spend_key,
        Some(v4_spend_key_for_test(&token, verifier_id, audience))
    );
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.contains(&authorization));
}

fn v4_spend_key_for_test(
    token: &freebird_crypto::RedemptionToken,
    verifier_id: &str,
    audience: &str,
) -> String {
    let nullifier = freebird_crypto::nullifier_key_v4(token, verifier_id, audience).unwrap();
    freebird_common::spend_key::v4_spend_key(&nullifier)
}
