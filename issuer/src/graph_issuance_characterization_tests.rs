// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Phase 3A characterization tests.  These tests deliberately exercise the
//! graph issuance facade as it exists today; they do not prescribe a module
//! split or expose production implementation children.

use super::*;
use crate::AppStateWithSybil;
use anyhow::{Context, Result};
use axum::{body::to_bytes, extract::Query, http::HeaderMap, Json};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::graph_issuance_api::{
    self, GraphIssuanceRequestV2, GraphIssuanceResultV2, GRAPH_ISSUANCE_VERSION_V2,
};
use freebird_crypto::provider::{software::SoftwareBlindRsaProvider, BlindRsaProvider};
use std::{
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

const GRAPH_ID: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEYSET_ID: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const DESCRIPTOR_ID: &str = "3333333333333333333333333333333333333333333333333333333333333333";

struct RedisHarness {
    child: Option<Child>,
    url: String,
    port: u16,
    dir: tempfile::TempDir,
}

impl RedisHarness {
    fn start() -> Result<Option<Self>> {
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
        let mut harness = Self {
            child: None,
            url: format!("redis://127.0.0.1:{port}/"),
            port,
            dir: tempfile::tempdir()?,
        };
        harness.spawn()?;
        Ok(Some(harness))
    }

    fn spawn(&mut self) -> Result<()> {
        self.child = Some(
            Command::new("redis-server")
                .args([
                    "--port",
                    &self.port.to_string(),
                    "--bind",
                    "127.0.0.1",
                    "--dir",
                    self.dir.path().to_str().context("non-UTF8 Redis path")?,
                    "--save",
                    "",
                    "--appendonly",
                    "no",
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
                anyhow::bail!("Redis exited during graph characterization startup")
            }
            thread::sleep(Duration::from_millis(20));
        }
        anyhow::bail!("Redis did not become reachable")
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

fn basic_profile(private_key_path: Option<String>) -> crate::exchange::profiles::ExchangeProfileV2 {
    use crate::exchange::profiles::{
        ExchangeDescriptorV2, ExchangeKeyV2, ExchangeKeysetV2, ExchangeProfileV2,
    };

    ExchangeProfileV2 {
        profile_id: crate::exchange::profiles::PROFILE_ID_V2.into(),
        graph_id: GRAPH_ID.into(),
        keysets: vec![ExchangeKeysetV2 {
            id: KEYSET_ID.into(),
            keys: vec![ExchangeKeyV2 {
                descriptor: ExchangeDescriptorV2 {
                    id: DESCRIPTOR_ID.into(),
                    profile_id: crate::exchange::profiles::PROFILE_ID_V2.into(),
                    issuer_id: "issuer:characterization".into(),
                    kid: "a".repeat(64),
                    audience: None,
                    spki_b64: Base64UrlUnpadded::encode_string(&[8; 32]),
                    suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
                    valid_from: 1,
                    valid_until: 4_102_444_800,
                },
                private_key_path,
            }],
        }],
        transitions: Vec::new(),
    }
}

fn matrix_document() -> GraphIssuancePolicyDocument {
    serde_json::from_str(include_str!(
        "../test-fixtures/graph-issuance-policy-matrix.json"
    ))
    .expect("graph policy characterization fixture")
}

fn fixed_policy() -> GraphIssuancePolicy {
    GraphIssuancePolicy {
        issuance_policy_id: "policy-v2-fixed".into(),
        graph_id: "11".repeat(32),
        keyset_id: "22".repeat(32),
        descriptor_id: "33".repeat(32),
        budget_id: "budget-v2-fixed".into(),
        budget_limit: 17,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::AcceptingNew,
        authorization_scheme: "hmac_sha256".into(),
        v4_local: None,
    }
}

fn fixed_v4_policy() -> GraphIssuancePolicy {
    GraphIssuancePolicy {
        issuance_policy_id: "v4-policy-fixed".into(),
        graph_id: "11".repeat(32),
        keyset_id: "22".repeat(32),
        descriptor_id: "33".repeat(32),
        budget_id: "v4-budget-fixed".into(),
        budget_limit: 23,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::RecoveryOnly,
        authorization_scheme: "v4_local".into(),
        v4_local: Some(GraphIssuanceV4LocalPolicy {
            verifier_id: "verifier:fixed".into(),
            audience: "audience:fixed".into(),
            trusted_issuers: vec![GraphIssuanceV4TrustedIssuer {
                issuer_id: "issuer:fixed".into(),
                key_ids: vec!["kid-fixed-1".into(), "kid-fixed-2".into()],
            }],
        }),
    }
}

#[test]
fn fixed_capability_hmac_nullifier_policy_digests_and_redis_keys_are_frozen() {
    let capability = [0x11; 32];
    {
        let nonce = [0x11; 32];
        let authorizer =
            HmacGraphIssuanceAuthorizer::new(b"0123456789abcdef0123456789abcdef".to_vec()).unwrap();
        let policy = GraphIssuancePolicy {
            issuance_policy_id: "bootstrap-v2".into(),
            graph_id: GRAPH_ID.into(),
            keyset_id: KEYSET_ID.into(),
            descriptor_id: DESCRIPTOR_ID.into(),
            budget_id: "bootstrap-budget".into(),
            budget_limit: 10,
            quantity: 1,
            admission_state: GraphIssuanceAdmissionState::AcceptingNew,
            authorization_scheme: "hmac_sha256".into(),
            v4_local: None,
        };
        let binding = [0x22; 32];
        let authorization = graph_issuance_api::build_hmac_authorization_v2(
            b"0123456789abcdef0123456789abcdef",
            &nonce,
            &policy.issuance_policy_id,
            &binding,
        )
        .unwrap();
        let claim = authorizer
            .authorize(&policy, &binding, &authorization)
            .unwrap();
        assert_eq!(
            Base64UrlUnpadded::encode_string(&claim.nullifier_digest),
            "LHJrbdh1mhd7vBHhnjLX6JDVhV15ze2h8lRPw5nEFhY"
        );
    }

    assert_eq!(
        Base64UrlUnpadded::encode_string(&test_support::status_digest(&capability)),
        "M-A9xcCXiSGDhUpvnUgVwMo2hSvjjEbd0r0miuSBhzU"
    );
    assert_eq!(
        Base64UrlUnpadded::encode_string(&test_support::policy_digest(&fixed_policy())),
        "iY3RkTMEbA98_5LjPROZ692Od8CRrOOA4yZciI6zIcY"
    );
    assert_eq!(
        Base64UrlUnpadded::encode_string(&test_support::policy_digest(&fixed_v4_policy())),
        "UOTPzsHIWmV_fscx8emajsWCxFav1Q5LqpWgOVOIVls"
    );

    let operation = [0x44; 16];
    assert_eq!(
        test_support::operation_key(&operation),
        "freebird:graph-issuance:v2:op:44444444444444444444444444444444"
    );
    assert_eq!(
        test_support::no_global_spend_key(&operation),
        "freebird:graph-issuance:v2:no-global-spend:44444444444444444444444444444444"
    );
    let probe = [0x55; 32];
    assert_eq!(
        GraphIssuanceStore::probe_key(&probe),
        "freebird:v4-replay-authority:v1:probe:5555555555555555555555555555555555555555555555555555555555555555"
    );
    assert_eq!(
        GraphIssuanceStore::ack_key(&probe),
        "freebird:v4-replay-authority:v1:ack:5555555555555555555555555555555555555555555555555555555555555555"
    );
    assert_eq!(
        REPLAY_AUTHORITY_ID_KEY,
        "freebird:v4-replay-authority:v1:id"
    );
    assert_eq!(
        test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY,
        "freebird:v4-replay-authority:v1:scope-tombstones"
    );
}

#[tokio::test]
async fn reservation_uses_frozen_authorization_budget_and_fallback_keys() {
    let Some(harness) = RedisHarness::start().unwrap() else {
        return;
    };
    let store = GraphIssuanceStore::new(&harness.url).unwrap();
    let policy = fixed_policy();
    let operation = [0x44; 16];
    let request_digest = [0x45; 32];
    let capability = [0x46; 32];
    let nullifier = [0x47; 32];
    let signer_key = "a".repeat(64);
    assert!(matches!(
        store
            .reserve(
                &operation,
                &request_digest,
                &capability,
                &policy,
                &nullifier,
                None,
                &signer_key,
                b"blind-signature",
                b"stored-response",
                1,
                i64::MAX,
            )
            .await
            .unwrap(),
        ReserveOutcome::Created
    ));

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let operation_key = test_support::operation_key(&operation);
    let authorization_key = "freebird:graph-issuance:v2:authorization:policy-v2-fixed:4747474747474747474747474747474747474747474747474747474747474747";
    let budget_key = "freebird:graph-issuance:v2:budget:budget-v2-fixed";
    let no_global_spend_key =
        "freebird:graph-issuance:v2:no-global-spend:44444444444444444444444444444444";
    assert_eq!(
        test_support::no_global_spend_key(&operation),
        no_global_spend_key
    );
    for key in [operation_key.as_str(), authorization_key, budget_key] {
        assert_eq!(
            redis::cmd("EXISTS")
                .arg(key)
                .query_async::<_, i64>(&mut connection)
                .await
                .unwrap(),
            1,
            "reservation did not use expected key {key}"
        );
    }
    assert_eq!(
        redis::cmd("HGET")
            .arg(authorization_key)
            .arg("authorization_nullifier_digest")
            .query_async::<_, Vec<u8>>(&mut connection)
            .await
            .unwrap(),
        nullifier.to_vec()
    );
    assert_eq!(
        redis::cmd("HGET")
            .arg(budget_key)
            .arg("charged")
            .query_async::<_, Vec<u8>>(&mut connection)
            .await
            .unwrap(),
        b"1".to_vec()
    );
    // The fallback is a real fourth Lua key, but deliberately remains a
    // non-durable sentinel when no V4 global spend marker is supplied.
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(no_global_spend_key)
            .query_async::<_, i64>(&mut connection)
            .await
            .unwrap(),
        0
    );
}

#[test]
fn policy_validation_discovery_order_and_secrecy_matrix_is_frozen() {
    let active = basic_profile(Some("/characterization/graph-signer.der".into()));
    let document = matrix_document();
    document.validate(&active, &[]).unwrap();

    let authority = Base64UrlUnpadded::encode_string(&[0x71; 32]);
    let first_scope = freebird_crypto::build_scope_digest(
        "verifier:characterization",
        "graph-issuance-characterization",
    )
    .unwrap();
    let discovery = document.discovery(
        &authority,
        &[
            Base64UrlUnpadded::encode_string(&first_scope),
            Base64UrlUnpadded::encode_string(&[0x72; 32]),
        ],
    );
    assert_eq!(
        discovery
            .policies
            .iter()
            .map(|policy| policy.issuance_policy_id.as_str())
            .collect::<Vec<_>>(),
        vec!["hmac-policy", "v4-policy", "mock-policy"]
    );
    assert_eq!(discovery.replay_authority.authority_id, authority);
    assert_eq!(
        discovery.replay_authority.v4_scope_digest_tombstones,
        vec![
            Base64UrlUnpadded::encode_string(&first_scope),
            Base64UrlUnpadded::encode_string(&[0x72; 32])
        ]
    );

    let encoded = serde_json::to_string(&discovery).unwrap();
    for secret in [
        "verifier:characterization",
        "graph-issuance-characterization",
        "issuer:characterization",
        "kid-characterization",
    ] {
        assert!(!encoded.contains(secret), "discovery leaked {secret}");
    }
    assert!(!encoded.contains("redis://"));
    assert!(!encoded.contains("secret"));
    assert!(encoded.contains("authorization_scope_digest_b64"));
    assert!(encoded.contains(&authority));

    let mut invalid = document.clone();
    invalid.version = "freebird/graph-blind-issuance-policy/v1".into();
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[0].graph_id = "4".repeat(64);
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[0].keyset_id = "4".repeat(64);
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[0].descriptor_id = "4".repeat(64);
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[0].budget_limit = 0;
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[0].quantity = 2;
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[0].authorization_scheme = "unknown".into();
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[0].v4_local = Some(GraphIssuanceV4LocalPolicy {
        verifier_id: "verifier:unexpected".into(),
        audience: "audience:unexpected".into(),
        trusted_issuers: vec![GraphIssuanceV4TrustedIssuer {
            issuer_id: "issuer:unexpected".into(),
            key_ids: vec!["kid-unexpected".into()],
        }],
    });
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[1].v4_local = None;
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[1].budget_id = invalid.policies[0].budget_id.clone();
    assert!(invalid.validate(&active, &[]).is_err());

    invalid = document.clone();
    invalid.policies[1].issuance_policy_id = invalid.policies[0].issuance_policy_id.clone();
    assert!(invalid.validate(&active, &[]).is_err());

    let no_signer = basic_profile(None);
    assert!(document.validate(&no_signer, &[]).is_err());

    let mut retained = basic_profile(Some("/characterization/retained.der".into()));
    retained.graph_id = "4".repeat(64);
    let accepting_retained = GraphIssuancePolicyDocument {
        version: POLICY_DOCUMENT_VERSION.into(),
        policies: vec![GraphIssuancePolicy {
            issuance_policy_id: "retained-accepting".into(),
            graph_id: retained.graph_id.clone(),
            keyset_id: retained.keysets[0].id.clone(),
            descriptor_id: retained.keysets[0].keys[0].descriptor.id.clone(),
            budget_id: "retained-budget".into(),
            budget_limit: 1,
            quantity: 1,
            admission_state: GraphIssuanceAdmissionState::AcceptingNew,
            authorization_scheme: "hmac_sha256".into(),
            v4_local: None,
        }],
    };
    assert!(accepting_retained.validate(&active, &[retained]).is_err());
}

fn bounded_recovery_policy(index: usize) -> GraphIssuancePolicy {
    GraphIssuancePolicy {
        issuance_policy_id: format!("bounded-policy-{index}"),
        graph_id: GRAPH_ID.into(),
        keyset_id: KEYSET_ID.into(),
        descriptor_id: DESCRIPTOR_ID.into(),
        budget_id: format!("bounded-budget-{index}"),
        budget_limit: 1,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::RecoveryOnly,
        authorization_scheme: "development_mock".into(),
        v4_local: None,
    }
}

#[test]
fn policy_document_and_v4_local_boundaries_are_exact() {
    let active = basic_profile(None);
    let max_items = freebird_common::exchange_api::MAX_ITEMS;
    let at_document_limit = GraphIssuancePolicyDocument {
        version: POLICY_DOCUMENT_VERSION.into(),
        policies: (0..max_items).map(bounded_recovery_policy).collect(),
    };
    assert!(at_document_limit.validate(&active, &[]).is_ok());

    let over_document_limit = GraphIssuancePolicyDocument {
        version: POLICY_DOCUMENT_VERSION.into(),
        policies: (0..=max_items).map(bounded_recovery_policy).collect(),
    };
    assert!(over_document_limit.validate(&active, &[]).is_err());

    let mut at_id_limit = bounded_recovery_policy(0);
    at_id_limit.issuance_policy_id = "i".repeat(128);
    at_id_limit.budget_id = "b".repeat(128);
    at_id_limit.budget_limit = freebird_common::api::EXCHANGE_MAX_BUDGET_LIMIT;
    let document = |policy| GraphIssuancePolicyDocument {
        version: POLICY_DOCUMENT_VERSION.into(),
        policies: vec![policy],
    };
    assert!(document(at_id_limit.clone()).validate(&active, &[]).is_ok());

    let mut over_id_limit = at_id_limit.clone();
    over_id_limit.issuance_policy_id = "i".repeat(129);
    assert!(document(over_id_limit).validate(&active, &[]).is_err());
    let mut over_budget_id_limit = at_id_limit.clone();
    over_budget_id_limit.budget_id = "b".repeat(129);
    assert!(document(over_budget_id_limit)
        .validate(&active, &[])
        .is_err());
    let mut over_budget_limit = at_id_limit.clone();
    over_budget_limit.budget_limit = freebird_common::api::EXCHANGE_MAX_BUDGET_LIMIT + 1;
    assert!(document(over_budget_limit).validate(&active, &[]).is_err());
    let mut zero_budget = at_id_limit.clone();
    zero_budget.budget_limit = 0;
    assert!(document(zero_budget).validate(&active, &[]).is_err());
    let mut non_ascii_id = at_id_limit;
    non_ascii_id.issuance_policy_id = "é".into();
    assert!(document(non_ascii_id).validate(&active, &[]).is_err());

    let mut v4_at_field_limits = fixed_v4_policy();
    v4_at_field_limits.v4_local = Some(GraphIssuanceV4LocalPolicy {
        verifier_id: "v".repeat(255),
        audience: "a".repeat(255),
        trusted_issuers: vec![GraphIssuanceV4TrustedIssuer {
            issuer_id: "r".repeat(255),
            key_ids: vec!["k".repeat(255)],
        }],
    });
    assert!(document(v4_at_field_limits.clone())
        .validate(&active, &[])
        .is_ok());

    let over_field_limit: [fn(&mut GraphIssuanceV4LocalPolicy); 4] = [
        |local: &mut GraphIssuanceV4LocalPolicy| local.verifier_id = "v".repeat(256),
        |local: &mut GraphIssuanceV4LocalPolicy| local.audience = "a".repeat(256),
        |local: &mut GraphIssuanceV4LocalPolicy| {
            local.trusted_issuers[0].issuer_id = "r".repeat(256)
        },
        |local: &mut GraphIssuanceV4LocalPolicy| {
            local.trusted_issuers[0].key_ids[0] = "k".repeat(256)
        },
    ];
    for mutate in over_field_limit {
        let mut policy = v4_at_field_limits.clone();
        mutate(policy.v4_local.as_mut().unwrap());
        assert!(document(policy).validate(&active, &[]).is_err());
    }

    let max_trusted_issuers = (0..max_items)
        .map(|index| GraphIssuanceV4TrustedIssuer {
            issuer_id: format!("issuer-{index}"),
            key_ids: vec![format!("kid-{index}")],
        })
        .collect();
    let mut policy = fixed_v4_policy();
    policy.v4_local.as_mut().unwrap().trusted_issuers = max_trusted_issuers;
    assert!(document(policy.clone()).validate(&active, &[]).is_ok());
    policy
        .v4_local
        .as_mut()
        .unwrap()
        .trusted_issuers
        .push(GraphIssuanceV4TrustedIssuer {
            issuer_id: "issuer-over-limit".into(),
            key_ids: vec!["kid-over-limit".into()],
        });
    assert!(document(policy).validate(&active, &[]).is_err());

    let max_key_ids = (0..max_items).map(|index| format!("kid-{index}")).collect();
    let mut policy = fixed_v4_policy();
    policy.v4_local.as_mut().unwrap().trusted_issuers = vec![GraphIssuanceV4TrustedIssuer {
        issuer_id: "issuer-key-limit".into(),
        key_ids: max_key_ids,
    }];
    assert!(document(policy.clone()).validate(&active, &[]).is_ok());
    policy.v4_local.as_mut().unwrap().trusted_issuers[0]
        .key_ids
        .push("kid-over-limit".into());
    assert!(document(policy).validate(&active, &[]).is_err());
}

#[test]
fn v4_local_policy_rejects_empty_and_duplicate_trust_configuration() {
    let mut invalid = fixed_v4_policy();
    invalid.v4_local.as_mut().unwrap().verifier_id.clear();
    assert!(validate_v4_local_policy(invalid.v4_local.as_ref().unwrap()).is_err());

    let mut invalid = fixed_v4_policy();
    invalid.v4_local.as_mut().unwrap().audience.clear();
    assert!(validate_v4_local_policy(invalid.v4_local.as_ref().unwrap()).is_err());

    let mut invalid = fixed_v4_policy();
    invalid.v4_local.as_mut().unwrap().trusted_issuers.clear();
    assert!(validate_v4_local_policy(invalid.v4_local.as_ref().unwrap()).is_err());

    let mut invalid = fixed_v4_policy();
    invalid.v4_local.as_mut().unwrap().trusted_issuers[0]
        .key_ids
        .clear();
    assert!(validate_v4_local_policy(invalid.v4_local.as_ref().unwrap()).is_err());

    let mut invalid = fixed_v4_policy();
    let duplicate_issuer = invalid.v4_local.as_ref().unwrap().trusted_issuers[0].clone();
    invalid
        .v4_local
        .as_mut()
        .unwrap()
        .trusted_issuers
        .push(duplicate_issuer);
    assert!(validate_v4_local_policy(invalid.v4_local.as_ref().unwrap()).is_err());

    let mut invalid = fixed_v4_policy();
    invalid.v4_local.as_mut().unwrap().trusted_issuers[0]
        .key_ids
        .push("kid-fixed-1".into());
    assert!(validate_v4_local_policy(invalid.v4_local.as_ref().unwrap()).is_err());
}

#[derive(Default)]
struct CountingAuthorizer {
    calls: AtomicUsize,
}

impl GraphIssuanceAuthorizer for CountingAuthorizer {
    fn authorize(
        &self,
        _policy: &GraphIssuancePolicy,
        _request_binding: &[u8; 32],
        _authorization: &str,
    ) -> Result<AuthorizationClaim> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AuthorizationClaim {
            nullifier_digest: [0x91; 32],
            global_spend_key: None,
        })
    }
}

fn generated_signer_fixture(
    valid_from: i64,
    valid_until: i64,
    budget_id: &str,
) -> Result<(
    tempfile::TempDir,
    crate::exchange::profiles::ExchangeProfileV2,
    GraphIssuancePolicy,
    GraphIssuanceRequestV2,
)> {
    use crate::exchange::profiles::{
        ExchangeDescriptorV2, ExchangeKeyV2, ExchangeKeysetV2, ExchangeProfileV2,
    };

    let provider = SoftwareBlindRsaProvider::generate(2048)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("graph-signer.der");
    std::fs::write(&path, provider.to_der()?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut descriptor = ExchangeDescriptorV2 {
        id: String::new(),
        profile_id: crate::exchange::profiles::PROFILE_ID_V2.into(),
        issuer_id: "issuer:characterization".into(),
        kid: hex::encode(provider.token_key_id()),
        audience: None,
        spki_b64: Base64UrlUnpadded::encode_string(provider.public_key_spki()),
        suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
        valid_from,
        valid_until,
    };
    descriptor.id = descriptor.canonical_id()?;
    let mut keyset = ExchangeKeysetV2 {
        id: String::new(),
        keys: vec![ExchangeKeyV2 {
            descriptor: descriptor.clone(),
            private_key_path: Some(path.display().to_string()),
        }],
    };
    keyset.id = keyset.canonical_id();
    let graph = ExchangeProfileV2 {
        profile_id: crate::exchange::profiles::PROFILE_ID_V2.into(),
        graph_id: GRAPH_ID.into(),
        keysets: vec![keyset],
        transitions: Vec::new(),
    };
    let policy = GraphIssuancePolicy {
        issuance_policy_id: format!("policy-{budget_id}"),
        graph_id: graph.graph_id.clone(),
        keyset_id: graph.keysets[0].id.clone(),
        descriptor_id: descriptor.id.clone(),
        budget_id: budget_id.into(),
        budget_limit: 2,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::AcceptingNew,
        authorization_scheme: "development_mock".into(),
        v4_local: None,
    };
    let request = GraphIssuanceRequestV2 {
        version: GRAPH_ISSUANCE_VERSION_V2,
        public_operation_id: Base64UrlUnpadded::encode_string(&[0x81; 16]),
        issuance_policy_id: policy.issuance_policy_id.clone(),
        graph_id: policy.graph_id.clone(),
        keyset_id: policy.keyset_id.clone(),
        descriptor_id: policy.descriptor_id.clone(),
        blinded_message: Base64UrlUnpadded::encode_string(&[0x82; 256]),
        authorization: Base64UrlUnpadded::encode_string(&[0x83; 32]),
    };
    Ok((directory, graph, policy, request))
}

#[tokio::test]
async fn future_and_expired_signer_windows_use_redis_time_before_authorization() {
    let Some(harness) = RedisHarness::start().unwrap() else {
        return;
    };
    let redis_now = GraphIssuanceStore::new(&harness.url)
        .unwrap()
        .redis_time()
        .await
        .unwrap();

    for (index, (valid_from, valid_until)) in [
        (redis_now + 600, redis_now + 1_200),
        (redis_now - 1_200, redis_now - 600),
    ]
    .into_iter()
    .enumerate()
    {
        let (_directory, graph, policy, mut request) =
            generated_signer_fixture(valid_from, valid_until, &format!("window-{index}")).unwrap();
        request.public_operation_id = Base64UrlUnpadded::encode_string(&[0x81 + index as u8; 16]);
        let authorizer = Arc::new(CountingAuthorizer::default());
        let engine = GraphIssuanceEngine::new_with_enabled(
            &graph,
            &[],
            GraphIssuancePolicyDocument {
                version: POLICY_DOCUMENT_VERSION.into(),
                policies: vec![policy],
            },
            &harness.url,
            authorizer.clone(),
            true,
        )
        .unwrap();
        // Initialization is intentionally not needed to characterize fresh
        // admission ordering; the Redis TIME read occurs in process itself.
        assert!(engine.issuance_enabled());
        let decision = engine.process(&request, &[0x84; 32]).await.unwrap();
        assert_eq!(decision, ProcessDecision::Rejected);
        assert_eq!(authorizer.calls.load(Ordering::SeqCst), 0);
        let mut connection = redis::Client::open(harness.url.clone())
            .unwrap()
            .get_async_connection()
            .await
            .unwrap();
        assert_eq!(
            redis::cmd("EXISTS")
                .arg(test_support::operation_key(
                    &request.operation_id().unwrap()
                ))
                .query_async::<_, i64>(&mut connection)
                .await
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn authorization_precedes_signing_but_malformed_rsa_has_no_durable_mutation() {
    let Some(harness) = RedisHarness::start().unwrap() else {
        return;
    };
    let now = GraphIssuanceStore::new(&harness.url)
        .unwrap()
        .redis_time()
        .await
        .unwrap();
    let (_directory, graph, policy, mut request) =
        generated_signer_fixture(now - 600, now + 600, "malformed-representative").unwrap();
    request.blinded_message = Base64UrlUnpadded::encode_string(&[0; 256]);
    let authorizer = Arc::new(CountingAuthorizer::default());
    let engine = GraphIssuanceEngine::new_with_enabled(
        &graph,
        &[],
        GraphIssuancePolicyDocument {
            version: POLICY_DOCUMENT_VERSION.into(),
            policies: vec![policy],
        },
        &harness.url,
        authorizer.clone(),
        true,
    )
    .unwrap();

    assert_eq!(
        engine.process(&request, &[0x85; 32]).await.unwrap(),
        ProcessDecision::Rejected
    );
    assert_eq!(authorizer.calls.load(Ordering::SeqCst), 1);

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("freebird:graph-issuance:v2:*")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(keys.is_empty(), "malformed signing input mutated {keys:?}");
}

fn recovery_engine(redis_url: &str) -> Result<Arc<GraphIssuanceEngine>> {
    let policy = GraphIssuancePolicy {
        issuance_policy_id: "recovery-policy".into(),
        graph_id: GRAPH_ID.into(),
        keyset_id: KEYSET_ID.into(),
        descriptor_id: DESCRIPTOR_ID.into(),
        budget_id: "recovery-budget".into(),
        budget_limit: 2,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::RecoveryOnly,
        authorization_scheme: "development_mock".into(),
        v4_local: None,
    };
    Ok(Arc::new(GraphIssuanceEngine::new_with_enabled(
        &basic_profile(None),
        &[],
        GraphIssuancePolicyDocument {
            version: POLICY_DOCUMENT_VERSION.into(),
            policies: vec![policy],
        },
        redis_url,
        Arc::new(DisabledGraphIssuanceAuthorizer),
        false,
    )?))
}

fn recovery_request(operation: [u8; 16]) -> GraphIssuanceRequestV2 {
    GraphIssuanceRequestV2 {
        version: GRAPH_ISSUANCE_VERSION_V2,
        public_operation_id: Base64UrlUnpadded::encode_string(&operation),
        issuance_policy_id: "recovery-policy".into(),
        graph_id: GRAPH_ID.into(),
        keyset_id: KEYSET_ID.into(),
        descriptor_id: DESCRIPTOR_ID.into(),
        blinded_message: Base64UrlUnpadded::encode_string(&[0x31; 32]),
        authorization: Base64UrlUnpadded::encode_string(&[0x32; 32]),
    }
}

fn valid_stored_result(request: &GraphIssuanceRequestV2) -> GraphIssuanceResultV2 {
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
        blind_signature: Base64UrlUnpadded::encode_string(&[0x33; 32]),
        result_digest: String::new(),
    };
    result.result_digest =
        Base64UrlUnpadded::encode_string(&result.calculated_result_digest().unwrap());
    result
}

async fn put_stored_record(
    redis_url: &str,
    request: &GraphIssuanceRequestV2,
    capability: &[u8; 32],
    response: Vec<u8>,
) -> Result<()> {
    let operation = request.operation_id()?;
    let request_digest = request.request_digest()?;
    let mut connection = redis::Client::open(redis_url.to_owned())
        .context("open characterization Redis")?
        .get_async_connection()
        .await?;
    let key = test_support::operation_key(&operation);
    let _: i64 = redis::cmd("HSET")
        .arg(key)
        .arg("request_digest")
        .arg(request_digest.as_slice())
        .arg("status_capability_digest")
        .arg(test_support::status_digest(capability).as_slice())
        .arg("issuance_policy_id")
        .arg(&request.issuance_policy_id)
        .arg("graph_id")
        .arg(&request.graph_id)
        .arg("keyset_id")
        .arg(&request.keyset_id)
        .arg("descriptor_id")
        .arg(&request.descriptor_id)
        .arg("signer_key_id")
        .arg("a".repeat(64))
        .arg("quantity")
        .arg("1")
        .arg("response")
        .arg(response)
        .query_async(&mut connection)
        .await?;
    Ok(())
}

async fn response_body(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

fn route_state(engine: Arc<GraphIssuanceEngine>) -> Arc<AppStateWithSybil> {
    Arc::new(AppStateWithSybil {
        issuer_id: "issuer:characterization".into(),
        kid: "a".repeat(64),
        pubkey_b64: "pubkey".into(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: None,
        invitation_system: None,
        public_issuer: None,
        exchange_engine: None,
        exchange_metadata: None,
        graph_issuance_engine: Some(engine),
        graph_issuance_metadata: None,
        epoch_duration_sec: 86_400,
        epoch_retention: 1,
        admin_api_key: None,
        sybil_summary: None,
    })
}

#[tokio::test]
async fn corrupted_stored_responses_fail_closed_and_routes_are_generic_with_capability_ordering() {
    let Some(harness) = RedisHarness::start().unwrap() else {
        return;
    };
    let engine = recovery_engine(&harness.url).unwrap();
    let capability = [0x41; 32];
    let wrong_capability = [0x42; 32];

    let request = recovery_request([0x51; 16]);
    let mut selector_corruption = valid_stored_result(&request);
    selector_corruption.graph_id = "4".repeat(64);
    selector_corruption.result_digest =
        Base64UrlUnpadded::encode_string(&selector_corruption.calculated_result_digest().unwrap());

    let mut request_digest_corruption = valid_stored_result(&request);
    request_digest_corruption.request_digest = Base64UrlUnpadded::encode_string(&[0x52; 32]);
    request_digest_corruption.result_digest = Base64UrlUnpadded::encode_string(
        &request_digest_corruption
            .calculated_result_digest()
            .unwrap(),
    );

    let mut result_digest_corruption = valid_stored_result(&request);
    result_digest_corruption.result_digest = Base64UrlUnpadded::encode_string(&[0x53; 32]);

    let corruptions = [
        (b"not-json".to_vec(), [0x61; 16]),
        (
            serde_json::to_vec(&selector_corruption).unwrap(),
            [0x62; 16],
        ),
        (
            serde_json::to_vec(&request_digest_corruption).unwrap(),
            [0x63; 16],
        ),
        (
            serde_json::to_vec(&result_digest_corruption).unwrap(),
            [0x64; 16],
        ),
    ];
    for (response, operation) in corruptions {
        let request = recovery_request(operation);
        put_stored_record(&harness.url, &request, &capability, response)
            .await
            .unwrap();
        assert!(engine.process(&request, &capability).await.is_err());
        assert!(engine.status(&operation, &capability).await.is_err());
    }

    // Status authorization is checked before parsing an unauthorized stored
    // response, so a caller with the wrong capability cannot turn corruption
    // into a storage oracle.
    let unauthorized_request = recovery_request([0x65; 16]);
    put_stored_record(
        &harness.url,
        &unauthorized_request,
        &capability,
        b"corrupt-response".to_vec(),
    )
    .await
    .unwrap();
    assert_eq!(
        engine.status(&[0x65; 16], &wrong_capability).await.unwrap(),
        StatusDecision::Unauthorized
    );
    assert_eq!(
        engine
            .process(&unauthorized_request, &wrong_capability)
            .await
            .unwrap_err()
            .to_string(),
        "corrupt stored graph issuance response"
    );

    let state = route_state(engine.clone());
    let voprf = Arc::new(
        crate::multi_key_voprf::MultiKeyVoprfCore::new(
            [7; 32],
            "pubkey".into(),
            "kid".into(),
            b"test",
        )
        .unwrap(),
    );
    let shared = (state, voprf);
    let mut headers = HeaderMap::new();
    headers.insert(
        crate::routes::public_graph_issuance::STATUS_CAPABILITY,
        Base64UrlUnpadded::encode_string(&capability)
            .parse()
            .unwrap(),
    );
    let mut invalid_headers = HeaderMap::new();
    invalid_headers.insert(
        crate::routes::public_graph_issuance::STATUS_CAPABILITY,
        "not-a-capability".parse().unwrap(),
    );
    let process_response = crate::routes::public_graph_issuance::post(
        axum::extract::State(shared.clone()),
        invalid_headers,
        Ok(Json(recovery_request([0x61; 16]))),
    )
    .await;
    // The operation is intentionally absent; invalid capability syntax is
    // still rejected before body/store work.
    assert_eq!(
        process_response.status(),
        axum::http::StatusCode::BAD_REQUEST
    );

    let corrupt_request = recovery_request([0x61; 16]);
    let process_response = crate::routes::public_graph_issuance::post(
        axum::extract::State(shared.clone()),
        headers.clone(),
        Ok(Json(corrupt_request)),
    )
    .await;
    assert_eq!(
        process_response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response_body(process_response).await,
        br#"{"error":"graph_issuance_unavailable"}"#
    );

    let status_response = crate::routes::public_graph_issuance::status(
        axum::extract::State(shared.clone()),
        headers,
        Ok(Query(
            crate::routes::public_graph_issuance::status_query_for_test(
                Base64UrlUnpadded::encode_string(&[0x61; 16]),
            ),
        )),
    )
    .await;
    assert_eq!(
        status_response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response_body(status_response).await,
        br#"{"error":"graph_issuance_unavailable"}"#
    );

    let mut unauthorized_headers = HeaderMap::new();
    unauthorized_headers.insert(
        crate::routes::public_graph_issuance::STATUS_CAPABILITY,
        Base64UrlUnpadded::encode_string(&wrong_capability)
            .parse()
            .unwrap(),
    );
    let unauthorized_status = crate::routes::public_graph_issuance::status(
        axum::extract::State(shared),
        unauthorized_headers,
        Ok(Query(
            crate::routes::public_graph_issuance::status_query_for_test(
                Base64UrlUnpadded::encode_string(&[0x65; 16]),
            ),
        )),
    )
    .await;
    assert_eq!(
        unauthorized_status.status(),
        axum::http::StatusCode::FORBIDDEN
    );
}

fn durable_v4_engine(redis_url: &str) -> Result<GraphIssuanceEngine> {
    let policy = GraphIssuancePolicy {
        issuance_policy_id: "durable-v4-policy".into(),
        graph_id: GRAPH_ID.into(),
        keyset_id: KEYSET_ID.into(),
        descriptor_id: DESCRIPTOR_ID.into(),
        budget_id: "durable-v4-budget".into(),
        budget_limit: 1,
        quantity: 1,
        admission_state: GraphIssuanceAdmissionState::RecoveryOnly,
        authorization_scheme: "v4_local".into(),
        v4_local: Some(GraphIssuanceV4LocalPolicy {
            verifier_id: "verifier:durable".into(),
            audience: "audience:durable".into(),
            trusted_issuers: vec![GraphIssuanceV4TrustedIssuer {
                issuer_id: "issuer:durable".into(),
                key_ids: vec!["kid-durable".into()],
            }],
        }),
    };
    GraphIssuanceEngine::new_with_enabled(
        &basic_profile(None),
        &[],
        GraphIssuancePolicyDocument {
            version: POLICY_DOCUMENT_VERSION.into(),
            policies: vec![policy],
        },
        redis_url,
        Arc::new(DisabledGraphIssuanceAuthorizer),
        false,
    )
}

#[tokio::test]
async fn durable_authority_and_tombstone_mutation_after_initialization_fails_discovery_or_readiness(
) {
    let Some(harness) = RedisHarness::start().unwrap() else {
        return;
    };
    let mut engine = durable_v4_engine(&harness.url).unwrap();
    let initial = engine.initialize().await.unwrap();
    assert!(engine.readiness_check().await);
    let authority =
        graph_issuance_api::decode_authority_id(&initial.replay_authority.authority_id).unwrap();

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: String = redis::cmd("SET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .arg("bad-authority")
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(engine.discovery_from_durable().await.is_err());
    assert!(!engine.readiness_check().await);

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: String = redis::cmd("SET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .arg(authority.as_slice())
        .arg("EX")
        .arg(60)
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(engine.discovery_from_durable().await.is_err());
    assert!(!engine.readiness_check().await);

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: String = redis::cmd("SET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .arg(authority.as_slice())
        .query_async(&mut connection)
        .await
        .unwrap();
    let _: i64 = redis::cmd("DEL")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(engine.discovery_from_durable().await.is_err());
    assert!(!engine.readiness_check().await);

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: String = redis::cmd("SET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .arg(authority.as_slice())
        .query_async(&mut connection)
        .await
        .unwrap();
    let _: i64 = redis::cmd("EXPIRE")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .arg(60)
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(engine.discovery_from_durable().await.is_err());
    assert!(!engine.readiness_check().await);

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: i64 = redis::cmd("PERSIST")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(engine.discovery_from_durable().await.is_ok());
    assert!(engine.readiness_check().await);

    let scope =
        graph_issuance_api::decode_digest(&initial.replay_authority.v4_scope_digest_tombstones[0])
            .unwrap();
    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: i64 = redis::cmd("HSET")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .arg("not-hex")
        .arg(scope.as_slice())
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(engine.discovery_from_durable().await.is_err());
    assert!(!engine.readiness_check().await);

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: i64 = redis::cmd("HDEL")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .arg("not-hex")
        .query_async(&mut connection)
        .await
        .unwrap();
    let mismatched_field = hex::encode([0x73; 32]);
    let _: i64 = redis::cmd("HSET")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .arg(&mismatched_field)
        .arg("mismatched-value")
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(engine.discovery_from_durable().await.is_err());
    assert!(!engine.readiness_check().await);

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: i64 = redis::cmd("HDEL")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .arg(&mismatched_field)
        .query_async(&mut connection)
        .await
        .unwrap();
    let uppercase_field = hex::encode([0xaa; 32]).to_uppercase();
    let _: i64 = redis::cmd("HSET")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .arg(&uppercase_field)
        .arg("uppercase-value")
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(engine.discovery_from_durable().await.is_err());
    assert!(!engine.readiness_check().await);

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: i64 = redis::cmd("HDEL")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .arg(&uppercase_field)
        .query_async(&mut connection)
        .await
        .unwrap();
    let _: i64 = redis::cmd("DEL")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    // A missing hash is a syntactically valid durable container, but the
    // initialized V4 scope is no longer ready to consume replay markers.
    assert!(engine.discovery_from_durable().await.is_ok());
    assert!(!engine.readiness_check().await);
}

#[tokio::test]
async fn wrong_replay_authority_redis_types_fail_closed() {
    let Some(harness) = RedisHarness::start().unwrap() else {
        return;
    };
    let mut engine = durable_v4_engine(&harness.url).unwrap();

    let mut connection = redis::Client::open(harness.url.clone())
        .unwrap()
        .get_async_connection()
        .await
        .unwrap();
    let _: i64 = redis::cmd("HSET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .arg("wrong-type-field")
        .arg("wrong-type-value")
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);

    assert!(engine.initialize().await.is_err());
    assert!(engine.discovery_from_durable().await.is_err());
    assert!(!engine.readiness_check().await);

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
    let _: String = redis::cmd("SET")
        .arg(test_support::REPLAY_AUTHORITY_SCOPE_TOMBSTONES_KEY)
        .arg("wrong-tombstone-container-type")
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);

    assert!(engine.initialize().await.is_err());
    assert!(engine.discovery_from_durable().await.is_err());
    assert!(!engine.readiness_check().await);
}
