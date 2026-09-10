use super::*;
use crate::sybil_resistance::SybilResistance;
use freebird_common::api::{BatchIssueReq, TokenResult};
use std::sync::Mutex;

#[derive(Default)]
struct CountingChecker(Mutex<Vec<SybilRequestContext>>);

impl SybilResistance for CountingChecker {
    fn verify(&self, _: &SybilProof) -> anyhow::Result<()> {
        panic!("handlers must supply request context")
    }
    fn verify_with_context(&self, _: &SybilProof, ctx: &SybilRequestContext) -> anyhow::Result<()> {
        self.0.lock().unwrap().push(ctx.clone());
        Ok(())
    }
    fn supports(&self, _: &SybilProof) -> bool {
        true
    }
    fn cost(&self) -> u64 {
        0
    }
}

fn fixture() -> (
    Arc<AppStateWithSybil>,
    Arc<MultiKeyVoprfCore>,
    Arc<CountingChecker>,
    String,
) {
    let checker = Arc::new(CountingChecker::default());
    let state = Arc::new(AppStateWithSybil {
        issuer_id: "test-issuer".into(),
        kid: "test-kid".into(),
        pubkey_b64: String::new(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: Some(checker.clone()),
        admission: Default::default(),
        invitation_system: None,
        native_bearer_v7: crate::main_state::test_native_bearer_v7(),
        native_bearer_v7_retained: vec![],
        native_exchange_v7: None,
        native_exchange_v7_discovery: None,
        native_graph_issuance_v7: None,
        native_graph_issuance_v7_discovery: None,
        replay_authority: None,
        epoch_duration_sec: 86400,
        epoch_retention: 1,
        admin_api_key: Some("admin-key".into()),
        sybil_summary: None,
    });
    let voprf = Arc::new(
        MultiKeyVoprfCore::new([1; 32], String::new(), "test-kid".into(), b"test").unwrap(),
    );
    let valid = Base64UrlUnpadded::encode_string(
        &freebird_crypto::Server::from_secret_key([1; 32], b"test")
            .unwrap()
            .public_key_sec1_compressed(),
    );
    (state, voprf, checker, valid)
}

fn proof() -> Option<SybilProof> {
    Some(SybilProof::RegisteredUser {
        user_id: "test-user".into(),
    })
}

#[tokio::test]
async fn saturated_admission_returns_503_for_v4_routes() {
    let (mut state, voprf, checker, valid) = fixture();
    Arc::get_mut(&mut state).unwrap().admission =
        crate::sybil_resistance::admission::AdmissionExecutor::new(0);
    for route in 0..3 {
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-key", "admin-key".parse().unwrap());
        let req = Json(IssueReq {
            blinded_element_b64: valid.clone(),
            ctx_b64: None,
            sybil_proof: proof(),
        });
        let error = match route {
            0 => handle(
                State((state.clone(), voprf.clone())),
                None,
                None,
                headers,
                req,
            )
            .await
            .unwrap_err(),
            1 => renew(
                State((state.clone(), voprf.clone())),
                None,
                None,
                headers,
                req,
            )
            .await
            .unwrap_err(),
            _ => crate::routes::batch_issue::handle_batch(
                State((state.clone(), voprf.clone())),
                None,
                None,
                headers,
                Json(BatchIssueReq {
                    blinded_elements: vec![valid.clone()],
                    ctx_b64: None,
                    sybil_proof: proof(),
                }),
            )
            .await
            .unwrap_err(),
        };
        assert_eq!(
            error,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Sybil resistance temporarily unavailable".into()
            )
        );
        assert!(checker.0.lock().unwrap().is_empty());
    }
}

fn malformed_inputs() -> Vec<String> {
    let mut invalid_x = [0xff; 33];
    invalid_x[0] = 2;
    vec![
        "invalid!".into(),
        Base64UrlUnpadded::encode_string(&[2; 32]),
        Base64UrlUnpadded::encode_string(&invalid_x),
        Base64UrlUnpadded::encode_string(&[0]), // SEC1 identity
        Base64UrlUnpadded::encode_string(&[0; 33]),
    ]
}

#[tokio::test]
async fn single_and_renew_preflight_before_admission() {
    let (state, voprf, checker, valid) = fixture();
    for renewal in [false, true] {
        let mut cases: Vec<_> = malformed_inputs().into_iter().map(|b| (b, None)).collect();
        cases.push((valid.clone(), Some("bad-context!".into())));
        for (blinded_element_b64, ctx_b64) in cases {
            let req = Json(IssueReq {
                blinded_element_b64,
                ctx_b64,
                sybil_proof: proof(),
            });
            let state = State((state.clone(), voprf.clone()));
            let mut headers = HeaderMap::new();
            headers.insert("x-admin-key", "admin-key".parse().unwrap());
            let result = if renewal {
                renew(state, None, None, headers, req).await
            } else {
                handle(state, None, None, headers, req).await
            };
            assert_eq!(result.unwrap_err().0, StatusCode::BAD_REQUEST);
            assert!(checker.0.lock().unwrap().is_empty());
        }
    }
    // Authentication retains precedence over malformed renewal inputs.
    assert_eq!(
        renew(
            State((state.clone(), voprf.clone())),
            None,
            None,
            HeaderMap::new(),
            Json(IssueReq {
                blinded_element_b64: "invalid!".into(),
                ctx_b64: None,
                sybil_proof: proof(),
            })
        )
        .await
        .unwrap_err()
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert!(checker.0.lock().unwrap().is_empty());

    // Valid inputs still reach admission and evaluation, for both entry points.
    for renewal in [false, true] {
        let req = Json(IssueReq {
            blinded_element_b64: valid.clone(),
            ctx_b64: Some(String::new()),
            sybil_proof: proof(),
        });
        let state = State((state.clone(), voprf.clone()));
        let mut headers = HeaderMap::new();
        headers.insert("x-admin-key", "admin-key".parse().unwrap());
        if renewal {
            let _ = renew(state, None, None, headers, req).await.unwrap();
        } else {
            let _ = handle(state, None, None, headers, req).await.unwrap();
        }
    }
    let calls = checker.0.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(!calls[0].allow_registered_user);
    assert!(calls[1].allow_registered_user);
}

#[tokio::test]
async fn batch_preflight_preserves_mixed_results_and_original_binding() {
    use crate::routes::batch_issue::{
        batch_request_binding, handle_batch, MIN_PARALLEL_BATCH_SIZE,
    };
    let (state, voprf, checker, valid) = fixture();
    for (blinded_elements, ctx_b64) in [
        (malformed_inputs(), None),
        (vec![valid.clone()], Some("bad-context!".into())),
    ] {
        let error = handle_batch(
            State((state.clone(), voprf.clone())),
            None,
            None,
            HeaderMap::new(),
            Json(BatchIssueReq {
                blinded_elements,
                ctx_b64,
                sybil_proof: proof(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(checker.0.lock().unwrap().is_empty());
    }
    // Cover sequential and concurrent processing, with successes between errors.
    for size in [3, MIN_PARALLEL_BATCH_SIZE + 1] {
        let invalid = malformed_inputs();
        let elements: Vec<_> = (0..size)
            .map(|i| {
                if i % 2 == 1 {
                    valid.clone()
                } else {
                    invalid[(i / 2) % invalid.len()].clone()
                }
            })
            .collect();
        let expected_binding = batch_request_binding("issue-batch", &state.issuer_id, &elements);
        let response = handle_batch(
            State((state.clone(), voprf.clone())),
            None,
            None,
            HeaderMap::new(),
            Json(BatchIssueReq {
                blinded_elements: elements,
                ctx_b64: None,
                sybil_proof: proof(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(response.results.len(), size);
        assert_eq!(response.successful, size / 2);
        assert_eq!(response.failed, size - size / 2);
        for (i, result) in response.results.iter().enumerate() {
            assert_eq!(matches!(result, TokenResult::Success { .. }), i % 2 == 1);
            if i % 2 == 0 {
                assert!(matches!(result, TokenResult::Error { .. }));
            }
        }
        let mut calls = checker.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].request_binding.as_deref(),
            Some(expected_binding.as_str())
        );
        calls.clear();
    }
}
