use super::*;
use crate::sybil_resistance::SybilResistance;
use std::sync::Mutex;

#[derive(Default)]
struct CountingChecker(Mutex<Vec<SybilRequestContext>>);

impl SybilResistance for CountingChecker {
    fn verify(&self, _: &SybilProof) -> anyhow::Result<()> {
        panic!("context required")
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

fn fixture(window: Option<(i64, i64)>) -> (StateTuple, Arc<CountingChecker>) {
    let checker = Arc::new(CountingChecker::default());
    let mut issuer = crate::main_state::test_native_bearer_v7();
    if let Some((from, until)) = window {
        Arc::get_mut(&mut issuer)
            .unwrap()
            .set_test_validity(from, until);
    }
    let state = Arc::new(AppStateWithSybil {
        issuer_id: "test-issuer".into(),
        kid: "test-kid".into(),
        pubkey_b64: String::new(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: Some(checker.clone()),
        invitation_system: None,
        native_bearer_v7: issuer,
        native_bearer_v7_retained: vec![],
        native_exchange_v7: None,
        native_exchange_v7_discovery: None,
        native_graph_issuance_v7: None,
        native_graph_issuance_v7_discovery: None,
        replay_authority: None,
        epoch_duration_sec: 86400,
        epoch_retention: 1,
        admin_api_key: None,
        sybil_summary: None,
    });
    let voprf = Arc::new(
        crate::multi_key_voprf::MultiKeyVoprfCore::new(
            [1; 32],
            String::new(),
            "test-kid".into(),
            b"test",
        )
        .unwrap(),
    );
    ((state, voprf), checker)
}

fn one() -> String {
    let mut bytes = [0; 384];
    bytes[383] = 1;
    Base64UrlUnpadded::encode_string(&bytes)
}

async fn invoke(
    state: &StateTuple,
    messages: Vec<String>,
    batch: bool,
) -> Result<Response, (StatusCode, String)> {
    let proof = Some(SybilProof::RegisteredUser {
        user_id: "test-user".into(),
    });
    let key = state.0.native_bearer_v7.metadata().token_key_id.clone();
    if batch {
        handle_batch(
            State(state.clone()),
            None,
            None,
            HeaderMap::new(),
            Json(NativeBearerV7BatchIssueReq {
                token_key_id: key,
                blinded_msgs_b64: messages,
                sybil_proof: proof,
            }),
        )
        .await
    } else {
        handle(
            State(state.clone()),
            None,
            None,
            HeaderMap::new(),
            Json(NativeBearerV7IssueReq {
                token_key_id: key,
                blinded_msg_b64: messages[0].clone(),
                sybil_proof: proof,
            }),
        )
        .await
    }
}

#[tokio::test]
async fn invalid_representatives_never_admit_or_sign() {
    let (state, checker) = fixture(None);
    let issuer = &state.0.native_bearer_v7;
    let key = blind_rsa_signatures::PublicKeySha384PSSRandomized::from_spki(
        issuer.binding().public_key_spki(),
    )
    .unwrap();
    let invalid = [
        Base64UrlUnpadded::encode_string(&[0; 384]),
        Base64UrlUnpadded::encode_string(&key.components().n()),
        Base64UrlUnpadded::encode_string(&[0xff; 384]),
        "malformed!".into(),
        Base64UrlUnpadded::encode_string(&[1; 383]),
    ];
    for value in invalid {
        for batch in [false, true] {
            // A valid prefix must not be signed/admitted before the invalid suffix.
            let messages = if batch {
                vec![one(), value.clone()]
            } else {
                vec![value.clone()]
            };
            assert_eq!(
                invoke(&state, messages, batch).await.unwrap_err(),
                invalid_message()
            );
            assert!(checker.0.lock().unwrap().is_empty());
            assert_eq!(issuer.inventory().active().sign_attempts(), 0);
        }
    }
}

#[tokio::test]
async fn unavailable_validity_never_admits_or_signs() {
    // Fixed windows are far outside the current epoch; no sleeps or boundary races.
    for window in [(1, 2), (i64::MAX - 1, i64::MAX)] {
        let (state, checker) = fixture(Some(window));
        for batch in [false, true] {
            let error = invoke(&state, vec![one(), one()], batch).await.unwrap_err();
            assert_eq!(
                error,
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "V7 signer temporarily unavailable".into()
                )
            );
            assert!(checker.0.lock().unwrap().is_empty());
            assert_eq!(
                state
                    .0
                    .native_bearer_v7
                    .inventory()
                    .active()
                    .sign_attempts(),
                0
            );
        }
    }
}

#[tokio::test]
async fn valid_single_and_batch_preserve_admission_binding_and_signing() {
    let (state, checker) = fixture(None);
    for batch in [false, true] {
        let messages = if batch {
            vec![one(), one()]
        } else {
            vec![one()]
        };
        let key = &state.0.native_bearer_v7.metadata().token_key_id;
        let expected = if batch {
            batch_request_binding(&state.0.issuer_id, key, &messages)
        } else {
            single_request_binding(&state.0.issuer_id, key, &messages[0])
        };
        let response = invoke(&state, messages, batch).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if batch {
            assert_eq!(value["successful"], 2);
            assert_eq!(value["failed"], 0);
            assert_eq!(value["blind_signatures_b64"].as_array().unwrap().len(), 2);
        } else {
            assert!(value["blind_signature_b64"].is_string());
        }
        let mut calls = checker.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].request_binding.as_deref(), Some(expected.as_str()));
        assert!(!calls[0].allow_registered_user);
        calls.clear();
    }
    assert_eq!(
        state
            .0
            .native_bearer_v7
            .inventory()
            .active()
            .sign_attempts(),
        3
    );
}
