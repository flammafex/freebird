use super::*;
use axum::{extract::State, http::HeaderMap, http::StatusCode, Json};
use freebird_common::api::{
    BatchIssueReq, IssueReq, NativeBearerV7BatchIssueReq, NativeBearerV7IssueReq,
};

async fn blocked_save_fixture() -> (tempfile::TempDir, Arc<InvitationSystem>, SybilProof) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-invitations.json");
    let system = Arc::new(InvitationSystem::new(
        SigningKey::random(&mut OsRng),
        InvitationConfig {
            persistence_path: path.clone(),
            autosave_interval_secs: 0,
            invite_cooldown_secs: 0,
            new_user_can_invite_after_secs: 0,
            ..Default::default()
        },
    ));
    system.add_bootstrap_user("admin".into(), 10).await;
    let (code, signature, _) = system.generate_invite("admin").await.unwrap();
    system.save().await.unwrap();
    // A directory at the temporary file target deterministically fails the write
    // before rename, even when the tests run with elevated permissions.
    std::fs::create_dir(path.with_extension("tmp")).unwrap();
    let proof = SybilProof::Invitation {
        code,
        signature: Base64UrlUnpadded::encode_string(&signature),
    };
    (dir, system, proof)
}

async fn assert_consumed(system: &InvitationSystem, proof: &SybilProof) {
    let SybilProof::Invitation { code, .. } = proof else {
        panic!("invitation expected")
    };
    let details = system.get_invitation_details(code).await.unwrap();
    assert!(details.redeemed());
    assert!(details.invitee_id().is_some());
    assert!(*system.dirty.read().await);
    // A retry cannot redeem again, even though the disk still has the old state.
    let retry = system.verify(proof).unwrap_err();
    assert!(!retry.is::<InvitationRedemptionPersistenceError>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_verification_paths_fail_closed_on_redemption_save_failure() {
    for with_context in [false, true] {
        let (dir, system, proof) = blocked_save_fixture().await;
        let path = dir.path().join("private-invitations.json");
        let before = std::fs::read(&path).unwrap();
        let result = if with_context {
            system.verify_with_context(&proof, &SybilRequestContext::default())
        } else {
            system.verify(&proof)
        };
        let error = result.unwrap_err();
        assert!(error.is::<InvitationRedemptionPersistenceError>());
        assert!(format!("{error:#}").contains("write temp file"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_consumed(&system, &proof).await;
    }
}

fn app_state(system: Arc<InvitationSystem>) -> Arc<crate::AppStateWithSybil> {
    Arc::new(crate::AppStateWithSybil {
        issuer_id: "test-issuer".into(),
        kid: "test-kid".into(),
        pubkey_b64: String::new(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: Some(system.clone()),
        invitation_system: Some(system),
        native_bearer_v7: crate::main_state::test_native_bearer_v7(),
        native_bearer_v7_retained: vec![],
        native_exchange_v7: None,
        native_exchange_v7_discovery: None,
        native_graph_issuance_v7: None,
        native_graph_issuance_v7_discovery: None,
        replay_authority: None,
        epoch_duration_sec: 86400,
        epoch_retention: 1,
        admin_api_key: Some("test-admin-key".into()),
        sybil_summary: None,
    })
}

fn assert_unavailable(error: (StatusCode, String)) {
    assert_eq!(
        error,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Sybil resistance temporarily unavailable".into()
        )
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuance_routes_fail_closed_on_redemption_save_failure() {
    let voprf = Arc::new(
        crate::multi_key_voprf::MultiKeyVoprfCore::new(
            [1; 32],
            String::new(),
            "test-kid".into(),
            b"test",
        )
        .unwrap(),
    );
    // Reuse the signing-key fixture, but give each call a fresh invitation system.
    let (_dir, initial_system, _) = blocked_save_fixture().await;
    let initial_state = app_state(initial_system);
    for route in 0..4 {
        let (_dir, system, proof) = blocked_save_fixture().await;
        let mut state = (*initial_state).clone();
        state.sybil_checker = Some(system.clone());
        state.invitation_system = Some(system.clone());
        let state = State((Arc::new(state), voprf.clone()));
        let mut v7_representative = [0; 384];
        v7_representative[383] = 1;
        let error = match route {
            0 => crate::routes::issue::handle(
                state,
                None,
                None,
                HeaderMap::new(),
                Json(IssueReq {
                    blinded_element_b64: Base64UrlUnpadded::encode_string(
                        &freebird_crypto::Server::from_secret_key([1; 32], b"test")
                            .unwrap()
                            .public_key_sec1_compressed(),
                    ),
                    ctx_b64: None,
                    sybil_proof: Some(proof.clone()),
                }),
            )
            .await
            .unwrap_err(),
            1 => crate::routes::batch_issue::handle_batch(
                state,
                None,
                None,
                HeaderMap::new(),
                Json(BatchIssueReq {
                    blinded_elements: vec![Base64UrlUnpadded::encode_string(
                        &freebird_crypto::Server::from_secret_key([1; 32], b"test")
                            .unwrap()
                            .public_key_sec1_compressed(),
                    )],
                    ctx_b64: None,
                    sybil_proof: Some(proof.clone()),
                }),
            )
            .await
            .unwrap_err(),
            2 => crate::routes::native_bearer_v7::handle(
                state,
                None,
                None,
                HeaderMap::new(),
                Json(NativeBearerV7IssueReq {
                    token_key_id: "01".repeat(32),
                    blinded_msg_b64: Base64UrlUnpadded::encode_string(&v7_representative),
                    sybil_proof: Some(proof.clone()),
                }),
            )
            .await
            .unwrap_err(),
            _ => crate::routes::native_bearer_v7::handle_batch(
                state,
                None,
                None,
                HeaderMap::new(),
                Json(NativeBearerV7BatchIssueReq {
                    token_key_id: "01".repeat(32),
                    blinded_msgs_b64: vec![Base64UrlUnpadded::encode_string(&v7_representative)],
                    sybil_proof: Some(proof.clone()),
                }),
            )
            .await
            .unwrap_err(),
        };
        assert_unavailable(error);
        assert_consumed(&system, &proof).await;
    }
}

#[test]
fn shared_issuance_and_renewal_error_mapping_is_typed_and_generic() {
    use crate::routes::issue::sybil_verification_error;
    let storage_error = anyhow::anyhow!("private-storage-path: permission denied")
        .context(InvitationRedemptionPersistenceError)
        .context("outer verification context");
    assert_unavailable(sybil_verification_error(&storage_error));
    // Ordinary invalid proofs remain forbidden; classification is not string-based.
    let invalid_proof = anyhow::anyhow!("invitation redemption persistence unavailable");
    assert_eq!(
        sybil_verification_error(&invalid_proof),
        (
            StatusCode::FORBIDDEN,
            "Sybil resistance verification failed".into(),
        )
    );
}
