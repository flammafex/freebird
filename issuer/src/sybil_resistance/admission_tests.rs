use super::*;

#[test]
fn threshold_preserves_typed_replay_unavailability() {
    struct Unavailable;
    impl SybilResistance for Unavailable {
        fn verify(&self, _: &SybilProof) -> Result<()> {
            Err(anyhow::anyhow!("private Redis error").context(AdmissionUnavailable))
        }
        fn supports(&self, _: &SybilProof) -> bool {
            true
        }
        fn cost(&self) -> u64 {
            0
        }
    }
    let checker =
        crate::sybil_resistance::CombinedThreshold::new(vec![Arc::new(Unavailable)], 1).unwrap();
    let proof = SybilProof::Multi {
        proofs: vec![SybilProof::RegisteredUser {
            user_id: "test".into(),
        }],
    };
    assert!(checker
        .verify(&proof)
        .unwrap_err()
        .is::<AdmissionUnavailable>());
    assert!(checker
        .verify_with_context(&proof, &SybilRequestContext::default())
        .unwrap_err()
        .is::<AdmissionUnavailable>());
}

#[tokio::test]
async fn cancellation_keeps_capacity_until_work_finishes() {
    let executor = AdmissionExecutor::new(1);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let work = executor.clone();
    let request = tokio::spawn(async move {
        work.run(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(())
        })
        .await
    });
    started_rx.await.unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    let error = executor
        .run::<(), _>(|| panic!("saturated work must not be queued"))
        .await
        .unwrap_err();
    assert!(error.is::<AdmissionUnavailable>());
    assert_eq!(
        crate::routes::issue::sybil_verification_error(&error),
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "Sybil resistance temporarily unavailable".into()
        )
    );
    release_tx.send(()).unwrap();
    let permit = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        executor.permits.clone().acquire_owned(),
    )
    .await
    .unwrap()
    .unwrap();
    drop(permit);
    executor.run(|| Ok(())).await.unwrap();
}

#[tokio::test]
async fn task_failure_is_availability_but_duplicate_is_not() {
    let executor = AdmissionExecutor::new(1);
    let error = executor
        .run::<(), _>(|| panic!("private task details"))
        .await
        .unwrap_err();
    assert!(error.is::<AdmissionUnavailable>());
    assert_eq!(
        crate::routes::issue::sybil_verification_error(&error).0,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    let duplicate = executor
        .run::<(), _>(|| Err(anyhow::anyhow!("Sybil proof already used")))
        .await
        .unwrap_err();
    assert!(!duplicate.is::<AdmissionUnavailable>());
    assert_eq!(
        crate::routes::issue::sybil_verification_error(&duplicate),
        (
            axum::http::StatusCode::FORBIDDEN,
            "Sybil resistance verification failed".into()
        )
    );
}
