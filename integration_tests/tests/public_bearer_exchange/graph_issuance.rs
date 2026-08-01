// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::support::*;

pub(super) async fn v4_local_graph_issuance_is_atomic_with_the_global_verifier_replay_marker(
) -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(20)?;
    fixture.write_v4_local_policies()?;
    let config = fixture.config_v4_local(redis.url.clone());

    let server = start_server(config.clone()).await?;
    let client = reqwest::Client::new();
    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?
        .json()
        .await?;
    let graph = discovery
        .exchange
        .as_ref()
        .context("V2 graph discovery missing")?
        .active_graph
        .clone();
    let issuance = discovery
        .graph_issuance
        .as_ref()
        .context("V4 graph issuance discovery missing")?;
    assert_eq!(issuance.policies.len(), 2);
    assert!(issuance
        .policies
        .iter()
        .all(|policy| policy.authorization_scheme == "v4_local"));
    let discovery_json = serde_json::to_string(&discovery)?;
    assert!(!discovery_json.contains(&Base64UrlUnpadded::encode_string(&V4_ADMISSION_SECRET)));
    assert!(!discovery_json.contains("secret_key"));
    assert!(!discovery_json.contains("trusted_issuers"));

    let credential = v4_admission_token(
        V4_ADMISSION_ISSUER,
        V4_ADMISSION_KID,
        V4_ADMISSION_VERIFIER,
        V4_ADMISSION_AUDIENCE,
        V4_ADMISSION_SECRET,
        [0x51; 32],
    )?;

    // Signing runs before reservation. Inject a signer failure with a malformed
    // RSA representative and prove that no credential, operation, or budget was
    // consumed before the request reached the atomic Redis reservation.
    let (mut signing_failure, _) = graph_issuance_request_with_authorization(
        &graph,
        &fixture.keys[0],
        [0x40; 16],
        [0x41; 32],
        "v4-bootstrap-one",
        v4_admission_token(
            V4_ADMISSION_ISSUER,
            V4_ADMISSION_KID,
            V4_ADMISSION_VERIFIER,
            V4_ADMISSION_AUDIENCE,
            V4_ADMISSION_SECRET,
            [0x42; 32],
        )?,
    )?;
    signing_failure.blinded_message =
        Base64UrlUnpadded::encode_string(b"not-an-rsa-representative");
    assert_eq!(
        post_graph_issuance(&client, &server.base, &signing_failure, &[0x43; 32])
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let mut failure_connection = ::redis::Client::open(redis.url.clone())?
        .get_async_connection()
        .await?;
    let failure_operation: Vec<Vec<u8>> = ::redis::cmd("HGETALL")
        .arg(format!("freebird:graph-issuance:v2:op:{}", "40".repeat(16)))
        .query_async(&mut failure_connection)
        .await?;
    assert!(failure_operation.is_empty());
    let failure_budget: Vec<Vec<u8>> = ::redis::cmd("HGETALL")
        .arg("freebird:graph-issuance:v2:budget:v4-bootstrap-budget-one")
        .query_async(&mut failure_connection)
        .await?;
    assert!(failure_budget.is_empty());
    assert!(::redis::cmd("GET")
        .arg(v4_spend_from_token(&signing_failure.authorization)?)
        .query_async::<_, Option<Vec<u8>>>(&mut failure_connection)
        .await?
        .is_none());
    drop(failure_connection);

    let (request, pending) = graph_issuance_request_with_authorization(
        &graph,
        &fixture.keys[0],
        [0x51; 16],
        [0x52; 32],
        "v4-bootstrap-one",
        credential.clone(),
    )?;
    let capability = [0x53; 32];
    let response = post_graph_issuance(&client, &server.base, &request, &capability).await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response_bytes = response.bytes().await?.to_vec();
    let result: GraphIssuanceResultV2 = serde_json::from_slice(&response_bytes)?;
    let artifact = finalize_graph_issuance(&result, pending, &fixture.keys[0])?;
    let exact_retry = post_graph_issuance(&client, &server.base, &request, &capability).await?;
    assert_eq!(exact_retry.status(), reqwest::StatusCode::OK);
    assert_eq!(
        exact_retry.bytes().await?.as_ref(),
        response_bytes.as_slice()
    );
    let changed_capability =
        post_graph_issuance(&client, &server.base, &request, &[0x54; 32]).await?;
    assert_eq!(changed_capability.status(), reqwest::StatusCode::CONFLICT);

    let mut connection = ::redis::Client::open(redis.url.clone())?
        .get_async_connection()
        .await?;
    let operation_record: std::collections::HashMap<Vec<u8>, Vec<u8>> = ::redis::cmd("HGETALL")
        .arg(format!("freebird:graph-issuance:v2:op:{}", "51".repeat(16)))
        .query_async(&mut connection)
        .await?;
    assert!(!operation_record.is_empty());
    assert!(!operation_record.iter().any(|(key, value)| {
        key.windows(credential.len())
            .any(|part| part == credential.as_bytes())
            || value
                .windows(credential.len())
                .any(|part| part == credential.as_bytes())
    }));
    let credential_bytes = Base64UrlUnpadded::decode_vec(&credential)?;
    let credential_token = parse_redemption_token(&credential_bytes)
        .map_err(|error| anyhow::anyhow!("parse V4 credential for inspection: {error:?}"))?;
    let credential_nullifier = nullifier_key_v4(
        &credential_token,
        V4_ADMISSION_VERIFIER,
        V4_ADMISSION_AUDIENCE,
    )
    .map_err(|error| anyhow::anyhow!("derive V4 credential nullifier: {error:?}"))?;
    let authorization_key = format!(
        "freebird:graph-issuance:v2:authorization:v4-bootstrap-one:{}",
        hex::encode(Base64UrlUnpadded::decode_vec(&credential_nullifier)?)
    );
    let inspection_keys = [
        format!("freebird:graph-issuance:v2:op:{}", "51".repeat(16)),
        "freebird:graph-issuance:v2:budget:v4-bootstrap-budget-one".into(),
        authorization_key,
        v4_spend_from_token(&credential)?,
    ];
    let mut inspected_material = Vec::new();
    for key in &inspection_keys {
        inspected_material.push(key.as_bytes().to_vec());
        if key.starts_with("freebird:spent:") {
            if let Some(value) = ::redis::cmd("GET")
                .arg(key)
                .query_async::<_, Option<Vec<u8>>>(&mut connection)
                .await?
            {
                inspected_material.push(value);
            }
        } else {
            let values: HashMap<Vec<u8>, Vec<u8>> = ::redis::cmd("HGETALL")
                .arg(key)
                .query_async(&mut connection)
                .await?;
            for (field, value) in values {
                inspected_material.push(field);
                inspected_material.push(value);
            }
        }
    }
    for material in &inspected_material {
        assert!(!material
            .windows(credential_bytes.len())
            .any(|window| window == credential_bytes.as_slice()));
        assert!(!material
            .windows(credential.len())
            .any(|window| window == credential.as_bytes()));
    }
    let marker: Option<String> = ::redis::cmd("GET")
        .arg(v4_spend_from_token(&credential)?)
        .query_async(&mut connection)
        .await?;
    assert_eq!(marker.as_deref(), Some("1"));
    drop(connection);

    let status = client
        .get(format!(
            "{}/v1/public/graph/issue/status?public_operation_id={}",
            server.base, request.public_operation_id
        ))
        .header(
            "graph-issuance-status-capability",
            Base64UrlUnpadded::encode_string(&capability),
        )
        .send()
        .await?;
    let status_bytes = status.bytes().await?;
    assert_eq!(status_bytes.as_ref(), response_bytes.as_slice());
    assert!(!std::str::from_utf8(&status_bytes)?.contains(&credential));

    for (index, policy) in ["v4-bootstrap-one", "v4-bootstrap-two"]
        .into_iter()
        .enumerate()
    {
        let (replay, _) = graph_issuance_request_with_authorization(
            &graph,
            &fixture.keys[0],
            [0x54 + index as u8; 16],
            [0x55 + index as u8; 32],
            policy,
            credential.clone(),
        )?;
        assert_eq!(
            post_graph_issuance(&client, &server.base, &replay, &[0x56 + index as u8; 32],)
                .await?
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
    }
    let verifier_store = RedisStore::new(&redis.url)?;
    // This is the issuance -> ordinary-verifier direction. The ordinary
    // verifier validates the credential and attempts the exact same global
    // marker, so it must reject the already-issued credential.
    assert!(!ordinary_v4_verify_and_consume(&verifier_store, &credential).await?);

    let verifier_first = v4_admission_token(
        V4_ADMISSION_ISSUER,
        V4_ADMISSION_KID,
        V4_ADMISSION_VERIFIER,
        V4_ADMISSION_AUDIENCE,
        V4_ADMISSION_SECRET,
        [0x60; 32],
    )?;
    // This is the ordinary-verifier -> issuance direction. A valid ordinary
    // verification consumes the marker before graph issuance sees it.
    assert!(ordinary_v4_verify_and_consume(&verifier_store, &verifier_first).await?);
    let (verifier_first_request, _) = graph_issuance_request_with_authorization(
        &graph,
        &fixture.keys[0],
        [0x60; 16],
        [0x61; 32],
        "v4-bootstrap-one",
        verifier_first,
    )?;
    assert_eq!(
        post_graph_issuance(&client, &server.base, &verifier_first_request, &[0x62; 32],)
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    let concurrent_credential = v4_admission_token(
        V4_ADMISSION_ISSUER,
        V4_ADMISSION_KID,
        V4_ADMISSION_VERIFIER,
        V4_ADMISSION_AUDIENCE,
        V4_ADMISSION_SECRET,
        [0x70; 32],
    )?;
    let (concurrent_a, _) = graph_issuance_request_with_authorization(
        &graph,
        &fixture.keys[0],
        [0x70; 16],
        [0x71; 32],
        "v4-bootstrap-one",
        concurrent_credential.clone(),
    )?;
    let (concurrent_b, _) = graph_issuance_request_with_authorization(
        &graph,
        &fixture.keys[0],
        [0x72; 16],
        [0x73; 32],
        "v4-bootstrap-two",
        concurrent_credential,
    )?;
    let (race_a, race_b) = tokio::join!(
        post_graph_issuance(&client, &server.base, &concurrent_a, &[0x74; 32]),
        post_graph_issuance(&client, &server.base, &concurrent_b, &[0x75; 32]),
    );
    let statuses = [race_a?.status(), race_b?.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == reqwest::StatusCode::OK)
            .count(),
        1
    );

    let mut wrong_scope_token =
        parse_redemption_token(&Base64UrlUnpadded::decode_vec(&credential)?).map_err(|error| {
            anyhow::anyhow!("parse V4 credential for scope mutation: {error:?}")
        })?;
    wrong_scope_token.scope_digest[0] ^= 1;
    let wrong_scope_bytes = build_redemption_token(&wrong_scope_token)
        .map_err(|error| anyhow::anyhow!("encode wrong-scope V4 credential: {error:?}"))?;
    let wrong_scope = Base64UrlUnpadded::encode_string(&wrong_scope_bytes);
    let mut forged_token = parse_redemption_token(&Base64UrlUnpadded::decode_vec(&credential)?)
        .map_err(|error| {
            anyhow::anyhow!("parse V4 credential for authenticator mutation: {error:?}")
        })?;
    forged_token.authenticator[0] ^= 1;
    let forged_bytes = build_redemption_token(&forged_token)
        .map_err(|error| anyhow::anyhow!("encode forged V4 credential: {error:?}"))?;
    let forged_authenticator = Base64UrlUnpadded::encode_string(&forged_bytes);
    for (index, invalid_credential) in [
        wrong_scope,
        v4_admission_token(
            V4_ADMISSION_ISSUER,
            V4_ADMISSION_KID,
            "verifier:wrong",
            V4_ADMISSION_AUDIENCE,
            V4_ADMISSION_SECRET,
            [0x80; 32],
        )?,
        v4_admission_token(
            V4_ADMISSION_ISSUER,
            V4_ADMISSION_KID,
            V4_ADMISSION_VERIFIER,
            "audience-wrong",
            V4_ADMISSION_SECRET,
            [0x81; 32],
        )?,
        v4_admission_token(
            "issuer:wrong",
            V4_ADMISSION_KID,
            V4_ADMISSION_VERIFIER,
            V4_ADMISSION_AUDIENCE,
            V4_ADMISSION_SECRET,
            [0x82; 32],
        )?,
        v4_admission_token(
            V4_ADMISSION_ISSUER,
            "kid-wrong",
            V4_ADMISSION_VERIFIER,
            V4_ADMISSION_AUDIENCE,
            V4_ADMISSION_SECRET,
            [0x83; 32],
        )?,
        forged_authenticator,
    ]
    .into_iter()
    .enumerate()
    {
        let (invalid, _) = graph_issuance_request_with_authorization(
            &graph,
            &fixture.keys[0],
            [0x80 + index as u8; 16],
            [0x84 + index as u8; 32],
            "v4-bootstrap-one",
            invalid_credential,
        )?;
        assert_eq!(
            post_graph_issuance(&client, &server.base, &invalid, &[0x88 + index as u8; 32],)
                .await?
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
    }

    server.stop().await;
    redis.restart()?;
    let restarted = start_server(config).await?;
    let recovered = post_graph_issuance(&client, &restarted.base, &request, &capability).await?;
    assert_eq!(recovered.status(), reqwest::StatusCode::OK);
    assert_eq!(recovered.bytes().await?.as_ref(), response_bytes.as_slice());

    let (exchange_request, exchange_pending) = request_from_discovery(
        &graph,
        2,
        artifact,
        &fixture.keys[2],
        [0x90; 16],
        [0x91; 32],
    )?;
    let exchange_response =
        post_exchange(&client, &restarted.base, &exchange_request, &[0x92; 32]).await?;
    assert_eq!(exchange_response.status(), reqwest::StatusCode::OK);
    let exchange_response: ExchangeResponseV2 = exchange_response.json().await?;
    let _ = finalize_output(&exchange_response, exchange_pending, &fixture.keys[2])?;
    restarted.stop().await;
    Ok(())
}

pub(super) async fn hmac_authorization_mutations_are_rejected_before_any_durable_state(
) -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(20)?;
    fixture.write_hmac_policies()?;
    let server = start_server(fixture.config_hmac(redis.url.clone())).await?;
    let client = reqwest::Client::new();
    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?
        .json()
        .await?;
    let graph = discovery
        .exchange
        .as_ref()
        .context("exchange discovery missing")?
        .active_graph
        .clone();
    let (base, _) =
        hmac_graph_issuance_request(&graph, &fixture.keys[0], [1; 16], [2; 32], "hmac-policy-a")?;

    let mut nonce_mutation = base.clone();
    nonce_mutation.public_operation_id = Base64UrlUnpadded::encode_string(&[3; 16]);
    let mut authorization = Base64UrlUnpadded::decode_vec(&nonce_mutation.authorization)?;
    authorization[0] ^= 1;
    nonce_mutation.authorization = Base64UrlUnpadded::encode_string(&authorization);

    let mut tag_mutation = base.clone();
    let mut authorization = Base64UrlUnpadded::decode_vec(&tag_mutation.authorization)?;
    authorization[32] ^= 1;
    tag_mutation.authorization = Base64UrlUnpadded::encode_string(&authorization);

    let mut policy_mutation = base.clone();
    policy_mutation.public_operation_id = Base64UrlUnpadded::encode_string(&[4; 16]);
    policy_mutation.issuance_policy_id = "hmac-policy-b".into();

    let mut request_mutation = base.clone();
    request_mutation.public_operation_id = Base64UrlUnpadded::encode_string(&[5; 16]);
    request_mutation.blinded_message = Base64UrlUnpadded::encode_string(&[0xaa; 32]);

    for request in [
        nonce_mutation,
        tag_mutation,
        policy_mutation,
        request_mutation,
    ] {
        assert_eq!(
            post_graph_issuance(&client, &server.base, &request, &[0x60; 32])
                .await?
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
    }
    assert!(
        redis_keys(&redis.url, "freebird:graph-issuance:v2:*")
            .await?
            .is_empty(),
        "authorization failures must be zero-state"
    );
    assert!(
        redis_keys(&redis.url, "freebird:spent:*").await?.is_empty(),
        "authorization failures must not create replay markers"
    );

    let valid_response = post_graph_issuance(&client, &server.base, &base, &[0x61; 32]).await?;
    assert_eq!(valid_response.status(), reqwest::StatusCode::OK);
    let result: GraphIssuanceResultV2 = valid_response.json().await?;
    result.validate_against(&base, &result.token_key_id)?;
    server.stop().await;
    redis.stop();
    Ok(())
}

pub(super) async fn graph_issuance_rejects_missing_signers_and_invalid_validity_without_authority_state(
) -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(20)?;
    let document: GraphIssuancePolicyDocument =
        serde_json::from_slice(&std::fs::read(&fixture.graph_issuance_policy_path)?)?;

    let mut missing_signer = fixture.graph.clone();
    missing_signer.keysets[0].keys[0].private_key_path = None;
    assert!(GraphIssuanceEngine::new(
        &missing_signer,
        std::slice::from_ref(&fixture.retained),
        document.clone(),
        &redis.url,
        Arc::new(DevelopmentMockAuthorizer),
    )
    .is_err());
    assert!(redis_keys(&redis.url, "freebird:graph-issuance:v2:*")
        .await?
        .is_empty());

    let mut invalid_validity = fixture.graph.clone();
    invalid_validity.keysets[0].keys[0].descriptor.valid_until =
        invalid_validity.keysets[0].keys[0].descriptor.valid_from;
    assert!(GraphIssuanceEngine::new(
        &invalid_validity,
        std::slice::from_ref(&fixture.retained),
        document,
        &redis.url,
        Arc::new(DevelopmentMockAuthorizer),
    )
    .is_err());
    let mut connection = ::redis::Client::open(redis.url.clone())?
        .get_async_connection()
        .await?;
    assert!(
        ::redis::cmd("GET")
            .arg(REPLAY_AUTHORITY_ID_KEY)
            .query_async::<_, Option<Vec<u8>>>(&mut connection)
            .await?
            .is_none(),
        "failed signer validation must not initialize replay authority"
    );
    drop(connection);
    redis.stop();
    Ok(())
}

pub(super) async fn redis_time_rejects_well_formed_future_and_expired_signer_windows_without_mutation(
) -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(20)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    for (index, (valid_from, valid_until)) in
        [(now + 3_600, now + 7_200), (now - 7_200, now - 3_600)]
            .into_iter()
            .enumerate()
    {
        let (graph, document) = retimed_graph_fixture(&fixture, valid_from, valid_until)?;
        let engine = GraphIssuanceEngine::new(
            &graph,
            std::slice::from_ref(&fixture.retained),
            document.clone(),
            &redis.url,
            Arc::new(DevelopmentMockAuthorizer),
        )?;
        let request = engine_request(
            &graph,
            &document,
            &fixture.keys[0],
            [0xa0 + index as u8; 16],
        )?;
        assert!(matches!(
            engine.process(&request, &[0xa1 + index as u8; 32]).await?,
            ProcessDecision::Rejected
        ));
        assert!(redis_keys(&redis.url, "freebird:graph-issuance:v2:*")
            .await?
            .is_empty());
        assert!(redis_keys(&redis.url, "freebird:spent:*").await?.is_empty());
    }
    redis.stop();
    Ok(())
}

pub(super) fn graph_issuance_result_requires_exact_quantity_digest_and_result_key() -> Result<()> {
    let request = GraphIssuanceRequestV2 {
        version: GRAPH_ISSUANCE_VERSION_V2,
        public_operation_id: Base64UrlUnpadded::encode_string(&[7; 16]),
        issuance_policy_id: "wire-policy".into(),
        graph_id: "1".repeat(64),
        keyset_id: "2".repeat(64),
        descriptor_id: "3".repeat(64),
        blinded_message: Base64UrlUnpadded::encode_string(&[4; 32]),
        authorization: Base64UrlUnpadded::encode_string(&[5; 64]),
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
        request_digest: Base64UrlUnpadded::encode_string(&request.request_digest()?),
        blind_signature: Base64UrlUnpadded::encode_string(&[9; 32]),
        result_digest: String::new(),
    };
    result.result_digest = Base64UrlUnpadded::encode_string(&result.calculated_result_digest()?);
    assert!(result.validate_against(&request, &"a".repeat(64)).is_ok());

    let mut quantity = result.clone();
    quantity.quantity = 2;
    assert!(quantity
        .validate_against(&request, &"a".repeat(64))
        .is_err());

    let mut request_digest = result.clone();
    request_digest.request_digest = Base64UrlUnpadded::encode_string(&[8; 32]);
    request_digest.result_digest =
        Base64UrlUnpadded::encode_string(&request_digest.calculated_result_digest()?);
    assert!(request_digest
        .validate_against(&request, &"a".repeat(64))
        .is_err());

    let mut result_key = result.clone();
    result_key.token_key_id = "b".repeat(64);
    result_key.result_digest =
        Base64UrlUnpadded::encode_string(&result_key.calculated_result_digest()?);
    assert!(result_key
        .validate_against(&request, &"a".repeat(64))
        .is_err());

    let mut digest = result;
    digest.result_digest = Base64UrlUnpadded::encode_string(&[0; 32]);
    assert!(digest.validate_against(&request, &"a".repeat(64)).is_err());
    Ok(())
}

pub(super) async fn raw_http_recovery_survives_policy_disable_and_removal_without_sdk_state(
) -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(20)?;
    let mut server = start_server(fixture.config(redis.url.clone())).await?;
    let client = reqwest::Client::new();
    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?
        .json()
        .await?;
    let graph = discovery
        .exchange
        .as_ref()
        .context("exchange discovery missing")?
        .active_graph
        .clone();
    let (request, _) =
        graph_issuance_request(&graph, &fixture.keys[0], [0x71; 16], [0x72; 32], [0x73; 32])?;
    let capability = [0x74; 32];
    let first = post_graph_issuance(&client, &server.base, &request, &capability).await?;
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let first_bytes = first.bytes().await?.to_vec();

    server.stop().await;
    fixture.write_disabled_v4_policies()?;
    server = start_server(fixture.config(redis.url.clone())).await?;
    let disabled_retry = post_graph_issuance(&client, &server.base, &request, &capability).await?;
    assert_eq!(disabled_retry.status(), reqwest::StatusCode::OK);
    assert_eq!(
        disabled_retry.bytes().await?.as_ref(),
        first_bytes.as_slice()
    );

    server.stop().await;
    fixture.write_removed_policies()?;
    server = start_server(fixture.config(redis.url.clone())).await?;
    let removed_retry = post_graph_issuance(&client, &server.base, &request, &capability).await?;
    assert_eq!(removed_retry.status(), reqwest::StatusCode::OK);
    assert_eq!(
        removed_retry.bytes().await?.as_ref(),
        first_bytes.as_slice()
    );

    server.stop().await;
    redis.stop();
    Ok(())
}
