// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::support::*;

pub(super) fn v2_graph_config_rejects_self_edges_and_conflicting_key_metadata() -> Result<()> {
    let fixture = GraphFixture::new(4)?;
    let mut self_edge = fixture.graph.clone();
    self_edge.transitions[0].target_keyset_id = self_edge.transitions[0].source_keyset_id.clone();
    self_edge.transitions[0].outputs[0].descriptor_id =
        self_edge.keysets[0].keys[0].descriptor.id.clone();
    self_edge.transitions[0].id = self_edge.transitions[0].canonical_id();
    self_edge.graph_id = self_edge.canonical_graph_id();
    assert!(self_edge
        .validate(ExchangeProfileValidationModeV2::Active, ISSUER_ID, None)
        .is_err());

    let mut conflicting = fixture.graph.clone();
    let mut duplicate = conflicting.keysets[0].keys[0].clone();
    duplicate.descriptor.audience = Some("conflicting-audience".into());
    duplicate.descriptor.id = duplicate.descriptor.canonical_id()?;
    conflicting.keysets[0].keys.push(duplicate);
    conflicting.keysets[0].id = conflicting.keysets[0].canonical_id();
    conflicting.graph_id = conflicting.canonical_graph_id();
    assert!(conflicting
        .validate(ExchangeProfileValidationModeV2::Active, ISSUER_ID, None)
        .is_err());
    Ok(())
}

pub(super) async fn disabled_v2_exchange_routes_are_generic_and_require_status_capability(
) -> Result<()> {
    use freebird_crypto::VOPRF_CONTEXT_V4;
    use freebird_issuer::{
        multi_key_voprf::MultiKeyVoprfCore,
        startup::{apply_public_layers, exchange_router},
        AppStateWithSybil,
    };
    use std::sync::Arc;

    let state = Arc::new(AppStateWithSybil {
        issuer_id: ISSUER_ID.into(),
        kid: "kid".into(),
        pubkey_b64: "public".into(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: None,
        invitation_system: None,
        public_issuer: None,
        exchange_engine: None,
        exchange_metadata: None,
        graph_issuance_engine: None,
        graph_issuance_metadata: None,
        epoch_duration_sec: 86_400,
        epoch_retention: 2,
        admin_api_key: None,
    });
    let voprf = Arc::new(MultiKeyVoprfCore::new(
        [7; 32],
        "public".into(),
        "kid".into(),
        VOPRF_CONTEXT_V4,
    )?);
    let app = apply_public_layers(exchange_router(64 * 1024, 5).with_state((state, voprf)))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let client = reqwest::Client::new();
    let capability = Base64UrlUnpadded::encode_string(&[9; 32]);
    let response = client
        .get(format!(
            "http://{address}/v2/public/exchange/status?public_operation_id={}",
            Base64UrlUnpadded::encode_string(&[1; 16])
        ))
        .header("exchange-status-capability", &capability)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.json::<serde_json::Value>().await?["error"],
        "exchange_unavailable"
    );

    let response = client
        .post(format!("http://{address}/v2/public/exchange"))
        .json(&serde_json::json!({}))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>().await?["error"],
        "invalid_status_capability"
    );
    task.abort();
    Ok(())
}

pub(super) async fn startup_characterizes_exchange_graph_modes_readiness_and_failure_precedence(
) -> Result<()> {
    let Some(redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(4)?;
    let client = reqwest::Client::new();

    let enabled = start_server(fixture.config(redis.url.clone())).await?;
    wait_for_issuer_status(
        &enabled,
        "/readyz",
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    let mut readiness = serde_json::Value::Null;
    for _ in 0..250 {
        readiness = client
            .get(format!("{}/admin/readiness", enabled.base))
            .header(
                "x-admin-key",
                "integration-admin-key-at-least-32-characters",
            )
            .send()
            .await?
            .json()
            .await?;
        if readiness["exchange"] == true && readiness["graph_issuance"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(readiness["exchange"], true);
    assert_eq!(readiness["graph_issuance"], true);
    assert_eq!(readiness["ready"], false);
    assert_eq!(readiness["redis"], false);
    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", enabled.base))
        .send()
        .await?
        .json()
        .await?;
    assert!(discovery.exchange.is_some());
    assert_eq!(
        discovery
            .graph_issuance
            .as_ref()
            .context("enabled graph issuance discovery missing")?
            .policies
            .len(),
        1
    );
    enabled.stop().await;

    let Some(mut exchange_redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let exchange_only =
        start_server(fixture.config_exchange_only(exchange_redis.url.clone())).await?;
    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", exchange_only.base))
        .send()
        .await?
        .json()
        .await?;
    assert!(discovery.exchange.is_some());
    assert_eq!(
        discovery
            .graph_issuance
            .as_ref()
            .context("disabled graph issuance discovery missing")?
            .policies
            .len(),
        0
    );
    let exchange_graph = discovery.exchange.as_ref().unwrap().active_graph.clone();
    let (disabled_request, _) = graph_issuance_request(
        &exchange_graph,
        &fixture.keys[0],
        [0x21; 16],
        [0x22; 32],
        [0x23; 32],
    )?;
    let response =
        post_graph_issuance(&client, &exchange_only.base, &disabled_request, &[0x24; 32]).await?;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    exchange_only.stop().await;
    exchange_redis.stop();

    let disabled = start_server(fixture.config_disabled()).await?;
    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", disabled.base))
        .send()
        .await?
        .json()
        .await?;
    assert!(discovery.exchange.is_none());
    assert!(discovery.graph_issuance.is_none());
    disabled.stop().await;

    // Exchange graph loading precedes Redis and policy/graph-issuance setup.
    // Both inputs are invalid, so the graph error is the frozen first failure.
    let mut graph_failure = fixture.config(redis.url.clone());
    graph_failure.exchange_config.active_graph_path =
        fixture._dir.path().join("missing-graph.json");
    graph_failure.exchange_config.graph_issuance.policy_path =
        fixture._dir.path().join("missing-policy.json");
    let error = match Application::build(graph_failure).await {
        Ok(_) => bail!("invalid exchange graph unexpectedly built"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("invalid active V2 exchange graph"),
        "{error}"
    );
    assert!(!error.contains("graph issuance policy"), "{error}");

    // With a valid graph and real Redis, the later policy-stage failure remains
    // distinct and is not reported as a bind or Redis startup error.
    let mut policy_failure = fixture.config(redis.url.clone());
    policy_failure.exchange_config.graph_issuance.policy_path =
        fixture._dir.path().join("missing-policy.json");
    let error = match Application::build(policy_failure).await {
        Ok(_) => bail!("missing graph policy unexpectedly built"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("graph issuance policy") || error.contains("No such file"),
        "{error}"
    );
    assert!(!error.contains("Failed to bind TCP listener"), "{error}");
    Ok(())
}

pub(super) async fn valid_exchange_graph_runtime_reaches_durable_state_before_occupied_bind(
) -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(4)?;
    let mut connection = ::redis::Client::open(redis.url.clone())?
        .get_async_connection()
        .await?;
    let authority_before: Option<Vec<u8>> = ::redis::cmd("GET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .query_async(&mut connection)
        .await?;
    let registry_before: HashMap<Vec<u8>, Vec<u8>> = ::redis::cmd("HGETALL")
        .arg("freebird:exchange:v2:key-registry:root")
        .query_async(&mut connection)
        .await?;
    assert!(authority_before.is_none());
    assert!(registry_before.is_empty());
    drop(connection);

    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut occupied = fixture.config(redis.url.clone());
    occupied.bind_addr = blocker.local_addr()?;
    let error = match Application::build(occupied).await {
        Ok(_) => bail!("occupied bind unexpectedly succeeded"),
        Err(error) => format!("{error:#}"),
    };
    assert!(error.contains("Failed to bind TCP listener"), "{error}");
    assert!(!error.contains("durability check failed"), "{error}");

    let mut connection = ::redis::Client::open(redis.url.clone())?
        .get_async_connection()
        .await?;
    let authority_after: Option<Vec<u8>> = ::redis::cmd("GET")
        .arg(REPLAY_AUTHORITY_ID_KEY)
        .query_async(&mut connection)
        .await?;
    let registry_after: HashMap<Vec<u8>, Vec<u8>> = ::redis::cmd("HGETALL")
        .arg("freebird:exchange:v2:key-registry:root")
        .query_async(&mut connection)
        .await?;
    assert!(authority_after.is_some_and(|authority| authority.len() == 32));
    assert!(!registry_after.is_empty());
    drop(connection);
    drop(blocker);
    redis.stop();
    Ok(())
}

pub(super) async fn startup_exchange_failure_precedence_isolated_by_redis() -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(4)?;
    redis_config_set(&redis.url, "appendfsync", "everysec").await?;
    let error = match Application::build(fixture.config(redis.url.clone())).await {
        Ok(_) => bail!("unsafe Redis durability unexpectedly built"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("exchange Redis durability check failed"),
        "{error}"
    );
    assert!(!error.contains("pending V2 exchange"), "{error}");
    redis.stop();

    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let pending_fixture = GraphFixture::new(4)?;
    seed_pending_exchange_record(&redis.url, &pending_fixture, [0x31; 16]).await?;
    let unavailable_fixture = GraphFixture::new(4)?;
    let error = match Application::build(unavailable_fixture.config(redis.url.clone())).await {
        Ok(_) => bail!("unavailable pending graph unexpectedly built"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("invalid pending V2 exchange graph references"),
        "{error}"
    );
    assert!(!error.contains("durability check failed"), "{error}");
    redis.stop();

    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let registry_fixture = GraphFixture::new(4)?;
    let initialized = Application::build(registry_fixture.config(redis.url.clone())).await?;
    drop(initialized);
    let conflicting_fixture = GraphFixture::new(4)?;
    let error = match Application::build(conflicting_fixture.config(redis.url.clone())).await {
        Ok(_) => bail!("conflicting durable registry unexpectedly built"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("V2 durable key registry conflicts with configured graph history"),
        "{error}"
    );
    assert!(
        !error.contains("disabled-publication acknowledgement"),
        "{error}"
    );
    redis.stop();

    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let acknowledgement_fixture = GraphFixture::new(4)?;
    let mut acknowledgement_failure = acknowledgement_fixture.config(redis.url.clone());
    acknowledgement_failure
        .exchange_config
        .disabled_publication_ack_paths = vec![acknowledgement_fixture
        ._dir
        .path()
        .join("missing-publication-ack.json")];
    let error = match Application::build(acknowledgement_failure).await {
        Ok(_) => bail!("missing publication acknowledgement unexpectedly built"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("disabled-publication acknowledgement"),
        "{error}"
    );
    assert!(!error.contains("graph issuance policy"), "{error}");
    redis.stop();

    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let policy_fixture = GraphFixture::new(4)?;
    let mut policy_failure = policy_fixture.config(redis.url.clone());
    policy_failure.exchange_config.graph_issuance.policy_path =
        policy_fixture._dir.path().join("missing-policy.json");
    let error = match Application::build(policy_failure).await {
        Ok(_) => bail!("missing graph policy unexpectedly built"),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        error.contains("missing-policy.json") || error.contains("No such file"),
        "{error}"
    );
    assert!(!error.contains("Failed to bind TCP listener"), "{error}");
    redis.stop();
    Ok(())
}

pub(super) async fn v2_graph_http_exchange_atomicity_binding_cycles_and_restart() -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let mut fixture = GraphFixture::new(4)?;
    let config = fixture.config(redis.url.clone());
    let server = start_server(config.clone()).await?;
    let client = reqwest::Client::new();

    let discovery_response = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?;
    assert_eq!(discovery_response.status(), reqwest::StatusCode::OK);
    let discovery_bytes = discovery_response.bytes().await?;
    let discovery_text = std::str::from_utf8(&discovery_bytes)?;
    for sensitive in [
        "private_key",
        "private_key_path",
        "redis_url",
        "status_capability",
        "source_artifact",
        "blinded_message",
    ] {
        assert!(!discovery_text.contains(sensitive));
    }
    assert!(!discovery_text.contains("\"authorization\":"));
    let issuer: KeyDiscoveryResp = serde_json::from_slice(&discovery_bytes)?;
    let trusted_keys = trusted_public_keys(ISSUER_ID, issuer.clone())?;
    let exchange = issuer
        .exchange
        .clone()
        .context("V2 exchange discovery missing")?;
    validate_exchange_discovery_v2(ISSUER_ID, &exchange).map_err(anyhow::Error::msg)?;
    assert_eq!(exchange.active_graph.profile_id, EXCHANGE_PROFILE_V2);
    assert_eq!(exchange.active_graph.transitions.len(), 4);
    assert_eq!(exchange.retained_graphs.len(), 1);
    assert_eq!(
        exchange.retained_graphs[0].graph_id,
        fixture.retained.graph_id
    );
    assert!(exchange
        .retained_graphs
        .iter()
        .flat_map(|graph| &graph.transitions)
        .all(|edge| edge.admission_state
            == freebird_common::api::ExchangeAdmissionStateV2::RecoveryOnly));
    assert_eq!(
        client
            .post(format!("{}/v1/public/exchange", server.base))
            .send()
            .await?
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    // Policy-authorized initial issuance creates the first artifact in keyset A without a source,
    // receipt, exchange spend key, or transition budget charge. The resulting artifact is then a
    // normal eligible source on A -> C.
    let issuance_discovery = issuer
        .graph_issuance
        .as_ref()
        .context("graph issuance discovery missing")?;
    assert_eq!(issuance_discovery.policies.len(), 1);
    assert_eq!(issuance_discovery.policies[0].quantity, 1);
    let (initial_request, initial_pending) = graph_issuance_request(
        &exchange.active_graph,
        &fixture.keys[0],
        [0x01; 16],
        [0x02; 32],
        [0x03; 32],
    )?;
    let initial_capability = [0x04; 32];
    let initial_response =
        post_graph_issuance(&client, &server.base, &initial_request, &initial_capability).await?;
    assert_eq!(initial_response.status(), reqwest::StatusCode::OK);
    assert_eq!(initial_response.headers()["cache-control"], "no-store");
    let initial_bytes = initial_response.bytes().await?.to_vec();
    let initial_text = std::str::from_utf8(&initial_bytes)?;
    assert!(!initial_text.contains(&initial_request.authorization));
    assert!(!initial_text.contains(&initial_request.blinded_message));
    let initial_result: GraphIssuanceResultV2 = serde_json::from_slice(&initial_bytes)?;
    assert_eq!(
        initial_result.request_digest,
        Base64UrlUnpadded::encode_string(&initial_request.request_digest()?)
    );
    let mut durable_connection = ::redis::Client::open(redis.url.clone())?
        .get_async_connection()
        .await?;
    let durable_record: std::collections::HashMap<Vec<u8>, Vec<u8>> = ::redis::cmd("HGETALL")
        .arg(format!("freebird:graph-issuance:v2:op:{}", "01".repeat(16)))
        .query_async(&mut durable_connection)
        .await?;
    let contains = |needle: &[u8]| {
        durable_record.iter().any(|(key, value)| {
            key.windows(needle.len()).any(|part| part == needle)
                || value.windows(needle.len()).any(|part| part == needle)
        })
    };
    assert!(!contains(initial_request.blinded_message.as_bytes()));
    assert!(!contains(initial_request.authorization.as_bytes()));
    assert!(!contains(
        Base64UrlUnpadded::encode_string(&initial_capability).as_bytes()
    ));
    assert!(!durable_record.contains_key(b"blinded_message".as_slice()));
    assert!(!durable_record.contains_key(b"authorization".as_slice()));
    drop(durable_connection);
    let initial_artifact =
        finalize_graph_issuance(&initial_result, initial_pending, &fixture.keys[0])?;
    let exact_retry =
        post_graph_issuance(&client, &server.base, &initial_request, &initial_capability).await?;
    assert_eq!(
        exact_retry.bytes().await?.as_ref(),
        initial_bytes.as_slice()
    );
    let mut changed_initial = initial_request.clone();
    changed_initial.authorization = Base64UrlUnpadded::encode_string(&[0x05; 32]);
    assert_eq!(
        post_graph_issuance(&client, &server.base, &changed_initial, &initial_capability,)
            .await?
            .status(),
        reqwest::StatusCode::CONFLICT
    );
    let status_url = format!(
        "{}/v1/public/graph/issue/status?public_operation_id={}",
        server.base, initial_request.public_operation_id
    );
    assert_eq!(
        client
            .get(&status_url)
            .header(
                "graph-issuance-status-capability",
                Base64UrlUnpadded::encode_string(&[0xff; 32]),
            )
            .send()
            .await?
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    for (index, mutate) in [
        |request: &mut GraphIssuanceRequestV2| request.issuance_policy_id = "wrong-policy".into(),
        |request: &mut GraphIssuanceRequestV2| request.graph_id = "a".repeat(64),
        |request: &mut GraphIssuanceRequestV2| request.keyset_id = "b".repeat(64),
        |request: &mut GraphIssuanceRequestV2| request.descriptor_id = "c".repeat(64),
        |request: &mut GraphIssuanceRequestV2| {
            request.blinded_message = Base64UrlUnpadded::encode_string(b"malformed")
        },
        |request: &mut GraphIssuanceRequestV2| {
            request.authorization = Base64UrlUnpadded::encode_string(&[7; 31])
        },
    ]
    .into_iter()
    .enumerate()
    {
        let mut invalid = initial_request.clone();
        invalid.public_operation_id = Base64UrlUnpadded::encode_string(&[0x20 + index as u8; 16]);
        mutate(&mut invalid);
        assert_eq!(
            post_graph_issuance(&client, &server.base, &invalid, &[0x30 + index as u8; 32],)
                .await?
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
    }
    let (issued_exchange, issued_pending) = request_from_discovery(
        &exchange.active_graph,
        2,
        initial_artifact,
        &fixture.keys[2],
        [0x06; 16],
        [0x07; 32],
    )?;
    let issued_exchange_response =
        post_exchange(&client, &server.base, &issued_exchange, &[0x08; 32]).await?;
    assert_eq!(issued_exchange_response.status(), reqwest::StatusCode::OK);
    let issued_exchange_response: ExchangeResponseV2 = issued_exchange_response.json().await?;
    let _ = finalize_output(&issued_exchange_response, issued_pending, &fixture.keys[2])?;

    // Direct V5 issuance remains isolated from every graph output key.
    assert_eq!(
        client
            .post(format!("{}/v1/public/issue", server.base))
            .json(&serde_json::json!({
                "blinded_msg_b64": initial_request.blinded_message,
                "token_key_id": initial_result.token_key_id
            }))
            .send()
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    // Concurrent reuse of one authorization has exactly one winner. A third unique claim reaches
    // the issuance budget; a fourth is rejected without charging any exchange budget.
    let (concurrent_a, _) = graph_issuance_request(
        &exchange.active_graph,
        &fixture.keys[0],
        [0x09; 16],
        [0x0a; 32],
        [0x0b; 32],
    )?;
    let (concurrent_b, _) = graph_issuance_request(
        &exchange.active_graph,
        &fixture.keys[0],
        [0x0c; 16],
        [0x0d; 32],
        [0x0b; 32],
    )?;
    let (concurrent_a_response, concurrent_b_response) = tokio::join!(
        post_graph_issuance(&client, &server.base, &concurrent_a, &[0x0e; 32]),
        post_graph_issuance(&client, &server.base, &concurrent_b, &[0x0f; 32]),
    );
    let concurrent_statuses = [
        concurrent_a_response?.status(),
        concurrent_b_response?.status(),
    ];
    assert_eq!(
        concurrent_statuses
            .iter()
            .filter(|status| **status == reqwest::StatusCode::OK)
            .count(),
        1
    );
    let (last_allowed, _) = graph_issuance_request(
        &exchange.active_graph,
        &fixture.keys[0],
        [0x10; 16],
        [0x11; 32],
        [0x12; 32],
    )?;
    assert_eq!(
        post_graph_issuance(&client, &server.base, &last_allowed, &[0x13; 32])
            .await?
            .status(),
        reqwest::StatusCode::OK
    );
    let (exhausted, _) = graph_issuance_request(
        &exchange.active_graph,
        &fixture.keys[0],
        [0x14; 16],
        [0x15; 32],
        [0x16; 32],
    )?;
    assert_eq!(
        post_graph_issuance(&client, &server.base, &exhausted, &[0x17; 32])
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    // The verifier and exchange must use one V5 spend namespace. The direct issuance key is also
    // a source-only graph alias with a longer validity, so verifier discovery must extend replay
    // retention through the graph's global identity horizon before writing the shared marker.
    let direct_spki = fixture.keys[3].pk.to_spki()?;
    let direct_key_id = token_key_id_from_spki(&direct_spki);
    let direct_metadata = issuer
        .public
        .iter()
        .find(|key| key.token_key_id == freebird_crypto::encode_token_key_id_hex(&direct_key_id))
        .context("direct V5 discovery key missing")?;
    let alias_metadata = exchange
        .active_graph
        .descriptors
        .iter()
        .find(|descriptor| {
            descriptor.token_key_id == freebird_crypto::encode_token_key_id_hex(&direct_key_id)
        })
        .context("source-only graph alias missing")?;
    let global_horizon = trusted_keys
        .get(&direct_key_id)
        .context("verifier did not trust direct V5 key")?
        .valid_until;
    assert!(direct_metadata.valid_until < alias_metadata.valid_until);
    assert_eq!(global_horizon, alias_metadata.valid_until);

    let verifier_first_artifact = mint_artifact(&fixture.keys[3], [0x0d; 32])?;
    let verifier_first_token =
        parse_public_bearer_pass(&Base64UrlUnpadded::decode_vec(&verifier_first_artifact)?)
            .map_err(|error| anyhow::anyhow!("parse verifier-first V5 token: {error:?}"))?;
    let verifier_spend_key = v5_spend_key(
        &nullifier_key_v5(&verifier_first_token)
            .map_err(|error| anyhow::anyhow!("derive verifier-first nullifier: {error:?}"))?,
    );
    let verifier_store = RedisStore::new(&redis.url)?;
    verifier_store.health_check().await?;
    assert!(
        verifier_store
            .mark_spent_through(&verifier_spend_key, global_horizon)
            .await?
    );
    let (verifier_first_exchange, _) = request_from_discovery(
        &exchange.active_graph,
        3,
        verifier_first_artifact,
        &fixture.keys[2],
        [0x0d; 16],
        [0x0e; 32],
    )?;
    assert_eq!(
        post_exchange(&client, &server.base, &verifier_first_exchange, &[0x0f; 32],)
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a verifier-first V5 replay marker must reject exchange of the same token"
    );

    // One source is raced over two independently authorized outgoing graph edges.
    let raced_artifact = mint_artifact(&fixture.keys[0], [0x11; 32])?;
    let (request_ab, _) = request_from_discovery(
        &exchange.active_graph,
        0,
        raced_artifact.clone(),
        &fixture.keys[1],
        [0x11; 16],
        [0x21; 32],
    )?;
    let (request_ac, _) = request_from_discovery(
        &exchange.active_graph,
        2,
        raced_artifact,
        &fixture.keys[2],
        [0x12; 16],
        [0x22; 32],
    )?;
    let capability_ab = [0x31; 32];
    let capability_ac = [0x32; 32];
    let (response_ab, response_ac) = tokio::join!(
        post_exchange(&client, &server.base, &request_ab, &capability_ab),
        post_exchange(&client, &server.base, &request_ac, &capability_ac),
    );
    let statuses = [response_ab?.status(), response_ac?.status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == reqwest::StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == reqwest::StatusCode::BAD_REQUEST)
            .count(),
        1
    );

    // Unknown edges and selector/artifact/output tampering fail before spending the source.
    let tamper_artifact = mint_artifact(&fixture.keys[0], [0x13; 32])?;
    let (valid_tamper_request, valid_tamper_pending) = request_from_discovery(
        &exchange.active_graph,
        2,
        tamper_artifact,
        &fixture.keys[2],
        [0x20; 16],
        [0x23; 32],
    )?;
    let mut tampered = Vec::new();
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.graph_id = "f".repeat(64);
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.transition_id = "e".repeat(64);
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.source_keyset_id = exchange.active_graph.transitions[1]
            .source_keyset_id
            .clone();
        value.sources[0].slot.keyset_id = value.source_keyset_id.clone();
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.target_keyset_id = exchange.active_graph.transitions[0]
            .target_keyset_id
            .clone();
        value.outputs[0].slot.keyset_id = value.target_keyset_id.clone();
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.sources[0].artifact = Base64UrlUnpadded::encode_string(b"tampered-source");
        value
    });
    tampered.push({
        let mut value = valid_tamper_request.clone();
        value.outputs[0].blinded_value = Base64UrlUnpadded::encode_string(b"tampered-output");
        value
    });
    for (index, mut request) in tampered.into_iter().enumerate() {
        request.public_operation_id = Base64UrlUnpadded::encode_string(&[0x30 + index as u8; 16]);
        assert_eq!(
            post_exchange(&client, &server.base, &request, &[0x40 + index as u8; 32])
                .await?
                .status(),
            reqwest::StatusCode::BAD_REQUEST
        );
    }
    let authorized_after_tamper =
        post_exchange(&client, &server.base, &valid_tamper_request, &[0x4f; 32]).await?;
    assert_eq!(
        authorized_after_tamper.status(),
        reqwest::StatusCode::OK,
        "400 responses on unauthorized/tampered edges must not spend the source"
    );
    let authorized_after_tamper: ExchangeResponseV2 = authorized_after_tamper.json().await?;
    let _ = finalize_output(
        &authorized_after_tamper,
        valid_tamper_pending,
        &fixture.keys[2],
    )?;

    // A -> B -> A can repeat without process restarts, but each edge has finite lifetime budget.
    let mut artifact_a = mint_artifact(&fixture.keys[0], [0x50; 32])?;
    let mut first_request = None;
    let mut first_capability = None;
    let mut first_response_bytes = None;
    let mut completed_cycles = 0usize;
    for cycle in 0..5u8 {
        let (request, pending) = request_from_discovery(
            &exchange.active_graph,
            0,
            artifact_a,
            &fixture.keys[1],
            [0x60 + cycle; 16],
            [0x70 + cycle; 32],
        )?;
        let capability = [0x80 + cycle; 32];
        let response = post_exchange(&client, &server.base, &request, &capability).await?;
        if response.status() == reqwest::StatusCode::BAD_REQUEST {
            break;
        }
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let bytes = response.bytes().await?.to_vec();
        let exchange_response: ExchangeResponseV2 = serde_json::from_slice(&bytes)?;
        exchange_response
            .receipt
            .validate_result(&exchange_response.result)?;
        let artifact_b = finalize_output(&exchange_response, pending, &fixture.keys[1])?;

        if first_request.is_none() {
            first_request = Some(request.clone());
            first_capability = Some(capability);
            first_response_bytes = Some(bytes.clone());
        }

        let (request_back, pending_back) = request_from_discovery(
            &exchange.active_graph,
            1,
            artifact_b,
            &fixture.keys[0],
            [0x90 + cycle; 16],
            [0xa0 + cycle; 32],
        )?;
        let response_back =
            post_exchange(&client, &server.base, &request_back, &[0xb0 + cycle; 32]).await?;
        assert_eq!(response_back.status(), reqwest::StatusCode::OK);
        let response_back: ExchangeResponseV2 = response_back.json().await?;
        artifact_a = finalize_output(&response_back, pending_back, &fixture.keys[0])?;
        completed_cycles += 1;
    }
    assert!((3..=4).contains(&completed_cycles));

    let first_request = first_request.context("cycle never committed")?;
    let first_capability = first_capability.unwrap();
    let first_response_bytes = first_response_bytes.unwrap();
    let first_response: ExchangeResponseV2 = serde_json::from_slice(&first_response_bytes)?;
    let original_request_digest = first_request.request_digest()?;
    let mut changed_request = first_request.clone();
    changed_request.outputs[0].blinded_value = Base64UrlUnpadded::encode_string(b"changed");
    assert_ne!(changed_request.request_digest()?, original_request_digest);
    assert_eq!(
        post_exchange(&client, &server.base, &changed_request, &first_capability)
            .await?
            .status(),
        reqwest::StatusCode::CONFLICT
    );

    // Exact idempotency, status authorization, malformed input, and no capability disclosure.
    let replay = post_exchange(&client, &server.base, &first_request, &first_capability).await?;
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    assert_eq!(
        replay.bytes().await?.as_ref(),
        first_response_bytes.as_slice()
    );
    let status_url = format!(
        "{}/v2/public/exchange/status?public_operation_id={}",
        server.base, first_request.public_operation_id
    );
    let status = client
        .get(&status_url)
        .header(
            "exchange-status-capability",
            Base64UrlUnpadded::encode_string(&first_capability),
        )
        .send()
        .await?;
    assert_eq!(status.status(), reqwest::StatusCode::OK);
    let status_bytes = status.bytes().await?;
    assert_eq!(status_bytes.as_ref(), first_response_bytes.as_slice());
    assert!(!std::str::from_utf8(&status_bytes)?.contains("status_capability"));
    assert_eq!(
        client
            .get(&status_url)
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[0xee; 32]),
            )
            .send()
            .await?
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .get(format!(
                "{}/v2/public/exchange/status?public_operation_id={}",
                server.base,
                Base64UrlUnpadded::encode_string(&[0xef; 16])
            ))
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[0xef; 32]),
            )
            .send()
            .await?
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .post(format!("{}/v2/public/exchange", server.base))
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[1; 32]),
            )
            .header("content-type", "application/json")
            .body("{")
            .send()
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .post(format!("{}/v2/public/exchange", server.base))
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[1; 16]),
            )
            .json(&first_request)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let mut duplicate_capability = reqwest::header::HeaderMap::new();
    duplicate_capability.append(
        "exchange-status-capability",
        Base64UrlUnpadded::encode_string(&first_capability).parse()?,
    );
    duplicate_capability.append(
        "exchange-status-capability",
        Base64UrlUnpadded::encode_string(&first_capability).parse()?,
    );
    assert_eq!(
        client
            .post(format!("{}/v2/public/exchange", server.base))
            .headers(duplicate_capability)
            .json(&first_request)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .get(format!("{}/v2/public/exchange/status", server.base))
            .header(
                "exchange-status-capability",
                Base64UrlUnpadded::encode_string(&[1; 32]),
            )
            .send()
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    // Result and receipt selectors/digests/signatures bind graph, edge, source, target and output.
    let mut result_mutations = Vec::new();
    for field in 0..5 {
        let mut value = first_response.result.clone();
        match field {
            0 => value.graph_id = "1".repeat(64),
            1 => value.transition_id = "2".repeat(64),
            2 => value.source_keyset_id = "3".repeat(64),
            3 => {
                value.target_keyset_id = "4".repeat(64);
                value.outputs[0].slot.keyset_id = value.target_keyset_id.clone();
            }
            _ => value.outputs[0].blind_signature = Base64UrlUnpadded::encode_string(&[5; 256]),
        }
        result_mutations.push(value);
    }
    assert!(result_mutations
        .iter()
        .all(|result| result.canonical_bytes().is_err()));

    let receipt_key = load_or_generate_receipt_key(&fixture.receipt_path)?;
    let receipt_signature = Base64UrlUnpadded::decode_vec(&first_response.receipt.signature)?;
    ReceiptKey::verify_receipt_v2(
        &first_response.receipt,
        &receipt_key.verifying_key(),
        &receipt_signature,
    )?;
    for field in 0..5 {
        let mut receipt = first_response.receipt.clone();
        match field {
            0 => receipt.graph_id = "1".repeat(64),
            1 => receipt.transition_id = "2".repeat(64),
            2 => receipt.source_keyset_id = "3".repeat(64),
            3 => receipt.target_keyset_id = "4".repeat(64),
            _ => receipt.result_digest = Base64UrlUnpadded::encode_string(&[5; 32]),
        }
        assert!(receipt.validate_result(&first_response.result).is_err());
        assert!(ReceiptKey::verify_receipt_v2(
            &receipt,
            &receipt_key.verifying_key(),
            &receipt_signature,
        )
        .is_err());
    }

    // Simulate a process crash plus durable Redis restart. Recovery-only state still serves the
    // exact committed operation, while refusing a new operation on the same edge.
    server.stop().await;
    redis.restart()?;
    fixture.write_recovery_only_graph()?;
    let restarted = start_server(fixture.config(redis.url.clone())).await?;
    let recovered =
        post_exchange(&client, &restarted.base, &first_request, &first_capability).await?;
    assert_eq!(recovered.status(), reqwest::StatusCode::OK);
    assert_eq!(
        recovered.bytes().await?.as_ref(),
        first_response_bytes.as_slice()
    );
    let recovered_initial = post_graph_issuance(
        &client,
        &restarted.base,
        &initial_request,
        &initial_capability,
    )
    .await?;
    assert_eq!(recovered_initial.status(), reqwest::StatusCode::OK);
    assert_eq!(
        recovered_initial.bytes().await?.as_ref(),
        initial_bytes.as_slice()
    );
    let (fresh_initial, _) = graph_issuance_request(
        &exchange.active_graph,
        &fixture.keys[0],
        [0xfa; 16],
        [0xfb; 32],
        [0xfc; 32],
    )?;
    assert_eq!(
        post_graph_issuance(&client, &restarted.base, &fresh_initial, &[0xfd; 32])
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    let recovery_discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", restarted.base))
        .send()
        .await?
        .json()
        .await?;
    let recovery_graph = recovery_discovery.exchange.unwrap().active_graph;
    assert!(recovery_graph.transitions.iter().all(|edge| {
        edge.admission_state == freebird_common::api::ExchangeAdmissionStateV2::RecoveryOnly
    }));
    let fresh_artifact = mint_artifact(&fixture.keys[0], [0xf1; 32])?;
    let (fresh_request, _) = request_from_discovery(
        &recovery_graph,
        0,
        fresh_artifact,
        &fixture.keys[1],
        [0xf1; 16],
        [0xf2; 32],
    )?;
    assert_eq!(
        post_exchange(&client, &restarted.base, &fresh_request, &[0xf3; 32])
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    restarted.stop().await;
    let mut disabled_policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.graph_issuance_policy_path)?)?;
    disabled_policy["policies"][0]["admission_state"] = serde_json::json!("disabled");
    std::fs::write(
        &fixture.graph_issuance_policy_path,
        serde_json::to_vec_pretty(&disabled_policy)?,
    )?;
    let disabled_server = start_server(fixture.config(redis.url.clone())).await?;
    let (disabled_fresh, _) = graph_issuance_request(
        &exchange.active_graph,
        &fixture.keys[0],
        [0xe1; 16],
        [0xe2; 32],
        [0xe3; 32],
    )?;
    assert_eq!(
        post_graph_issuance(&client, &disabled_server.base, &disabled_fresh, &[0xe4; 32],)
            .await?
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    disabled_server.stop().await;
    Ok(())
}

pub(super) fn discovery_constructor_is_public_only_and_sufficient_for_graph_clients() -> Result<()>
{
    let fixture = GraphFixture::new(4)?;
    let key = load_or_generate_receipt_key(&fixture.receipt_path)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let metadata = ExchangeReceiptKeyInfo {
        key_id: key.key_id(),
        algorithm: "Ed25519".into(),
        purpose: "exchange_receipt_active".into(),
        public_key_b64: Base64UrlUnpadded::encode_string(key.verifying_key().as_bytes()),
        valid_from: now - 60,
        valid_until: now + 3600,
    };
    let discovery: ExchangeDiscoveryV2 = exchange_discovery_v2(
        &fixture.graph,
        std::slice::from_ref(&fixture.retained),
        &[metadata],
    )?;
    validate_exchange_discovery_v2(ISSUER_ID, &discovery).map_err(anyhow::Error::msg)?;
    let json = serde_json::to_string(&discovery)?;
    assert!(!json.contains("private_key"));
    assert!(!json.contains("status_capability"));
    let (request, _) = request_from_discovery(
        &discovery.active_graph,
        0,
        mint_artifact(&fixture.keys[0], [7; 32])?,
        &fixture.keys[1],
        [8; 16],
        [9; 32],
    )?;
    assert!(request.validate().is_ok());
    Ok(())
}
