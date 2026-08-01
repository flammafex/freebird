// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::support::*;

pub(super) async fn cross_service_replay_authority_requires_the_same_redis_namespace() -> Result<()>
{
    let Some(mut issuer_redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let Some(mut different_redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let Some(mut cloned_redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(20)?;
    fixture.write_v4_local_policies()?;
    let server = start_server(fixture.config_v4_local(issuer_redis.url.clone())).await?;
    let client = reqwest::Client::new();
    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?
        .json()
        .await?;
    let scope = build_scope_digest(V4_ADMISSION_VERIFIER, V4_ADMISSION_AUDIENCE)
        .map_err(|error| anyhow::anyhow!("build replay scope: {error:?}"))?;

    let same_store = Arc::new(RedisStore::new(&issuer_redis.url)?);
    let same = ReplayAuthorityHealth::new(
        same_store,
        ReplayAuthorityConfig {
            graph_issuer_urls: vec![server.base.clone()],
            probe_interval: Duration::from_secs(30),
            max_staleness: Duration::from_secs(60),
        },
        scope,
    )?;
    same.update_discovery(&server.base, &discovery).await?;
    same.probe_all().await;
    assert!(same.healthy().await, "shared Redis must attest the issuer");
    assert!(same.allows_v4_replay(false).await);

    clone_replay_authority_state(&issuer_redis.url, &cloned_redis.url).await?;
    let different = ReplayAuthorityHealth::new(
        Arc::new(RedisStore::new(&different_redis.url)?),
        ReplayAuthorityConfig {
            graph_issuer_urls: vec![server.base.clone()],
            probe_interval: Duration::from_secs(30),
            max_staleness: Duration::from_secs(60),
        },
        scope,
    )?;
    different.update_discovery(&server.base, &discovery).await?;
    different.probe_all().await;
    assert!(!different.healthy().await);
    assert!(!different.allows_v4_replay(false).await);

    let cloned = ReplayAuthorityHealth::new(
        Arc::new(RedisStore::new(&cloned_redis.url)?),
        ReplayAuthorityConfig {
            graph_issuer_urls: vec![server.base.clone()],
            probe_interval: Duration::from_secs(30),
            max_staleness: Duration::from_secs(60),
        },
        scope,
    )?;
    cloned.update_discovery(&server.base, &discovery).await?;
    cloned.probe_all().await;
    assert!(!cloned.healthy().await);
    assert!(!cloned.allows_v4_replay(false).await);

    server.stop().await;
    issuer_redis.stop();
    different_redis.stop();
    cloned_redis.stop();
    Ok(())
}

pub(super) async fn v4_replay_authority_proof_and_staleness_gate_before_spend_mutation(
) -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(20)?;
    fixture.write_v4_local_policies()?;
    let issuer = start_server(fixture.config_v4_local(redis.url.clone())).await?;
    let client = reqwest::Client::new();
    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", issuer.base))
        .send()
        .await?
        .json()
        .await?;
    let scope = build_scope_digest(V4_ADMISSION_VERIFIER, V4_ADMISSION_AUDIENCE)
        .map_err(|error| anyhow::anyhow!("build replay scope: {error:?}"))?;
    let spend_store: Arc<dyn SpendStore> = Arc::new(RedisStore::new(&redis.url)?);
    let (bad_url, bad_task) = start_bad_replay_probe_server().await?;
    let bad = ReplayAuthorityHealth::new(
        Arc::clone(&spend_store),
        ReplayAuthorityConfig {
            graph_issuer_urls: vec![bad_url.clone()],
            probe_interval: Duration::from_secs(30),
            max_staleness: Duration::from_secs(60),
        },
        scope,
    )?;
    bad.update_discovery(&bad_url, &discovery).await?;
    bad.probe_all().await;
    assert!(!bad.healthy().await);
    assert!(!bad.allows_v4_replay(false).await);
    if bad.allows_v4_replay(false).await {
        anyhow::ensure!(
            spend_store
                .mark_spent("freebird:spent:v4:authority-gate", None)
                .await?,
            "unexpected replay marker result"
        );
    }
    assert!(
        redis_keys(&redis.url, "freebird:spent:v4:authority-gate")
            .await?
            .is_empty(),
        "failed proof must not reach V4 spend mutation"
    );
    bad_task.abort();

    let stale = ReplayAuthorityHealth::new(
        Arc::clone(&spend_store),
        ReplayAuthorityConfig {
            graph_issuer_urls: vec![issuer.base.clone()],
            probe_interval: Duration::from_secs(30),
            max_staleness: Duration::from_millis(1),
        },
        scope,
    )?;
    stale.update_discovery(&issuer.base, &discovery).await?;
    stale.probe_all().await;
    assert!(stale.healthy().await);
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!stale.healthy().await);
    assert!(!stale.allows_v4_replay(false).await);
    assert!(redis_keys(&redis.url, "freebird:spent:v4:authority-gate")
        .await?
        .is_empty());

    issuer.stop().await;
    redis.stop();
    Ok(())
}

pub(super) async fn retained_v4_scope_is_probed_after_policy_disable_and_removal() -> Result<()> {
    let Some(mut redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(20)?;
    fixture.write_v4_local_policies()?;
    let mut server = start_server(fixture.config_v4_local(redis.url.clone())).await?;
    let client = reqwest::Client::new();
    let scope = build_scope_digest(V4_ADMISSION_VERIFIER, V4_ADMISSION_AUDIENCE)
        .map_err(|error| anyhow::anyhow!("build replay scope: {error:?}"))?;

    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?
        .json()
        .await?;
    let retained = discovery
        .graph_issuance
        .as_ref()
        .context("graph issuance discovery missing")?
        .replay_authority
        .v4_scope_digest_tombstones
        .clone();
    assert!(retained.contains(&Base64UrlUnpadded::encode_string(&scope)));
    let first = ReplayAuthorityHealth::new(
        Arc::new(RedisStore::new(&redis.url)?),
        ReplayAuthorityConfig {
            graph_issuer_urls: vec![server.base.clone()],
            probe_interval: Duration::from_secs(30),
            max_staleness: Duration::from_secs(60),
        },
        scope,
    )?;
    first.update_discovery(&server.base, &discovery).await?;
    first.probe_all().await;
    assert!(first.healthy().await);

    server.stop().await;
    fixture.write_disabled_v4_policies()?;
    server = start_server(fixture.config_v4_local(redis.url.clone())).await?;
    let disabled: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?
        .json()
        .await?;
    assert!(disabled
        .graph_issuance
        .as_ref()
        .unwrap()
        .policies
        .iter()
        .all(|policy| policy.admission_state
            == freebird_common::api::ExchangeAdmissionStateV2::Disabled));
    assert!(disabled
        .graph_issuance
        .as_ref()
        .unwrap()
        .replay_authority
        .v4_scope_digest_tombstones
        .contains(&Base64UrlUnpadded::encode_string(&scope)));
    let disabled_health = ReplayAuthorityHealth::new(
        Arc::new(RedisStore::new(&redis.url)?),
        ReplayAuthorityConfig {
            graph_issuer_urls: vec![server.base.clone()],
            probe_interval: Duration::from_secs(30),
            max_staleness: Duration::from_secs(60),
        },
        scope,
    )?;
    disabled_health
        .update_discovery(&server.base, &disabled)
        .await?;
    disabled_health.probe_all().await;
    assert!(disabled_health.healthy().await);

    server.stop().await;
    fixture.write_removed_policies()?;
    server = start_server(fixture.config_v4_local(redis.url.clone())).await?;
    let removed: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", server.base))
        .send()
        .await?
        .json()
        .await?;
    assert!(removed
        .graph_issuance
        .as_ref()
        .context("removed-policy discovery missing")?
        .policies
        .is_empty());
    assert!(removed
        .graph_issuance
        .as_ref()
        .unwrap()
        .replay_authority
        .v4_scope_digest_tombstones
        .contains(&Base64UrlUnpadded::encode_string(&scope)));
    let removed_health = ReplayAuthorityHealth::new(
        Arc::new(RedisStore::new(&redis.url)?),
        ReplayAuthorityConfig {
            graph_issuer_urls: vec![server.base.clone()],
            probe_interval: Duration::from_secs(30),
            max_staleness: Duration::from_secs(60),
        },
        scope,
    )?;
    removed_health
        .update_discovery(&server.base, &removed)
        .await?;
    removed_health.probe_all().await;
    assert!(removed_health.healthy().await);

    server.stop().await;
    redis.stop();
    Ok(())
}

pub(super) async fn actual_verifier_single_and_batch_gate_v4_before_replay_mutation() -> Result<()>
{
    let Some(mut issuer_redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let Some(mut verifier_redis) = RedisHarness::start_if_available()? else {
        return Ok(());
    };
    let fixture = GraphFixture::new(20)?;
    fixture.write_v4_local_policies()?;
    let issuer_config = fixture.config_v4_local(issuer_redis.url.clone());
    write_secret(&issuer_config.key_config.sk_path, &VERIFIER_V4_SECRET)?;
    let issuer = start_server(issuer_config).await?;
    let client = reqwest::Client::new();
    let discovery: KeyDiscoveryResp = client
        .get(format!("{}/.well-known/keys", issuer.base))
        .send()
        .await?
        .json()
        .await?;
    let token = v4_admission_token(
        ISSUER_ID,
        &discovery.voprf.kid,
        V4_ADMISSION_VERIFIER,
        V4_ADMISSION_AUDIENCE,
        VERIFIER_V4_SECRET,
        [0xb1; 32],
    )?;
    let spend_key = v4_spend_from_token(&token)?;

    // The verifier's replay store has no authority identity or probe state in
    // common with the issuer. Both production HTTP handlers must gate before
    // touching this store.
    let unhealthy = start_verifier(&verifier_redis.url, &issuer.base, VERIFIER_V4_SECRET).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let single = client
        .post(format!("{}/v1/verify", unhealthy.base))
        .json(&serde_json::json!({"token_b64": token}))
        .send()
        .await?;
    assert_eq!(single.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let batch = client
        .post(format!("{}/v1/verify/batch", unhealthy.base))
        .json(&serde_json::json!({
            "tokens": [{"token_b64": token}]
        }))
        .send()
        .await?;
    assert_eq!(batch.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let mut verifier_connection = ::redis::Client::open(verifier_redis.url.clone())?
        .get_async_connection()
        .await?;
    assert!(
        ::redis::cmd("GET")
            .arg(&spend_key)
            .query_async::<_, Option<Vec<u8>>>(&mut verifier_connection)
            .await?
            .is_none(),
        "unhealthy authority must not mutate the single or batch replay marker"
    );
    drop(verifier_connection);
    unhealthy.stop();

    // With the shared Redis authority, readiness is initially healthy. Stop
    // the issuer and wait for the real background probe to make the authority
    // stale/unhealthy, then exercise both handlers again.
    let stale = start_verifier(&issuer_redis.url, &issuer.base, VERIFIER_V4_SECRET).await?;
    wait_for_verifier_status(&stale, "/ready", reqwest::StatusCode::OK).await?;
    issuer.stop().await;
    wait_for_verifier_status(&stale, "/ready", reqwest::StatusCode::SERVICE_UNAVAILABLE).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let stale_token = v4_admission_token(
        ISSUER_ID,
        &discovery.voprf.kid,
        V4_ADMISSION_VERIFIER,
        V4_ADMISSION_AUDIENCE,
        VERIFIER_V4_SECRET,
        [0xb2; 32],
    )?;
    let stale_spend_key = v4_spend_from_token(&stale_token)?;
    let stale_single = client
        .post(format!("{}/v1/verify", stale.base))
        .json(&serde_json::json!({"token_b64": stale_token}))
        .send()
        .await?;
    assert_eq!(
        stale_single.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let stale_batch = client
        .post(format!("{}/v1/verify/batch", stale.base))
        .json(&serde_json::json!({
            "tokens": [{"token_b64": stale_token}]
        }))
        .send()
        .await?;
    assert_eq!(
        stale_batch.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let mut issuer_connection = ::redis::Client::open(issuer_redis.url.clone())?
        .get_async_connection()
        .await?;
    assert!(
        ::redis::cmd("GET")
            .arg(&stale_spend_key)
            .query_async::<_, Option<Vec<u8>>>(&mut issuer_connection)
            .await?
            .is_none(),
        "stale authority must gate both handlers before replay mutation"
    );
    drop(issuer_connection);
    stale.stop();
    issuer_redis.stop();
    verifier_redis.stop();
    Ok(())
}
