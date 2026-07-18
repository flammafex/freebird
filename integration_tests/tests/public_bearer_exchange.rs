// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSDeterministic};
use freebird_common::api::{
    ExchangeDescriptorInfo, ExchangeDiscoveryInfo, ExchangePublicHistory, ExchangeReceiptKeyInfo,
    ExchangeTargetKeysetInfo, KeyDiscoveryResp, PublicIssueReq, PublicKeyInfo, VoprfKeyInfo,
};
use freebird_crypto::provider::BlindRsaProvider;
use freebird_crypto::{
    build_public_bearer_message_from_parts, build_public_bearer_pass, nullifier_key_v5,
    token_key_id_from_spki, PublicBearerPass, VOPRF_CONTEXT_V4,
};
use freebird_issuer::{
    config::PublicKeyConfig,
    exchange::{load_or_generate_receipt_key, ReceiptKey},
    multi_key_voprf::MultiKeyVoprfCore,
    public_tokens::PublicTokenIssuer,
    routes::public_issue,
    startup::{apply_public_layers, exchange_router},
    AppStateWithSybil,
};
use freebird_verifier::{
    discovery::trusted_public_keys,
    routes::admin::IssuerInfo,
    store::{InMemoryStore, SpendStore},
    verify::verify_v5_public_token,
};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::test]
async fn legacy_issuance_cannot_mint_a_historical_exchange_target() -> Result<()> {
    const ISSUER: &str = "issuer:test:historical-target";
    let dir = tempfile::tempdir()?;
    let legacy_issuer = Arc::new(
        PublicTokenIssuer::load_or_generate(
            &PublicKeyConfig {
                enabled: true,
                sk_path: dir.path().join("legacy.der"),
                metadata_path: dir.path().join("legacy.json"),
                validity_secs: 3600,
                audience: None,
                modulus_bits: 2048,
            },
            ISSUER,
        )?
        .unwrap(),
    );
    let target = freebird_crypto::provider::software::SoftwareBlindRsaProvider::generate(2048)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut descriptor = ExchangeDescriptorInfo {
        descriptor_id: String::new(),
        keyset_id: String::new(),
        purpose: "exchange_target".into(),
        profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
        role: "target".into(),
        issuer_id: ISSUER.into(),
        class: "target".into(),
        token_key_id: freebird_crypto::encode_token_key_id_hex(target.token_key_id()),
        pubkey_spki_b64: Base64UrlUnpadded::encode_string(target.public_key_spki()),
        suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
        valid_from: now - 60,
        valid_until: now + 3600,
        max_quantity: 1,
        audience: None,
    };
    descriptor.descriptor_id = descriptor.canonical_descriptor_id().unwrap();
    let mut keyset = ExchangeTargetKeysetInfo {
        keyset_id: String::new(),
        descriptor_ids: vec![descriptor.descriptor_id.clone()],
    };
    keyset.keyset_id = keyset.canonical_keyset_id();
    descriptor.keyset_id = keyset.keyset_id.clone();
    let history = ExchangePublicHistory {
        target_keysets: vec![keyset],
        target_descriptors: vec![descriptor.clone()],
        receipt_keys: vec![],
    };
    let legacy_spki = Base64UrlUnpadded::decode_vec(&legacy_issuer.metadata().pubkey_spki_b64)?;
    freebird_issuer::exchange::history::validate_public_history(
        &history,
        ISSUER,
        Some(&legacy_spki),
    )?;

    let state = Arc::new(AppStateWithSybil {
        issuer_id: ISSUER.into(),
        kid: "kid".into(),
        pubkey_b64: "public".into(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: None,
        invitation_system: None,
        public_issuer: Some(legacy_issuer),
        exchange_engine: None,
        exchange_metadata: None,
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
    let error = public_issue::handle(
        axum::extract::State((state, voprf)),
        None,
        None,
        axum::http::HeaderMap::new(),
        axum::Json(PublicIssueReq {
            blinded_msg_b64: "AA".into(),
            token_key_id: Some(descriptor.token_key_id),
            sybil_proof: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(error.0, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(error.1, "requested token_key_id is not active");
    Ok(())
}

async fn disabled_exchange_server() -> Result<(String, tokio::task::JoinHandle<()>)> {
    let state = Arc::new(AppStateWithSybil {
        issuer_id: "issuer:test:http-exchange".into(),
        kid: "kid".into(),
        pubkey_b64: "public".into(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: None,
        invitation_system: None,
        public_issuer: None,
        exchange_engine: None,
        exchange_metadata: None,
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
    let app = exchange_router(64 * 1024, 5).with_state((state, voprf));
    let app = apply_public_layers(app)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Ok((format!("http://{address}"), task))
}

#[tokio::test]
async fn exchange_http_capability_errors_are_generic_and_no_store() -> Result<()> {
    let (base, task) = disabled_exchange_server().await?;
    let client = reqwest::Client::new();
    let capability = Base64UrlUnpadded::encode_string(&[9; 16]);
    let response = client
        .get(format!("{base}/v1/public/exchange/status"))
        .header("idempotency-key", &capability)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.json::<serde_json::Value>().await?["error"],
        "exchange_unavailable"
    );

    let mut duplicate = reqwest::header::HeaderMap::new();
    duplicate.append("idempotency-key", capability.parse()?);
    duplicate.append("idempotency-key", capability.parse()?);
    let response = client
        .post(format!("{base}/v1/public/exchange"))
        .headers(duplicate)
        .json(&serde_json::json!({}))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.json::<serde_json::Value>().await?["error"],
        "invalid_idempotency_key"
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn exchange_output_and_retired_public_history_verify_and_spend_once() -> Result<()> {
    const ISSUER: &str = "issuer:test:exchange-output";
    const AUDIENCE: &str = "exchange-audience";
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut rng = DefaultRng;
    let exchange_key = KeyPairSha384PSSDeterministic::generate(&mut rng, 2048)?;
    let exchange_spki = exchange_key.pk.to_spki()?;
    let exchange_kid = token_key_id_from_spki(&exchange_spki);
    let nonce = [0x71; 32];
    let message = build_public_bearer_message_from_parts(&nonce, &exchange_kid, ISSUER)
        .map_err(|error| anyhow::anyhow!("build exchange output message: {error:?}"))?;
    let blinding = exchange_key.pk.blind(&mut rng, message)?;
    let exchange_blind_signature = exchange_key.sk.blind_sign(&blinding.blind_message)?;
    let finalized = exchange_key
        .pk
        .finalize(&exchange_blind_signature, &blinding, message)?;
    let artifact = PublicBearerPass {
        nonce,
        token_key_id: exchange_kid,
        issuer_id: ISSUER.into(),
        signature: finalized.0,
    };
    let artifact_b64 = Base64UrlUnpadded::encode_string(
        &build_public_bearer_pass(&artifact)
            .map_err(|error| anyhow::anyhow!("build exchange output artifact: {error:?}"))?,
    );

    let legacy_key = KeyPairSha384PSSDeterministic::generate(&mut rng, 2048)?;
    let legacy_spki = legacy_key.pk.to_spki()?;
    let legacy_kid = token_key_id_from_spki(&legacy_spki);
    let mut descriptor = ExchangeDescriptorInfo {
        descriptor_id: String::new(),
        keyset_id: String::new(),
        purpose: "exchange_target".into(),
        profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
        role: "target".into(),
        issuer_id: ISSUER.into(),
        class: "exchange".into(),
        token_key_id: freebird_crypto::encode_token_key_id_hex(&exchange_kid),
        pubkey_spki_b64: Base64UrlUnpadded::encode_string(&exchange_spki),
        suite: "RSABSSA-SHA384-PSS-Deterministic".into(),
        valid_from: now - 60,
        valid_until: now + 3600,
        max_quantity: 1,
        audience: Some(AUDIENCE.into()),
    };
    descriptor.descriptor_id = descriptor.canonical_descriptor_id().unwrap();
    let mut target_keyset = ExchangeTargetKeysetInfo {
        keyset_id: String::new(),
        descriptor_ids: vec![descriptor.descriptor_id.clone()],
    };
    target_keyset.keyset_id = target_keyset.canonical_keyset_id();
    descriptor.keyset_id = target_keyset.keyset_id.clone();

    let dir = tempfile::tempdir()?;
    let receipt_path = dir.path().join("retired-receipt.key");
    let receipt_key = load_or_generate_receipt_key(&receipt_path)?;
    let mut receipt = freebird_common::exchange_api::ExchangeReceipt {
        operation_id: Base64UrlUnpadded::encode_string(&[0x72; 16]),
        profile: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
        target_keyset_id: descriptor.keyset_id.clone(),
        result_digest: Base64UrlUnpadded::encode_string(&[0x73; 32]),
        created_at: u64::try_from(now)?,
        expires_at: u64::try_from(now + 3600)?,
        receipt_key_id: receipt_key.key_id(),
        signature: String::new(),
    };
    let receipt_signature = receipt_key.sign_receipt(&receipt)?;
    receipt.signature = Base64UrlUnpadded::encode_string(&receipt_signature);
    let receipt_public = receipt_key.verifying_key();
    let receipt_metadata = ExchangeReceiptKeyInfo {
        key_id: receipt.receipt_key_id.clone(),
        algorithm: "Ed25519".into(),
        purpose: "exchange_receipt_retained".into(),
        public_key_b64: Base64UrlUnpadded::encode_string(receipt_public.as_bytes()),
        valid_from: u64::try_from(now - 60)?,
        valid_until: u64::try_from(now + 3600)?,
    };
    drop(receipt_key);
    std::fs::remove_file(&receipt_path)?;
    drop(exchange_key);

    let history = ExchangePublicHistory {
        target_keysets: vec![target_keyset],
        target_descriptors: vec![descriptor.clone()],
        receipt_keys: vec![receipt_metadata.clone()],
    };
    freebird_issuer::exchange::history::validate_public_history(&history, ISSUER, None)?;
    ReceiptKey::verify_receipt(&receipt, &receipt_public, &receipt_signature)?;

    let discovery = KeyDiscoveryResp {
        issuer_id: ISSUER.into(),
        current_epoch: 1,
        valid_epochs: vec![1],
        epoch_duration_sec: 86_400,
        voprf: VoprfKeyInfo {
            suite: "suite".into(),
            kid: "kid".into(),
            pubkey: "public".into(),
        },
        public: vec![PublicKeyInfo {
            token_key_id: freebird_crypto::encode_token_key_id_hex(&legacy_kid),
            token_type: freebird_crypto::PUBLIC_BEARER_TOKEN_TYPE.into(),
            rfc9474_variant: freebird_crypto::PUBLIC_BEARER_RFC9474_VARIANT.into(),
            modulus_bits: 2048,
            pubkey_spki_b64: Base64UrlUnpadded::encode_string(&legacy_spki),
            issuer_id: ISSUER.into(),
            valid_from: now - 60,
            valid_until: now + 3600,
            audience: Some(AUDIENCE.into()),
            spend_policy: freebird_crypto::PUBLIC_BEARER_SPEND_POLICY_SINGLE_USE.into(),
            max_uses: Some(1),
        }],
        exchange: Some(ExchangeDiscoveryInfo {
            profile_id: freebird_common::exchange_api::EXCHANGE_PROFILE_V1.into(),
            target_keysets: history.target_keysets,
            descriptors: history.target_descriptors,
            receipt_keys: history.receipt_keys,
        }),
    };
    let public_keys = trusted_public_keys(ISSUER, discovery)?;
    assert!(public_keys.contains_key(&legacy_kid));
    assert!(public_keys.contains_key(&exchange_kid));
    let issuers = HashMap::from([(
        ISSUER.into(),
        IssuerInfo {
            pubkey_bytes: Vec::new(),
            kid: "unused".into(),
            ctx: Vec::new(),
            verification_key: None,
            deprecated_verification_keys: HashMap::new(),
            public_keys,
            last_refreshed: None,
        },
    )]);
    let (verified, _) = verify_v5_public_token(&artifact_b64, &issuers, AUDIENCE)
        .map_err(|(_, error)| anyhow::anyhow!(error))?;
    let nullifier = nullifier_key_v5(&verified)
        .map_err(|error| anyhow::anyhow!("derive exchange output nullifier: {error:?}"))?;
    let spend_key = freebird_common::spend_key::v5_spend_key(&nullifier);
    let store = InMemoryStore::default();
    assert!(store.mark_spent(&spend_key, None).await?);
    assert!(!store.mark_spent(&spend_key, None).await?);
    Ok(())
}
