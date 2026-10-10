// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit opt-in, real-Redis evidence for the enabled V7 graph issuer lane.

use super::exchange_runtime::ExchangeRuntime;
use crate::{
    config::{
        Config, ExchangeConfig, GraphIssuanceAuthorizationConfig, GraphIssuanceConfig,
        GraphIssuanceV4VerificationKey, KeyConfig, NativeBearerV7Config, SybilConfig,
    },
    multi_key_voprf::MultiKeyVoprfCore,
    native_bearer_v7::NativeBearerV7Issuer,
    startup::graph_issuance_router,
    v7_signers::{V7Signer, V7SignerInventory, V7SignerSpec},
    AppStateWithSybil,
};
use anyhow::{bail, Context, Result};
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signer, SigningKey};
use freebird_common::api::{
    NativeExchangeV3Descriptor, NativeExchangeV3Discovery, NativeExchangeV3Keyset,
    NativeExchangeV3Profile, NativeExchangeV3Slot, NativeExchangeV3Transition,
    NativeGraphIssuanceV7Discovery, NativeGraphIssuanceV7Policy, NativeGraphIssuanceV7Request,
    NativeGraphIssuanceV7Result, V7KeyDiscoveryResp, NATIVE_EXCHANGE_V3_PROFILE_ID,
    NATIVE_EXCHANGE_V3_SUITE, NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
};
use freebird_crypto::{
    blind_v7, build_native_bearer_v7_token, build_private_token_input, build_redemption_token,
    build_scope_digest, finalize_v7, nullifier_key_v4, parse_native_bearer_v7_token,
    PublicBearerV7Body, RedemptionToken, Server, V7BlindSignature, V7BodyPolicy, V7KeyIdentity,
    V7PublicKeyBinding, V7TokenKeyId, VOPRF_CONTEXT_V4,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use tower::Service;

const DISPOSABLE_CONFIRMATION: &str = "I_OWN_THIS_EMPTY_INSTANCE";
const REPLAY_AUTHORITY_ID_KEY: &str = "freebird:v4-replay-authority:v1:id";
const REPLAY_AUTHORITY_TOMBSTONES_KEY: &str = "freebird:v4-replay-authority:v1:scope-tombstones";

/// Run only against an operator-provisioned disposable Redis database.
///
/// This test never creates a Redis instance and never flushes a database. Its
/// entry point fails closed unless all four explicit opt-in values are set.
#[tokio::test]
#[ignore = "requires an exclusively owned disposable Redis and private artifact directory"]
async fn u2b_enabled_graph_v4_redis() {
    let opt_in = match OptIn::from_environment() {
        Ok(opt_in) => opt_in,
        Err(error) => panic!("explicit U2b opt-in validation failed: {error:#}"),
    };
    if let Err(error) = run_enabled_graph_evidence(opt_in).await {
        panic!("opted-in U2b graph evidence failed: {error:#}");
    }
}

struct OptIn {
    redis_url: String,
    run_id: String,
    artifact_path: PathBuf,
}

impl OptIn {
    fn from_environment() -> Result<Self> {
        let redis_url = std::env::var("FREEBIRD_REDIS_LIVE_URL")
            .context("FREEBIRD_REDIS_LIVE_URL is required")?;
        let confirmation = std::env::var("FREEBIRD_U2B_DISPOSABLE_REDIS")
            .context("FREEBIRD_U2B_DISPOSABLE_REDIS is required")?;
        if confirmation != DISPOSABLE_CONFIRMATION {
            bail!("FREEBIRD_U2B_DISPOSABLE_REDIS did not explicitly confirm ownership")
        }
        let run_id =
            std::env::var("FREEBIRD_U2B_RUN_ID").context("FREEBIRD_U2B_RUN_ID is required")?;
        if run_id.is_empty()
            || run_id.len() > 64
            || !run_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            bail!("FREEBIRD_U2B_RUN_ID must be 1-64 ASCII alphanumeric, '-' or '_' characters")
        }
        let artifact_path = PathBuf::from(
            std::env::var_os("FREEBIRD_U2B_ARTIFACT_FILE")
                .context("FREEBIRD_U2B_ARTIFACT_FILE is required")?,
        );
        if !artifact_path.is_absolute() || artifact_path.exists() {
            bail!("artifact path must be absolute and not already exist")
        }
        let parent = artifact_path
            .parent()
            .context("artifact path has no parent directory")?;
        let parent_metadata =
            fs::symlink_metadata(parent).context("read artifact parent directory metadata")?;
        if !parent_metadata.file_type().is_dir() {
            bail!("artifact parent must be a real directory, not a symlink")
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if parent_metadata.permissions().mode() & 0o777 != 0o700 {
                bail!("artifact parent directory must have mode 0700")
            }
        }
        Ok(Self {
            redis_url,
            run_id,
            artifact_path,
        })
    }
}

struct GeneratedFixture {
    _directory: tempfile::TempDir,
    config: Config,
    inventory: Arc<V7SignerInventory>,
    direct_config: NativeBearerV7Config,
    graph_policy: NativeGraphIssuanceV7Policy,
    source_signer: Arc<V7Signer>,
}

struct PreparedRequest {
    request: NativeGraphIssuanceV7Request,
    body: PublicBearerV7Body,
    randomizer: freebird_crypto::V7MessageRandomizer,
    blind_state: freebird_crypto::V7BlindState,
}

fn random16() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_id() -> String {
    hex::encode(random32())
}

fn lp32(transcript: &mut Vec<u8>, bytes: &[u8]) {
    transcript.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    transcript.extend_from_slice(bytes);
}

fn canonical_keyset_id(descriptor_ids: &[String]) -> String {
    let mut transcript = Vec::new();
    for descriptor_id in descriptor_ids {
        lp32(&mut transcript, descriptor_id.as_bytes());
    }
    hex::encode(Sha256::digest(
        [
            b"freebird native exchange keyset v3\0".as_slice(),
            transcript.as_slice(),
        ]
        .concat(),
    ))
}

fn canonical_transition_id(transition: &NativeExchangeV3Transition) -> String {
    let mut transcript = Vec::new();
    lp32(&mut transcript, transition.source_keyset_id.as_bytes());
    lp32(&mut transcript, transition.target_keyset_id.as_bytes());
    for slots in [&transition.source_slots, &transition.output_slots] {
        transcript.extend_from_slice(&(slots.len() as u32).to_be_bytes());
        for slot in slots {
            lp32(&mut transcript, slot.descriptor_id.as_bytes());
            lp32(&mut transcript, slot.keyset_id.as_bytes());
            lp32(&mut transcript, slot.slot_id.as_bytes());
            transcript.extend_from_slice(&slot.quantity.to_be_bytes());
        }
    }
    hex::encode(Sha256::digest(
        [
            b"freebird native exchange transition v3\0".as_slice(),
            transcript.as_slice(),
        ]
        .concat(),
    ))
}

fn canonical_exchange_graph_id(exchange: &NativeExchangeV3Discovery) -> String {
    let mut transcript = Vec::new();
    lp32(&mut transcript, exchange.profile.profile_id.as_bytes());
    for keyset in exchange
        .active_keysets
        .iter()
        .chain(&exchange.retained_keysets)
    {
        lp32(&mut transcript, keyset.keyset_id.as_bytes());
    }
    for transition in &exchange.transitions {
        lp32(&mut transcript, transition.transition_id.as_bytes());
    }
    hex::encode(Sha256::digest(
        [
            b"freebird native exchange graph v3\0".as_slice(),
            transcript.as_slice(),
        ]
        .concat(),
    ))
}

fn canonical_graph_policy_id(policy: &NativeGraphIssuanceV7Policy) -> String {
    let mut transcript = Vec::new();
    for value in [
        &policy.profile_id,
        &policy.graph_id,
        &policy.keyset_id,
        &policy.descriptor_id,
        &policy.token_key_id,
        &policy.issuer_id,
        &policy.asset_id,
        &policy.amount_minor,
        &policy.suite,
    ] {
        lp32(&mut transcript, value.as_bytes());
    }
    transcript.extend_from_slice(&policy.modulus_bits.to_be_bytes());
    transcript.extend_from_slice(&policy.exponent.to_be_bytes());
    transcript.extend_from_slice(&policy.quantity.to_be_bytes());
    let spki = Base64UrlUnpadded::decode_vec(&policy.pubkey_spki_b64)
        .expect("generated exchange SPKI is canonical base64url");
    lp32(&mut transcript, &spki);
    lp32(&mut transcript, policy.spki_fingerprint.as_bytes());
    transcript.extend_from_slice(&(policy.valid_from as u64).to_be_bytes());
    transcript.extend_from_slice(&(policy.valid_until as u64).to_be_bytes());
    hex::encode(Sha256::digest(
        [
            b"freebird native graph issuance policy v7\0".as_slice(),
            transcript.as_slice(),
        ]
        .concat(),
    ))
}

fn signer_config(
    root: &Path,
    registry_path: &Path,
    profile_id: &str,
    key_byte: u8,
    amount_minor: u64,
) -> NativeBearerV7Config {
    NativeBearerV7Config {
        sk_path: root.join(format!("signer-{key_byte:02x}.der")),
        metadata_path: root.join(format!("signer-{key_byte:02x}.json")),
        registry_path: registry_path.to_path_buf(),
        profile_id: profile_id.to_owned(),
        descriptor_id: String::new(),
        token_key_id: format!("{key_byte:02x}").repeat(32),
        asset_id: "USD".into(),
        amount_minor,
        validity_secs: 86_400,
    }
}

fn descriptor_from(signer: &V7Signer) -> NativeExchangeV3Descriptor {
    let metadata = signer.metadata();
    NativeExchangeV3Descriptor {
        descriptor_id: metadata.descriptor_id.clone(),
        profile_id: metadata.profile_id.clone(),
        issuer_id: metadata.issuer_id.clone(),
        token_key_id: metadata.token_key_id.clone(),
        asset_id: metadata.asset_id.clone(),
        amount_minor: metadata.amount_minor.to_string(),
        suite: metadata.suite.clone(),
        modulus_bits: metadata.modulus_bits,
        exponent: metadata.exponent,
        pubkey_spki_b64: metadata.pubkey_spki_b64.clone(),
        spki_fingerprint: metadata.spki_fingerprint.clone(),
        valid_from: metadata.valid_from as u64,
        valid_until: metadata.valid_until as u64,
    }
}

fn generated_fixture(opt_in: &OptIn) -> Result<GeneratedFixture> {
    let directory = tempfile::tempdir().context("create ephemeral issuer material directory")?;
    let issuer_id = format!("issuer:u2b:{}", opt_in.run_id);
    let registry_path = directory.path().join("registry.json");
    let direct_config = signer_config(
        directory.path(),
        &registry_path,
        freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
        0x31,
        1,
    );
    let source_config = signer_config(
        directory.path(),
        &registry_path,
        NATIVE_EXCHANGE_V3_PROFILE_ID,
        0x32,
        42,
    );
    let target_config = signer_config(
        directory.path(),
        &registry_path,
        NATIVE_EXCHANGE_V3_PROFILE_ID,
        0x33,
        43,
    );
    let direct_spec = V7SignerSpec::from_native_config(&direct_config, &issuer_id)?;
    let source_spec = V7SignerSpec::from_native_config(&source_config, &issuer_id)?;
    let target_spec = V7SignerSpec::from_native_config(&target_config, &issuer_id)?;
    let _direct_generated =
        V7SignerInventory::load_or_generate(direct_spec.clone(), Vec::new(), &registry_path)?;
    let _source_generated =
        V7SignerInventory::load_or_generate(source_spec.clone(), Vec::new(), &registry_path)?;
    let _target_generated =
        V7SignerInventory::load_or_generate(target_spec.clone(), Vec::new(), &registry_path)?;
    let direct = Arc::new(V7Signer::load_existing(&direct_spec, true)?);
    let source = Arc::new(V7Signer::load_existing(&source_spec, true)?);
    let target = Arc::new(V7Signer::load_existing(&target_spec, true)?);
    let inventory = Arc::new(V7SignerInventory::from_signers(
        direct.clone(),
        vec![direct, source.clone(), target.clone()],
        None,
    )?);

    let source_descriptor = descriptor_from(&source);
    let target_descriptor = descriptor_from(&target);
    let source_keyset_id =
        canonical_keyset_id(std::slice::from_ref(&source_descriptor.descriptor_id));
    let target_keyset_id =
        canonical_keyset_id(std::slice::from_ref(&target_descriptor.descriptor_id));
    if source_keyset_id == target_keyset_id
        || source_descriptor.descriptor_id == target_descriptor.descriptor_id
        || inventory.len() != 3
        || inventory.active().identity().profile_id()
            != freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID
        || source.identity().profile_id() != NATIVE_EXCHANGE_V3_PROFILE_ID
    {
        bail!("generated U2b fixture did not produce distinct direct and exchange roles")
    }
    let mut transition = NativeExchangeV3Transition {
        transition_id: String::new(),
        profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
        source_keyset_id: source_keyset_id.clone(),
        target_keyset_id: target_keyset_id.clone(),
        source_slots: vec![NativeExchangeV3Slot {
            descriptor_id: source_descriptor.descriptor_id.clone(),
            keyset_id: source_keyset_id.clone(),
            slot_id: format!("u2b-source-{}", opt_in.run_id),
            quantity: 1,
        }],
        output_slots: vec![NativeExchangeV3Slot {
            descriptor_id: target_descriptor.descriptor_id.clone(),
            keyset_id: target_keyset_id.clone(),
            slot_id: format!("u2b-output-{}", opt_in.run_id),
            quantity: 1,
        }],
    };
    transition.transition_id = canonical_transition_id(&transition);
    let exchange_discovery = NativeExchangeV3Discovery {
        version: 3,
        profile: NativeExchangeV3Profile {
            version: 3,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
            graph_id: String::new(),
            suite: NATIVE_EXCHANGE_V3_SUITE.into(),
            modulus_bits: 3072,
            exponent: 65_537,
        },
        active_descriptors: vec![source_descriptor.clone(), target_descriptor],
        retained_descriptors: Vec::new(),
        active_keysets: vec![
            NativeExchangeV3Keyset {
                keyset_id: source_keyset_id.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![source_descriptor.descriptor_id.clone()],
            },
            NativeExchangeV3Keyset {
                keyset_id: target_keyset_id,
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.into(),
                descriptor_ids: vec![transition.output_slots[0].descriptor_id.clone()],
            },
        ],
        retained_keysets: Vec::new(),
        transitions: vec![transition],
    };
    let mut exchange_discovery = exchange_discovery;
    exchange_discovery.profile.graph_id = canonical_exchange_graph_id(&exchange_discovery);

    let source_metadata = source.metadata();
    let mut graph_policy = NativeGraphIssuanceV7Policy {
        policy_id: String::new(),
        profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
        graph_id: exchange_discovery.profile.graph_id.clone(),
        keyset_id: source_keyset_id,
        descriptor_id: source_descriptor.descriptor_id.clone(),
        token_key_id: source_metadata.token_key_id.clone(),
        issuer_id: issuer_id.clone(),
        asset_id: source_metadata.asset_id.clone(),
        amount_minor: source_metadata.amount_minor.to_string(),
        suite: source_metadata.suite.clone(),
        modulus_bits: source_metadata.modulus_bits,
        exponent: source_metadata.exponent,
        quantity: 1,
        pubkey_spki_b64: source_metadata.pubkey_spki_b64.clone(),
        spki_fingerprint: source_metadata.spki_fingerprint.clone(),
        valid_from: source_metadata.valid_from,
        valid_until: source_metadata.valid_until,
    };
    graph_policy.policy_id = canonical_graph_policy_id(&graph_policy);
    let graph_discovery = NativeGraphIssuanceV7Discovery {
        version: 7,
        profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
        active_policies: vec![graph_policy],
        retained_policies: Vec::new(),
    };

    let receipt_key_path = directory.path().join("receipt.key");
    let receipt_signing = SigningKey::from_bytes(&random32());
    fs::write(&receipt_key_path, receipt_signing.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&receipt_key_path, fs::Permissions::from_mode(0o600))?;
    }
    let receipt_metadata = crate::exchange::ReceiptKeyMetadata {
        key_id: hex::encode(Sha256::digest(receipt_signing.verifying_key().as_bytes())),
        algorithm: "Ed25519".into(),
        purpose: "exchange_receipt_v7".into(),
        public_key_b64: Base64UrlUnpadded::encode_string(
            receipt_signing.verifying_key().as_bytes(),
        ),
        valid_from: 1,
        valid_until: freebird_common::api::EXCHANGE_MAX_VALID_UNTIL as u64,
    };
    let receipt_metadata_path = directory.path().join("receipt.json");
    fs::write(
        &receipt_metadata_path,
        serde_json::to_vec(&receipt_metadata)?,
    )?;
    let exchange_discovery_path = directory.path().join("exchange.json");
    fs::write(
        &exchange_discovery_path,
        serde_json::to_vec(&exchange_discovery)?,
    )?;
    let graph_policy_path = directory.path().join("graph-policy.json");
    fs::write(&graph_policy_path, serde_json::to_vec(&graph_discovery)?)?;

    let v4_secret = loop {
        let candidate = random32();
        if Server::from_secret_key(candidate, VOPRF_CONTEXT_V4).is_ok() {
            break candidate;
        }
    };
    let config = Config {
        issuer_id,
        bind_addr: "127.0.0.1:8081".parse().expect("test bind address parses"),
        require_tls: false,
        behind_proxy: false,
        key_config: KeyConfig {
            sk_path: directory.path().join("voprf.key"),
            rotation_state_path: directory.path().join("rotation.json"),
            kid_override: None,
            hsm: None,
        },
        native_bearer_v7_config: direct_config.clone(),
        exchange_config: ExchangeConfig {
            enabled: true,
            active_graph_path: exchange_discovery_path,
            retained_graph_paths: Vec::new(),
            active_receipt_key_path: receipt_key_path,
            active_receipt_metadata_path: receipt_metadata_path,
            retained_receipt_key_paths: Vec::new(),
            retained_receipt_metadata_paths: Vec::new(),
            redis_url: None,
            receipt_lifetime_secs: 2_592_000,
            request_body_limit: 1_048_576,
            request_timeout_secs: 30,
            graph_issuance: GraphIssuanceConfig {
                enabled: true,
                policy_path: graph_policy_path,
                v7_verifier_id: format!("verifier:u2b:{}", opt_in.run_id),
                v7_audience: format!("audience:u2b:{}", opt_in.run_id),
                authorization: GraphIssuanceAuthorizationConfig::V4Local {
                    keys: vec![GraphIssuanceV4VerificationKey {
                        issuer_id: format!("v4-issuer:u2b:{}", opt_in.run_id),
                        kid: format!("v4-kid:u2b:{}", opt_in.run_id),
                        secret_key: v4_secret,
                    }],
                },
            },
        },
        sybil_config: empty_sybil_config(directory.path()),
        webauthn_config: None,
        admin_api_key: None,
        epoch_duration_sec: 86_400,
        epoch_retention: 2,
        allow_unsafe_v4_rotation: false,
        audit_log_path: directory.path().join("audit.json"),
        unsafe_development_mode: false,
    };
    Ok(GeneratedFixture {
        _directory: directory,
        config,
        inventory,
        direct_config,
        graph_policy: graph_discovery.active_policies[0].clone(),
        source_signer: source,
    })
}

fn empty_sybil_config(root: &Path) -> SybilConfig {
    SybilConfig {
        mode: "none".into(),
        pow_difficulty: 0,
        rate_limit_secs: 0,
        invite_per_user: 0,
        invite_cooldown_secs: 0,
        invite_expires_secs: 0,
        invite_new_user_wait_secs: 0,
        invite_persistence_path: root.join("invites.json"),
        invite_autosave_interval_secs: 0,
        invite_signing_key_path: root.join("invite.key"),
        bootstrap_users: None,
        webauthn_max_proof_age: None,
        progressive_trust_levels: Vec::new(),
        progressive_trust_persistence_path: root.join("trust.json"),
        progressive_trust_autosave_interval: 0,
        progressive_trust_hmac_secret: None,
        progressive_trust_hmac_secret_path: root.join("trust.secret"),
        progressive_trust_salt: String::new(),
        progressive_trust_allow_insecure: false,
        proof_of_diversity_min_score: 0,
        proof_of_diversity_persistence_path: root.join("diversity.json"),
        proof_of_diversity_autosave_interval: 0,
        proof_of_diversity_hmac_secret: None,
        proof_of_diversity_hmac_secret_path: root.join("diversity.secret"),
        proof_of_diversity_fingerprint_salt: String::new(),
        proof_of_diversity_allow_insecure: false,
        multi_party_vouching_required_vouchers: 0,
        multi_party_vouching_cooldown_secs: 0,
        multi_party_vouching_expires_secs: 0,
        multi_party_vouching_new_user_wait_secs: 0,
        multi_party_vouching_persistence_path: root.join("vouches.json"),
        multi_party_vouching_autosave_interval: 0,
        multi_party_vouching_hmac_secret: None,
        multi_party_vouching_hmac_secret_path: root.join("vouches.secret"),
        multi_party_vouching_salt: String::new(),
        multi_party_vouching_allow_insecure: false,
        social_graph_attesters_path: root.join("attesters.json"),
        social_graph_jwks_url: None,
        social_graph_key_refresh_interval_secs: 0,
        social_graph_min_level: 0,
        social_graph_accepted_policy_ids: Vec::new(),
        social_graph_attestation_max_age_secs: 0,
        social_graph_clock_skew_secs: 0,
        social_graph_require_request_binding: false,
        social_graph_require_quota_nullifier: false,
        social_graph_replay_ttl_secs: 0,
        social_graph_state_path: root.join("social.json"),
        social_graph_fail_closed: false,
        combined_mechanisms: Vec::new(),
        combined_mode: "or".into(),
        combined_threshold: 0,
    }
}

async fn send_json(
    router: Router,
    path: &str,
    payload: &[u8],
) -> Result<(StatusCode, axum::http::HeaderMap, Vec<u8>)> {
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_vec()))?;
    let response = call_router(router, request).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 1_048_576).await?.to_vec();
    Ok((status, headers, body))
}

async fn call_router(router: Router, request: Request<Body>) -> Result<axum::response::Response> {
    let mut service = router;
    std::future::poll_fn(|context| {
        <Router as Service<Request<Body>>>::poll_ready(&mut service, context)
    })
    .await?;
    Ok(<Router as Service<Request<Body>>>::call(&mut service, request).await?)
}

fn graph_router(
    config: &Config,
    runtime: &ExchangeRuntime,
    direct_config: &NativeBearerV7Config,
) -> Result<(Router, Arc<AppStateWithSybil>, Arc<MultiKeyVoprfCore>)> {
    let direct_issuer = Arc::new(NativeBearerV7Issuer::load_existing(
        direct_config,
        &config.issuer_id,
    )?);
    let direct_metadata = direct_issuer.metadata().clone();
    let graph_engine = runtime
        .native_graph_issuance_v7
        .as_ref()
        .context("enabled runtime did not return graph engine")?;
    graph_engine.validate_bindings()?;
    let state = Arc::new(AppStateWithSybil {
        issuer_id: config.issuer_id.clone(),
        kid: "u2b-direct-kid".into(),
        pubkey_b64: direct_metadata.pubkey_spki_b64.clone(),
        require_tls: false,
        behind_proxy: false,
        sybil_checker: None,
        admission: crate::sybil_resistance::admission::AdmissionExecutor::default(),
        invitation_system: None,
        native_bearer_v7: direct_issuer,
        native_bearer_v7_retained: Vec::new(),
        native_exchange_v7: runtime.native_exchange_v7.clone(),
        native_exchange_v7_discovery: runtime.native_exchange_v7_discovery.clone(),
        native_graph_issuance_v7: runtime.native_graph_issuance_v7.clone(),
        native_graph_issuance_v7_discovery: runtime.native_graph_issuance_v7_discovery.clone(),
        replay_authority: runtime.replay_authority.clone(),
        epoch_duration_sec: 86_400,
        epoch_retention: 2,
        admin_api_key: None,
        sybil_summary: None,
    });
    if runtime.native_exchange_v7.is_none()
        || runtime.native_exchange_v7_discovery.is_none()
        || runtime.native_graph_issuance_v7_discovery.is_none()
        || runtime.replay_authority.is_none()
    {
        bail!("enabled runtime omitted required U2b engines or discovery")
    }
    let voprf_secret = [0x19; 32];
    let voprf_public = crypto_result(
        Server::from_secret_key(voprf_secret, b"u2b-test")
            .map(|server| server.public_key_sec1_compressed()),
    )?;
    let voprf = Arc::new(MultiKeyVoprfCore::new(
        voprf_secret,
        Base64UrlUnpadded::encode_string(&voprf_public),
        "u2b-voprf-kid".into(),
        b"u2b-test",
    )?);
    let router = graph_issuance_router(1_048_576, 10).with_state((state.clone(), voprf.clone()));
    Ok((router, state, voprf))
}

async fn redis_dbsize(client: &redis::Client) -> Result<usize> {
    let mut connection = client.get_async_connection().await?;
    Ok(redis::cmd("DBSIZE").query_async(&mut connection).await?)
}

async fn redis_key_exists(client: &redis::Client, key: &str) -> Result<bool> {
    let mut connection = client.get_async_connection().await?;
    let exists: bool = redis::cmd("EXISTS")
        .arg(key)
        .query_async(&mut connection)
        .await?;
    Ok(exists)
}

fn graph_operation_key(public_operation_id: &str) -> Result<String> {
    Ok(format!(
        "freebird:native-graph-issuance:v7:operation:{}",
        hex::encode(decode_operation_id(public_operation_id)?)
    ))
}

async fn run_enabled_graph_evidence(opt_in: OptIn) -> Result<()> {
    // All opt-in and artifact ownership checks precede the first Redis connection.
    let redis_client = redis::Client::open(opt_in.redis_url.as_str())
        .context("parse explicitly supplied U2b Redis URL")?;
    let mut preflight_connection = redis_client
        .get_async_connection()
        .await
        .context("connect to explicitly supplied disposable Redis")?;
    let _: String = redis::cmd("PING")
        .query_async(&mut preflight_connection)
        .await
        .context("ping explicitly supplied disposable Redis")?;
    let before_runtime: usize = redis::cmd("DBSIZE")
        .query_async(&mut preflight_connection)
        .await
        .context("preflight disposable Redis database size")?;
    if before_runtime != 0 {
        bail!("disposable Redis database is not empty; refusing to initialize")
    }
    drop(preflight_connection);

    let mut fixture = generated_fixture(&opt_in)?;
    fixture.config.exchange_config.redis_url = Some(opt_in.redis_url.clone());
    let source_signer = fixture.source_signer.clone();
    let runtime = ExchangeRuntime::build(&fixture.config, fixture.inventory.clone()).await?;
    if runtime.native_graph_issuance_v7.is_none()
        || runtime.native_exchange_v7.is_none()
        || runtime.native_graph_issuance_v7_discovery.is_none()
        || runtime.native_exchange_v7_discovery.is_none()
        || runtime.replay_authority.is_none()
    {
        bail!("ExchangeRuntime::build omitted enabled V7 runtime components")
    }
    let (router, state, voprf) = graph_router(&fixture.config, &runtime, &fixture.direct_config)?;
    let discovery = crate::routes::metadata::keys_handler(axum::extract::State((state, voprf)))
        .await
        .map_err(|status| anyhow::anyhow!("production V7 discovery handler returned {status}"))?
        .0;
    let registry = discovery.validated_registry().map_err(anyhow::Error::msg)?;
    if registry.entries().len() != 3
        || registry
            .entries()
            .iter()
            .any(|entry| entry.profile_id == NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID)
    {
        bail!("Common discovery registry did not retain only the direct and exchange signers")
    }
    let binding = binding_from_reservation(&registry, &fixture.graph_policy.descriptor_id)?;
    let graph_discovery = discovery
        .native_graph_issuance_v7
        .clone()
        .context("production V7 discovery omitted graph role")?;
    let policy = graph_discovery
        .active_policies
        .iter()
        .find(|policy| policy.policy_id == fixture.graph_policy.policy_id)
        .context("runtime graph discovery omitted configured policy")?;

    let base_dbsize = redis_dbsize(&redis_client).await?;
    if base_dbsize != 2 {
        bail!("runtime replay-authority initialization did not create exactly its two owned keys")
    }
    let source_sign_attempts = source_signer.sign_attempts();

    let v4_key = match &fixture.config.exchange_config.graph_issuance.authorization {
        GraphIssuanceAuthorizationConfig::V4Local { keys } => {
            keys.first().context("V4 key missing")?
        }
        _ => bail!("generated fixture unexpectedly lacks V4-local authorization"),
    };
    let verifier_id = fixture
        .config
        .exchange_config
        .graph_issuance
        .v7_verifier_id
        .clone();
    let audience = fixture
        .config
        .exchange_config
        .graph_issuance
        .v7_audience
        .clone();
    let issuer_id = fixture.config.issuer_id.clone();
    let mut negative_cases = Vec::<(NativeGraphIssuanceV7Request, String)>::new();

    for (wrong_issuer, wrong_kid, scope_variant, bad_authenticator) in [
        (false, false, false, true),
        (true, false, false, false),
        (false, true, false, false),
        (false, false, true, false),
    ] {
        let holder = SigningKey::from_bytes(&random32());
        let holder_nonce = holder.verifying_key().to_bytes();
        let v4_issuer = if wrong_issuer {
            format!("{issuer_id}:wrong")
        } else {
            v4_key.issuer_id.clone()
        };
        let v4_kid = if wrong_kid {
            format!("{}:wrong", v4_key.kid)
        } else {
            v4_key.kid.clone()
        };
        let v4_verifier = if scope_variant {
            format!("{verifier_id}:wrong")
        } else {
            verifier_id.clone()
        };
        let (token, credential_bytes) = make_v4_credential(
            v4_key.secret_key,
            &v4_issuer,
            &v4_kid,
            holder_nonce,
            &v4_verifier,
            &audience,
            bad_authenticator,
        )?;
        let credential = (token, credential_bytes, holder);
        let mut prepared = request_for(policy, &binding, &credential, random16())?;
        if bad_authenticator {
            // Holder proof is valid for the malformed V4 credential; rejection
            // must therefore come from V4 authentication, before any write.
            attach_holder_proof(&mut prepared.request, &credential.1, &credential.2)?;
        }
        let candidate_spend = freebird_common::spend_key::v4_spend_key(&crypto_result(
            nullifier_key_v4(&credential.0, &verifier_id, &audience),
        )?);
        negative_cases.push((prepared.request, candidate_spend));
    }

    let invalid_proof_credential = make_credential_for_key(
        v4_key.secret_key,
        &v4_key.issuer_id,
        &v4_key.kid,
        &verifier_id,
        &audience,
    )?;
    let mut invalid_proof = request_for(policy, &binding, &invalid_proof_credential, random16())?;
    let mut proof = Base64UrlUnpadded::decode_vec(&invalid_proof.request.authorization_proof)?;
    proof[0] ^= 1;
    invalid_proof.request.authorization_proof = Base64UrlUnpadded::encode_string(&proof);
    let invalid_proof_spend = freebird_common::spend_key::v4_spend_key(&crypto_result(
        nullifier_key_v4(&invalid_proof_credential.0, &verifier_id, &audience),
    )?);
    negative_cases.push((invalid_proof.request, invalid_proof_spend));

    let bound_credential = make_credential_for_key(
        v4_key.secret_key,
        &v4_key.issuer_id,
        &v4_key.kid,
        &verifier_id,
        &audience,
    )?;
    let mut bound_mutation = request_for(policy, &binding, &bound_credential, random16())?;
    bound_mutation.request.amount_minor = (policy.amount_minor.parse::<u64>()? + 1).to_string();
    attach_holder_proof(
        &mut bound_mutation.request,
        &bound_credential.1,
        &bound_credential.2,
    )?;
    let bound_spend = freebird_common::spend_key::v4_spend_key(&crypto_result(nullifier_key_v4(
        &bound_credential.0,
        &verifier_id,
        &audience,
    ))?);
    negative_cases.push((bound_mutation.request, bound_spend));

    for (request, candidate_spend_key) in negative_cases {
        request.validate().map_err(anyhow::Error::msg)?;
        let payload = serde_json::to_vec(&request).context("serialize negative graph request")?;
        let (status, _, _) = send_json(router.clone(), "/v7/public/graph/issue", &payload).await?;
        if status != StatusCode::BAD_REQUEST {
            bail!("negative graph request was not rejected with HTTP 400")
        }
        let candidate_operation_key = graph_operation_key(&request.public_operation_id)?;
        if redis_key_exists(&redis_client, &candidate_operation_key).await?
            || redis_key_exists(&redis_client, &candidate_spend_key).await?
            || redis_dbsize(&redis_client).await? != base_dbsize
            || source_signer.sign_attempts() != source_sign_attempts
        {
            bail!("a pre-commit negative request changed Redis or invoked the graph signer")
        }
    }

    let success_credential = make_credential_for_key(
        v4_key.secret_key,
        &v4_key.issuer_id,
        &v4_key.kid,
        &verifier_id,
        &audience,
    )?;
    let successful = request_for(policy, &binding, &success_credential, random16())?;
    successful.request.validate().map_err(anyhow::Error::msg)?;
    let frozen_request_digest = successful
        .request
        .request_digest()
        .map_err(anyhow::Error::msg)?;
    let payload = serde_json::to_vec(&successful.request)?;
    let serialized_request: NativeGraphIssuanceV7Request = serde_json::from_slice(&payload)?;
    if serialized_request
        .request_digest()
        .map_err(anyhow::Error::msg)?
        != frozen_request_digest
    {
        bail!("serialized graph request digest changed")
    }
    let operation_id = successful.request.public_operation_id.clone();
    let (first_status, first_headers, first_response) =
        send_json(router.clone(), "/v7/public/graph/issue", &payload).await?;
    if first_status != StatusCode::OK {
        bail!("enabled graph router did not commit a valid request")
    }
    ensure_graph_response_headers(&first_headers)?;
    let dropped_response_digest = Sha256::digest(&first_response);
    if redis_dbsize(&redis_client).await? != base_dbsize + 2
        || source_signer.sign_attempts() != source_sign_attempts + 1
    {
        bail!("valid graph request did not create exactly one operation/spend marker and one signature")
    }
    drop(first_response);
    drop(router);
    drop(runtime);

    // Rebuild the production runtime against the same signer files and Redis
    // state, then recover the exact POST after the simulated dropped response.
    let restarted = ExchangeRuntime::build(&fixture.config, fixture.inventory.clone()).await?;
    let (restarted_router, restarted_state, restarted_voprf) =
        graph_router(&fixture.config, &restarted, &fixture.direct_config)?;
    let status_uri = format!("/v7/public/graph/issue/status?public_operation_id={operation_id}");
    let status_request = Request::builder()
        .method(Method::GET)
        .uri(&status_uri)
        .body(Body::empty())?;
    let status_response = call_router(restarted_router.clone(), status_request).await?;
    if status_response.status() != StatusCode::OK {
        bail!("graph status GET did not observe the committed result")
    }
    ensure_graph_response_headers(status_response.headers())?;
    let status_body = to_bytes(status_response.into_body(), 1_048_576)
        .await?
        .to_vec();
    if Sha256::digest(&status_body) != dropped_response_digest
        || redis_dbsize(&redis_client).await? != base_dbsize + 2
        || source_signer.sign_attempts() != source_sign_attempts + 1
    {
        bail!("status GET changed the operation or failed to observe its committed response")
    }

    let (retry_status, retry_headers, retry_body) =
        send_json(restarted_router.clone(), "/v7/public/graph/issue", &payload).await?;
    if retry_status != StatusCode::OK {
        bail!("exact POST retry failed to recover the committed graph response")
    }
    ensure_graph_response_headers(&retry_headers)?;
    if retry_body != status_body
        || Sha256::digest(&retry_body) != dropped_response_digest
        || redis_dbsize(&redis_client).await? != base_dbsize + 2
        || source_signer.sign_attempts() != source_sign_attempts + 1
    {
        bail!("exact retry changed the stored response or repeated graph signing")
    }

    let result: NativeGraphIssuanceV7Result =
        serde_json::from_slice(&retry_body).context("parse committed graph response")?;
    result.validate().map_err(anyhow::Error::msg)?;
    if result.issuer_id != successful.request.issuer_id
        || result.public_operation_id != successful.request.public_operation_id
        || result.graph_id != successful.request.graph_id
        || result.policy_id != successful.request.policy_id
        || result.keyset_id != successful.request.keyset_id
        || result.descriptor_id != successful.request.descriptor_id
        || result.token_key_id != successful.request.token_key_id
        || result.asset_id != successful.request.asset_id
        || result.amount_minor != successful.request.amount_minor
        || result.blinded_message != successful.request.blinded_message
        || result.request_commitment != successful.request.request_commitment
        || result.quantity != successful.request.quantity
    {
        bail!("committed graph result fields did not match the signed request")
    }
    // V7 results do not carry request_digest as a wire field; recomputing and
    // checking it here ensures the exact held POST is still canonical.
    if successful
        .request
        .request_digest()
        .map_err(anyhow::Error::msg)?
        != frozen_request_digest
    {
        bail!("held graph request digest changed during recovery")
    }
    let blind_signature = crypto_result(V7BlindSignature::from_bytes(
        &Base64UrlUnpadded::decode_vec(&result.blind_signature)?,
    ))?;
    let finalized = crypto_result(finalize_v7(
        &binding,
        successful.blind_state,
        &blind_signature,
    ))?;
    let artifact_bytes = crypto_result(build_native_bearer_v7_token(
        &successful.body,
        successful.randomizer,
        finalized,
    ))?;
    let parsed_artifact = crypto_result(parse_native_bearer_v7_token(&artifact_bytes))?;
    crypto_result(parsed_artifact.verify(
        &binding,
        &crypto_result(V7BodyPolicy::new(
            policy.asset_id.clone(),
            policy.amount_minor.parse()?,
        ))?,
    ))?;
    let assembled_discovery = crate::routes::metadata::keys_handler(axum::extract::State((
        restarted_state,
        restarted_voprf,
    )))
    .await
    .map_err(|status| anyhow::anyhow!("restarted V7 discovery handler returned {status}"))?
    .0;
    assembled_discovery
        .validated_registry()
        .map_err(anyhow::Error::msg)?;

    let changed_credential = (
        success_credential.0.clone(),
        success_credential.1.clone(),
        success_credential.2.clone(),
    );
    let mut conflict = request_for(
        policy,
        &binding,
        &changed_credential,
        decode_operation_id(&successful.request.public_operation_id)?,
    )?;
    conflict.request.request_commitment = random_id();
    attach_holder_proof(
        &mut conflict.request,
        &changed_credential.1,
        &changed_credential.2,
    )?;
    let conflict_payload = serde_json::to_vec(&conflict.request)?;
    let (conflict_status, _, _) = send_json(
        restarted_router.clone(),
        "/v7/public/graph/issue",
        &conflict_payload,
    )
    .await?;
    if conflict_status != StatusCode::CONFLICT
        || redis_dbsize(&redis_client).await? != base_dbsize + 2
        || source_signer.sign_attempts() != source_sign_attempts + 1
    {
        bail!("changed request under an existing operation was not rejected as a conflict")
    }

    let mut replay = successful.request.clone();
    replay.public_operation_id = Base64UrlUnpadded::encode_string(&random16());
    attach_holder_proof(&mut replay, &success_credential.1, &success_credential.2)?;
    let replay_payload = serde_json::to_vec(&replay)?;
    let (replay_status, _, _) =
        send_json(restarted_router, "/v7/public/graph/issue", &replay_payload).await?;
    if replay_status != StatusCode::BAD_REQUEST
        || redis_dbsize(&redis_client).await? != base_dbsize + 2
        || source_signer.sign_attempts() != source_sign_attempts + 1
    {
        bail!("same V4 authorization was not rejected under a fresh operation ID")
    }

    let spend_key = freebird_common::spend_key::v4_spend_key(&crypto_result(nullifier_key_v4(
        &success_credential.0,
        &verifier_id,
        &audience,
    ))?);
    let operation_key = graph_operation_key(&successful.request.public_operation_id)?;
    cleanup_owned_redis_keys(
        &redis_client,
        &[
            &operation_key,
            &spend_key,
            REPLAY_AUTHORITY_ID_KEY,
            REPLAY_AUTHORITY_TOMBSTONES_KEY,
        ],
    )
    .await?;
    if redis_dbsize(&redis_client).await? != 0 {
        bail!("explicit cleanup left keys in the exclusively owned Redis database")
    }

    write_private_artifact(&opt_in, &assembled_discovery, &artifact_bytes)?;
    Ok(())
}

fn make_v4_credential(
    secret: [u8; 32],
    issuer_id: &str,
    kid: &str,
    nonce: [u8; 32],
    verifier_id: &str,
    audience: &str,
    bad_authenticator: bool,
) -> Result<(RedemptionToken, Vec<u8>)> {
    let scope_digest = crypto_result(build_scope_digest(verifier_id, audience))?;
    let input = crypto_result(build_private_token_input(
        issuer_id,
        kid,
        &nonce,
        &scope_digest,
    ))?;
    let server = crypto_result(Server::from_secret_key(secret, VOPRF_CONTEXT_V4))?;
    let mut authenticator = crypto_result(server.evaluate_unblinded(&input))?;
    if bad_authenticator {
        authenticator[0] ^= 0x80;
    }
    let token = RedemptionToken {
        nonce,
        scope_digest,
        kid: kid.to_owned(),
        issuer_id: issuer_id.to_owned(),
        authenticator,
    };
    Ok((
        token.clone(),
        crypto_result(build_redemption_token(&token))?,
    ))
}

fn crypto_result<T>(result: std::result::Result<T, freebird_crypto::Error>) -> Result<T> {
    result.map_err(|error| anyhow::anyhow!("V7/V4 test crypto operation failed: {error:?}"))
}

fn make_credential_for_key(
    secret: [u8; 32],
    issuer_id: &str,
    kid: &str,
    verifier_id: &str,
    audience: &str,
) -> Result<(RedemptionToken, Vec<u8>, SigningKey)> {
    let holder = SigningKey::from_bytes(&random32());
    let nonce = holder.verifying_key().to_bytes();
    let (token, bytes) =
        make_v4_credential(secret, issuer_id, kid, nonce, verifier_id, audience, false)?;
    Ok((token, bytes, holder))
}

fn attach_holder_proof(
    request: &mut NativeGraphIssuanceV7Request,
    credential: &[u8],
    holder: &SigningKey,
) -> Result<()> {
    request.authorization = Base64UrlUnpadded::encode_string(credential);
    request.authorization_proof = Base64UrlUnpadded::encode_string(&[0u8; 64]);
    request.authorization_proof = Base64UrlUnpadded::encode_string(
        &holder
            .sign(&request.authorization_proof_digest()?)
            .to_bytes(),
    );
    Ok(())
}

fn request_for(
    policy: &NativeGraphIssuanceV7Policy,
    binding: &V7PublicKeyBinding,
    credential: &(RedemptionToken, Vec<u8>, SigningKey),
    operation_id: [u8; 16],
) -> Result<PreparedRequest> {
    let body = crypto_result(PublicBearerV7Body::new_derived(
        policy.asset_id.clone(),
        policy.amount_minor.parse()?,
        policy.issuer_id.clone(),
        *binding.identity().token_key_id(),
        random32(),
        random32(),
    ))?;
    let (blind, randomizer, blind_state) = crypto_result(blind_v7(binding, &body))?;
    let mut request = NativeGraphIssuanceV7Request {
        version: 7,
        profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.into(),
        issuer_id: policy.issuer_id.clone(),
        public_operation_id: Base64UrlUnpadded::encode_string(&operation_id),
        graph_id: policy.graph_id.clone(),
        policy_id: policy.policy_id.clone(),
        keyset_id: policy.keyset_id.clone(),
        descriptor_id: policy.descriptor_id.clone(),
        token_key_id: policy.token_key_id.clone(),
        asset_id: policy.asset_id.clone(),
        amount_minor: policy.amount_minor.clone(),
        quantity: 1,
        blinded_message: Base64UrlUnpadded::encode_string(blind.as_bytes()),
        request_commitment: random_id(),
        authorization: String::new(),
        authorization_proof: String::new(),
    };
    attach_holder_proof(&mut request, &credential.1, &credential.2)?;
    Ok(PreparedRequest {
        request,
        body,
        randomizer,
        blind_state,
    })
}

fn binding_from_reservation(
    registry: &freebird_common::v7_registry::BearerKeyRegistry,
    descriptor_id: &str,
) -> Result<V7PublicKeyBinding> {
    let entry = registry
        .lookup_descriptor(descriptor_id)
        .context("validated registry has no graph exchange reservation")?;
    if entry.profile_id != NATIVE_EXCHANGE_V3_PROFILE_ID {
        bail!("graph reservation did not resolve to the exchange profile")
    }
    let token_key_id: [u8; 32] = hex::decode(&entry.token_key_id)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("validated registry token key ID is malformed"))?;
    let spki = Base64UrlUnpadded::decode_vec(&entry.pubkey_spki_b64)?;
    crypto_result(V7PublicKeyBinding::new(
        crypto_result(V7KeyIdentity::new(
            entry.issuer_id.clone(),
            V7TokenKeyId::new(token_key_id),
        ))?,
        &spki,
    ))
}

fn decode_operation_id(value: &str) -> Result<[u8; 16]> {
    let bytes = Base64UrlUnpadded::decode_vec(value)?;
    if bytes.len() != 16 || Base64UrlUnpadded::encode_string(&bytes) != value {
        bail!("generated operation ID is not canonical raw16")
    }
    bytes.try_into().map_err(|_| anyhow::anyhow!("bad raw16"))
}

fn ensure_graph_response_headers(headers: &axum::http::HeaderMap) -> Result<()> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
        || headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            != Some("no-store")
        || headers.contains_key(crate::routes::public_exchange::STATUS_CAPABILITY)
    {
        bail!("graph route response headers violated its public contract")
    }
    Ok(())
}

async fn cleanup_owned_redis_keys(client: &redis::Client, keys: &[&str]) -> Result<()> {
    let mut connection = client.get_async_connection().await?;
    let _: usize = redis::cmd("DEL")
        .arg(keys)
        .query_async(&mut connection)
        .await?;
    Ok(())
}

fn write_private_artifact(
    opt_in: &OptIn,
    discovery: &V7KeyDiscoveryResp,
    artifact_bytes: &[u8],
) -> Result<()> {
    if artifact_bytes.is_empty() || artifact_bytes.len() > 16_384 {
        bail!("finalized V7 artifact exceeded the bounded test artifact size")
    }
    let payload = serde_json::json!({
        "version": "freebird/u2b-graph-artifact/v1",
        "run_id": &opt_in.run_id,
        "issuer_id": &discovery.issuer_id,
        "discovery": discovery,
        "artifact_b64": Base64UrlUnpadded::encode_string(artifact_bytes),
        "artifact_sha256_hex": hex::encode(Sha256::digest(artifact_bytes)),
    });
    let bytes = serde_json::to_vec(&payload)?;
    if bytes.len() > 2_000_000 {
        bail!("U2b artifact bundle exceeds the bounded size")
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&opt_in.artifact_path)
        .context("create exclusive private U2b artifact file")?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&opt_in.artifact_path)?.permissions().mode() & 0o777 != 0o600 {
            bail!("U2b artifact file mode is not 0600")
        }
    }
    Ok(())
}
