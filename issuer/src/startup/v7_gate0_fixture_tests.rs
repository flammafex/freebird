// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicitly invoked, offline generator for the public/private Gate 0 fixture.

use anyhow::{bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::SigningKey;
use freebird_common::api::{
    NativeExchangeV3Descriptor, NativeExchangeV3Discovery, NativeExchangeV3Keyset,
    NativeExchangeV3Profile, NativeExchangeV3Slot, NativeExchangeV3Transition,
    NativeGraphIssuanceV7Discovery, NativeGraphIssuanceV7Policy, V7KeyDiscoveryResp,
    NATIVE_EXCHANGE_V3_PROFILE_ID, NATIVE_EXCHANGE_V3_SUITE, NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID,
    NATIVE_GRAPH_ISSUANCE_V7_VERSION,
};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use zeroize::{Zeroize, Zeroizing};

const GENERATOR_OPT_IN: &str = "I_OWN_THIS_EMPTY_DIRECTORY";
const VERSION: &str = "freebird/gate0-private-fixture/v1";
const ENV_VERSION: &str = "freebird/gate0-private-env/v1";
const USD: &str = "USD";
const AMOUNT: u64 = 42;
const VALIDITY_SECONDS: u64 = 86_400;
const FIXED_FILES: &[&str] = &[
    "manifest.json",
    "fixture.private.json",
    "issuer.env.json",
    "verifier.env.json",
    "v4.key",
    "v7-direct.der",
    "v7-direct.json",
    "v7-exchange-source.der",
    "v7-exchange-source.json",
    "v7-exchange-target.der",
    "v7-exchange-target.json",
    "v7-registry.json",
    "v7-extra-signers.json",
    "exchange.json",
    "graph.json",
    "receipt.key",
    "receipt.json",
];
const FIXED_DIRS: &[&str] = &[
    "runtime",
    "runtime/issuer",
    "runtime/verifier",
    "runtime/redis",
    "logs",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct Inputs {
    directory: PathBuf,
    run_id: String,
    issuer_port: u16,
    verifier_port: u16,
    redis_port: u16,
}

impl Inputs {
    fn from_environment() -> Result<Self> {
        let vars = [
            "FREEBIRD_GATE0_GENERATE",
            "FREEBIRD_GATE0_DIRECTORY",
            "FREEBIRD_GATE0_RUN_ID",
            "FREEBIRD_GATE0_ISSUER_PORT",
            "FREEBIRD_GATE0_VERIFIER_PORT",
            "FREEBIRD_GATE0_REDIS_PORT",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), env::var(name).ok()))
        .collect::<HashMap<_, _>>();
        Self::parse(&vars)
    }

    fn parse(vars: &HashMap<String, Option<String>>) -> Result<Self> {
        let required = |name: &str| -> Result<&str> {
            vars.get(name).and_then(Option::as_deref).context(format!(
                "{name} is required for explicit fixture generation"
            ))
        };
        if required("FREEBIRD_GATE0_GENERATE")? != GENERATOR_OPT_IN {
            bail!("FREEBIRD_GATE0_GENERATE did not explicitly confirm directory ownership")
        }
        let directory = PathBuf::from(required("FREEBIRD_GATE0_DIRECTORY")?);
        validate_output_directory(&directory)?;
        let run_id = required("FREEBIRD_GATE0_RUN_ID")?;
        if !valid_run_id(run_id) {
            bail!("FREEBIRD_GATE0_RUN_ID is not a G0.1-safe bounded run ID")
        }
        let issuer_port = parse_port(required("FREEBIRD_GATE0_ISSUER_PORT")?, "issuer")?;
        let verifier_port = parse_port(required("FREEBIRD_GATE0_VERIFIER_PORT")?, "verifier")?;
        let redis_port = parse_port(required("FREEBIRD_GATE0_REDIS_PORT")?, "Redis")?;
        if issuer_port == verifier_port || issuer_port == redis_port || verifier_port == redis_port
        {
            bail!("issuer, verifier, and Redis ports must be distinct")
        }
        Ok(Self {
            directory,
            run_id: run_id.to_owned(),
            issuer_port,
            verifier_port,
            redis_port,
        })
    }
}

fn valid_run_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| match index {
            0 => byte.is_ascii_alphanumeric(),
            _ => byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'),
        })
}

fn parse_port(value: &str, label: &str) -> Result<u16> {
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
        bail!("{label} port must be canonical high-decimal text")
    }
    let port = value
        .parse::<u16>()
        .with_context(|| format!("invalid {label} port"))?;
    if port.to_string() != value || !(20_000..=65_535).contains(&port) {
        bail!("{label} port must be canonical decimal in 20000..=65535")
    }
    Ok(port)
}

fn validate_output_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("FREEBIRD_GATE0_DIRECTORY must be absolute")
    }
    let metadata = fs::symlink_metadata(path).context("read caller-owned output directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("FREEBIRD_GATE0_DIRECTORY must be a real nonsymlink directory")
    }
    if path
        .canonicalize()
        .context("canonicalize output directory")?
        != path
    {
        bail!("FREEBIRD_GATE0_DIRECTORY must use its canonical absolute path")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            bail!("FREEBIRD_GATE0_DIRECTORY must have exact mode 0700")
        }
    }
    if fs::read_dir(path)
        .context("inspect caller-owned output directory")?
        .next()
        .is_some()
    {
        bail!("FREEBIRD_GATE0_DIRECTORY must be empty")
    }
    Ok(())
}

/// Only this exact ignored test can generate retained material; no Redis or
/// HTTP client is constructed by the generator.
#[test]
#[ignore = "explicitly generate a retained Gate 0 fixture in an owned empty 0700 directory"]
fn generate_gate0_fixture() {
    if let Err(error) = generate() {
        panic!("Gate 0 fixture generation failed: {error:#}");
    }
}

fn generate() -> Result<()> {
    let inputs = Inputs::from_environment()?;
    let mut cleanup = OutputCleanup::new(&inputs.directory);
    for relative in FIXED_DIRS {
        create_private_dir(&inputs.directory.join(relative))?;
    }
    build_fixture(&inputs)?;
    cleanup.preserve = true;
    Ok(())
}

struct OutputCleanup<'a> {
    root: &'a Path,
    preserve: bool,
}

impl<'a> OutputCleanup<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            preserve: false,
        }
    }
}

impl Drop for OutputCleanup<'_> {
    fn drop(&mut self) {
        if self.preserve {
            return;
        }
        for name in FIXED_FILES.iter().rev() {
            let _ = fs::remove_file(self.root.join(name));
        }
        for name in FIXED_DIRS.iter().rev() {
            let _ = fs::remove_dir_all(self.root.join(name));
        }
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)
        .with_context(|| format!("create private fixture directory {}", path.display()))?;
    set_mode(path, 0o700)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        if fs::symlink_metadata(path)?.permissions().mode() & 0o777 != mode {
            bail!("fixture permission verification failed")
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        bail!("Gate 0 fixture generation requires Unix file permission semantics")
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create private fixture file {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    set_mode(path, 0o600)
}

fn write_json<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).context("serialize fixture JSON")?;
    write_private(&root.join(name), &bytes)?;
    Ok(bytes)
}

fn random32() -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    bytes
}

fn random_hex32() -> String {
    hex::encode(random32().as_ref())
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn signer_config(root: &Path, name: &str, profile: &str) -> crate::config::NativeBearerV7Config {
    crate::config::NativeBearerV7Config {
        sk_path: root.join(format!("{name}.der")),
        metadata_path: root.join(format!("{name}.json")),
        registry_path: root.join("v7-registry.json"),
        profile_id: profile.to_owned(),
        descriptor_id: String::new(),
        token_key_id: random_hex32(),
        asset_id: USD.to_owned(),
        amount_minor: AMOUNT,
        validity_secs: VALIDITY_SECONDS,
    }
}

fn signer_spec(
    config: &crate::config::NativeBearerV7Config,
    issuer_id: &str,
) -> Result<crate::v7_signers::V7SignerSpec> {
    crate::v7_signers::V7SignerSpec::from_native_config(config, issuer_id)
}

fn generate_signer(
    config: &crate::config::NativeBearerV7Config,
    issuer_id: &str,
) -> Result<crate::v7_signers::V7Signer> {
    let spec = signer_spec(config, issuer_id)?;
    crate::v7_signers::V7SignerInventory::load_or_generate(
        spec.clone(),
        Vec::new(),
        &config.registry_path,
    )?;
    crate::v7_signers::V7Signer::load_existing(&spec, true)
}

fn keyset_id(descriptor_ids: &[String]) -> String {
    let mut transcript = Vec::new();
    for descriptor in descriptor_ids {
        transcript.extend_from_slice(&(descriptor.len() as u32).to_be_bytes());
        transcript.extend_from_slice(descriptor.as_bytes());
    }
    hex::encode(Sha256::digest(
        [
            b"freebird native exchange keyset v3\0".as_slice(),
            transcript.as_slice(),
        ]
        .concat(),
    ))
}

fn transition_id(transition: &NativeExchangeV3Transition) -> String {
    let mut transcript = Vec::new();
    for keyset in [&transition.source_keyset_id, &transition.target_keyset_id] {
        transcript.extend_from_slice(&(keyset.len() as u32).to_be_bytes());
        transcript.extend_from_slice(keyset.as_bytes());
    }
    for slots in [&transition.source_slots, &transition.output_slots] {
        transcript.extend_from_slice(&(slots.len() as u32).to_be_bytes());
        for slot in slots {
            for value in [&slot.descriptor_id, &slot.keyset_id, &slot.slot_id] {
                transcript.extend_from_slice(&(value.len() as u32).to_be_bytes());
                transcript.extend_from_slice(value.as_bytes());
            }
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

fn exchange_graph_id(exchange: &NativeExchangeV3Discovery) -> String {
    let mut transcript = Vec::new();
    let profile = &exchange.profile.profile_id;
    transcript.extend_from_slice(&(profile.len() as u32).to_be_bytes());
    transcript.extend_from_slice(profile.as_bytes());
    for keyset in exchange
        .active_keysets
        .iter()
        .chain(&exchange.retained_keysets)
    {
        transcript.extend_from_slice(&(keyset.keyset_id.len() as u32).to_be_bytes());
        transcript.extend_from_slice(keyset.keyset_id.as_bytes());
    }
    for transition in &exchange.transitions {
        transcript.extend_from_slice(&(transition.transition_id.len() as u32).to_be_bytes());
        transcript.extend_from_slice(transition.transition_id.as_bytes());
    }
    hex::encode(Sha256::digest(
        [
            b"freebird native exchange graph v3\0".as_slice(),
            transcript.as_slice(),
        ]
        .concat(),
    ))
}

fn graph_policy_id(policy: &NativeGraphIssuanceV7Policy) -> Result<String> {
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
        transcript.extend_from_slice(&(value.len() as u32).to_be_bytes());
        transcript.extend_from_slice(value.as_bytes());
    }
    transcript.extend_from_slice(&policy.modulus_bits.to_be_bytes());
    transcript.extend_from_slice(&policy.exponent.to_be_bytes());
    transcript.extend_from_slice(&policy.quantity.to_be_bytes());
    let spki = Base64UrlUnpadded::decode_vec(&policy.pubkey_spki_b64)
        .context("decode generated graph SPKI")?;
    transcript.extend_from_slice(&(spki.len() as u32).to_be_bytes());
    transcript.extend_from_slice(&spki);
    transcript.extend_from_slice(&(policy.spki_fingerprint.len() as u32).to_be_bytes());
    transcript.extend_from_slice(policy.spki_fingerprint.as_bytes());
    transcript.extend_from_slice(&(policy.valid_from as u64).to_be_bytes());
    transcript.extend_from_slice(&(policy.valid_until as u64).to_be_bytes());
    Ok(hex::encode(Sha256::digest(
        [
            b"freebird native graph issuance policy v7\0".as_slice(),
            transcript.as_slice(),
        ]
        .concat(),
    )))
}

fn build_fixture(input: &Inputs) -> Result<()> {
    let root = &input.directory;
    let issuer_id = format!("issuer:gate0:{}", input.run_id);
    let verifier_id = format!("verifier:gate0:{}", input.run_id);
    let audience = format!("audience:gate0:{}", input.run_id);
    let issuer_origin = format!("http://127.0.0.1:{}", input.issuer_port);
    let verifier_origin = format!("http://127.0.0.1:{}", input.verifier_port);
    let redis_url = format!("redis://127.0.0.1:{}/0", input.redis_port);

    let direct_config = signer_config(
        root,
        "v7-direct",
        freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID,
    );
    let source_config = signer_config(root, "v7-exchange-source", NATIVE_EXCHANGE_V3_PROFILE_ID);
    let target_config = signer_config(root, "v7-exchange-target", NATIVE_EXCHANGE_V3_PROFILE_ID);
    let direct = generate_signer(&direct_config, &issuer_id)?;
    let source = generate_signer(&source_config, &issuer_id)?;
    let target = generate_signer(&target_config, &issuer_id)?;
    let mut direct_config = direct_config;
    let mut source_config = source_config;
    let mut target_config = target_config;
    direct_config.descriptor_id = direct.metadata().descriptor_id.clone();
    source_config.descriptor_id = source.metadata().descriptor_id.clone();
    target_config.descriptor_id = target.metadata().descriptor_id.clone();
    let inventory = crate::v7_signers::V7SignerInventory::from_signers(
        std::sync::Arc::new(crate::v7_signers::V7Signer::load_existing(
            &signer_spec(&direct_config, &issuer_id)?,
            true,
        )?),
        vec![
            std::sync::Arc::new(crate::v7_signers::V7Signer::load_existing(
                &signer_spec(&direct_config, &issuer_id)?,
                true,
            )?),
            std::sync::Arc::new(crate::v7_signers::V7Signer::load_existing(
                &signer_spec(&source_config, &issuer_id)?,
                true,
            )?),
            std::sync::Arc::new(crate::v7_signers::V7Signer::load_existing(
                &signer_spec(&target_config, &issuer_id)?,
                true,
            )?),
        ],
        Some(&root.join("v7-registry.json")),
    )?;

    let source_descriptor = descriptor(&source);
    let target_descriptor = descriptor(&target);
    let source_keyset_id = keyset_id(std::slice::from_ref(&source_descriptor.descriptor_id));
    let target_keyset_id = keyset_id(std::slice::from_ref(&target_descriptor.descriptor_id));
    let mut transition = NativeExchangeV3Transition {
        transition_id: String::new(),
        profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.to_owned(),
        source_keyset_id: source_keyset_id.clone(),
        target_keyset_id: target_keyset_id.clone(),
        source_slots: vec![NativeExchangeV3Slot {
            descriptor_id: source_descriptor.descriptor_id.clone(),
            keyset_id: source_keyset_id.clone(),
            slot_id: format!("source-{}", input.run_id),
            quantity: 1,
        }],
        output_slots: vec![NativeExchangeV3Slot {
            descriptor_id: target_descriptor.descriptor_id.clone(),
            keyset_id: target_keyset_id.clone(),
            slot_id: format!("target-{}", input.run_id),
            quantity: 1,
        }],
    };
    transition.transition_id = transition_id(&transition);
    let mut exchange = NativeExchangeV3Discovery {
        version: 3,
        profile: NativeExchangeV3Profile {
            version: 3,
            profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.to_owned(),
            graph_id: String::new(),
            suite: NATIVE_EXCHANGE_V3_SUITE.to_owned(),
            modulus_bits: 3072,
            exponent: 65_537,
        },
        active_descriptors: vec![source_descriptor.clone(), target_descriptor.clone()],
        retained_descriptors: Vec::new(),
        active_keysets: vec![
            NativeExchangeV3Keyset {
                keyset_id: source_keyset_id.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.to_owned(),
                descriptor_ids: vec![source_descriptor.descriptor_id.clone()],
            },
            NativeExchangeV3Keyset {
                keyset_id: target_keyset_id.clone(),
                profile_id: NATIVE_EXCHANGE_V3_PROFILE_ID.to_owned(),
                descriptor_ids: vec![target_descriptor.descriptor_id.clone()],
            },
        ],
        retained_keysets: Vec::new(),
        transitions: vec![transition],
    };
    exchange.profile.graph_id = exchange_graph_id(&exchange);
    let source_metadata = source.metadata();
    let mut policy = NativeGraphIssuanceV7Policy {
        policy_id: String::new(),
        profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.to_owned(),
        graph_id: exchange.profile.graph_id.clone(),
        keyset_id: source_keyset_id,
        descriptor_id: source_descriptor.descriptor_id.clone(),
        token_key_id: source_metadata.token_key_id.clone(),
        issuer_id: issuer_id.clone(),
        asset_id: USD.to_owned(),
        amount_minor: AMOUNT.to_string(),
        suite: source_metadata.suite.clone(),
        modulus_bits: source_metadata.modulus_bits,
        exponent: source_metadata.exponent,
        quantity: 1,
        pubkey_spki_b64: source_metadata.pubkey_spki_b64.clone(),
        spki_fingerprint: source_metadata.spki_fingerprint.clone(),
        valid_from: source_metadata.valid_from,
        valid_until: source_metadata.valid_until,
    };
    policy.policy_id = graph_policy_id(&policy)?;
    let graph = NativeGraphIssuanceV7Discovery {
        version: NATIVE_GRAPH_ISSUANCE_V7_VERSION,
        profile_id: NATIVE_GRAPH_ISSUANCE_V7_PROFILE_ID.to_owned(),
        active_policies: vec![policy.clone()],
        retained_policies: Vec::new(),
    };
    exchange.validate().map_err(anyhow::Error::msg)?;
    graph.validate().map_err(anyhow::Error::msg)?;
    freebird_common::api::validate_native_graph_issuance_v7_exchange_bindings(
        &issuer_id, &graph, &exchange,
    )
    .map_err(anyhow::Error::msg)?;
    if source.metadata().amount_minor != target.metadata().amount_minor
        || source.metadata().amount_minor != AMOUNT
        || inventory.len() != 3
        || direct.identity().profile_id() != freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID
    {
        bail!("generated signer roles or equal-denomination transition are inconsistent")
    }

    let exchange_bytes = write_json(root, "exchange.json", &exchange)?;
    let graph_bytes = write_json(root, "graph.json", &graph)?;
    let _ = (exchange_bytes, graph_bytes);
    write_json(
        root,
        "v7-extra-signers.json",
        &[source_config.clone(), target_config.clone()],
    )?;

    let v4_path = root.join("v4.key");
    let (v4_secret, v4_public_b64, v4_kid) =
        crate::keys::load_or_generate_keypair_b64_at(&v4_path)?;
    ensure_private_file(&v4_path)?;
    u8::try_from(verifier_id.len()).context("verifier ID is too long")?;
    u8::try_from(audience.len()).context("audience is too long")?;
    let scope_digest = freebird_crypto::build_scope_digest(&verifier_id, &audience)
        .map_err(|error| anyhow::anyhow!("derive pinned V4 scope digest: {error:?}"))?;
    let scope_b64 = b64(&scope_digest);
    let mut authority = random32();
    let receipt_seed = random32();
    let receipt_signing = SigningKey::from_bytes(&receipt_seed);
    let receipt_public = receipt_signing.verifying_key().to_bytes();
    let receipt_id = hex::encode(Sha256::digest(receipt_public));
    let receipt_metadata = crate::exchange::ReceiptKeyMetadata {
        key_id: receipt_id.clone(),
        algorithm: "Ed25519".into(),
        purpose: "exchange_receipt_v7".into(),
        public_key_b64: b64(&receipt_public),
        valid_from: source_metadata.valid_from.max(1) as u64,
        valid_until: freebird_common::api::EXCHANGE_MAX_VALID_UNTIL as u64,
    };
    write_private(&root.join("receipt.key"), receipt_seed.as_ref())?;
    write_json(root, "receipt.json", &receipt_metadata)?;

    let v4_key_b64 = b64(v4_secret.as_ref());
    let issuer_keyring = serde_json::to_string(&BTreeMap::from([(
        issuer_id.clone(),
        BTreeMap::from([(v4_kid.clone(), v4_key_b64.clone())]),
    )]))?;
    let verifier_keyring = serde_json::to_string(&BTreeMap::from([(v4_kid.clone(), v4_key_b64)]))?;
    let issuer_admin = b64(random32().as_ref());
    let verifier_admin = b64(random32().as_ref());
    let native_config = |config: &crate::config::NativeBearerV7Config| -> Result<String> {
        Ok(config.descriptor_id.clone())
    };
    let issuer_env = build_issuer_env(
        input,
        root,
        &issuer_id,
        &issuer_origin,
        &redis_url,
        &verifier_id,
        &audience,
        &issuer_admin,
        &issuer_keyring,
        &direct_config,
        &native_config(&direct_config)?,
    )?;
    let verifier_env = build_verifier_env(
        input,
        &issuer_origin,
        &verifier_origin,
        &redis_url,
        &verifier_id,
        &audience,
        &verifier_admin,
        &verifier_keyring,
    );
    let issuer_envelope = EnvEnvelope {
        version: ENV_VERSION,
        run_id: &input.run_id,
        role: "issuer",
        env: &issuer_env,
    };
    let verifier_envelope = EnvEnvelope {
        version: ENV_VERSION,
        run_id: &input.run_id,
        role: "verifier",
        env: &verifier_env,
    };
    write_json(root, "issuer.env.json", &issuer_envelope)?;
    write_json(root, "verifier.env.json", &verifier_envelope)?;

    let manifest = build_manifest(
        input,
        &issuer_id,
        &issuer_origin,
        &verifier_origin,
        &verifier_id,
        &audience,
        &v4_kid,
        &v4_public_b64,
        &scope_b64,
        &authority,
        &receipt_metadata,
        &direct,
        &exchange,
        &graph,
    )?;
    let manifest_bytes = write_json(root, "manifest.json", &manifest)?;

    validate_generated_native(root, &issuer_env, &manifest_bytes)?;
    run_strict_sdk_adapter(root)?;
    for name in FIXED_FILES
        .iter()
        .filter(|name| **name != "fixture.private.json")
    {
        ensure_private_file(&root.join(name))?;
    }

    let handoff = json!({
        "version": VERSION,
        "run_id": input.run_id,
        "manifest_file": "manifest.json",
        "manifest_sha256_hex": hex::encode(Sha256::digest(&manifest_bytes)),
        "issuer_env_file": "issuer.env.json",
        "verifier_env_file": "verifier.env.json",
        "redis": {"host": "127.0.0.1", "port": input.redis_port, "database": 0}
    });
    write_json(root, "fixture.private.json", &handoff)?;
    authority.zeroize();
    Ok(())
}

fn descriptor(signer: &crate::v7_signers::V7Signer) -> NativeExchangeV3Descriptor {
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

#[derive(Serialize)]
struct EnvEnvelope<'a> {
    version: &'static str,
    run_id: &'a str,
    role: &'static str,
    env: &'a BTreeMap<String, String>,
}

// Keep independently pinned generated environment inputs explicit in this test fixture.
#[allow(clippy::too_many_arguments)]
fn build_issuer_env(
    input: &Inputs,
    root: &Path,
    issuer_id: &str,
    _issuer_origin: &str,
    redis_url: &str,
    verifier_id: &str,
    audience: &str,
    admin: &str,
    v4_keyring: &str,
    direct: &crate::config::NativeBearerV7Config,
    direct_descriptor_id: &str,
) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    let mut put = |key: &str, value: String| {
        values.insert(key.to_owned(), value);
    };
    put("BIND_ADDR", format!("127.0.0.1:{}", input.issuer_port));
    put("ISSUER_ID", issuer_id.to_owned());
    put("ADMIN_API_KEY", admin.to_owned());
    put("FREEBIRD_ENV", "production".to_owned());
    put("FREEBIRD_UNSAFE_DEVELOPMENT_MODE", "false".to_owned());
    put("ALLOW_UNSAFE_V4_ROTATION", "false".to_owned());
    put("REQUIRE_TLS", "false".to_owned());
    put("BEHIND_PROXY", "false".to_owned());
    put("HSM_ENABLE", "false".to_owned());
    put("ISSUER_SK_PATH", root.join("v4.key").display().to_string());
    put(
        "KEY_ROTATION_STATE_PATH",
        root.join("runtime/issuer/rotation.json")
            .display()
            .to_string(),
    );
    put(
        "AUDIT_LOG_PATH",
        root.join("logs/issuer-audit.json").display().to_string(),
    );
    put("NATIVE_BEARER_V7_ENABLE", "true".to_owned());
    put(
        "NATIVE_BEARER_V7_SK_PATH",
        direct.sk_path.display().to_string(),
    );
    put(
        "NATIVE_BEARER_V7_METADATA_PATH",
        direct.metadata_path.display().to_string(),
    );
    put(
        "NATIVE_BEARER_V7_REGISTRY_PATH",
        direct.registry_path.display().to_string(),
    );
    put("NATIVE_BEARER_V7_PROFILE_ID", direct.profile_id.clone());
    put(
        "NATIVE_BEARER_V7_DESCRIPTOR_ID",
        direct_descriptor_id.to_owned(),
    );
    put("NATIVE_BEARER_V7_TOKEN_KEY_ID", direct.token_key_id.clone());
    put("NATIVE_BEARER_V7_ASSET_ID", USD.to_owned());
    put("NATIVE_BEARER_V7_AMOUNT_MINOR", AMOUNT.to_string());
    put("NATIVE_BEARER_V7_VALIDITY", "1d".to_owned());
    put(
        "NATIVE_V7_SIGNER_CONFIG_PATHS",
        root.join("v7-extra-signers.json").display().to_string(),
    );
    put("NATIVE_EXCHANGE_V7_ENABLE", "true".to_owned());
    put(
        "NATIVE_EXCHANGE_V7_DISCOVERY_PATH",
        root.join("exchange.json").display().to_string(),
    );
    put(
        "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_KEY_PATH",
        root.join("receipt.key").display().to_string(),
    );
    put(
        "NATIVE_EXCHANGE_V7_ACTIVE_RECEIPT_METADATA_PATH",
        root.join("receipt.json").display().to_string(),
    );
    put("NATIVE_EXCHANGE_V7_REDIS_URL", redis_url.to_owned());
    put("NATIVE_EXCHANGE_V7_RECEIPT_LIFETIME", "2592000".to_owned());
    put("NATIVE_GRAPH_ISSUANCE_V7_ENABLE", "true".to_owned());
    put(
        "NATIVE_GRAPH_ISSUANCE_V7_POLICY_PATH",
        root.join("graph.json").display().to_string(),
    );
    put(
        "NATIVE_GRAPH_ISSUANCE_V7_AUTHORIZATION",
        "v4_local".to_owned(),
    );
    put(
        "NATIVE_GRAPH_ISSUANCE_V7_VERIFIER_ID",
        verifier_id.to_owned(),
    );
    put("NATIVE_GRAPH_ISSUANCE_V7_AUDIENCE", audience.to_owned());
    put(
        "NATIVE_GRAPH_ISSUANCE_V7_V4_KEYRING_B64",
        v4_keyring.to_owned(),
    );
    put("SYBIL_REPLAY_STORE", "redis".to_owned());
    put("SYBIL_REPLAY_REDIS_URL", redis_url.to_owned());
    put("SYBIL_RESISTANCE", "pow".to_owned());
    put("SYBIL_POW_DIFFICULTY", "8".to_owned());
    put("SYBIL_PROGRESSIVE_TRUST_SALT", b64(random32().as_ref()));
    put("SYBIL_PROOF_OF_DIVERSITY_SALT", b64(random32().as_ref()));
    put("SYBIL_MULTI_PARTY_VOUCHING_SALT", b64(random32().as_ref()));
    Ok(values)
}

// Keep independently pinned generated environment inputs explicit in this test fixture.
#[allow(clippy::too_many_arguments)]
fn build_verifier_env(
    input: &Inputs,
    issuer_origin: &str,
    _verifier_origin: &str,
    redis_url: &str,
    verifier_id: &str,
    audience: &str,
    admin: &str,
    keyring: &str,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "BIND_ADDR".into(),
            format!("127.0.0.1:{}", input.verifier_port),
        ),
        ("ADMIN_API_KEY".into(), admin.to_owned()),
        ("VERIFIER_ENV".into(), "production".into()),
        ("VERIFIER_ALLOW_UNSAFE".into(), "false".into()),
        ("IN_MEMORY_REPLAY_STORE".into(), "false".into()),
        ("REDIS_URL".into(), redis_url.to_owned()),
        ("VERIFIER_ACCEPTED_TOKEN_VERSIONS".into(), "v4,v7".into()),
        (
            "ISSUER_URLS".into(),
            format!("{issuer_origin}/.well-known/issuer"),
        ),
        ("VERIFIER_KEYRING_B64".into(), keyring.to_owned()),
        ("VERIFIER_ID".into(), verifier_id.to_owned()),
        ("VERIFIER_AUDIENCE".into(), audience.to_owned()),
        (
            "VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS".into(),
            issuer_origin.to_owned(),
        ),
        ("REFRESH_INTERVAL_MIN".into(), "1".into()),
        (
            "VERIFIER_REPLAY_AUTHORITY_PROBE_INTERVAL".into(),
            "2s".into(),
        ),
        (
            "VERIFIER_REPLAY_AUTHORITY_MAX_STALENESS".into(),
            "10s".into(),
        ),
        ("REQUIRE_TLS".into(), "false".into()),
        ("BEHIND_PROXY".into(), "false".into()),
    ])
}

// Keep public manifest pins explicit so test-fixture provenance remains reviewable.
#[allow(clippy::too_many_arguments)]
fn build_manifest(
    input: &Inputs,
    issuer_id: &str,
    issuer_origin: &str,
    verifier_origin: &str,
    verifier_id: &str,
    audience: &str,
    v4_kid: &str,
    v4_public_b64: &str,
    scope_b64: &str,
    authority: &[u8; 32],
    receipt: &crate::exchange::ReceiptKeyMetadata,
    direct: &crate::v7_signers::V7Signer,
    exchange: &NativeExchangeV3Discovery,
    graph: &NativeGraphIssuanceV7Discovery,
) -> Result<Value> {
    let v4 = json!({
        "credential_issuer_id": issuer_id,
        "kid": v4_kid,
        "public_key_b64": v4_public_b64,
        "verifier_id": verifier_id,
        "audience": audience,
        "scope_digest_b64": scope_b64,
    });
    let direct = direct.metadata();
    Ok(json!({
        "version": "scarcity/freebird-gate0/v1",
        "run_id": input.run_id,
        "issuer_origin": issuer_origin,
        "verifier_origin": verifier_origin,
        "issuer_id": issuer_id,
        "graph_issuer_id": issuer_id,
        "asset_id": USD,
        "graph_policy_id": graph.active_policies.first().context("graph policy missing")?.policy_id,
        "v4": v4,
        "replay_authority": {
            "authority_id": b64(authority),
            "v4_scope_digest_tombstones": [scope_b64],
        },
        "receipt_keyset": {
            "issuer_id": issuer_id,
            "origin": issuer_origin,
            "profile_id": NATIVE_EXCHANGE_V3_PROFILE_ID,
            "keys": [{
                "key_id": receipt.key_id,
                "algorithm": receipt.algorithm,
                "purpose": receipt.purpose,
                "public_key_b64": receipt.public_key_b64,
                "status": "active",
                "valid_from": receipt.valid_from,
                "valid_until": receipt.valid_until,
            }],
        },
        "discovery_pins": {
            "native_bearer_v7": direct,
            "native_bearer_v7_retained": [],
            "native_exchange_v7": exchange,
            "native_graph_issuance_v7": graph,
        },
        "sybil": {"type": "proof_of_work", "difficulty": 8},
    }))
}

fn validate_generated_native(
    root: &Path,
    issuer_env: &BTreeMap<String, String>,
    manifest_bytes: &[u8],
) -> Result<()> {
    let exchange_redis_url = issuer_env
        .get("NATIVE_EXCHANGE_V7_REDIS_URL")
        .context("exchange Redis URL missing from generated issuer env")?;
    validate_sybil_replay_settings(issuer_env, exchange_redis_url)?;
    let discovery: V7KeyDiscoveryResp = serde_json::from_slice(&serde_json::to_vec(&json!({
        "issuer_id": issuer_env.get("ISSUER_ID").context("issuer ID missing")?,
        "current_epoch": 1,
        "valid_epochs": [1],
        "epoch_duration_sec": 86_400,
        "voprf": {"suite":"VOPRF-P256-SHA256","kid":"gate0-shape","pubkey":"gate0-shape"},
        "native_bearer_v7": serde_json::from_slice::<Value>(&fs::read(root.join("v7-direct.json"))?)?,
        "native_bearer_v7_retained": [],
        "native_exchange_v7": serde_json::from_slice::<Value>(&fs::read(root.join("exchange.json"))?)?,
        "native_graph_issuance_v7": serde_json::from_slice::<Value>(&fs::read(root.join("graph.json"))?)?,
    }))?)?;
    discovery.validated_registry().map_err(anyhow::Error::msg)?;

    let env_guard = ProcessEnvGuard::install(issuer_env)?;
    if env::var("SYBIL_REPLAY_STORE").as_deref() != Ok("redis")
        || env::var("SYBIL_REPLAY_REDIS_URL").as_deref() != Ok(exchange_redis_url.as_str())
    {
        bail!("generated issuer replay-store environment differs from its pinned Redis URL")
    }
    // This only constructs the selected backend. RedisReplayStore::new is
    // deliberately lazy; generation never pings or otherwise contacts Redis.
    let _sybil_replay_store = crate::sybil_resistance::replay_store::replay_store_from_env()?;
    let mut config = crate::config::Config::from_env()?;
    let _admin = super::preflight::run(&mut config)?;
    super::validate_v7_runtime_config(&config)?;
    drop(env_guard);

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("issuer crate has no repository root")?;
    let python = Command::new("python3")
        .arg(repo_root.join("scripts/gate0/validate_manifest.py"))
        .arg(root.join("manifest.json"))
        .output()
        .context("run the approved G0.1 public manifest validator")?;
    if !python.status.success() {
        bail!("approved G0.1 manifest validation failed")
    }
    let _ = manifest_bytes;
    Ok(())
}

fn validate_sybil_replay_settings(
    issuer_env: &BTreeMap<String, String>,
    exchange_redis_url: &str,
) -> Result<()> {
    if issuer_env.get("SYBIL_REPLAY_STORE").map(String::as_str) != Some("redis") {
        bail!("issuer Sybil replay store must explicitly select Redis")
    }
    if issuer_env.get("SYBIL_REPLAY_REDIS_URL").map(String::as_str) != Some(exchange_redis_url) {
        bail!("issuer Sybil replay Redis URL must equal the pinned exchange DB0 URL")
    }
    if !exchange_redis_url.starts_with("redis://127.0.0.1:") || !exchange_redis_url.ends_with("/0")
    {
        bail!("issuer replay store requires its owned loopback Redis DB 0")
    }
    Ok(())
}

struct ProcessEnvGuard {
    previous: Vec<(String, Option<std::ffi::OsString>)>,
}

impl ProcessEnvGuard {
    fn install(values: &BTreeMap<String, String>) -> Result<Self> {
        let previous = values
            .keys()
            .map(|key| (key.clone(), env::var_os(key)))
            .collect::<Vec<_>>();
        for (key, value) in values {
            env::set_var(key, value);
        }
        Ok(Self { previous })
    }
}

impl Drop for ProcessEnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            if let Some(value) = value {
                env::set_var(key, value);
            } else {
                env::remove_var(key);
            }
        }
    }
}

fn run_strict_sdk_adapter(root: &Path) -> Result<()> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("issuer crate has no repository root")?;
    let sdk_dir = repo_root.join("sdk/js");
    let adapter = sdk_dir.join("tests/gate0-fixture.test.ts");
    if !adapter.is_file() {
        bail!("strict SDK Gate 0 adapter is absent; refusing to publish the fixture handoff")
    }
    let output = Command::new("npm")
        .args(["test", "--", "--run", "tests/gate0-fixture.test.ts"])
        .current_dir(&sdk_dir)
        .env("FREEBIRD_GATE0_DIRECTORY", root)
        .output()
        .context("execute strict SDK Gate 0 adapter")?;
    if !output.status.success() {
        bail!("strict SDK Gate 0 adapter failed; refusing to publish the fixture handoff")
    }
    Ok(())
}

fn ensure_private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("generated private key is not a regular nonsymlink file")
    }
    set_mode(path, 0o600)
}

#[cfg(test)]
mod input_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::tempdir;

    fn env_for(path: &Path) -> HashMap<String, Option<String>> {
        HashMap::from([
            (
                "FREEBIRD_GATE0_GENERATE".into(),
                Some(GENERATOR_OPT_IN.into()),
            ),
            (
                "FREEBIRD_GATE0_DIRECTORY".into(),
                Some(path.display().to_string()),
            ),
            ("FREEBIRD_GATE0_RUN_ID".into(), Some("gate0-test.1".into())),
            ("FREEBIRD_GATE0_ISSUER_PORT".into(), Some("21001".into())),
            ("FREEBIRD_GATE0_VERIFIER_PORT".into(), Some("21002".into())),
            ("FREEBIRD_GATE0_REDIS_PORT".into(), Some("21003".into())),
        ])
    }

    fn private_empty_dir(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn explicit_input_parsing_accepts_only_canonical_distinct_high_ports() {
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("owned");
        private_empty_dir(&root);
        let vars = env_for(&root);
        let parsed = Inputs::parse(&vars).unwrap();
        assert_eq!(parsed.issuer_port, 21_001);
        assert_eq!(parsed.verifier_port, 21_002);
        assert_eq!(parsed.redis_port, 21_003);
        for value in ["020001", "19999", "65536", "+21001", "21001 "] {
            let mut bad = vars.clone();
            bad.insert("FREEBIRD_GATE0_ISSUER_PORT".into(), Some(value.into()));
            assert!(
                Inputs::parse(&bad).is_err(),
                "accepted invalid port {value}"
            );
        }
        let mut duplicate = vars.clone();
        duplicate.insert("FREEBIRD_GATE0_REDIS_PORT".into(), Some("21002".into()));
        assert!(Inputs::parse(&duplicate).is_err());
    }

    #[test]
    fn explicit_opt_in_and_all_required_environment_values_are_enforced() {
        assert!(Inputs::parse(&HashMap::new()).is_err());
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap().join("owned");
        private_empty_dir(&root);
        let mut vars = env_for(&root);
        vars.insert("FREEBIRD_GATE0_GENERATE".into(), Some("yes".into()));
        assert!(Inputs::parse(&vars).is_err());
        vars = env_for(&root);
        vars.remove("FREEBIRD_GATE0_REDIS_PORT");
        assert!(Inputs::parse(&vars).is_err());
        vars = env_for(&root);
        vars.insert("FREEBIRD_GATE0_RUN_ID".into(), Some("../unsafe".into()));
        assert!(Inputs::parse(&vars).is_err());
    }

    #[test]
    fn caller_directory_must_be_empty_nonsymlink_and_exactly_private() {
        let temp = tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let empty = base.join("empty");
        private_empty_dir(&empty);
        assert!(validate_output_directory(&empty).is_ok());

        let nonempty = base.join("nonempty");
        private_empty_dir(&nonempty);
        fs::write(nonempty.join("sentinel"), b"owned elsewhere").unwrap();
        assert!(validate_output_directory(&nonempty).is_err());

        let permissive = base.join("permissive");
        fs::create_dir(&permissive).unwrap();
        fs::set_permissions(&permissive, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_output_directory(&permissive).is_err());

        let target = base.join("target");
        private_empty_dir(&target);
        let link = base.join("link");
        symlink(&target, &link).unwrap();
        assert!(validate_output_directory(&link).is_err());
    }

    #[test]
    fn issuer_and_verifier_replay_and_metadata_urls_are_pinned_to_one_owned_redis() {
        let temp = tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let input = Inputs {
            directory: root.clone(),
            run_id: "gate0-test".into(),
            issuer_port: 21_101,
            verifier_port: 21_102,
            redis_port: 21_103,
        };
        let redis = "redis://127.0.0.1:21103/0";
        let direct = crate::config::NativeBearerV7Config {
            sk_path: root.join("v7-direct.der"),
            metadata_path: root.join("v7-direct.json"),
            registry_path: root.join("v7-registry.json"),
            profile_id: freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID.into(),
            descriptor_id: "11".repeat(32),
            token_key_id: "22".repeat(32),
            asset_id: USD.into(),
            amount_minor: AMOUNT,
            validity_secs: VALIDITY_SECONDS,
        };
        let issuer_env = build_issuer_env(
            &input,
            &root,
            "issuer:gate0:test",
            "http://127.0.0.1:21101",
            redis,
            "verifier:gate0:test",
            "audience:gate0:test",
            &"a".repeat(32),
            "{}",
            &direct,
            &direct.descriptor_id,
        )
        .unwrap();
        validate_sybil_replay_settings(&issuer_env, redis).unwrap();
        assert_eq!(
            issuer_env.get("SYBIL_REPLAY_STORE").map(String::as_str),
            Some("redis")
        );
        assert_eq!(
            issuer_env.get("SYBIL_REPLAY_REDIS_URL").map(String::as_str),
            Some(redis)
        );
        assert_eq!(
            issuer_env
                .get("NATIVE_EXCHANGE_V7_REDIS_URL")
                .map(String::as_str),
            Some(redis)
        );

        let verifier_env = build_verifier_env(
            &input,
            "http://127.0.0.1:21101",
            "http://127.0.0.1:21102",
            redis,
            "verifier:gate0:test",
            "audience:gate0:test",
            &"b".repeat(32),
            "{}",
        );
        assert_eq!(
            verifier_env.get("REDIS_URL").map(String::as_str),
            Some(redis)
        );
        assert_eq!(
            verifier_env.get("ISSUER_URLS").map(String::as_str),
            Some("http://127.0.0.1:21101/.well-known/issuer")
        );
        assert_eq!(
            verifier_env
                .get("VERIFIER_GRAPH_ISSUANCE_ISSUER_URLS")
                .map(String::as_str),
            Some("http://127.0.0.1:21101")
        );
    }

    #[test]
    fn sybil_replay_backend_fails_closed_for_missing_memory_and_wrong_targets() {
        let url = "redis://127.0.0.1:21103/0";
        let valid = BTreeMap::from([
            ("SYBIL_REPLAY_STORE".to_owned(), "redis".to_owned()),
            ("SYBIL_REPLAY_REDIS_URL".to_owned(), url.to_owned()),
        ]);
        validate_sybil_replay_settings(&valid, url).unwrap();
        let missing_store = BTreeMap::from([("SYBIL_REPLAY_REDIS_URL".to_owned(), url.to_owned())]);
        assert!(validate_sybil_replay_settings(&missing_store, url).is_err());
        let memory = BTreeMap::from([
            ("SYBIL_REPLAY_STORE".to_owned(), "memory".to_owned()),
            ("SYBIL_REPLAY_REDIS_URL".to_owned(), url.to_owned()),
        ]);
        assert!(validate_sybil_replay_settings(&memory, url).is_err());
        let wrong_target = BTreeMap::from([
            ("SYBIL_REPLAY_STORE".to_owned(), "redis".to_owned()),
            (
                "SYBIL_REPLAY_REDIS_URL".to_owned(),
                "redis://127.0.0.1:21104/0".to_owned(),
            ),
        ]);
        assert!(validate_sybil_replay_settings(&wrong_target, url).is_err());
    }
}
