// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{IssueReq, IssueResp, SybilProof, VerifyReq, VerifyResp};
use freebird_crypto::voprf::core::Client;
use rand::RngCore;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
struct SavedToken {
    token_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayFixture {
    schema_version: u32,
    issuer_url: String,
    verifier_url: String,
    token_b64: String,
    issuer_id: String,
    kid: String,
    issuer_voprf_pubkey_b64: String,
    verifier_id: String,
    audience: String,
    scope_digest_b64: String,
}

struct IssuedToken {
    token_b64: String,
    fixture: ReplayFixture,
}

#[derive(Clone, Debug)]
struct ClientOptions {
    issuer_url: String,
    verifier_url: String,
    sybil_proof_json: Option<PathBuf>,
    pow_difficulty: Option<u32>,
}

impl ClientOptions {
    fn from_env() -> Self {
        Self {
            issuer_url: std::env::var("FREEBIRD_ISSUER_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string()),
            verifier_url: std::env::var("FREEBIRD_VERIFIER_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8082".to_string()),
            sybil_proof_json: std::env::var("FREEBIRD_SYBIL_PROOF_JSON")
                .ok()
                .map(PathBuf::from),
            pow_difficulty: std::env::var("FREEBIRD_POW_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok()),
        }
    }
}

#[derive(Debug)]
struct ParsedCli {
    mode: String,
    stress_count: usize,
    options: ClientOptions,
    path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let parsed = parse_cli()?;

    match parsed.mode.as_str() {
        "--help" | "-h" => {
            print_help();
            return Ok(());
        }
        "--replay" => {
            println!("🔁 REPLAY ATTACK TEST MODE");
            test_replay_attack(&parsed.options).await?;
        }
        "--double-spend" => {
            println!("💸 DOUBLE-SPEND TEST MODE");
            test_double_spend(&parsed.options).await?;
        }
        "--save" => {
            println!("💾 SAVE TOKEN MODE");
            save_token_mode(&parsed.options).await?;
        }
        "--load" => {
            println!("📂 LOAD TOKEN MODE");
            load_token_mode(&parsed.options).await?;
        }
        "--expired" => {
            println!("⏰ EXPIRED TOKEN TEST MODE");
            test_expired_token(&parsed.options).await?;
        }
        "--stress" => {
            println!("⚡ STRESS TEST MODE (n={})", parsed.stress_count);
            stress_test(parsed.stress_count, &parsed.options).await?;
        }
        "backup-fixture-create" => {
            create_replay_fixture(&parsed.options, parsed.path.as_ref().unwrap()).await?;
        }
        "backup-fixture-validate-replay" => {
            validate_replay_fixture(&parsed.options, parsed.path.as_ref().unwrap()).await?;
        }
        _ => {
            println!("🕊️ NORMAL MODE - Fresh token issuance and verification");
            normal_flow(&parsed.options).await?;
        }
    }

    Ok(())
}

fn parse_cli() -> Result<ParsedCli> {
    let mut options = ClientOptions::from_env();
    let mut mode: Option<String> = None;
    let mut stress_count = 5usize;
    let mut path = None;
    let mut args = std::env::args().skip(1).peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "backup-fixture" => mode = Some("backup-fixture".to_string()),
            "create" | "validate-replay" => {
                if mode.as_deref() != Some("backup-fixture") {
                    return Err(anyhow!("{} must follow backup-fixture", arg));
                }
                mode = Some(format!("backup-fixture-{}", arg));
            }
            "--output" | "--input" => {
                path = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("{} requires a path", arg))?,
                ));
            }
            "--issuer-url" => {
                options.issuer_url = args
                    .next()
                    .ok_or_else(|| anyhow!("--issuer-url requires a value"))?;
            }
            "--verifier-url" => {
                options.verifier_url = args
                    .next()
                    .ok_or_else(|| anyhow!("--verifier-url requires a value"))?;
            }
            "--sybil-proof-json" => {
                options.sybil_proof_json =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        anyhow!("--sybil-proof-json requires a path")
                    })?));
            }
            "--pow-difficulty" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("--pow-difficulty requires a value"))?;
                options.pow_difficulty = Some(value.parse()?);
            }
            "--help" | "-h" | "--replay" | "--double-spend" | "--save" | "--load" | "--expired"
            | "--stress" => {
                mode = Some(arg.clone());
                if arg == "--stress" {
                    if let Some(next) = args.peek() {
                        if !next.starts_with("--") {
                            stress_count = args.next().unwrap().parse()?;
                        }
                    }
                }
            }
            other => {
                if mode.is_none() {
                    mode = Some(other.to_string());
                } else {
                    return Err(anyhow!("unexpected argument: {}", other));
                }
            }
        }
    }

    if options.sybil_proof_json.is_some() && options.pow_difficulty.is_some() {
        return Err(anyhow!(
            "use either --sybil-proof-json or --pow-difficulty, not both"
        ));
    }

    if matches!(
        mode.as_deref(),
        Some("backup-fixture-create") | Some("backup-fixture-validate-replay")
    ) && path.is_none()
    {
        return Err(anyhow!("backup-fixture mode requires --output or --input"));
    }

    Ok(ParsedCli {
        mode: mode.unwrap_or_else(|| "normal".to_string()),
        stress_count,
        options,
        path,
    })
}

fn print_help() {
    println!("Freebird Interface - VOPRF Token Tester");
    println!();
    println!("USAGE:");
    println!("  interface.exe [MODE]");
    println!();
    println!("MODES:");
    println!("  (no args)       Normal flow - issue and verify a fresh token");
    println!("  --replay        Test replay protection (reuse same token twice)");
    println!("  --double-spend  Same as --replay (clearer name)");
    println!("  --expired       Test expiration validation");
    println!("  --save          Issue token and save to token.json");
    println!("  --load          Load token from token.json and try to verify");
    println!("  --stress N      Issue and verify N tokens in sequence (default: 5)");
    println!("  backup-fixture create --output PATH   Create a spent replay fixture");
    println!("  backup-fixture validate-replay --input PATH   Validate replay rejection");
    println!("  --help, -h      Show this help message");
    println!();
    println!("OPTIONS:");
    println!("  --issuer-url URL          Issuer base URL (env: FREEBIRD_ISSUER_URL)");
    println!("  --verifier-url URL        Verifier base URL (env: FREEBIRD_VERIFIER_URL)");
    println!("  --sybil-proof-json PATH   Attach a Sybil proof JSON object to issuance");
    println!("  --pow-difficulty N        Compute a request-bound proof-of-work proof");
    println!();
    println!("EXAMPLES:");
    println!("  interface.exe                    # Normal flow");
    println!("  interface.exe --pow-difficulty 20");
    println!("  interface.exe --sybil-proof-json proof.json");
    println!("  interface.exe --save             # Save a token");
    println!("  interface.exe --load             # Try to reuse saved token");
    println!("  interface.exe --replay           # Demonstrate replay protection");
    println!("  interface.exe --expired          # Test expiration validation");
    println!("  interface.exe --stress 10        # Issue 10 tokens");
}

async fn normal_flow(options: &ClientOptions) -> Result<()> {
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder().timeout(HTTP_TIMEOUT).build()?;

    // Issue token
    let token_b64 = issue_token(&http, options, ctx).await?;

    println!("✅ Token issued (V4 private-verification redemption token)");

    // Verify token
    let success = verify_token(&http, &options.verifier_url, &token_b64).await?;

    if success {
        println!("✅ SUCCESS! Token verified");
    } else {
        println!("❌ FAILED! Token rejected");
    }

    Ok(())
}

async fn test_replay_attack(options: &ClientOptions) -> Result<()> {
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder().timeout(HTTP_TIMEOUT).build()?;

    // Issue token
    println!("\n Step 1: Issuing fresh token...");
    let token_b64 = issue_token(&http, options, ctx).await?;

    // First verification (should succeed)
    println!("\n Step 2: First verification attempt...");
    let success1 = verify_token(&http, &options.verifier_url, &token_b64).await?;

    if !success1 {
        println!("First verification failed! Something is wrong.");
        return Ok(());
    }
    println!("First verification: SUCCESS");

    // Wait a moment
    println!("\n Waiting 2 seconds...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Second verification with SAME token (should fail)
    println!("\n Step 3: Replay attack - reusing the same token...");
    let success2 = verify_token(&http, &options.verifier_url, &token_b64).await?;

    if !success2 {
        println!("✅ REPLAY PROTECTION WORKING! Token was rejected on second use.");
        println!("   This proves the nullifier system prevents double-spending.");
    } else {
        println!("❌ SECURITY ISSUE! Token was accepted twice!");
        println!("   The replay protection is not working correctly.");
    }

    Ok(())
}

async fn test_double_spend(options: &ClientOptions) -> Result<()> {
    test_replay_attack(options).await
}

async fn test_expired_token(options: &ClientOptions) -> Result<()> {
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder().timeout(HTTP_TIMEOUT).build()?;

    // Issue token
    println!("\n Step 1: Issuing token...");
    let token_b64 = issue_token(&http, options, ctx).await?;
    println!("Token issued (V4 private-verification token)");

    // V4 tokens rely on verifier key acceptance policy, so verify normally.
    // The token's exp is set by the issuer and cannot be faked by the client.
    println!("\n Step 2: Verifying token...");
    let success = verify_token(&http, &options.verifier_url, &token_b64).await?;

    if success {
        println!("Token verified successfully.");
        println!("Note: V4 tokens do not carry client-controlled expiration.");
    } else {
        println!("Token verification failed.");
    }

    Ok(())
}

async fn save_token_mode(options: &ClientOptions) -> Result<()> {
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder().timeout(HTTP_TIMEOUT).build()?;

    let token_b64 = issue_token(&http, options, ctx).await?;

    let saved = SavedToken { token_b64 };

    std::fs::write("token.json", serde_json::to_string_pretty(&saved)?)?;
    println!("\n Token saved to token.json");
    println!("   Run 'interface.exe --load' to attempt replay");

    Ok(())
}

async fn load_token_mode(options: &ClientOptions) -> Result<()> {
    let data = std::fs::read_to_string("token.json")
        .map_err(|_| anyhow!("token.json not found. Run with --save first."))?;
    let saved: SavedToken = serde_json::from_str(&data)?;

    println!("Loaded token from token.json");

    let http = HttpClient::builder().timeout(HTTP_TIMEOUT).build()?;

    let success = verify_token(&http, &options.verifier_url, &saved.token_b64).await?;

    if success {
        println!("⚠️  WARNING: Token was accepted (either first use or replay protection failed)");
    } else {
        println!("✅ Token was rejected (likely already spent or expired)");
    }

    Ok(())
}

async fn stress_test(count: usize, options: &ClientOptions) -> Result<()> {
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder().timeout(HTTP_TIMEOUT).build()?;

    let mut successes = 0;
    let mut failures = 0;

    println!("\n⚡ Starting stress test with {} tokens...\n", count);

    for i in 1..=count {
        print!("Token {}/{}: ", i, count);

        match issue_token(&http, options, ctx).await {
            Ok(token_b64) => match verify_token(&http, &options.verifier_url, &token_b64).await {
                Ok(true) => {
                    println!("✅ SUCCESS");
                    successes += 1;
                }
                Ok(false) => {
                    println!("❌ REJECTED");
                    failures += 1;
                }
                Err(e) => {
                    println!("❌ ERROR: {}", e);
                    failures += 1;
                }
            },
            Err(e) => {
                println!("❌ ISSUE FAILED: {}", e);
                failures += 1;
            }
        }
    }

    println!("\n📊 RESULTS:");
    println!("   Successes: {}/{}", successes, count);
    println!("   Failures:  {}/{}", failures, count);

    Ok(())
}

async fn issue_token(http: &HttpClient, options: &ClientOptions, ctx: &[u8]) -> Result<String> {
    Ok(issue_token_detailed(http, options, ctx).await?.token_b64)
}

async fn issue_token_detailed(
    http: &HttpClient,
    options: &ClientOptions,
    ctx: &[u8],
) -> Result<IssuedToken> {
    // Get issuer metadata first; V4 binds the issuer/kid into the blinded input.
    let wk: serde_json::Value = http
        .get(format!("{}/.well-known/issuer", options.issuer_url))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let issuer_id = wk["issuer_id"]
        .as_str()
        .ok_or_else(|| anyhow!("missing issuer_id"))?
        .to_string();
    let kid = wk["voprf"]["kid"]
        .as_str()
        .ok_or_else(|| anyhow!("missing kid"))?
        .to_string();
    let pubkey_b64 = wk["voprf"]["pubkey"]
        .as_str()
        .ok_or_else(|| anyhow!("missing pubkey"))?
        .to_string();
    let issuer_pubkey_bytes = Base64UrlUnpadded::decode_vec(&pubkey_b64)?;

    // Get verifier metadata so the token is bound to this verifier/audience.
    let verifier_meta: serde_json::Value = http
        .get(format!("{}/.well-known/verifier", options.verifier_url))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let verifier_id = verifier_meta["verifier_id"]
        .as_str()
        .ok_or_else(|| anyhow!("missing verifier_id"))?;
    let audience = verifier_meta["audience"]
        .as_str()
        .ok_or_else(|| anyhow!("missing audience"))?;
    let scope_digest_b64 = verifier_meta["scope_digest_b64"]
        .as_str()
        .ok_or_else(|| anyhow!("missing scope_digest_b64"))?;
    let scope_digest_vec = Base64UrlUnpadded::decode_vec(scope_digest_b64)?;
    let scope_digest: [u8; freebird_crypto::PRIVATE_TOKEN_SCOPE_DIGEST_LEN] = scope_digest_vec
        .try_into()
        .map_err(|_| anyhow!("scope_digest must be 32 bytes"))?;
    let expected_scope = freebird_crypto::build_scope_digest(verifier_id, audience)
        .map_err(|e| anyhow!("{:?}", e))?;
    if scope_digest != expected_scope {
        return Err(anyhow!("verifier scope metadata is inconsistent"));
    }

    // Initialize OPRF client with a random nonce and verifier-bound scope.
    let mut client = Client::new(ctx);
    let mut nonce = [0u8; freebird_crypto::PRIVATE_TOKEN_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let input = freebird_crypto::build_private_token_input(&issuer_id, &kid, &nonce, &scope_digest)
        .map_err(|e| anyhow!("{:?}", e))?;

    // Blind
    let (blinded_bytes, blind_state) = client.blind(&input).map_err(|e| anyhow!("{:?}", e))?;
    let blinded_b64 = Base64UrlUnpadded::encode_string(&blinded_bytes);
    let sybil_proof = build_sybil_proof(options, &issuer_id, &blinded_b64)?;

    // Send to issuer
    let issue_resp: IssueResp = http
        .post(format!("{}/v1/oprf/issue", options.issuer_url))
        .json(&IssueReq {
            blinded_element_b64: blinded_b64,
            ctx_b64: None,
            sybil_proof,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if issue_resp.kid != kid || issue_resp.issuer_id != issuer_id {
        return Err(anyhow!("issuer metadata changed during issuance"));
    }

    // Finalize: unblind the VOPRF evaluation to get the V4 authenticator.
    let token_bytes = Base64UrlUnpadded::decode_vec(&issue_resp.token)?;
    let output = client
        .finalize(blind_state, &token_bytes, &issuer_pubkey_bytes)
        .map_err(|e| anyhow!("{:?}", e))?;

    // Build the V4 private-verification redemption token.
    let redemption_token = freebird_crypto::RedemptionToken {
        nonce,
        scope_digest,
        kid: issue_resp.kid,
        issuer_id: issue_resp.issuer_id,
        authenticator: output,
    };

    let token_wire = freebird_crypto::build_redemption_token(&redemption_token)
        .map_err(|e| anyhow!("{:?}", e))?;

    let token_b64 = Base64UrlUnpadded::encode_string(&token_wire);
    Ok(IssuedToken {
        token_b64: token_b64.clone(),
        fixture: ReplayFixture {
            schema_version: 2,
            issuer_url: options.issuer_url.clone(),
            verifier_url: options.verifier_url.clone(),
            token_b64,
            issuer_id,
            kid,
            issuer_voprf_pubkey_b64: pubkey_b64,
            verifier_id: verifier_id.to_string(),
            audience: audience.to_string(),
            scope_digest_b64: scope_digest_b64.to_string(),
        },
    })
}

fn build_sybil_proof(
    options: &ClientOptions,
    issuer_id: &str,
    blinded_b64: &str,
) -> Result<Option<SybilProof>> {
    if let Some(path) = &options.sybil_proof_json {
        let json = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("failed to read Sybil proof JSON {}: {}", path.display(), e))?;
        let proof = serde_json::from_str(&json)
            .map_err(|e| anyhow!("failed to parse Sybil proof JSON {}: {}", path.display(), e))?;
        return Ok(Some(proof));
    }

    if let Some(difficulty) = options.pow_difficulty {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("system clock before Unix epoch: {}", e))?
            .as_secs();
        let input = format!("freebird:issue:v1:{issuer_id}:{blinded_b64}");
        let nonce = compute_pow_nonce(difficulty, &input, timestamp)?;
        println!("Computed request-bound PoW proof at difficulty {difficulty}");
        return Ok(Some(SybilProof::ProofOfWork {
            nonce,
            input,
            timestamp,
        }));
    }

    Ok(None)
}

fn compute_pow_nonce(difficulty: u32, input: &str, timestamp: u64) -> Result<u64> {
    if difficulty > 32 {
        return Err(anyhow!(
            "--pow-difficulty currently supports up to 32 bits, got {}",
            difficulty
        ));
    }

    for nonce in 0..u64::MAX {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hasher.update(nonce.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash = hasher.finalize();
        if has_leading_zero_bits(&hash, difficulty) {
            return Ok(nonce);
        }
    }

    Err(anyhow!("no proof-of-work nonce found"))
}

fn has_leading_zero_bits(hash: &[u8], difficulty: u32) -> bool {
    let full_zero_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;

    if !hash[..full_zero_bytes].iter().all(|&b| b == 0) {
        return false;
    }

    if remaining_bits == 0 {
        return true;
    }

    let mask = 0xff << (8 - remaining_bits);
    hash.get(full_zero_bytes)
        .map(|byte| byte & mask == 0)
        .unwrap_or(false)
}

async fn create_replay_fixture(options: &ClientOptions, output: &PathBuf) -> Result<()> {
    let http = HttpClient::builder().timeout(HTTP_TIMEOUT).build()?;
    let issued = issue_token_detailed(&http, options, freebird_crypto::VOPRF_CONTEXT_V4).await?;
    if !check_token(&http, &options.verifier_url, &issued.token_b64).await? {
        return Err(anyhow!("fixture token failed /v1/check"));
    }
    if !verify_token(&http, &options.verifier_url, &issued.token_b64).await? {
        return Err(anyhow!("fixture token failed /v1/verify"));
    }
    write_fixture_atomically(output, &issued.fixture)?;
    println!("fixture created: {}", output.display());
    Ok(())
}

async fn validate_replay_fixture(options: &ClientOptions, input: &PathBuf) -> Result<()> {
    let bytes = std::fs::read(input)
        .map_err(|e| anyhow!("failed to read fixture {}: {}", input.display(), e))?;
    let fixture: ReplayFixture =
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("invalid replay fixture: {}", e))?;
    if fixture.schema_version != 2 || fixture.token_b64.is_empty() {
        return Err(anyhow!("invalid replay fixture schema"));
    }
    if fixture.issuer_url != options.issuer_url || fixture.verifier_url != options.verifier_url {
        return Err(anyhow!(
            "fixture endpoint binding does not match the local Compose endpoints"
        ));
    }
    Base64UrlUnpadded::decode_vec(&fixture.token_b64)
        .map_err(|e| anyhow!("invalid fixture token encoding: {e}"))?;

    let http = HttpClient::builder().timeout(HTTP_TIMEOUT).build()?;
    let issuer_meta: serde_json::Value = http
        .get(format!("{}/.well-known/issuer", options.issuer_url))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let verifier_meta: serde_json::Value = http
        .get(format!("{}/.well-known/verifier", options.verifier_url))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if issuer_meta["issuer_id"] != fixture.issuer_id
        || issuer_meta["voprf"]["kid"] != fixture.kid
        || issuer_meta["voprf"]["pubkey"] != fixture.issuer_voprf_pubkey_b64
        || verifier_meta["verifier_id"] != fixture.verifier_id
        || verifier_meta["audience"] != fixture.audience
        || verifier_meta["scope_digest_b64"] != fixture.scope_digest_b64
    {
        return Err(anyhow!(
            "fixture metadata does not match Compose discovery metadata"
        ));
    }
    if !check_token(&http, &options.verifier_url, &fixture.token_b64).await? {
        return Err(anyhow!("fixture token did not pass /v1/check"));
    }
    match verify_token_status(&http, &options.verifier_url, &fixture.token_b64).await? {
        reqwest::StatusCode::UNAUTHORIZED => {
            println!("replay rejected: 401");
            Ok(())
        }
        status => Err(anyhow!("expected replay rejection 401, got {}", status)),
    }
}

fn write_fixture_atomically(path: &PathBuf, fixture: &ReplayFixture) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let tmp = parent.join(format!(".{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(fixture)?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow!("failed to atomically write fixture: {}", e)
    })
}

async fn check_token(http: &HttpClient, verifier_url: &str, token_b64: &str) -> Result<bool> {
    let response = http
        .post(format!("{verifier_url}/v1/check"))
        .json(&VerifyReq {
            token_b64: token_b64.to_string(),
        })
        .send()
        .await?;
    if !response.status().is_success() {
        return Ok(false);
    }
    Ok(response.json::<VerifyResp>().await?.ok)
}

async fn verify_token_status(
    http: &HttpClient,
    verifier_url: &str,
    token_b64: &str,
) -> Result<reqwest::StatusCode> {
    Ok(http
        .post(format!("{verifier_url}/v1/verify"))
        .json(&VerifyReq {
            token_b64: token_b64.to_string(),
        })
        .send()
        .await?
        .status())
}

async fn verify_token(http: &HttpClient, verifier_url: &str, token_b64: &str) -> Result<bool> {
    // V4: just send the private-verification redemption token
    let resp = http
        .post(format!("{verifier_url}/v1/verify"))
        .json(&VerifyReq {
            token_b64: token_b64.to_string(),
        })
        .send()
        .await?;

    if resp.status().is_success() {
        let verify_resp: VerifyResp = resp.json().await?;
        Ok(verify_resp.ok)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> ReplayFixture {
        ReplayFixture {
            schema_version: 2,
            issuer_url: "http://issuer".into(),
            verifier_url: "http://verifier".into(),
            token_b64: "AQ".into(),
            issuer_id: "issuer:test".into(),
            kid: "kid-1".into(),
            issuer_voprf_pubkey_b64: "AQ".into(),
            verifier_id: "verifier:test".into(),
            audience: "test".into(),
            scope_digest_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        }
    }

    #[test]
    fn replay_fixture_rejects_unknown_fields() {
        let mut value = serde_json::to_value(fixture()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ReplayFixture>(value).is_err());
    }

    #[test]
    fn replay_fixture_is_atomically_written_with_restricted_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.json");
        write_fixture_atomically(&path, &fixture()).unwrap();
        let parsed: ReplayFixture = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(parsed.schema_version, 2);
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
