// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{IssueReq, IssueResp, VerifyReq, VerifyResp}; // <--- IMPORT SHARED TYPES
use freebird_crypto::voprf::core::Client;
use rand::RngCore;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
struct SavedToken {
    token_b64: String,
    issuer_id: String,
    exp: i64,
    epoch: u32, // Epoch for key rotation
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    let mode = if args.len() > 1 {
        args[1].as_str()
    } else {
        "normal"
    };

    match mode {
        "--help" | "-h" => {
            print_help();
            return Ok(());
        }
        "--replay" => {
            println!("🔁 REPLAY ATTACK TEST MODE");
            test_replay_attack().await?;
        }
        "--double-spend" => {
            println!("💸 DOUBLE-SPEND TEST MODE");
            test_double_spend().await?;
        }
        "--save" => {
            println!("💾 SAVE TOKEN MODE");
            save_token_mode().await?;
        }
        "--load" => {
            println!("📂 LOAD TOKEN MODE");
            load_token_mode().await?;
        }
        "--expired" => {
            println!("⏰ EXPIRED TOKEN TEST MODE");
            test_expired_token().await?;
        }
        "--stress" => {
            let count = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
            println!("⚡ STRESS TEST MODE (n={})", count);
            stress_test(count).await?;
        }
        _ => {
            println!("🕊️ NORMAL MODE - Fresh token issuance and verification");
            normal_flow().await?;
        }
    }

    Ok(())
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
    println!("  --help, -h      Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("  interface.exe                    # Normal flow");
    println!("  interface.exe --save             # Save a token");
    println!("  interface.exe --load             # Try to reuse saved token");
    println!("  interface.exe --replay           # Demonstrate replay protection");
    println!("  interface.exe --expired          # Test expiration validation");
    println!("  interface.exe --stress 10        # Issue 10 tokens");
}

async fn normal_flow() -> Result<()> {
    let issuer_url = "http://127.0.0.1:8081";
    let verifier_url = "http://127.0.0.1:8082";
    let ctx = b"freebird:v1";

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Issue token
    let (token_b64, issuer_id, exp, epoch) = issue_token(&http, issuer_url, ctx).await?;

    println!("✅ Token issued: exp={} ({}s from now), epoch={}", exp, exp - now(), epoch);

    // Verify token
    let success = verify_token(&http, verifier_url, &token_b64, &issuer_id, exp, epoch).await?;

    if success {
        println!("✅ SUCCESS! Token verified");
    } else {
        println!("❌ FAILED! Token rejected");
    }

    Ok(())
}

async fn test_replay_attack() -> Result<()> {
    let issuer_url = "http://127.0.0.1:8081";
    let verifier_url = "http://127.0.0.1:8082";
    let ctx = b"freebird:v1";

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Issue token
    println!("\n📥 Step 1: Issuing fresh token...");
    let (token_b64, issuer_id, exp, epoch) = issue_token(&http, issuer_url, ctx).await?;

    // First verification (should succeed)
    println!("\n✅ Step 2: First verification attempt...");
    let success1 = verify_token(&http, verifier_url, &token_b64, &issuer_id, exp, epoch).await?;

    if !success1 {
        println!("❌ First verification failed! Something is wrong.");
        return Ok(());
    }
    println!("✅ First verification: SUCCESS");

    // Wait a moment
    println!("\n⏱️  Waiting 2 seconds...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Second verification with SAME token (should fail)
    println!("\n🔁 Step 3: Replay attack - reusing the same token...");
    let success2 = verify_token(&http, verifier_url, &token_b64, &issuer_id, exp, epoch).await?;

    if !success2 {
        println!("✅ REPLAY PROTECTION WORKING! Token was rejected on second use.");
        println!("   This proves the nullifier system prevents double-spending.");
    } else {
        println!("❌ SECURITY ISSUE! Token was accepted twice!");
        println!("   The replay protection is not working correctly.");
    }

    Ok(())
}

async fn test_double_spend() -> Result<()> {
    test_replay_attack().await
}

async fn test_expired_token() -> Result<()> {
    let issuer_url = "http://127.0.0.1:8081";
    let verifier_url = "http://127.0.0.1:8082";
    let ctx = b"freebird:v1";

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Issue token
    println!("\n📥 Step 1: Issuing token...");
    let (token_b64, issuer_id, real_exp, epoch) = issue_token(&http, issuer_url, ctx).await?;
    println!("✅ Token issued with exp={}", real_exp);

    // Try to verify with a past expiration time
    let fake_exp = now() - 600; // 10 minutes ago
    println!("\n⏰ Step 2: Attempting verification with expired timestamp...");
    println!("   Fake exp: {} (600s ago)", fake_exp);

    let success = verify_token(&http, verifier_url, &token_b64, &issuer_id, fake_exp, epoch).await?;

    if !success {
        println!("✅ EXPIRATION VALIDATION WORKING! Expired token was rejected.");
        println!("   This prevents using tokens beyond their validity period.");
    } else {
        println!("❌ SECURITY ISSUE! Expired token was accepted!");
        println!("   The expiration validation is not working correctly.");
    }

    Ok(())
}

async fn save_token_mode() -> Result<()> {
    let issuer_url = "http://127.0.0.1:8081";
    let ctx = b"freebird:v1";

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let (token_b64, issuer_id, exp, epoch) = issue_token(&http, issuer_url, ctx).await?;

    let saved = SavedToken {
        token_b64,
        issuer_id,
        exp,
        epoch,
    };

    std::fs::write("token.json", serde_json::to_string_pretty(&saved)?)?;
    println!("\n💾 Token saved to token.json");
    println!("   Expiration: {} ({}s from now)", exp, exp - now());
    println!("   Epoch: {}", epoch);
    println!("   Run 'interface.exe --load' to attempt replay");

    Ok(())
}

async fn load_token_mode() -> Result<()> {
    let verifier_url = "http://127.0.0.1:8082";

    let data = std::fs::read_to_string("token.json")
        .map_err(|_| anyhow!("token.json not found. Run with --save first."))?;
    let saved: SavedToken = serde_json::from_str(&data)?;

    println!("📂 Loaded token from token.json");
    println!("   Issuer: {}", saved.issuer_id);
    println!(
        "   Expiration: {} ({}s from now)",
        saved.exp,
        saved.exp - now()
    );

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let success = verify_token(
        &http,
        verifier_url,
        &saved.token_b64,
        &saved.issuer_id,
        saved.exp,
        saved.epoch,
    )
    .await?;

    if success {
        println!("⚠️  WARNING: Token was accepted (either first use or replay protection failed)");
    } else {
        println!("✅ Token was rejected (likely already spent or expired)");
    }

    Ok(())
}

async fn stress_test(count: usize) -> Result<()> {
    let issuer_url = "http://127.0.0.1:8081";
    let verifier_url = "http://127.0.0.1:8082";
    let ctx = b"freebird:v1";

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let mut successes = 0;
    let mut failures = 0;

    println!("\n⚡ Starting stress test with {} tokens...\n", count);

    for i in 1..=count {
        print!("Token {}/{}: ", i, count);

        match issue_token(&http, issuer_url, ctx).await {
            Ok((token_b64, issuer_id, exp, epoch)) => {
                match verify_token(&http, verifier_url, &token_b64, &issuer_id, exp, epoch).await {
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
                }
            }
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

async fn issue_token(
    http: &HttpClient,
    issuer_url: &str,
    ctx: &[u8],
) -> Result<(String, String, i64, u32)> {
    // Initialize OPRF client
    let mut client = Client::new(ctx);

    // Random input
    let mut input = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut input);

    // Blind
    let (blinded_bytes, blind_state) = client.blind(&input).map_err(|e| anyhow!("{:?}", e))?;
    let blinded_b64 = Base64UrlUnpadded::encode_string(&blinded_bytes);

    // Send to issuer
    let issue_resp: IssueResp = http
        .post(format!("{issuer_url}/v1/oprf/issue"))
        .json(&IssueReq {
            blinded_element_b64: blinded_b64,
            ctx_b64: None,      // <--- Initialize new field
            sybil_proof: None,  // <--- Initialize new field
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    // Get issuer metadata
    let wk: serde_json::Value = http
        .get(format!("{issuer_url}/.well-known/issuer"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let pubkey_b64 = wk["voprf"]["pubkey"]
        .as_str()
        .ok_or_else(|| anyhow!("missing pubkey"))?;
    let issuer_id = wk["issuer_id"]
        .as_str()
        .ok_or_else(|| anyhow!("missing issuer_id"))?
        .to_string();
    let issuer_pubkey_bytes = Base64UrlUnpadded::decode_vec(pubkey_b64)?;

    // Finalize token
    let token_bytes = Base64UrlUnpadded::decode_vec(&issue_resp.token)?;
    let (token_raw, _out_cli_raw) = client
        .finalize(blind_state, &token_bytes, &issuer_pubkey_bytes)
        .map_err(|e| anyhow!("{:?}", e))?;

    let token_b64 = Base64UrlUnpadded::encode_string(&token_raw);

    Ok((token_b64, issuer_id, issue_resp.exp, issue_resp.epoch))
}

async fn verify_token(
    http: &HttpClient,
    verifier_url: &str,
    token_b64: &str,
    issuer_id: &str,
    exp: i64,
    epoch: u32,
) -> Result<bool> {
    // Send to verifier with expiration time and epoch
    let resp = http
        .post(format!("{verifier_url}/v1/verify"))
        .json(&VerifyReq {
            token_b64: token_b64.to_string(),
            issuer_id: issuer_id.to_string(),
            exp: Some(exp), // Include expiration for validation
            epoch,          // Include epoch for key rotation
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

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64
}
