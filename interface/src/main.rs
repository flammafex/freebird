// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_common::api::{IssueReq, IssueResp, VerifyReq, VerifyResp};
use freebird_crypto::voprf::core::Client;
use rand::RngCore;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
struct SavedToken {
    token_b64: String,
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
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Issue token
    let token_b64 = issue_token(&http, issuer_url, verifier_url, ctx).await?;

    println!("✅ Token issued (V4 private-verification redemption token)");

    // Verify token
    let success = verify_token(&http, verifier_url, &token_b64).await?;

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
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Issue token
    println!("\n Step 1: Issuing fresh token...");
    let token_b64 = issue_token(&http, issuer_url, verifier_url, ctx).await?;

    // First verification (should succeed)
    println!("\n Step 2: First verification attempt...");
    let success1 = verify_token(&http, verifier_url, &token_b64).await?;

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
    let success2 = verify_token(&http, verifier_url, &token_b64).await?;

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
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Issue token
    println!("\n Step 1: Issuing token...");
    let token_b64 = issue_token(&http, issuer_url, verifier_url, ctx).await?;
    println!("Token issued (V4 private-verification token)");

    // V4 tokens rely on verifier key acceptance policy, so verify normally.
    // The token's exp is set by the issuer and cannot be faked by the client.
    println!("\n Step 2: Verifying token...");
    let success = verify_token(&http, verifier_url, &token_b64).await?;

    if success {
        println!("Token verified successfully.");
        println!("Note: V4 tokens do not carry client-controlled expiration.");
    } else {
        println!("Token verification failed.");
    }

    Ok(())
}

async fn save_token_mode() -> Result<()> {
    let issuer_url = "http://127.0.0.1:8081";
    let verifier_url = "http://127.0.0.1:8082";
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let token_b64 = issue_token(&http, issuer_url, verifier_url, ctx).await?;

    let saved = SavedToken { token_b64 };

    std::fs::write("token.json", serde_json::to_string_pretty(&saved)?)?;
    println!("\n Token saved to token.json");
    println!("   Run 'interface.exe --load' to attempt replay");

    Ok(())
}

async fn load_token_mode() -> Result<()> {
    let verifier_url = "http://127.0.0.1:8082";

    let data = std::fs::read_to_string("token.json")
        .map_err(|_| anyhow!("token.json not found. Run with --save first."))?;
    let saved: SavedToken = serde_json::from_str(&data)?;

    println!("Loaded token from token.json");

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let success = verify_token(&http, verifier_url, &saved.token_b64).await?;

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
    let ctx = freebird_crypto::VOPRF_CONTEXT_V4;

    let http = HttpClient::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let mut successes = 0;
    let mut failures = 0;

    println!("\n⚡ Starting stress test with {} tokens...\n", count);

    for i in 1..=count {
        print!("Token {}/{}: ", i, count);

        match issue_token(&http, issuer_url, verifier_url, ctx).await {
            Ok(token_b64) => match verify_token(&http, verifier_url, &token_b64).await {
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

async fn issue_token(
    http: &HttpClient,
    issuer_url: &str,
    verifier_url: &str,
    ctx: &[u8],
) -> Result<String> {
    // Get issuer metadata first; V4 binds the issuer/kid into the blinded input.
    let wk: serde_json::Value = http
        .get(format!("{issuer_url}/.well-known/issuer"))
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
        .get(format!("{verifier_url}/.well-known/verifier"))
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

    // Send to issuer
    let issue_resp: IssueResp = http
        .post(format!("{issuer_url}/v1/oprf/issue"))
        .json(&IssueReq {
            blinded_element_b64: blinded_b64,
            ctx_b64: None,
            sybil_proof: None,
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

    Ok(Base64UrlUnpadded::encode_string(&token_wire))
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
