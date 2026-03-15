// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
//
// Smoke test: Full V3 round-trip flow
//
// Tests the complete lifecycle:
// 1. Client blinds -> Server evaluates -> Client finalizes (unblinds)
// 2. Sign metadata with ECDSA
// 3. Build V3 redemption token -> Parse -> Verify ECDSA
// 4. Derive nullifier
// 5. Nullifier determinism: same input with different `r` produces same nullifier

use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_crypto::{
    build_redemption_token, compute_token_signature, nullifier_key, parse_redemption_token,
    verify_token_signature, Client, RedemptionToken, Server,
};

#[test]
fn smoke_voprf_v3_roundtrip() {
    let ctx = b"freebird:v1";
    let sk = [0x2Au8; 32];
    let issuer_id = "issuer:freebird:v1";
    let kid = "kid-smoke-001";
    let exp = 1700000000i64;

    // Issuer-side server and public key (SEC1 compressed)
    let server = Server::from_secret_key(sk, ctx).expect("server from sk");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);

    // ---- Client blinds some input (simulate wallet) ----
    let mut client = Client::new(ctx);
    let input32 = [0x11u8; 32];
    let (blinded_b64, st) = client.blind(&input32).expect("blind");
    println!("blinded_b64={}", blinded_b64);

    // ---- Issuer evaluates (opaque token bytes, base64url) ----
    let eval_b64 = server
        .evaluate_with_proof(&blinded_b64)
        .expect("server evaluate");
    println!("eval_b64={}", eval_b64);

    // ---- Client finalizes to produce PRF output ----
    let out_cli_b64 = client.finalize(st, &eval_b64, &pk_b64).expect("finalize");
    println!("out_cli_b64={}", out_cli_b64);

    // Verify output decodes to exactly 32 bytes
    let out_cli_raw = Base64UrlUnpadded::decode_vec(&out_cli_b64).expect("cli b64");
    assert_eq!(out_cli_raw.len(), 32, "PRF output must be 32 bytes");

    // ---- Sign metadata with ECDSA (V3: metadata only) ----
    let sig = compute_token_signature(&sk, kid, exp, issuer_id).expect("compute signature");
    assert_eq!(sig.len(), 64, "ECDSA signature must be 64 bytes");

    // ---- Verify ECDSA signature ----
    assert!(
        verify_token_signature(&pk, &sig, kid, exp, issuer_id),
        "signature must verify"
    );

    // ---- Build V3 redemption token ----
    let output: [u8; 32] = out_cli_raw.try_into().expect("output 32 bytes");
    let redemption = RedemptionToken {
        output,
        kid: kid.to_string(),
        exp,
        issuer_id: issuer_id.to_string(),
        sig,
    };
    let token_bytes = build_redemption_token(&redemption).expect("build redemption token");
    assert_eq!(token_bytes[0], 0x03, "V3 version byte");

    // ---- Parse V3 redemption token ----
    let parsed = parse_redemption_token(&token_bytes).expect("parse redemption token");
    assert_eq!(parsed.output, output);
    assert_eq!(parsed.kid, kid);
    assert_eq!(parsed.exp, exp);
    assert_eq!(parsed.issuer_id, issuer_id);
    assert_eq!(parsed.sig, sig);

    // ---- Verify ECDSA on parsed token ----
    assert!(
        verify_token_signature(&pk, &parsed.sig, &parsed.kid, parsed.exp, &parsed.issuer_id),
        "parsed token signature must verify"
    );

    // ---- Derive nullifier from PRF output (as verifier would) ----
    let output_b64 = Base64UrlUnpadded::encode_string(&parsed.output);
    let n1 = nullifier_key(issuer_id, &output_b64);
    let n2 = nullifier_key(issuer_id, &output_b64);
    assert!(!n1.is_empty());
    assert_eq!(n1, n2, "nullifier must be deterministic");

    println!(
        "roundtrip ok: out.len(b64)={} nullifier(prefix)={}",
        out_cli_b64.len(),
        &n1[..std::cmp::min(16, n1.len())]
    );
}

/// Test nullifier determinism: same user input with different blinding factors
/// must produce the same VOPRF output and thus the same nullifier.
#[test]
fn nullifier_determinism_different_r() {
    let ctx = b"freebird:v1";
    let sk = [0x2Au8; 32];
    let issuer_id = "issuer:freebird:v1";

    let server = Server::from_secret_key(sk, ctx).expect("server from sk");
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);

    let input = [0x42u8; 32];

    // Run the VOPRF protocol twice with the same input.
    // Each run uses a fresh Client which generates a new random `r`.
    let mut outputs = Vec::new();
    for _ in 0..3 {
        let mut client = Client::new(ctx);
        let (blinded_b64, st) = client.blind(&input).expect("blind");
        let eval_b64 = server
            .evaluate_with_proof(&blinded_b64)
            .expect("evaluate");
        let out_b64 = client.finalize(st, &eval_b64, &pk_b64).expect("finalize");
        outputs.push(out_b64);
    }

    // All outputs must be identical (blinding factor cancels out)
    assert_eq!(outputs[0], outputs[1], "outputs must match across runs");
    assert_eq!(outputs[1], outputs[2], "outputs must match across runs");

    // Nullifiers must all be the same
    let nullifiers: Vec<String> = outputs
        .iter()
        .map(|o| nullifier_key(issuer_id, o))
        .collect();
    assert_eq!(nullifiers[0], nullifiers[1]);
    assert_eq!(nullifiers[1], nullifiers[2]);

    println!(
        "nullifier determinism ok: 3 runs, same nullifier prefix={}",
        &nullifiers[0][..std::cmp::min(16, nullifiers[0].len())]
    );
}
