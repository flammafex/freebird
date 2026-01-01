// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_crypto::nullifier_key;
use freebird_crypto::{Client, Server, Verifier};
#[test]
fn smoke_voprf_roundtrip() {
    // Keep context consistent across client/server/verifier
    let ctx = b"freebird:v1";
    // Fixed 32-byte secret for determinism in test
    let sk = [0x2Au8; 32];
    // Issuer-side server and public key (SEC1 compressed)
    let server = Server::from_secret_key(sk, ctx).expect("server from sk");
    let pk = server.public_key_sec1_compressed();
    // ---- Client blinds some input (simulate wallet) ----
    let mut client = Client::new(ctx);
    let input32 = [0x11u8; 32]; // deterministic test input
    let (blinded_b64, st) = client.blind(&input32).expect("blind");
    println!("blinded_b64={}", blinded_b64);
    // ---- Issuer evaluates (opaque token bytes, base64url) ----
    let eval_b64 = server
        .evaluate_with_proof(&blinded_b64)
        .expect("server evaluate");
    println!("eval_b64={}", eval_b64);
    // ---- Client finalizes to produce token + token_output ----
    let (token_b64, out_cli_b64) = client.finalize(st, &eval_b64, &pk).expect("finalize");
    println!("token_b64={}", token_b64);
    // ---- Verifier derives the same token_output from the opaque token ----
    let verifier = Verifier::new(ctx);
    let out_ver_b64 = verifier.verify(&token_b64, &pk).expect("verify");
    println!("out_ver_b64={}", out_ver_b64);
    println!("out_cli_b64={}", out_cli_b64);
    let out_cli_raw = Base64UrlUnpadded::decode_vec(&out_cli_b64).expect("cli b64");
    let out_ver_raw = Base64UrlUnpadded::decode_vec(&out_ver_b64).expect("ver b64");
    println!("out_cli_raw_len={}", out_cli_raw.len());
    println!("out_ver_raw_len={}", out_ver_raw.len());
    println!("out_cli_raw_hex={:02x?}", out_cli_raw);
    println!("out_ver_raw_hex={:02x?}", out_ver_raw);
    // Must match exactly
    assert_eq!(out_cli_b64, out_ver_b64, "client/verifier outputs differ");
    // Nullifier determinism (anti-replay seed)
    let issuer_id = "issuer:freebird:v1";
    let n1 = nullifier_key(issuer_id, &out_ver_b64);
    let n2 = nullifier_key(issuer_id, &out_ver_b64);
    assert!(!n1.is_empty());
    assert_eq!(n1, n2);
    // Friendly smoke output
    println!(
        "✅ roundtrip ok\n  blinded.len(b64)={}  eval.len(b64)={}\n  token.len(b64)={}  out.len(b64)={}\n  nullifier(prefix)={}",
        blinded_b64.len(),
        eval_b64.len(),
        token_b64.len(),
        out_ver_b64.len(),
        &n1[..std::cmp::min(16, n1.len())]
    );
}
