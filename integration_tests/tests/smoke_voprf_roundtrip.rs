// SPDX-License-Identifier: Apache-2.0 OR MIT

use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_crypto::{
    build_private_token_input, build_redemption_token, build_scope_digest, nullifier_key_v4,
    parse_redemption_token, verify_private_token_authenticator, Client, RedemptionToken, Server,
    VOPRF_CONTEXT_V4,
};

const ISSUER_ID: &str = "issuer:freebird:v4";
const KID: &str = "kid-smoke-v4";
const VERIFIER_ID: &str = "verifier:smoke:v4";
const AUDIENCE: &str = "smoke";

fn issue_v4_token(sk: [u8; 32], nonce: [u8; 32]) -> RedemptionToken {
    let server = Server::from_secret_key(sk, VOPRF_CONTEXT_V4).expect("server from sk");
    let pubkey = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pubkey);
    let scope_digest = build_scope_digest(VERIFIER_ID, AUDIENCE).expect("scope digest");
    let input =
        build_private_token_input(ISSUER_ID, KID, &nonce, &scope_digest).expect("token input");

    let mut client = Client::new(VOPRF_CONTEXT_V4);
    let (blinded_b64, st) = client.blind(&input).expect("blind");
    let eval_b64 = server
        .evaluate_with_proof(&blinded_b64)
        .expect("server evaluate");
    let authenticator_b64 = client.finalize(st, &eval_b64, &pk_b64).expect("finalize");
    let authenticator_bytes =
        Base64UrlUnpadded::decode_vec(&authenticator_b64).expect("authenticator b64");
    let authenticator: [u8; 32] = authenticator_bytes
        .try_into()
        .expect("authenticator 32 bytes");

    RedemptionToken {
        nonce,
        scope_digest,
        kid: KID.to_string(),
        issuer_id: ISSUER_ID.to_string(),
        authenticator,
    }
}

#[test]
fn smoke_voprf_v4_roundtrip() {
    let sk = [0x2Au8; 32];
    let token = issue_v4_token(sk, [0x11u8; 32]);
    let token_bytes = build_redemption_token(&token).expect("build redemption token");
    assert_eq!(token_bytes[0], freebird_crypto::REDEMPTION_TOKEN_VERSION_V4);

    let parsed = parse_redemption_token(&token_bytes).expect("parse redemption token");
    assert_eq!(parsed.nonce, token.nonce);
    assert_eq!(parsed.scope_digest, token.scope_digest);
    assert_eq!(parsed.kid, token.kid);
    assert_eq!(parsed.issuer_id, token.issuer_id);
    assert_eq!(parsed.authenticator, token.authenticator);

    verify_private_token_authenticator(sk, VOPRF_CONTEXT_V4, &parsed)
        .expect("private authenticator should verify");

    let n1 = nullifier_key_v4(&parsed, VERIFIER_ID, AUDIENCE).expect("nullifier");
    let n2 = nullifier_key_v4(&parsed, VERIFIER_ID, AUDIENCE).expect("nullifier");
    assert!(!n1.is_empty());
    assert_eq!(n1, n2, "nullifier must be deterministic");
}

#[test]
fn same_v4_input_with_different_blinding_produces_same_authenticator() {
    let sk = [0x2Au8; 32];
    let token_a = issue_v4_token(sk, [0x42u8; 32]);
    let token_b = issue_v4_token(sk, [0x42u8; 32]);

    assert_eq!(token_a.authenticator, token_b.authenticator);
    assert_eq!(
        nullifier_key_v4(&token_a, VERIFIER_ID, AUDIENCE).unwrap(),
        nullifier_key_v4(&token_b, VERIFIER_ID, AUDIENCE).unwrap()
    );
    assert_ne!(
        nullifier_key_v4(&token_a, VERIFIER_ID, AUDIENCE).unwrap(),
        nullifier_key_v4(&token_a, "verifier:other:v4", AUDIENCE).unwrap()
    );
}

#[test]
fn v4_authenticator_rejects_tampered_public_fields() {
    let sk = [0x2Au8; 32];
    let token = issue_v4_token(sk, [0x51u8; 32]);

    let mut tampered_nonce = token.clone();
    tampered_nonce.nonce[0] ^= 1;
    assert!(verify_private_token_authenticator(sk, VOPRF_CONTEXT_V4, &tampered_nonce).is_err());

    let mut tampered_scope = token.clone();
    tampered_scope.scope_digest[0] ^= 1;
    assert!(verify_private_token_authenticator(sk, VOPRF_CONTEXT_V4, &tampered_scope).is_err());

    let mut tampered_kid = token.clone();
    tampered_kid.kid.push_str("-other");
    assert!(verify_private_token_authenticator(sk, VOPRF_CONTEXT_V4, &tampered_kid).is_err());

    let mut tampered_authenticator = token;
    tampered_authenticator.authenticator[0] ^= 1;
    assert!(
        verify_private_token_authenticator(sk, VOPRF_CONTEXT_V4, &tampered_authenticator).is_err()
    );
}
