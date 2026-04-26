// SPDX-License-Identifier: Apache-2.0 OR MIT

use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_crypto::{
    build_private_token_input, build_redemption_token, build_scope_digest, Client, RedemptionToken,
    Server, VOPRF_CONTEXT_V4,
};
use freebird_verifier::{routes::admin::IssuerInfo, verify::verify_v4_token};
use std::{collections::HashMap, time::Instant};

const ISSUER_ID: &str = "issuer:test:v4";
const ACTIVE_KID: &str = "kid-active-v4";
const OLD_KID: &str = "kid-old-v4";
const VERIFIER_ID: &str = "verifier:test:v4";
const AUDIENCE: &str = "test";

fn issue(sk: [u8; 32], kid: &str, nonce: [u8; 32]) -> RedemptionToken {
    let server = Server::from_secret_key(sk, VOPRF_CONTEXT_V4).expect("server");
    let pubkey = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pubkey);
    let scope_digest = build_scope_digest(VERIFIER_ID, AUDIENCE).expect("scope digest");
    let input =
        build_private_token_input(ISSUER_ID, kid, &nonce, &scope_digest).expect("token input");

    let mut client = Client::new(VOPRF_CONTEXT_V4);
    let (blinded_b64, st) = client.blind(&input).expect("blind");
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");
    let authenticator_b64 = client.finalize(st, &eval_b64, &pk_b64).expect("finalize");
    let authenticator_bytes = Base64UrlUnpadded::decode_vec(&authenticator_b64).unwrap();
    let authenticator: [u8; 32] = authenticator_bytes.try_into().unwrap();

    RedemptionToken {
        nonce,
        scope_digest,
        kid: kid.to_string(),
        issuer_id: ISSUER_ID.to_string(),
        authenticator,
    }
}

fn token_b64(token: &RedemptionToken) -> String {
    Base64UrlUnpadded::encode_string(&build_redemption_token(token).expect("encode"))
}

fn issuer_info(active_sk: [u8; 32], old_keys: HashMap<String, [u8; 32]>) -> IssuerInfo {
    let active_server = Server::from_secret_key(active_sk, VOPRF_CONTEXT_V4).expect("server");
    IssuerInfo {
        pubkey_bytes: active_server.public_key_sec1_compressed().to_vec(),
        kid: ACTIVE_KID.to_string(),
        ctx: VOPRF_CONTEXT_V4.to_vec(),
        verification_key: Some(active_sk),
        deprecated_verification_keys: old_keys,
        public_keys: HashMap::new(),
        last_refreshed: Some(Instant::now()),
    }
}

#[test]
fn verifier_accepts_legitimate_v4_token() {
    let active_sk = [0x41u8; 32];
    let token = issue(active_sk, ACTIVE_KID, [0x01u8; 32]);
    let issuers = HashMap::from([(
        ISSUER_ID.to_string(),
        issuer_info(active_sk, HashMap::new()),
    )]);

    let expected_scope = build_scope_digest(VERIFIER_ID, AUDIENCE).unwrap();
    let (parsed, issuer) =
        verify_v4_token(&token_b64(&token), &issuers, &expected_scope).expect("verify");

    assert_eq!(parsed.kid, ACTIVE_KID);
    assert_eq!(issuer.kid, ACTIVE_KID);
}

#[test]
fn verifier_rejects_forged_v4_authenticator() {
    let active_sk = [0x41u8; 32];
    let mut token = issue(active_sk, ACTIVE_KID, [0x02u8; 32]);
    token.authenticator = [0xDEu8; 32];
    let issuers = HashMap::from([(
        ISSUER_ID.to_string(),
        issuer_info(active_sk, HashMap::new()),
    )]);

    let expected_scope = build_scope_digest(VERIFIER_ID, AUDIENCE).unwrap();
    assert!(verify_v4_token(&token_b64(&token), &issuers, &expected_scope).is_err());
}

#[test]
fn verifier_rejects_wrong_scope() {
    let active_sk = [0x41u8; 32];
    let token = issue(active_sk, ACTIVE_KID, [0x06u8; 32]);
    let issuers = HashMap::from([(
        ISSUER_ID.to_string(),
        issuer_info(active_sk, HashMap::new()),
    )]);
    let wrong_scope = build_scope_digest("verifier:other:v4", AUDIENCE).unwrap();

    assert!(verify_v4_token(&token_b64(&token), &issuers, &wrong_scope).is_err());
}

#[test]
fn verifier_accepts_deprecated_key_when_keyring_contains_old_kid() {
    let active_sk = [0x41u8; 32];
    let old_sk = [0x42u8; 32];
    let token = issue(old_sk, OLD_KID, [0x03u8; 32]);
    let old_keys = HashMap::from([(OLD_KID.to_string(), old_sk)]);
    let issuers = HashMap::from([(ISSUER_ID.to_string(), issuer_info(active_sk, old_keys))]);

    let expected_scope = build_scope_digest(VERIFIER_ID, AUDIENCE).unwrap();
    assert!(verify_v4_token(&token_b64(&token), &issuers, &expected_scope).is_ok());
}

#[test]
fn verifier_rejects_unknown_kid() {
    let active_sk = [0x41u8; 32];
    let old_sk = [0x42u8; 32];
    let token = issue(old_sk, OLD_KID, [0x04u8; 32]);
    let issuers = HashMap::from([(
        ISSUER_ID.to_string(),
        issuer_info(active_sk, HashMap::new()),
    )]);

    let expected_scope = build_scope_digest(VERIFIER_ID, AUDIENCE).unwrap();
    assert!(verify_v4_token(&token_b64(&token), &issuers, &expected_scope).is_err());
}

#[test]
fn verifier_rejects_when_private_key_missing() {
    let active_sk = [0x41u8; 32];
    let token = issue(active_sk, ACTIVE_KID, [0x05u8; 32]);
    let active_server = Server::from_secret_key(active_sk, VOPRF_CONTEXT_V4).expect("server");
    let issuers = HashMap::from([(
        ISSUER_ID.to_string(),
        IssuerInfo {
            pubkey_bytes: active_server.public_key_sec1_compressed().to_vec(),
            kid: ACTIVE_KID.to_string(),
            ctx: VOPRF_CONTEXT_V4.to_vec(),
            verification_key: None,
            deprecated_verification_keys: HashMap::new(),
            public_keys: HashMap::new(),
            last_refreshed: Some(Instant::now()),
        },
    )]);

    let expected_scope = build_scope_digest(VERIFIER_ID, AUDIENCE).unwrap();
    assert!(verify_v4_token(&token_b64(&token), &issuers, &expected_scope).is_err());
}
