use base64ct::{Base64UrlUnpadded, Encoding};
use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSDeterministic};
use freebird_crypto::{
    build_public_bearer_message_from_parts, build_public_bearer_pass, token_key_id_from_spki,
    PublicBearerPass, PUBLIC_BEARER_NONCE_LEN, VOPRF_CONTEXT_V4,
};
use freebird_verifier::routes::admin::{IssuerInfo, PublicIssuerKey};
use freebird_verifier::verify::verify_v5_public_token;
use std::collections::HashMap;
use std::time::Instant;

const ISSUER_ID: &str = "issuer:test:v5-public";
const AUDIENCE: &str = "verifier:test:v5-public";

fn issue_v5_token() -> (String, Vec<u8>, [u8; 32]) {
    let mut rng = DefaultRng;
    let key_pair = KeyPairSha384PSSDeterministic::generate(&mut rng, 2048).unwrap();
    let spki = key_pair.pk.to_spki().unwrap();
    let token_key_id = token_key_id_from_spki(&spki);
    let nonce = [0x25; PUBLIC_BEARER_NONCE_LEN];
    let msg = build_public_bearer_message_from_parts(&nonce, &token_key_id, ISSUER_ID).unwrap();
    let blinding_result = key_pair.pk.blind(&mut rng, msg).unwrap();
    let blind_sig = key_pair
        .sk
        .blind_sign(&blinding_result.blind_message)
        .unwrap();
    let signature = key_pair
        .pk
        .finalize(&blind_sig, &blinding_result, msg)
        .unwrap();

    let token = PublicBearerPass {
        nonce,
        token_key_id,
        issuer_id: ISSUER_ID.to_string(),
        signature: signature.0,
    };
    let token_b64 = Base64UrlUnpadded::encode_string(&build_public_bearer_pass(&token).unwrap());
    (token_b64, spki, token_key_id)
}

fn issuers(spki: Vec<u8>, token_key_id: [u8; 32]) -> HashMap<String, IssuerInfo> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token_key_id_hex = freebird_crypto::encode_token_key_id_hex(&token_key_id);
    let public_key = PublicIssuerKey {
        token_key_id,
        token_key_id_hex,
        pubkey_spki: spki,
        issuer_id: ISSUER_ID.to_string(),
        valid_from: now - 60,
        valid_until: now + 3600,
        audience: Some(AUDIENCE.to_string()),
    };

    HashMap::from([(
        ISSUER_ID.to_string(),
        IssuerInfo {
            pubkey_bytes: Vec::new(),
            kid: "unused-v4-kid".to_string(),
            ctx: VOPRF_CONTEXT_V4.to_vec(),
            verification_key: None,
            deprecated_verification_keys: HashMap::new(),
            public_keys: HashMap::from([(token_key_id, public_key)]),
            last_refreshed: Some(Instant::now()),
        },
    )])
}

#[test]
fn verifier_accepts_legitimate_v5_public_bearer_token() {
    let (token_b64, spki, token_key_id) = issue_v5_token();
    let issuers = issuers(spki, token_key_id);

    let (parsed, key) =
        verify_v5_public_token(&token_b64, &issuers, AUDIENCE).expect("token should verify");
    assert_eq!(parsed.issuer_id, ISSUER_ID);
    assert_eq!(key.token_key_id, token_key_id);
}

#[test]
fn verifier_rejects_v5_public_bearer_token_for_wrong_audience() {
    let (token_b64, spki, token_key_id) = issue_v5_token();
    let issuers = issuers(spki, token_key_id);

    assert!(verify_v5_public_token(&token_b64, &issuers, "wrong-audience").is_err());
}
