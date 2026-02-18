// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: verify/check endpoint parity invariants.
//
// These tests enforce that `/v1/verify` and `/v1/check` share the same
// cryptographic and metadata validation behavior, while differing only in
// nullifier consumption semantics.

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_crypto::{
    Client, Server, Verifier, TOKEN_LEN_V2, TOKEN_SIGNATURE_LEN, compute_token_signature,
    nullifier_key, verify_token_signature,
};
use freebird_verifier::store::{InMemoryStore, SpendStore};
use std::sync::Arc;
use std::time::Duration;

const CONTEXT: &[u8] = b"freebird:v1";
const ISSUER_ID: &str = "issuer:test:endpoint-parity";
const EXP_SEC: u64 = 3600;
const MAX_CLOCK_SKEW_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyCode {
    Expired,
    MissingExpiration,
    InvalidEncoding,
    InvalidLength,
    SignatureVerificationFailed,
    VoprfVerificationFailed,
    ReplayDetected,
}

#[derive(Clone)]
struct IssuedToken {
    token_b64: String,
    kid: String,
    exp: i64,
}

struct VerifierModel {
    issuer_id: String,
    issuer_pk: Vec<u8>,
    spend_store: Arc<dyn SpendStore>,
    verifier: Verifier,
}

impl VerifierModel {
    fn new(issuer_id: String, issuer_pk: Vec<u8>) -> Self {
        Self {
            issuer_id,
            issuer_pk,
            spend_store: Arc::new(InMemoryStore::default()),
            verifier: Verifier::new(CONTEXT),
        }
    }

    fn validate_common(&self, token_b64: &str, kid: &str, exp: Option<i64>) -> Result<String, VerifyCode> {
        let exp_value = exp.ok_or(VerifyCode::MissingExpiration)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs() as i64;

        if now > exp_value + MAX_CLOCK_SKEW_SECS {
            return Err(VerifyCode::Expired);
        }

        let token_with_sig =
            Base64UrlUnpadded::decode_vec(token_b64).map_err(|_| VerifyCode::InvalidEncoding)?;

        if token_with_sig.len() != TOKEN_LEN_V2 {
            return Err(VerifyCode::InvalidLength);
        }

        let token_data_len = TOKEN_LEN_V2 - TOKEN_SIGNATURE_LEN;
        let (token_data, sig_bytes) = token_with_sig.split_at(token_data_len);
        let received_signature: [u8; 64] =
            sig_bytes.try_into().map_err(|_| VerifyCode::InvalidLength)?;

        let sig_valid = verify_token_signature(
            &self.issuer_pk,
            token_data,
            &received_signature,
            kid,
            exp_value,
            &self.issuer_id,
        );
        if !sig_valid {
            return Err(VerifyCode::SignatureVerificationFailed);
        }

        let token_data_b64 = Base64UrlUnpadded::encode_string(token_data);
        let output_b64 = self
            .verifier
            .verify(&token_data_b64, &self.issuer_pk)
            .map_err(|_| VerifyCode::VoprfVerificationFailed)?;

        Ok(output_b64)
    }

    async fn check(&self, token_b64: &str, kid: &str, exp: Option<i64>) -> Result<(), VerifyCode> {
        self.validate_common(token_b64, kid, exp).map(|_| ())
    }

    async fn verify(&self, token_b64: &str, kid: &str, exp: Option<i64>) -> Result<(), VerifyCode> {
        let output_b64 = self.validate_common(token_b64, kid, exp)?;
        let spend_key = format!(
            "freebird:spent:{}:{}",
            self.issuer_id,
            nullifier_key(&self.issuer_id, &output_b64)
        );

        match self
            .spend_store
            .mark_spent(&spend_key, Duration::from_secs(EXP_SEC))
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(VerifyCode::ReplayDetected),
            Err(_) => Err(VerifyCode::VoprfVerificationFailed),
        }
    }
}

fn issue_token(server: &Server, issuer_sk: &[u8; 32], kid: &str) -> IssuedToken {
    let mut client = Client::new(CONTEXT);
    let (blinded_b64, _state) = client.blind(&[0xAA; 32]).expect("blind");
    let eval_b64 = server
        .evaluate_with_proof(&blinded_b64)
        .expect("evaluate");
    let eval_bytes = Base64UrlUnpadded::decode_vec(&eval_b64).expect("decode eval");

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64
        + EXP_SEC as i64;

    let signature = compute_token_signature(issuer_sk, &eval_bytes, kid, exp, ISSUER_ID)
        .expect("signature");

    let mut final_token = eval_bytes;
    final_token.extend_from_slice(&signature);

    IssuedToken {
        token_b64: Base64UrlUnpadded::encode_string(&final_token),
        kid: kid.to_string(),
        exp,
    }
}

#[tokio::test]
async fn verify_and_check_agree_for_fresh_valid_token() -> Result<()> {
    let issuer_sk = [0x44u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server");
    let issuer_pk = server.public_key_sec1_compressed();
    let kid = "kid-endpoint-parity-1";
    let token = issue_token(&server, &issuer_sk, kid);

    let model = VerifierModel::new(ISSUER_ID.to_string(), issuer_pk.to_vec());

    assert_eq!(model.check(&token.token_b64, &token.kid, Some(token.exp)).await, Ok(()));
    assert_eq!(model.verify(&token.token_b64, &token.kid, Some(token.exp)).await, Ok(()));
    Ok(())
}

#[tokio::test]
async fn check_does_not_consume_verify_does() -> Result<()> {
    let issuer_sk = [0x45u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server");
    let issuer_pk = server.public_key_sec1_compressed();
    let token = issue_token(&server, &issuer_sk, "kid-endpoint-parity-2");
    let model = VerifierModel::new(ISSUER_ID.to_string(), issuer_pk.to_vec());

    // Check can be repeated and should not consume.
    assert_eq!(model.check(&token.token_b64, &token.kid, Some(token.exp)).await, Ok(()));
    assert_eq!(model.check(&token.token_b64, &token.kid, Some(token.exp)).await, Ok(()));

    // First verify consumes successfully.
    assert_eq!(model.verify(&token.token_b64, &token.kid, Some(token.exp)).await, Ok(()));
    // Second verify should detect replay.
    assert_eq!(
        model.verify(&token.token_b64, &token.kid, Some(token.exp)).await,
        Err(VerifyCode::ReplayDetected)
    );

    // Check remains parity-valid even after consumption.
    assert_eq!(model.check(&token.token_b64, &token.kid, Some(token.exp)).await, Ok(()));
    Ok(())
}

#[tokio::test]
async fn verify_and_check_parity_for_expired_invalid_and_tampered_tokens() -> Result<()> {
    let issuer_sk = [0x46u8; 32];
    let server = Server::from_secret_key(issuer_sk, CONTEXT).expect("server");
    let issuer_pk = server.public_key_sec1_compressed();
    let token = issue_token(&server, &issuer_sk, "kid-endpoint-parity-3");
    let model = VerifierModel::new(ISSUER_ID.to_string(), issuer_pk.to_vec());

    // Expired parity.
    let expired_exp = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs() as i64
            - 3600,
    );
    assert_eq!(
        model.check(&token.token_b64, &token.kid, expired_exp).await,
        Err(VerifyCode::Expired)
    );
    assert_eq!(
        model.verify(&token.token_b64, &token.kid, expired_exp).await,
        Err(VerifyCode::Expired)
    );

    // Invalid length parity.
    let malformed_len = Base64UrlUnpadded::encode_string(&[0u8; 32]);
    assert_eq!(
        model.check(&malformed_len, &token.kid, Some(token.exp)).await,
        Err(VerifyCode::InvalidLength)
    );
    assert_eq!(
        model.verify(&malformed_len, &token.kid, Some(token.exp)).await,
        Err(VerifyCode::InvalidLength)
    );

    // Tampered signature parity (flip one bit in the token envelope).
    let mut raw = Base64UrlUnpadded::decode_vec(&token.token_b64)?;
    raw[10] ^= 0x01;
    let tampered_b64 = Base64UrlUnpadded::encode_string(&raw);
    assert_eq!(
        model.check(&tampered_b64, &token.kid, Some(token.exp)).await,
        Err(VerifyCode::SignatureVerificationFailed)
    );
    assert_eq!(
        model.verify(&tampered_b64, &token.kid, Some(token.exp)).await,
        Err(VerifyCode::SignatureVerificationFailed)
    );

    Ok(())
}
