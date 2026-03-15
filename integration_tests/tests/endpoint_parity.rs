// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: verify/check endpoint parity invariants (V3).
//
// These tests enforce that `/v1/verify` and `/v1/check` share the same
// cryptographic and metadata validation behavior, while differing only in
// nullifier consumption semantics.
//
// In V3, the verifier receives the PRF output inside the redemption token.

use anyhow::Result;
use freebird_crypto::{
    compute_token_signature, nullifier_key, verify_token_signature, Client, Server,
};
use base64ct::{Base64UrlUnpadded, Encoding};
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
    SignatureVerificationFailed,
    ReplayDetected,
}

/// V3 issued token: carries the client's unblinded PRF output and ECDSA metadata sig
#[derive(Clone)]
struct IssuedToken {
    output_b64: String,
    kid: String,
    exp: i64,
    signature: [u8; 64],
}

struct VerifierModel {
    issuer_id: String,
    issuer_pk: Vec<u8>,
    spend_store: Arc<dyn SpendStore>,
}

impl VerifierModel {
    fn new(issuer_id: String, issuer_pk: Vec<u8>) -> Self {
        Self {
            issuer_id,
            issuer_pk,
            spend_store: Arc::new(InMemoryStore::default()),
        }
    }

    fn validate_common(
        &self,
        token: &IssuedToken,
        exp: Option<i64>,
    ) -> Result<String, VerifyCode> {
        let exp_value = exp.ok_or(VerifyCode::MissingExpiration)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs() as i64;

        if now > exp_value + MAX_CLOCK_SKEW_SECS {
            return Err(VerifyCode::Expired);
        }

        // V3: verify ECDSA signature over metadata (kid, exp, issuer_id)
        if !verify_token_signature(
            &self.issuer_pk,
            &token.signature,
            &token.kid,
            exp_value,
            &self.issuer_id,
        ) {
            return Err(VerifyCode::SignatureVerificationFailed);
        }

        // V3: PRF output comes from the redemption token
        Ok(token.output_b64.clone())
    }

    async fn check(&self, token: &IssuedToken, exp: Option<i64>) -> Result<(), VerifyCode> {
        self.validate_common(token, exp).map(|_| ())
    }

    async fn verify(&self, token: &IssuedToken, exp: Option<i64>) -> Result<(), VerifyCode> {
        let output_b64 = self.validate_common(token, exp)?;
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
            Err(_) => Err(VerifyCode::SignatureVerificationFailed),
        }
    }
}

fn issue_token(server: &Server, issuer_sk: &[u8; 32], kid: &str) -> IssuedToken {
    let pk = server.public_key_sec1_compressed();
    let pk_b64 = Base64UrlUnpadded::encode_string(&pk);

    let mut client = Client::new(CONTEXT);
    let (blinded_b64, state) = client.blind(&[0xAA; 32]).expect("blind");
    let eval_b64 = server.evaluate_with_proof(&blinded_b64).expect("evaluate");

    // Client unblinds to get PRF output
    let output_b64 = client.finalize(state, &eval_b64, &pk_b64).expect("finalize");

    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64
        + EXP_SEC as i64;

    // V3: sign metadata only
    let signature =
        compute_token_signature(issuer_sk, kid, exp, ISSUER_ID).expect("signature");

    IssuedToken {
        output_b64,
        kid: kid.to_string(),
        exp,
        signature,
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

    assert_eq!(model.check(&token, Some(token.exp)).await, Ok(()));
    assert_eq!(model.verify(&token, Some(token.exp)).await, Ok(()));
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
    assert_eq!(model.check(&token, Some(token.exp)).await, Ok(()));
    assert_eq!(model.check(&token, Some(token.exp)).await, Ok(()));

    // First verify consumes successfully.
    assert_eq!(model.verify(&token, Some(token.exp)).await, Ok(()));
    // Second verify should detect replay.
    assert_eq!(
        model.verify(&token, Some(token.exp)).await,
        Err(VerifyCode::ReplayDetected)
    );

    // Check remains parity-valid even after consumption.
    assert_eq!(model.check(&token, Some(token.exp)).await, Ok(()));
    Ok(())
}

#[tokio::test]
async fn verify_and_check_parity_for_expired_and_tampered_tokens() -> Result<()> {
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
        model.check(&token, expired_exp).await,
        Err(VerifyCode::Expired)
    );
    assert_eq!(
        model.verify(&token, expired_exp).await,
        Err(VerifyCode::Expired)
    );

    // Tampered signature parity (flip one bit in the signature).
    let mut tampered_token = token.clone();
    tampered_token.signature[0] ^= 0x01;
    assert_eq!(
        model.check(&tampered_token, Some(token.exp)).await,
        Err(VerifyCode::SignatureVerificationFailed)
    );
    assert_eq!(
        model.verify(&tampered_token, Some(token.exp)).await,
        Err(VerifyCode::SignatureVerificationFailed)
    );

    Ok(())
}
