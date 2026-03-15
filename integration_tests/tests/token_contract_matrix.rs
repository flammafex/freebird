// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: token contract matrix (issuer <-> verifier compatibility, V3)
//
// This suite enforces format/verification invariants across issuance paths:
// - Single issuance contract
// - Batch issuance contract
// - V3 metadata signature verification

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_crypto::{
    verify_token_signature, Client, Server,
};
use freebird_issuer::multi_key_voprf::MultiKeyVoprfCore;

const CONTEXT: &[u8] = b"freebird:v1";
const ISSUER_ID: &str = "issuer:test:contract";

/// V3 issued token: eval_b64 (for VOPRF verification) + metadata + ECDSA sig
#[derive(Clone)]
struct IssuedToken {
    kid: String,
    exp: i64,
    signature: [u8; 64],
}

async fn issue_like_single_route(
    voprf: &MultiKeyVoprfCore,
    issuer_id: &str,
    blinded_b64: &str,
    exp: i64,
) -> Result<IssuedToken> {
    let eval = voprf.evaluate_b64(blinded_b64).await?;

    // V3: sign metadata only
    let signature = voprf
        .sign_token_metadata(&eval.kid, exp, issuer_id)
        .await?;

    Ok(IssuedToken {
        kid: eval.kid,
        exp,
        signature,
    })
}

async fn issue_like_batch_route(
    voprf: &MultiKeyVoprfCore,
    issuer_id: &str,
    blinded: &[String],
    exp: i64,
) -> Result<Vec<IssuedToken>> {
    let mut out = Vec::with_capacity(blinded.len());
    for b in blinded {
        let eval = voprf.evaluate_b64(b).await?;

        // V3: sign metadata only
        let signature = voprf
            .sign_token_metadata(&eval.kid, exp, issuer_id)
            .await?;

        out.push(IssuedToken {
            kid: eval.kid,
            exp,
            signature,
        });
    }
    Ok(out)
}

fn verifier_style_validate(
    token: &IssuedToken,
    issuer_id: &str,
    issuer_pubkey: &[u8],
) -> Result<()> {
    // V3: verify ECDSA signature over metadata
    let sig_ok = verify_token_signature(
        issuer_pubkey,
        &token.signature,
        &token.kid,
        token.exp,
        issuer_id,
    );
    if !sig_ok {
        anyhow::bail!("signature verification failed");
    }
    Ok(())
}

fn make_blinded_inputs(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| {
            let mut client = Client::new(CONTEXT);
            let mut input = [0u8; 32];
            input[0] = i as u8;
            input[31] = (i as u8).wrapping_mul(3);
            client.blind(&input).expect("blind").0
        })
        .collect()
}

fn test_exp() -> i64 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64)
        + 3600
}

#[tokio::test]
async fn single_contract_is_verifier_compatible() -> Result<()> {
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT)
        .map_err(|e| anyhow::anyhow!("server init failed: {:?}", e))?;
    let issuer_pubkey = server.public_key_sec1_compressed();
    let pubkey_b64 = Base64UrlUnpadded::encode_string(&issuer_pubkey);
    let voprf = MultiKeyVoprfCore::new(sk, pubkey_b64, "kid-contract-1".to_string(), CONTEXT)?;

    let blinded = make_blinded_inputs(1).pop().expect("one input");
    let token = issue_like_single_route(&voprf, ISSUER_ID, &blinded, test_exp()).await?;

    verifier_style_validate(&token, ISSUER_ID, &issuer_pubkey)?;
    Ok(())
}

#[tokio::test]
async fn batch_contract_tokens_are_verifier_compatible() -> Result<()> {
    let sk = [0x24u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT)
        .map_err(|e| anyhow::anyhow!("server init failed: {:?}", e))?;
    let issuer_pubkey = server.public_key_sec1_compressed();
    let pubkey_b64 = Base64UrlUnpadded::encode_string(&issuer_pubkey);
    let voprf = MultiKeyVoprfCore::new(sk, pubkey_b64, "kid-contract-2".to_string(), CONTEXT)?;

    let blinded = make_blinded_inputs(8);
    let tokens = issue_like_batch_route(&voprf, ISSUER_ID, &blinded, test_exp()).await?;
    assert_eq!(tokens.len(), blinded.len());

    for token in &tokens {
        verifier_style_validate(token, ISSUER_ID, &issuer_pubkey)?;
    }
    Ok(())
}
