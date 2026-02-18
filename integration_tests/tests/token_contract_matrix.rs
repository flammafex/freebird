// SPDX-License-Identifier: Apache-2.0 OR MIT
// Integration test: token contract matrix (issuer <-> verifier compatibility)
//
// This suite enforces format/verification invariants across issuance paths:
// - Single issuance contract
// - Batch issuance contract
// - Rejection of non-V2 token envelope lengths

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_crypto::{
    Client, Server, Verifier, TOKEN_LEN_V2, TOKEN_SIGNATURE_LEN,
    verify_token_signature,
};
use freebird_issuer::multi_key_voprf::MultiKeyVoprfCore;

const CONTEXT: &[u8] = b"freebird:v1";
const ISSUER_ID: &str = "issuer:test:contract";
const VOPRF_TOKEN_LEN: usize = 131;

#[derive(Clone)]
struct IssuedToken {
    token_b64: String,
    kid: String,
    exp: i64,
}

fn parse_v2_token(token_b64: &str) -> Result<(Vec<u8>, [u8; 64])> {
    let token_with_sig = Base64UrlUnpadded::decode_vec(token_b64)?;
    if token_with_sig.len() != TOKEN_LEN_V2 {
        anyhow::bail!(
            "invalid token length: got {}, expected {}",
            token_with_sig.len(),
            TOKEN_LEN_V2
        );
    }
    let token_data_len = TOKEN_LEN_V2 - TOKEN_SIGNATURE_LEN;
    let (token_data, sig_bytes) = token_with_sig.split_at(token_data_len);
    let signature: [u8; 64] = sig_bytes.try_into()?;
    Ok((token_data.to_vec(), signature))
}

async fn issue_like_single_route(
    voprf: &MultiKeyVoprfCore,
    issuer_id: &str,
    blinded_b64: &str,
    exp: i64,
) -> Result<IssuedToken> {
    let eval = voprf.evaluate_b64(blinded_b64).await?;
    let token_bytes = Base64UrlUnpadded::decode_vec(&eval.token)?;
    if token_bytes.len() != VOPRF_TOKEN_LEN {
        anyhow::bail!("unexpected VOPRF token length {}", token_bytes.len());
    }

    let signature = voprf
        .sign_token_metadata(&token_bytes, &eval.kid, exp, issuer_id)
        .await?;

    let mut final_token = token_bytes;
    final_token.extend_from_slice(&signature);

    Ok(IssuedToken {
        token_b64: Base64UrlUnpadded::encode_string(&final_token),
        kid: eval.kid,
        exp,
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
        let token_bytes = Base64UrlUnpadded::decode_vec(&eval.token)?;
        if token_bytes.len() != VOPRF_TOKEN_LEN {
            anyhow::bail!("unexpected VOPRF token length {}", token_bytes.len());
        }

        let signature = voprf
            .sign_token_metadata(&token_bytes, &eval.kid, exp, issuer_id)
            .await?;

        let mut final_token = token_bytes;
        final_token.extend_from_slice(&signature);
        out.push(IssuedToken {
            token_b64: Base64UrlUnpadded::encode_string(&final_token),
            kid: eval.kid,
            exp,
        });
    }
    Ok(out)
}

fn verifier_style_validate(
    token: &IssuedToken,
    issuer_id: &str,
    issuer_pubkey: &[u8],
) -> Result<()> {
    let (token_data, signature) = parse_v2_token(&token.token_b64)?;

    let sig_ok = verify_token_signature(
        issuer_pubkey,
        &token_data,
        &signature,
        &token.kid,
        token.exp,
        issuer_id,
    );
    if !sig_ok {
        anyhow::bail!("signature verification failed");
    }

    let verifier = Verifier::new(CONTEXT);
    let token_data_b64 = Base64UrlUnpadded::encode_string(&token_data);
    verifier
        .verify(&token_data_b64, issuer_pubkey)
        .map_err(|e| anyhow::anyhow!("voprf verify failed: {:?}", e))?;
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
async fn single_contract_is_v2_and_verifier_compatible() -> Result<()> {
    let sk = [0x42u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT)
        .map_err(|e| anyhow::anyhow!("server init failed: {:?}", e))?;
    let issuer_pubkey = server.public_key_sec1_compressed();
    let pubkey_b64 = Base64UrlUnpadded::encode_string(&issuer_pubkey);
    let voprf = MultiKeyVoprfCore::new(sk, pubkey_b64, "kid-contract-1".to_string(), CONTEXT)?;

    let blinded = make_blinded_inputs(1).pop().expect("one input");
    let token = issue_like_single_route(&voprf, ISSUER_ID, &blinded, test_exp()).await?;

    let raw = Base64UrlUnpadded::decode_vec(&token.token_b64)?;
    assert_eq!(raw.len(), TOKEN_LEN_V2);
    verifier_style_validate(&token, ISSUER_ID, &issuer_pubkey)?;
    Ok(())
}

#[tokio::test]
async fn batch_contract_tokens_are_v2_and_verifier_compatible() -> Result<()> {
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
        let raw = Base64UrlUnpadded::decode_vec(&token.token_b64)?;
        assert_eq!(raw.len(), TOKEN_LEN_V2);
        verifier_style_validate(token, ISSUER_ID, &issuer_pubkey)?;
    }
    Ok(())
}

#[tokio::test]
async fn contract_rejects_non_v2_token_envelope() -> Result<()> {
    // Create a valid V1 VOPRF token and intentionally do not append a signature.
    let sk = [0x55u8; 32];
    let server = Server::from_secret_key(sk, CONTEXT)
        .map_err(|e| anyhow::anyhow!("server init failed: {:?}", e))?;
    let mut client = Client::new(CONTEXT);
    let (blinded_b64, _state) = client
        .blind(&[0xAB; 32])
        .map_err(|e| anyhow::anyhow!("blind failed: {:?}", e))?;
    let v1_token_b64 = server
        .evaluate_with_proof(&blinded_b64)
        .map_err(|e| anyhow::anyhow!("evaluate failed: {:?}", e))?;
    let v1_raw = Base64UrlUnpadded::decode_vec(&v1_token_b64)?;
    assert_eq!(v1_raw.len(), VOPRF_TOKEN_LEN);

    let malformed = IssuedToken {
        token_b64: v1_token_b64,
        kid: "kid-malformed".to_string(),
        exp: test_exp(),
    };

    let parsed = parse_v2_token(&malformed.token_b64);
    assert!(parsed.is_err(), "non-V2 token must be rejected by contract parser");
    Ok(())
}
