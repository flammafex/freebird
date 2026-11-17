//! Deliberately limited to this experimental Origin's three-parameter challenge.
use anyhow::{ensure, Context, Result};
use base64ct::{Base64Url, Base64UrlUnpadded, Encoding};
use freebird_common::privacy_pass::{
    build_authorization_header, Token, TokenChallenge, TokenRequest, TokenResponse,
};
use freebird_crypto::privacy_pass::PublicKey;
use reqwest::{header::HeaderMap, Client, Response, Url};
use std::{io::Read, net::IpAddr, time::Duration};

fn base(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    ensure!(
        url.scheme() == "http"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "expected a loopback HTTP base URL"
    );
    let host = url.host_str().context("missing host")?;
    let ip: IpAddr = host.trim_matches(['[', ']']).parse()?;
    ensure!(ip.is_loopback(), "expected numeric loopback address");
    Ok(url)
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().context("missing required header")?.to_str()?;
    ensure!(values.next().is_none(), "duplicate header");
    Ok(value)
}

// Not a general RFC 9577 parser: accept only the exact layout our Origin emits.
fn challenge(value: &str) -> Result<(TokenChallenge, Vec<u8>)> {
    let value = value
        .strip_prefix("PrivateToken challenge=\"")
        .context("challenge scheme")?;
    let (encoded, rest) = value
        .split_once("\", token-key=\"")
        .context("challenge parameter")?;
    let (key, age) = rest.split_once("\", max-age=").context("key parameter")?;
    ensure!(
        !age.is_empty() && age.bytes().all(|b| b.is_ascii_digit()),
        "invalid max-age"
    );
    ensure!(age.parse::<u64>()? > 0, "expired challenge");
    let decoded = Base64Url::decode_vec(encoded)?;
    ensure!(
        Base64Url::encode_string(&decoded) == encoded,
        "challenge encoding"
    );
    let spki = Base64Url::decode_vec(key)?;
    ensure!(Base64Url::encode_string(&spki) == key, "key encoding");
    Ok((TokenChallenge::parse(&decoded)?, spki))
}

async fn body(mut response: Response, status: u16, cap: usize) -> Result<Vec<u8>> {
    ensure!(
        response.status().as_u16() == status,
        "unexpected HTTP status"
    );
    ensure!(
        response.content_length().is_none_or(|n| n <= cap as u64),
        "oversized response"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(chunk.len() <= cap - bytes.len(), "oversized response");
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: loopback_client ISSUER_BASE ORIGIN_BASE"
    );
    let issuer = base(&args[0])?;
    let origin = base(&args[1])?;
    // Bounded stdin, never included in errors or output. Interactive input may echo;
    // prefer piping a protected file.
    let mut invitation = String::new();
    std::io::stdin()
        .lock()
        .take(46)
        .read_to_string(&mut invitation)?;
    let invitation = invitation.trim_end_matches(['\r', '\n']);
    ensure!(invitation.len() == 43, "invalid invitation");
    let decoded = Base64UrlUnpadded::decode_vec(invitation)?;
    ensure!(
        decoded.len() == 32 && Base64UrlUnpadded::encode_string(&decoded) == invitation,
        "invalid invitation"
    );
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    let response = client
        .get(issuer.join(".well-known/private-token-issuer-directory")?)
        .header("Accept", "application/private-token-issuer-directory")
        .send()
        .await?;
    ensure!(
        single(response.headers(), "content-type")? == "application/private-token-issuer-directory",
        "directory media type"
    );
    let directory: serde_json::Value = serde_json::from_slice(&body(response, 200, 16384).await?)?;
    let advertised = Url::parse(
        directory["issuer-request-uri"]
            .as_str()
            .context("directory URI")?,
    )?;
    ensure!(
        matches!(advertised.scheme(), "http" | "https")
            && advertised.username().is_empty()
            && advertised.password().is_none()
            && advertised.query().is_none()
            && advertised.fragment().is_none()
            && advertised.path() == "/private-token/issue",
        "invalid advertised URI"
    );
    let keys = directory["token-keys"]
        .as_array()
        .context("directory keys")?;
    ensure!(
        keys.len() == 1 && keys[0]["token-type"] == 2,
        "unsupported directory keys"
    );
    let encoded = keys[0]["token-key"].as_str().context("directory key")?;
    let spki = Base64Url::decode_vec(encoded)?;
    ensure!(
        Base64Url::encode_string(&spki) == encoded,
        "directory key encoding"
    );
    let public = PublicKey::from_spki(&spki)?;
    let protected = origin.join("private-token/protected")?;
    let response = client
        .get(protected.clone())
        .header("Cache-Control", "no-store")
        .send()
        .await?;
    let (challenge, challenge_key) = challenge(single(response.headers(), "www-authenticate")?)?;
    body(response, 401, 4096).await?;
    ensure!(
        challenge_key == spki,
        "challenge key differs from directory"
    );
    let identity = advertised
        .as_str()
        .split_once("://")
        .context("issuer scheme")?
        .1
        .strip_suffix("/private-token/issue")
        .context("issuer path")?;
    ensure!(
        challenge.issuer_name() == identity,
        "issuer identity mismatch"
    );
    let mut token = Token {
        nonce: rand::random(),
        challenge_digest: challenge.digest(),
        token_key_id: public.key_id(),
        authenticator: [0; 256],
    };
    let (blinded_msg, state) = public.blind(&token.token_input())?;
    let request = TokenRequest {
        truncated_token_key_id: public.key_id()[31],
        blinded_msg,
    }
    .to_bytes();
    let issue = || {
        client
            .post(issuer.join("private-token/issue").expect("fixed path"))
            .header("Content-Type", "application/private-token-request")
            .header("Accept", "application/private-token-response")
            .header("Cache-Control", "no-store")
            .header("Freebird-Admission", invitation)
            .body(request.to_vec())
    };
    let response = issue().send().await?;
    ensure!(
        single(response.headers(), "content-type")? == "application/private-token-response"
            && single(response.headers(), "cache-control")? == "no-store",
        "issuance headers"
    );
    let response = TokenResponse::from_bytes(&body(response, 200, 256).await?)?;
    token.authenticator = public.finalize(state, &response.blind_sig)?;
    public.verify(&token.token_input(), &token.authenticator)?;
    let authorization = build_authorization_header(&token);
    for status in [200, 401] {
        let response = client
            .get(protected.clone())
            .header("Authorization", &authorization)
            .header("Cache-Control", "no-store")
            .send()
            .await?;
        if status == 401 {
            challenge_header(response.headers())?;
        }
        body(response, status, 4096).await?;
    }
    body(issue().send().await?, 403, 4096).await?;
    println!("issuance: 200; redemption: 200; replay: 401; invitation retry: 403");
    Ok(())
}

fn challenge_header(headers: &HeaderMap) -> Result<()> {
    challenge(single(headers, "www-authenticate")?)?;
    Ok(())
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // Avoid reqwest error chains, which can carry sensitive request data.
        eprintln!("loopback client failed (no secrets displayed)");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_nonlocal_and_ambiguous_inputs() {
        for url in [
            "https://127.0.0.1",
            "http://localhost",
            "http://192.0.2.1",
            "http://u@127.0.0.1",
            "http://127.0.0.1/x",
            "http://127.0.0.1/?x",
            "http://127.0.0.1/#x",
        ] {
            assert!(base(url).is_err());
        }
        assert!(base("http://127.0.0.1:8081").is_ok());
        assert!(base("http://[::1]:8081").is_ok());
        for value in [
            "PrivateToken challenge=\"AA\", token-key=\"AA==\", max-age=1",
            "PrivateToken challenge=\"AA\", token-key=\"AA==\", max-age=1, extra=2",
        ] {
            assert!(challenge(value).is_err());
        }
    }
}
