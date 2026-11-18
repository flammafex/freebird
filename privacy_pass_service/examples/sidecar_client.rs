//! This client tests an application route that nginx protects through `auth_request` to the origin.
//! It fetches a challenge from `CHALLENGE_URL`, obtains one token, and presents it twice to
//! `PRESENT_URL` using `METHOD`. If `PRESENT_URL` is omitted, it uses `CHALLENGE_URL`.
//! It prints the status codes and first presentation's response body and does not print
//! the invitation, token, or challenge bytes.
//!
//! Pass `--scope-header V` to send `Freebird-Scope` with each presentation and test that nginx replaces it.
//!
//! Run the client with an invitation file on stdin to test the protected route:
//!
//! ```text
//! sidecar_client [--method M] [--scope-header V] --tls-ca CA --connect IP ISSUER_BASE CHALLENGE_URL [PRESENT_URL] < invitation
//! ```
use anyhow::{bail, ensure, Context, Result};
use base64ct::{Base64Url, Base64UrlUnpadded, Encoding};
use freebird_common::privacy_pass::{
    build_authorization_header, Token, TokenChallenge, TokenRequest, TokenResponse,
};
use freebird_crypto::privacy_pass::PublicKey;
use reqwest::{header::HeaderMap, Client, Method, Response, Url};
use std::{
    fs::File,
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

struct Options {
    method: Method,
    scope_header: Option<String>,
    tls_ca: String,
    ip: IpAddr,
    issuer: Url,
    challenge: Url,
    present: Url,
}

fn tls_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| !host.starts_with('[') && host.parse::<IpAddr>().is_err())
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "expected an https DNS URL"
    );
    Ok(url)
}

fn options(args: &[String]) -> Result<Options> {
    let mut method = Method::GET;
    let mut scope_header = None;
    let mut args = args;
    loop {
        match args {
            [flag, value, rest @ ..] if flag == "--method" => {
                method = Method::from_bytes(value.as_bytes())?;
                args = rest;
            }
            [flag, value, rest @ ..] if flag == "--scope-header" => {
                scope_header = Some(value.clone());
                args = rest;
            }
            _ => break,
        }
    }
    let [flag, tls_ca, connect, ip, issuer, challenge, present @ ..] = args else {
        bail!("invalid arguments");
    };
    ensure!(
        flag == "--tls-ca" && connect == "--connect" && present.len() <= 1,
        "invalid arguments"
    );
    let ip: IpAddr = ip.parse()?;
    ensure!(ip.is_loopback(), "expected numeric loopback address");
    let issuer = tls_url(issuer)?;
    ensure!(
        issuer.path() == "/" && issuer.query().is_none(),
        "issuer must be a base URL"
    );
    let challenge = tls_url(challenge)?;
    let present = match present.first() {
        Some(value) => tls_url(value)?,
        None => challenge.clone(),
    };
    Ok(Options {
        method,
        scope_header,
        tls_ca: tls_ca.clone(),
        ip,
        issuer,
        challenge,
        present,
    })
}

/// Returns `host:port` from a TLS URL with an explicit port to match the identities configured on the origin.
fn authority(url: &Url) -> Result<String> {
    Ok(format!(
        "{}:{}",
        url.host_str().context("missing host")?,
        url.port().context("explicit port required")?
    ))
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().context("missing required header")?.to_str()?;
    ensure!(values.next().is_none(), "duplicate header");
    Ok(value)
}

// Require the parameter names and order that the reference origin uses for its RFC 9577 challenge.
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

/// After the caller checks the headers, this function returns the status and body if the body fits the limit.
async fn finish(mut response: Response, cap: usize) -> Result<(u16, Vec<u8>)> {
    let status = response.status().as_u16();
    ensure!(
        response.content_length().is_none_or(|n| n <= cap as u64),
        "oversized response"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(chunk.len() <= cap - bytes.len(), "oversized response");
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}

fn read_invitation() -> Result<String> {
    // Limit the read from stdin and omit the invitation from output and diagnostics.
    let mut invitation = String::new();
    std::io::stdin()
        .lock()
        .take(46)
        .read_to_string(&mut invitation)?;
    let invitation = invitation.trim_end_matches(['\r', '\n']).to_owned();
    ensure!(invitation.len() == 43, "invalid invitation");
    let decoded = Base64UrlUnpadded::decode_vec(&invitation)?;
    ensure!(
        decoded.len() == 32 && Base64UrlUnpadded::encode_string(&decoded) == invitation,
        "invalid invitation"
    );
    Ok(invitation)
}

async fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let options = options(&args)?;
    let invitation = read_invitation()?;
    let mut pem = Vec::new();
    File::open(&options.tls_ca)?
        .take(65537)
        .read_to_end(&mut pem)?;
    ensure!(pem.len() <= 65536, "CA file too large");
    let certificates = reqwest::Certificate::from_pem_bundle(&pem)?;
    ensure!(!certificates.is_empty(), "empty CA bundle");
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .tls_built_in_root_certs(false)
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_2);
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    for url in [&options.issuer, &options.challenge, &options.present] {
        builder = builder.resolve(
            url.host_str().context("missing host")?,
            SocketAddr::new(
                options.ip,
                url.port_or_known_default().context("missing port")?,
            ),
        );
    }
    let client = builder.build()?;

    let response = client
        .get(
            options
                .issuer
                .join(".well-known/private-token-issuer-directory")?,
        )
        .header("Accept", "application/private-token-issuer-directory")
        .send()
        .await?;
    ensure!(
        single(response.headers(), "content-type")? == "application/private-token-issuer-directory",
        "directory media type"
    );
    let (status, directory) = finish(response, 16384).await?;
    ensure!(status == 200, "directory status");
    let directory: serde_json::Value = serde_json::from_slice(&directory)?;
    let advertised = Url::parse(
        directory["issuer-request-uri"]
            .as_str()
            .context("directory URI")?,
    )?;
    ensure!(
        advertised == options.issuer.join("private-token/issue")?,
        "advertised issuer mismatch"
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

    // Request the route without credentials and check that the challenge matches the directory key
    // and the configured issuer and origin.
    let response = client
        .get(options.challenge.clone())
        .header("Cache-Control", "no-store")
        .send()
        .await?;
    ensure!(response.status().as_u16() == 401, "challenge status");
    let (token_challenge, challenge_key) =
        challenge(single(response.headers(), "www-authenticate")?)?;
    finish(response, 4096).await?;
    ensure!(
        challenge_key == spki,
        "challenge key differs from directory"
    );
    ensure!(
        token_challenge.issuer_name() == authority(&options.issuer)?,
        "issuer identity mismatch"
    );
    ensure!(
        token_challenge.origin_info() == authority(&options.challenge)?,
        "origin identity mismatch"
    );

    let mut token = Token {
        nonce: rand::random(),
        challenge_digest: token_challenge.digest(),
        token_key_id: public.key_id(),
        authenticator: [0; 256],
    };
    let (blinded_msg, state) = public.blind(&token.token_input())?;
    let request = TokenRequest {
        truncated_token_key_id: public.key_id()[31],
        blinded_msg,
    }
    .to_bytes();
    let response = client
        .post(options.issuer.join("private-token/issue")?)
        .header("Content-Type", "application/private-token-request")
        .header("Accept", "application/private-token-response")
        .header("Cache-Control", "no-store")
        .header("Freebird-Admission", invitation)
        .body(request.to_vec())
        .send()
        .await?;
    ensure!(
        single(response.headers(), "content-type")? == "application/private-token-response"
            && single(response.headers(), "cache-control")? == "no-store",
        "issuance headers"
    );
    let (status, response_body) = finish(response, 256).await?;
    ensure!(status == 200, "issuance status");
    let response = TokenResponse::from_bytes(&response_body)?;
    token.authenticator = public.finalize(state, &response.blind_sig)?;
    public.verify(&token.token_input(), &token.authenticator)?;
    let authorization = build_authorization_header(&token);

    let payload: &'static [u8] = if options.method == Method::POST {
        b"ping"
    } else {
        b""
    };
    let mut results = Vec::new();
    for _ in 0..2 {
        let mut request = client
            .request(options.method.clone(), options.present.clone())
            .header("Authorization", &authorization)
            .header("Cache-Control", "no-store")
            .body(payload);
        if let Some(scope) = &options.scope_header {
            request = request.header("Freebird-Scope", scope);
        }
        let response = request.send().await?;
        if response.status().as_u16() == 401 {
            // Require a valid challenge with HTTP 401 so that a client can obtain another token.
            challenge(single(response.headers(), "www-authenticate")?)?;
        }
        results.push(finish(response, 4096).await?);
    }
    let (first, first_body) = results.remove(0);
    let (replay, _) = results.remove(0);
    let mut out = std::io::stdout().lock();
    writeln!(out, "challenge: 401; first: {first}; replay: {replay}")?;
    out.write_all(&first_body)?;
    Ok(())
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // Use a generic error because the client error chain can include sensitive request data.
        eprintln!("sidecar client failed (no secrets displayed)");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_and_urls() {
        let parse =
            |args: &[&str]| options(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(parse(&[
            "--tls-ca",
            "ca.pem",
            "--connect",
            "127.0.0.1",
            "https://issuer.test:8443/",
            "https://origin.test:9443/app/x",
        ])
        .is_ok());
        assert!(parse(&[
            "--method",
            "POST",
            "--tls-ca",
            "ca.pem",
            "--connect",
            "127.0.0.1",
            "https://issuer.test:8443/",
            "https://origin.test:9443/ballot/?ballot=1",
            "https://origin.test:9443/ballot/?ballot=2",
        ])
        .is_ok());
        for invalid in [
            vec![
                "--tls-ca",
                "ca.pem",
                "--connect",
                "192.0.2.1",
                "https://issuer.test/",
                "https://origin.test/",
            ],
            vec![
                "--tls-ca",
                "ca.pem",
                "--connect",
                "127.0.0.1",
                "https://issuer.test/x",
                "https://origin.test/",
            ],
            vec![
                "--tls-ca",
                "ca.pem",
                "--connect",
                "127.0.0.1",
                "https://issuer.test/",
                "http://origin.test/",
            ],
            vec![
                "--tls-ca",
                "ca.pem",
                "--connect",
                "127.0.0.1",
                "https://issuer.test/",
                "https://origin.test/#f",
            ],
            vec![
                "--tls-ca",
                "ca.pem",
                "--connect",
                "127.0.0.1",
                "https://issuer.test/",
                "https://origin.test/",
                "a",
                "b",
            ],
        ] {
            assert!(parse(&invalid).is_err(), "{invalid:?}");
        }
    }
}
