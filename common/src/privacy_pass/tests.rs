use super::*;
use serde_json::Value;

fn field(v: &Value, name: &str) -> Vec<u8> {
    hex::decode(v[name].as_str().unwrap()).unwrap()
}
fn vectors(text: &str) -> Vec<Value> {
    serde_json::from_str::<Value>(text).unwrap()["vectors"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn rfc9577_inputs() {
    for v in vectors(include_str!(
        "../../test-fixtures/privacy-pass/rfc9577-a1.json"
    )) {
        let input = field(&v, "token_authenticator_input");
        if v["token_type"] == "0000" {
            assert!(Token::from_bytes(&input).is_err());
            assert!(TokenRequest::from_bytes(&input).is_err());
            assert!(TokenChallenge::parse(&input).is_err());
            continue;
        }
        let issuer = String::from_utf8(field(&v, "issuer_name")).unwrap();
        let origins = String::from_utf8(field(&v, "origin_info")).unwrap();
        let c = TokenChallenge::from_parts(&issuer, &field(&v, "redemption_context"), &origins)
            .unwrap();
        assert_eq!(TokenChallenge::parse(&c.serialize()).unwrap(), c);
        assert_eq!(
            token_input(
                &field(&v, "nonce").try_into().unwrap(),
                &c.digest(),
                &field(&v, "token_key_id").try_into().unwrap()
            )
            .as_slice(),
            input
        );
        if origins.is_empty() || origins.contains(',') {
            assert!(TokenChallenge::new(&issuer, &[], &origins).is_err());
        }
    }
}

#[test]
fn rfc9578_wire_bytes() {
    for v in vectors(include_str!(
        "../../test-fixtures/privacy-pass/rfc9578-a2.json"
    )) {
        let request = field(&v, "token_request");
        let response = field(&v, "token_response");
        let token = field(&v, "token");
        let challenge = field(&v, "token_challenge");
        let r = TokenRequest::from_bytes(&request).unwrap();
        let t = Token::from_bytes(&token).unwrap();
        let c = TokenChallenge::parse(&challenge).unwrap();
        assert_eq!(r.to_bytes().as_slice(), request);
        assert_eq!(
            TokenResponse::from_bytes(&response)
                .unwrap()
                .to_bytes()
                .as_slice(),
            response
        );
        assert_eq!(t.to_bytes().as_slice(), token);
        assert_eq!(t.token_input().as_slice(), &token[..98]);
        assert_eq!(c.serialize(), challenge);
        assert_eq!(c.digest(), t.challenge_digest);
        assert_eq!(token_key_id(&field(&v, "pkI")), t.token_key_id);
        assert_eq!(
            truncated_token_key_id(&t.token_key_id),
            r.truncated_token_key_id
        );
        for bytes in [&request, &response, &token, &challenge] {
            for end in 0..bytes.len() {
                let invalid = &bytes[..end];
                if std::ptr::eq(bytes, &request) {
                    assert!(TokenRequest::from_bytes(invalid).is_err());
                } else if std::ptr::eq(bytes, &response) {
                    assert!(TokenResponse::from_bytes(invalid).is_err());
                } else if std::ptr::eq(bytes, &token) {
                    assert!(Token::from_bytes(invalid).is_err());
                } else {
                    assert!(TokenChallenge::parse(invalid).is_err());
                }
            }
        }
        let mut extra = request.clone();
        extra.push(0);
        assert!(TokenRequest::from_bytes(&extra).is_err());
        let mut extra = response.clone();
        extra.push(0);
        assert!(TokenResponse::from_bytes(&extra).is_err());
        let mut extra = token.clone();
        extra.push(0);
        assert!(Token::from_bytes(&extra).is_err());
        let mut extra = challenge.clone();
        extra.push(0);
        assert!(TokenChallenge::parse(&extra).is_err());
        for typ in [[0, 0], [0, 1], [2, 0]] {
            let mut bad = token.clone();
            bad[..2].copy_from_slice(&typ);
            assert!(Token::from_bytes(&bad).is_err());
            let mut bad = request.clone();
            bad[..2].copy_from_slice(&typ);
            assert!(TokenRequest::from_bytes(&bad).is_err());
        }
    }
}

#[test]
fn challenge_rejects_bad_names_contexts_and_lengths() {
    for name in [
        "",
        "user@issuer.example",
        "https://issuer.example",
        "a\r\nb",
        "é",
        "a b",
        "a,b",
    ] {
        assert!(TokenChallenge::new(name, &[], "origin.example").is_err());
        assert!(TokenChallenge::new("issuer.example", &[], name).is_err());
    }
    for n in [1, 31, 33, 255, 256] {
        assert!(TokenChallenge::new("issuer.example", &vec![0; n], "origin.example").is_err());
    }
    let c = TokenChallenge::new("issuer.example", &[], "origin.example").unwrap();
    let mut bad = c.serialize();
    bad[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(TokenChallenge::parse(&bad).is_err());
    let mut bad = c.serialize();
    bad[18] = 1;
    assert!(TokenChallenge::parse(&bad).is_err());
}

#[test]
fn http_headers() {
    let t = Token {
        nonce: [1; 32],
        challenge_digest: [2; 32],
        token_key_id: [3; 32],
        authenticator: [4; 256],
    };
    let h = build_authorization_header(&t);
    assert_eq!(parse_authorization_header(&h).unwrap(), t);
    let value = Base64Url::encode_string(&t.to_bytes());
    assert_eq!(
        parse_authorization_header(&format!(
            "pRiVaTeToKeN extra=\"a,b\\\"c\", ToKeN=\"{value}\", ignored=yes"
        ))
        .unwrap(),
        t
    );
    // Full tokens are divisible by three; challenge values exercise padding.
    let c = TokenChallenge::new("issuer.example", &[], "origin.example").unwrap();
    assert_eq!(
        build_challenge_header(&c, &[0], 42),
        format!(
            "PrivateToken challenge=\"{}\", token-key=\"AA==\", max-age=42",
            Base64Url::encode_string(&c.serialize())
        )
    );
    for h in [
        format!("PrivateToken token=\"{value}\", TOKEN=\"{value}\""),
        format!("PrivateToken token=\"{value}"),
        format!("PrivateToken token=\"{value}\"junk"),
        format!("PrivateToken token=\"{value}\","),
        format!("PrivateToken token=\"{value}\"\r\nX: y"),
        format!("Basic token=\"{value}\""),
        "PrivateToken token=\"AA==\"".into(),
        "PrivateToken token=\"%%%\"".into(),
        "PrivateToken unknown=yes".into(),
        format!("PrivateToken token=\"{value}=\""),
    ] {
        assert!(parse_authorization_header(&h).is_err(), "{h}");
    }
}
