use base64ct::{Base64, Encoding};
use freebird_crypto::privacy_pass::{PublicKey, SecretKey};
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../common/test-fixtures/privacy-pass/rfc9578-a2.json"
    ))
    .unwrap()
}
fn private(v: &Value) -> SecretKey {
    let pem = String::from_utf8(hex(v["skI"].as_str().unwrap())).unwrap();
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    SecretKey::from_pkcs8(&Base64::decode_vec(&b64).unwrap()).unwrap()
}

#[test]
fn privacy_pass_rfc9578_all_five_vectors() {
    let f = fixtures();
    let vectors = f["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5);
    for v in vectors {
        let spki = hex(v["pkI"].as_str().unwrap());
        let pk = PublicKey::from_spki(&spki).unwrap();
        let sk = private(v);
        assert_eq!(pk.to_spki(), spki);
        assert_eq!(sk.public_key().unwrap().to_spki(), spki);
        let token = hex(v["token"].as_str().unwrap());
        assert_eq!(pk.key_id().as_slice(), &token[66..98]);
        pk.verify(
            token[..98].try_into().unwrap(),
            token[98..].try_into().unwrap(),
        )
        .unwrap();
        let req = hex(v["token_request"].as_str().unwrap());
        assert_eq!(
            sk.blind_sign(req[3..].try_into().unwrap())
                .unwrap()
                .as_slice(),
            hex(v["token_response"].as_str().unwrap())
        );
        assert_eq!(req[2], pk.key_id()[31]);
    }
}

#[test]
fn privacy_pass_roundtrip_and_negatives() {
    let sk = SecretKey::generate().unwrap();
    let sk = SecretKey::from_pkcs8(&sk.to_pkcs8().unwrap()).unwrap();
    let pk = sk.public_key().unwrap();
    let other = private(&fixtures()["vectors"][0]).public_key().unwrap();
    let mut input = [7; 98];
    input[..2].copy_from_slice(&[0, 2]);
    let (request, state) = pk.blind(&input).unwrap();
    let response = sk.blind_sign(&request).unwrap();
    let mut sig = pk.finalize(state, &response).unwrap();
    pk.verify(&input, &sig).unwrap();
    assert!(other.verify(&input, &sig).is_err());
    input[5] ^= 1;
    assert!(pk.verify(&input, &sig).is_err());
    input[5] ^= 1;
    sig[0] ^= 1;
    assert!(pk.verify(&input, &sig).is_err());
    let (_, state) = pk.blind(&input).unwrap();
    assert!(other.finalize(state, &response).is_err());
    assert!(sk.blind_sign(&[255; 256]).is_err());
    let spki = pk.to_spki();
    for i in 0..71 {
        let mut bad = spki.to_vec();
        bad[i] ^= 1;
        assert!(PublicKey::from_spki(&bad).is_err(), "SPKI byte {i}");
    }
    assert!(PublicKey::from_spki(&spki[..spki.len() - 1]).is_err());
    let mut trailing = spki.to_vec();
    trailing.push(0);
    assert!(PublicKey::from_spki(&trailing).is_err());
    assert!(SecretKey::from_pkcs8(&[]).is_err());
}
