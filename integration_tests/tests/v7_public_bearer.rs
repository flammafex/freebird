use base64ct::{Base64UrlUnpadded, Encoding};
use freebird_crypto::{
    blind_v7, finalize_v7, provider::software::SoftwareV7BlindRsaProvider, NativeBearerV7Token,
    PublicBearerV7Body, V7BodyPolicy, V7KeyIdentity, V7TokenKeyId,
};
use freebird_verifier::{
    state::{V7DescriptorIdentity, V7IssuerTrustEntry, V7IssuerTrustSnapshot, V7TrustRegistry},
    verify::verify_v7_public_token,
};
use std::collections::HashMap;

const ISSUER_ID: &str = "issuer:test:v7-public";

struct Artifact {
    token: NativeBearerV7Token,
    entry: V7IssuerTrustEntry,
}

async fn issue_v7(label: &str, key_byte: u8) -> Artifact {
    let token_key_id = V7TokenKeyId::new([key_byte; 32]);
    let identity = V7KeyIdentity::new(ISSUER_ID, token_key_id).unwrap();
    let provider = SoftwareV7BlindRsaProvider::generate(identity).unwrap();
    let body = PublicBearerV7Body::new_derived(
        "USD",
        42,
        ISSUER_ID,
        token_key_id,
        [key_byte.wrapping_add(1); 32],
        [key_byte.wrapping_add(2); 32],
    )
    .unwrap();
    let (blind_message, randomizer, state) = blind_v7(provider.binding(), &body).unwrap();
    let blind_signature = provider
        .blind_sign(provider.binding().identity(), &blind_message)
        .await
        .unwrap();
    let signature = finalize_v7(provider.binding(), state, &blind_signature).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    Artifact {
        token: NativeBearerV7Token::new(body, randomizer, signature),
        entry: V7IssuerTrustEntry {
            binding: provider.binding().clone(),
            policy: V7BodyPolicy::new("USD", 42).unwrap(),
            identity: V7DescriptorIdentity {
                profile_id: format!("profile:{label}"),
                descriptor_id: format!("{label}:descriptor"),
            },
            valid_from: now - 60,
            valid_until: now + 60,
        },
    }
}

fn registry(artifacts: &[&Artifact]) -> V7TrustRegistry {
    let mut snapshot = V7IssuerTrustSnapshot::default();
    for artifact in artifacts {
        snapshot.by_token_key_id.insert(
            *artifact.token.body().token_key_id(),
            artifact.entry.clone(),
        );
    }
    HashMap::from([(ISSUER_ID.to_owned(), snapshot)])
}

fn encoded(token: &NativeBearerV7Token) -> String {
    Base64UrlUnpadded::encode_string(&token.serialize().unwrap())
}

#[tokio::test]
async fn verifier_accepts_direct_exchange_and_graph_v7_artifacts() {
    let direct = issue_v7("direct", 1).await;
    let exchange = issue_v7("exchange", 2).await;
    let graph = issue_v7("graph", 3).await;
    let trust = registry(&[&direct, &exchange, &graph]);

    for artifact in [&direct, &exchange, &graph] {
        verify_v7_public_token(&encoded(&artifact.token), &trust).unwrap();
    }
}

#[tokio::test]
async fn verifier_enforces_v7_policy_identity_and_generic_failures() {
    let artifact = issue_v7("direct", 4).await;
    let token_b64 = encoded(&artifact.token);

    let mut wrong_policy = registry(&[&artifact]);
    wrong_policy
        .get_mut(ISSUER_ID)
        .unwrap()
        .by_token_key_id
        .values_mut()
        .next()
        .unwrap()
        .policy = V7BodyPolicy::new("EUR", 99).unwrap();
    assert_eq!(
        verify_v7_public_token(&token_b64, &wrong_policy)
            .unwrap_err()
            .1,
        "verification failed"
    );

    let wrong_issuer = HashMap::from([(
        "issuer:other".into(),
        registry(&[&artifact])[ISSUER_ID].clone(),
    )]);
    assert!(verify_v7_public_token(&token_b64, &wrong_issuer).is_err());

    let mut malformed = artifact.token.serialize().unwrap();
    malformed[1] ^= 1;
    assert!(verify_v7_public_token(
        &Base64UrlUnpadded::encode_string(&malformed),
        &registry(&[&artifact])
    )
    .is_err());
}

#[tokio::test]
async fn verifier_rejects_noncanonical_encoding_and_bad_randomizer_or_signature() {
    let artifact = issue_v7("direct", 5).await;
    let trust = registry(&[&artifact]);
    let token_b64 = encoded(&artifact.token);
    assert!(verify_v7_public_token(&format!("{token_b64}=0"), &trust).is_err());

    let mut randomizer = artifact.token.message_randomizer().into_bytes();
    randomizer[0] ^= 1;
    let altered = NativeBearerV7Token::new(
        artifact.token.body().clone(),
        freebird_crypto::V7MessageRandomizer::new(randomizer),
        *artifact.token.signature(),
    );
    let error = verify_v7_public_token(&encoded(&altered), &trust).unwrap_err();
    assert_eq!(error.1, "verification failed");
}
