// SPDX-License-Identifier: Apache-2.0 OR MIT

use attester::{
    api::create_attestation,
    keys::{canonical_attestation, AttesterKey},
    scoring::{clout_signature_message, evaluate_social_graph, ScoringConfig, ScoringResult},
    types::{AttestRequest, AttesterConfig, TrustEdge},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::rngs::OsRng;

#[test]
fn creates_and_verifies_attestation() {
    let now = 1_760_000_000;
    let r = SigningKey::generate(&mut OsRng);
    let a = SigningKey::generate(&mut OsRng);
    let b = SigningKey::generate(&mut OsRng);
    let t = SigningKey::generate(&mut OsRng);
    let rp = hex::encode(r.verifying_key().as_bytes());
    let ap = hex::encode(a.verifying_key().as_bytes());
    let bp = hex::encode(b.verifying_key().as_bytes());
    let tp = hex::encode(t.verifying_key().as_bytes());
    let mut edges = vec![
        mk(&r, &rp, &ap, 0.8, 120, now),
        mk(&r, &rp, &bp, 0.8, 120, now),
        mk(&a, &ap, &tp, 0.4, 8, now),
        mk(&b, &bp, &tp, 0.3, 8, now),
    ];
    assert!(matches!(
        evaluate_social_graph(&tp, &edges, &[rp], now, &ScoringConfig::default()),
        ScoringResult::Pass { .. }
    ));
    let sk = SigningKey::generate(&mut OsRng);
    let key = AttesterKey::from_signing_key("kid1".into(), sk);
    let cfg = AttesterConfig {
        bind_addr: "x".into(),
        private_key_path: "x".into(),
        kid: "kid1".into(),
        attester_id: "attester:local:v1".into(),
        policy_id: "clout-trust-v1".into(),
        ttl_secs: 300,
        trusted_roots: vec![],
        scoring: ScoringConfig::default(),
    };
    let req = AttestRequest {
        holder_commitment: "a".repeat(64),
        subject: tp,
        evidence: std::mem::take(&mut edges),
    };
    let att = create_attestation(&req, 2, now, &cfg, &key).unwrap();
    assert_eq!(att.contract_version, "sophia/v1");
    assert_eq!(att.expires_at, now + 300);
    assert_eq!(att.holder_commitment, req.holder_commitment);
    let msg = canonical_attestation(&att).unwrap();
    let sig: [u8; 64] = hex::decode(&att.signature).unwrap().try_into().unwrap();
    key.public_key()
        .verify(msg.as_bytes(), &Signature::from_bytes(&sig))
        .unwrap();
}
fn mk(sk: &SigningKey, truster: &str, trustee: &str, weight: f64, age: u64, now: u64) -> TrustEdge {
    let mut e = TrustEdge {
        truster: truster.into(),
        trustee: trustee.into(),
        weight,
        timestamp: now - age * 86_400,
        revoked: false,
        signature: String::new(),
    };
    let msg = clout_signature_message(&e).unwrap();
    e.signature = hex::encode(sk.sign(&msg).to_bytes());
    e
}
