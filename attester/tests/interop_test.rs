// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::Result;
use attester::keys::{canonical_attestation, canonical_json, AttesterKey};
use attester::types::SocialGraphAttestation;
use ed25519_dalek::{Signature, Verifier};
use rand::rngs::OsRng;
use serde_json::{json, Value};

fn gate_canonical_json(value: &Value) -> Result<String> {
    Ok(match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (idx, key) in keys.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                out.push_str(&gate_canonical_json(&map[*key])?);
            }
            out.push('}');
            out
        }
        Value::Array(values) => {
            let parts: Result<Vec<_>> = values.iter().map(gate_canonical_json).collect();
            format!("[{}]", parts?.join(","))
        }
        _ => serde_json::to_string(value)?,
    })
}

#[test]
fn canonical_json_matches_gate_algorithm_for_nested_values() -> Result<()> {
    let cases = [
        json!({"z": 1, "a": 2, "m": {"b": true, "a": null}}),
        json!({"array": [{"z": "last", "a": "first"}, 3, false], "empty": {}}),
        json!({"escaped": "quote: \" backslash: \\ newline: \n", "n": 10}),
    ];

    for case in cases {
        assert_eq!(
            canonical_json(&case)?,
            gate_canonical_json(&case)?.into_bytes()
        );
    }

    Ok(())
}

#[test]
fn signed_attestation_verifies_with_gate_canonical_json() -> Result<()> {
    let signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let key = AttesterKey::from_signing_key("attester-key-2026-06".to_owned(), signing);
    let mut attestation = SocialGraphAttestation {
        contract_version: "sophia/v1".to_owned(),
        artifact_type: "social_graph.attestation".to_owned(),
        version: "1".to_owned(),
        attester_id: "attester:example:v1".to_owned(),
        kid: "attester-key-2026-06".to_owned(),
        policy_id: "clout-trust-v1".to_owned(),
        issued_at: 1_718_999_700,
        expires_at: 1_719_000_000,
        eligibility_level: 2,
        quota_nullifier: Some(
            "9e86d0818844414a0e2e5b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7e4b7".to_owned(),
        ),
        jti: "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_owned(),
        holder_commitment: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
            .to_owned(),
        signature: String::new(),
    };

    key.sign_attestation(&mut attestation)?;

    let mut unsigned = serde_json::to_value(&attestation)?;
    unsigned
        .as_object_mut()
        .expect("attestation serializes to an object")
        .remove("signature");
    let gate_message = gate_canonical_json(&unsigned)?;
    assert_eq!(canonical_attestation(&attestation)?, gate_message);

    let sig_bytes = hex::decode(&attestation.signature)?;
    let sig_array: [u8; 64] = sig_bytes.try_into().expect("Ed25519 signature length");
    key.public_key()
        .verify(gate_message.as_bytes(), &Signature::from_bytes(&sig_array))?;

    Ok(())
}
