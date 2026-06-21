// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use freebird_common::api::SybilProof;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tracing::warn;

use crate::sybil_resistance::replay_store::ReplayStore;
use crate::sybil_resistance::{SybilRequestContext, SybilResistance};

#[derive(Debug, Clone)]
pub struct SocialGraphConfig {
    pub attesters_path: PathBuf,
    pub jwks_url: Option<String>,
    pub key_refresh_interval: Duration,
    pub min_level: u8,
    pub accepted_policy_ids: Vec<String>,
    pub attestation_max_age: Duration,
    pub clock_skew_secs: u64,
    pub require_request_binding: bool,
    pub require_quota_nullifier: bool,
    pub replay_ttl: Duration,
    pub state_path: PathBuf,
    pub fail_closed: bool,
}

impl Default for SocialGraphConfig {
    fn default() -> Self {
        Self {
            attesters_path: PathBuf::from("social_graph_attesters.json"),
            jwks_url: None,
            key_refresh_interval: Duration::from_secs(3600),
            min_level: 1,
            accepted_policy_ids: Vec::new(),
            attestation_max_age: Duration::from_secs(300),
            clock_skew_secs: 30,
            require_request_binding: true,
            require_quota_nullifier: false,
            replay_ttl: Duration::from_secs(600),
            state_path: PathBuf::from("social_graph_state.json"),
            fail_closed: true,
        }
    }
}

pub struct SocialGraphState {
    pub trusted_attesters: HashMap<(String, String), VerifyingKey>,
    pub accepted_policy_ids: HashSet<String>,
    pub key_refresh_timestamp: SystemTime,
    pub revoked_key_ids: HashSet<String>,
}

pub struct SocialGraphGate {
    config: SocialGraphConfig,
    state: RwLock<SocialGraphState>,
    replay_store: Arc<dyn ReplayStore>,
}

#[derive(Deserialize)]
struct AttesterKeyConfig {
    #[allow(dead_code)]
    kid: String,
    public_key_hex: String,
}

impl SocialGraphGate {
    pub fn new(config: SocialGraphConfig, replay_store: Arc<dyn ReplayStore>) -> Result<Arc<Self>> {
        let trusted_attesters = load_attester_keys(&config.attesters_path).with_context(|| {
            format!(
                "load social graph attesters from {:?}",
                config.attesters_path
            )
        })?;
        if config.fail_closed && trusted_attesters.is_empty() {
            bail!("social_graph has no trusted attester keys configured");
        }
        if config.jwks_url.is_some() {
            warn!("SOCIAL_GRAPH_JWKS_URL is configured but JWKS key refresh is not yet implemented; keys loaded from local config only");
        }
        if !config.state_path.as_os_str().is_empty() {
            warn!("SOCIAL_GRAPH_STATE_PATH is configured but local revocation state is not yet implemented");
        }
        let state = SocialGraphState {
            trusted_attesters,
            accepted_policy_ids: config.accepted_policy_ids.iter().cloned().collect(),
            key_refresh_timestamp: SystemTime::now(),
            revoked_key_ids: HashSet::new(),
        };
        Ok(Arc::new(Self {
            config,
            state: RwLock::new(state),
            replay_store,
        }))
    }
}

pub fn load_attester_keys(path: &Path) -> Result<HashMap<(String, String), VerifyingKey>> {
    let bytes = std::fs::read(path).with_context(|| format!("read {:?}", path))?;
    let raw: HashMap<String, AttesterKeyConfig> = serde_json::from_slice(&bytes)?;
    raw.into_iter()
        .map(|(attester_id, cfg)| {
            let key_bytes = hex::decode(cfg.public_key_hex)
                .with_context(|| format!("decode public key for {attester_id}"))?;
            let key_array: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| anyhow!("invalid Ed25519 public key length for {attester_id}"))?;
            Ok((
                (attester_id, cfg.kid),
                VerifyingKey::from_bytes(&key_array)?,
            ))
        })
        .collect()
}

impl SybilResistance for SocialGraphGate {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        self.verify_with_context(proof, &SybilRequestContext::default())
    }

    fn verify_with_context(&self, proof: &SybilProof, ctx: &SybilRequestContext) -> Result<()> {
        let (presentation_json, presentation_sig_hex) = match proof {
            SybilProof::SocialGraph {
                attestation,
                presentation,
            } => (attestation, presentation),
            _ => bail!("social_graph proof required"),
        };

        let presentation: Value = serde_json::from_str(presentation_json)?;
        require_str(&presentation, "contract_version", "sophia/v1")?;
        require_str(&presentation, "artifact_type", "cred.presentation")?;
        let attestation = presentation
            .get("artifacts")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|a| a.get("artifact"))
            .ok_or_else(|| anyhow!("missing embedded social graph attestation"))?;
        require_str(attestation, "artifact_type", "social_graph.attestation")?;
        require_str(attestation, "contract_version", "sophia/v1")?;

        let controller_key_hex = presentation
            .get("controller_public_key")
            .or_else(|| presentation.get("cred_controller_public_key"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing Cred controller public key"))?;
        let controller_key_bytes = hex::decode(controller_key_hex)?;
        let controller_key: [u8; 32] = controller_key_bytes
            .try_into()
            .map_err(|_| anyhow!("invalid Cred controller public key length"))?;
        let controller_vk = VerifyingKey::from_bytes(&controller_key)?;
        let holder_commitment = required_string(attestation, "holder_commitment")?;
        constant_time_hex_eq(
            &holder_commitment,
            &hex::encode(Sha256::digest(controller_key)),
        )?;
        verify_json_signature(
            &controller_vk,
            &presentation,
            "presentation_signature",
            presentation_sig_hex,
        )?;

        let attester_id = required_string(attestation, "attester_id")?;
        let kid = required_string(attestation, "kid")?;
        let attester_vk = {
            let state = self
                .state
                .read()
                .map_err(|_| anyhow!("social graph lock poisoned"))?;
            if state.revoked_key_ids.contains(&kid) {
                bail!("social graph attester key is revoked");
            }
            if state.accepted_policy_ids.is_empty() {
                bail!("no social graph policies accepted");
            }
            if !state
                .accepted_policy_ids
                .contains(&required_string(attestation, "policy_id")?)
            {
                bail!("social graph policy is not accepted");
            }
            state
                .trusted_attesters
                .get(&(attester_id.clone(), kid.clone()))
                .copied()
                .ok_or_else(|| anyhow!("untrusted social graph attester key"))?
        };
        verify_json_signature(
            &attester_vk,
            attestation,
            "signature",
            &required_string(attestation, "signature")?,
        )?;

        validate_times(attestation, &self.config)?;
        if required_u64(attestation, "eligibility_level")? < u64::from(self.config.min_level) {
            bail!("social graph eligibility level below threshold");
        }
        if self.config.require_request_binding {
            let binding = ctx
                .request_binding
                .as_ref()
                .ok_or_else(|| anyhow!("social graph request binding required"))?;
            let expected = hex::encode(Sha256::digest(binding.as_bytes()));
            constant_time_hex_eq(
                &required_string(&presentation, "request_binding_hash")?,
                &expected,
            )?;
        }

        let replay_ttl = replay_ttl(attestation, self.config.replay_ttl)?;
        let jti_key = format!("{}:{}", attester_id, required_string(attestation, "jti")?);
        self.replay_store
            .mark_once("social_graph:jti", &jti_key, replay_ttl)?;
        if self.config.require_quota_nullifier {
            let quota = attestation
                .get("quota_nullifier")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("quota nullifier required"))?;
            let quota_key = format!("{}:{}", attester_id, quota);
            self.replay_store
                .mark_once("social_graph:quota", &quota_key, replay_ttl)?;
        }
        Ok(())
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::SocialGraph { .. })
    }

    fn cost(&self) -> u64 {
        10
    }
}

fn verify_json_signature(
    vk: &VerifyingKey,
    value: &Value,
    sig_field: &str,
    sig_hex: &str,
) -> Result<()> {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| anyhow!("signed artifact must be a JSON object"))?
        .remove(sig_field);
    let canonical = canonical_json(&unsigned)?;
    let sig_bytes = hex::decode(sig_hex)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow!("invalid Ed25519 signature length"))?;
    vk.verify(canonical.as_bytes(), &Signature::from_bytes(&sig_array))
        .map_err(|_| anyhow!("invalid Ed25519 signature"))
}

fn canonical_json(value: &Value) -> Result<String> {
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
                out.push_str(&canonical_json(&map[*key])?);
            }
            out.push('}');
            out
        }
        Value::Array(values) => {
            let parts: Result<Vec<_>> = values.iter().map(canonical_json).collect();
            format!("[{}]", parts?.join(","))
        }
        _ => serde_json::to_string(value)?,
    })
}

fn validate_times(attestation: &Value, config: &SocialGraphConfig) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let issued_at = required_u64(attestation, "issued_at")?;
    let expires_at = required_u64(attestation, "expires_at")?;
    if expires_at <= issued_at || expires_at.saturating_add(config.clock_skew_secs) < now {
        bail!("social graph attestation expired");
    }
    if issued_at > now.saturating_add(config.clock_skew_secs) {
        bail!("social graph attestation issued in future");
    }
    if now.saturating_sub(issued_at) > config.attestation_max_age.as_secs() + config.clock_skew_secs
    {
        bail!("social graph attestation too old");
    }
    Ok(())
}

fn replay_ttl(attestation: &Value, configured_ttl: Duration) -> Result<Duration> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expires_at = required_u64(attestation, "expires_at")?;
    Ok(configured_ttl.min(Duration::from_secs(expires_at.saturating_sub(now))))
}

fn required_string(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("missing {field}"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing {field}"))
}

fn require_str(value: &Value, field: &str, expected: &str) -> Result<()> {
    if required_string(value, field)? != expected {
        bail!("invalid {field}");
    }
    Ok(())
}

fn constant_time_hex_eq(actual: &str, expected: &str) -> Result<()> {
    if actual.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        bail!("social graph hash mismatch")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sybil_resistance::replay_store::InMemoryReplayStore;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::fs;

    struct Fixture {
        gate: Arc<SocialGraphGate>,
        attester: SigningKey,
        controller: SigningKey,
    }

    fn fixture(min_level: u8, policies: Vec<String>) -> Fixture {
        let attester = SigningKey::generate(&mut OsRng);
        let controller = SigningKey::generate(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attesters.json");
        fs::write(
            &path,
            json!({
                "attester:example:v1": {
                    "kid": "key-1",
                    "public_key_hex": hex::encode(attester.verifying_key().to_bytes())
                }
            })
            .to_string(),
        )
        .unwrap();
        let config = SocialGraphConfig {
            attesters_path: path,
            min_level,
            accepted_policy_ids: policies,
            state_path: dir.path().join("state.json"),
            ..SocialGraphConfig::default()
        };
        let gate = SocialGraphGate::new(config, Arc::new(InMemoryReplayStore::default())).unwrap();
        Fixture {
            gate,
            attester,
            controller,
        }
    }

    fn proof(f: &Fixture, overrides: impl FnOnce(&mut Value)) -> SybilProof {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let holder = hex::encode(Sha256::digest(f.controller.verifying_key().to_bytes()));
        let mut att = json!({
            "contract_version":"sophia/v1",
            "artifact_type":"social_graph.attestation",
            "version":"1",
            "attester_id":"attester:example:v1",
            "kid":"key-1",
            "policy_id":"clout-trust-v1",
            "issued_at":now,
            "expires_at":now + 120,
            "eligibility_level":2,
            "quota_nullifier":hex::encode(Sha256::digest(b"quota")),
            "jti":"jti-1",
            "holder_commitment":holder
        });
        overrides(&mut att);
        let sig = f.attester.sign(canonical_json(&att).unwrap().as_bytes());
        att.as_object_mut()
            .unwrap()
            .insert("signature".into(), json!(hex::encode(sig.to_bytes())));

        let binding = "request-binding";
        let mut pres = json!({
            "contract_version":"sophia/v1",
            "artifact_type":"cred.presentation",
            "presentation_id":"presentation-1",
            "cred_id":"cred:local:example",
            "request_id":"request-1",
            "grant_id":"grant-1",
            "app_id":"issuer:freebird:test",
            "created_at":now,
            "controller_public_key":hex::encode(f.controller.verifying_key().to_bytes()),
            "artifacts":[{"artifact_type":"social_graph.attestation","disclosure":"embedded","artifact":att}],
            "request_binding_hash":hex::encode(Sha256::digest(binding.as_bytes()))
        });
        let psig = f.controller.sign(canonical_json(&pres).unwrap().as_bytes());
        let psig_hex = hex::encode(psig.to_bytes());
        pres.as_object_mut()
            .unwrap()
            .insert("presentation_signature".into(), json!(psig_hex.clone()));
        SybilProof::SocialGraph {
            attestation: pres.to_string(),
            presentation: psig_hex,
        }
    }

    fn ctx() -> SybilRequestContext {
        SybilRequestContext {
            request_binding: Some("request-binding".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_valid_attestation_passes() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(&proof(&f, |_| {}), &ctx())
            .is_ok());
    }

    #[test]
    fn test_expired_attestation_fails() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(
                &proof(&f, |a| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    a["issued_at"] = json!(now - 1000);
                    a["expires_at"] = json!(now - 900);
                }),
                &ctx()
            )
            .is_err());
    }

    #[test]
    fn test_wrong_policy_fails() {
        let f = fixture(1, vec!["accepted".into()]);
        assert!(f
            .gate
            .verify_with_context(&proof(&f, |_| {}), &ctx())
            .is_err());
    }

    #[test]
    fn test_below_threshold_fails() {
        let f = fixture(3, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(&proof(&f, |_| {}), &ctx())
            .is_err());
    }

    #[test]
    fn test_bad_attester_signature_fails() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(&proof(&f, |a| a["jti"] = json!("tampered")), &ctx())
            .is_ok());
        // Rebuild then tamper after signing by editing JSON.
        if let SybilProof::SocialGraph {
            attestation,
            presentation,
        } = proof(&f, |_| {})
        {
            let mut v: Value = serde_json::from_str(&attestation).unwrap();
            v["artifacts"][0]["artifact"]["eligibility_level"] = json!(3);
            assert!(f
                .gate
                .verify_with_context(
                    &SybilProof::SocialGraph {
                        attestation: v.to_string(),
                        presentation
                    },
                    &ctx()
                )
                .is_err());
        }
    }

    #[test]
    fn test_bad_presentation_signature_fails() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        if let SybilProof::SocialGraph {
            attestation,
            presentation,
        } = proof(&f, |_| {})
        {
            let mut v: Value = serde_json::from_str(&attestation).unwrap();
            v["request_id"] = json!("tampered");
            assert!(f
                .gate
                .verify_with_context(
                    &SybilProof::SocialGraph {
                        attestation: v.to_string(),
                        presentation
                    },
                    &ctx()
                )
                .is_err());
        }
    }

    #[test]
    fn test_replay_rejected() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        let p = proof(&f, |_| {});
        assert!(f.gate.verify_with_context(&p, &ctx()).is_ok());
        assert!(f.gate.verify_with_context(&p, &ctx()).is_err());
    }

    #[test]
    fn test_empty_policy_list_rejects() {
        let f = fixture(1, vec![]);
        assert!(f
            .gate
            .verify_with_context(&proof(&f, |_| {}), &ctx())
            .is_err());
    }

    #[test]
    fn test_kid_mismatch_rejects() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(&proof(&f, |a| a["kid"] = json!("key-2")), &ctx())
            .is_err());
    }

    #[test]
    fn test_revoked_kid_rejects() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        f.gate
            .state
            .write()
            .unwrap()
            .revoked_key_ids
            .insert("key-1".to_string());
        assert!(f
            .gate
            .verify_with_context(&proof(&f, |_| {}), &ctx())
            .is_err());
    }

    #[test]
    fn test_holder_commitment_mismatch_rejects() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(
                &proof(&f, |a| a["holder_commitment"] =
                    json!(hex::encode([7u8; 32]))),
                &ctx()
            )
            .is_err());
    }

    #[test]
    fn test_missing_request_binding_rejects() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(&proof(&f, |_| {}), &SybilRequestContext::default())
            .is_err());
    }

    #[test]
    fn test_untrusted_attester_rejects() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(
                &proof(&f, |a| a["attester_id"] = json!("attester:unknown:v1")),
                &ctx()
            )
            .is_err());
    }

    #[test]
    fn test_future_issued_at_rejects() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(
                &proof(&f, |a| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    a["issued_at"] = json!(now + 3600);
                    a["expires_at"] = json!(now + 7200);
                }),
                &ctx()
            )
            .is_err());
    }

    #[test]
    fn test_wrong_contract_version_rejects() {
        let f = fixture(1, vec!["clout-trust-v1".into()]);
        assert!(f
            .gate
            .verify_with_context(
                &proof(&f, |a| a["contract_version"] = json!("sophia/v2")),
                &ctx()
            )
            .is_err());

        if let SybilProof::SocialGraph {
            attestation,
            presentation,
        } = proof(&f, |_| {})
        {
            let mut v: Value = serde_json::from_str(&attestation).unwrap();
            v["contract_version"] = json!("sophia/v2");
            assert!(f
                .gate
                .verify_with_context(
                    &SybilProof::SocialGraph {
                        attestation: v.to_string(),
                        presentation,
                    },
                    &ctx()
                )
                .is_err());
        }
    }
}
