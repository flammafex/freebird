// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::types::TrustEdge;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct ScoringConfig {
    pub min_independent_edges: usize,
    pub min_edge_age_days: u64,
    pub min_weighted_score: f64,
    pub fanout_cap: usize,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            min_independent_edges: 2,
            min_edge_age_days: 7,
            min_weighted_score: 0.3,
            fanout_cap: 20,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScoringResult {
    Pass {
        weighted_score: f64,
        independent_edges: usize,
        eligibility_level: u8,
    },
    Fail {
        reasons: Vec<String>,
        weighted_score: f64,
        independent_edges: usize,
    },
}

pub fn clout_signature_message(edge: &TrustEdge) -> Option<Vec<u8>> {
    if !(0.0..=1.0).contains(&edge.weight) || (edge.revoked && edge.weight != 0.0) {
        return None;
    }
    let mut map = serde_json::Map::new();
    map.insert("timestamp".into(), json!(edge.timestamp));
    map.insert("trustee".into(), json!(edge.trustee));
    map.insert("truster".into(), json!(edge.truster));
    map.insert("weight".into(), json!(edge.weight));
    if edge.revoked || edge.weight == 0.0 {
        map.insert("revoked".into(), Value::Bool(true));
    }
    let canonical = serde_json::to_string(&Value::Object(map)).ok()?;
    let hash = hex::encode(Sha256::digest(canonical.as_bytes()));
    Some(format!("CLOUT_TRUST_SIGNAL_V1:{hash}").into_bytes())
}

pub fn verify_edge_signature(edge: &TrustEdge) -> bool {
    let Ok(pubkey) = hex::decode(&edge.truster) else {
        return false;
    };
    let Ok(sig) = hex::decode(&edge.signature) else {
        return false;
    };
    let Ok(key_bytes) = <[u8; 32]>::try_from(pubkey.as_slice()) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(sig.as_slice()) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    clout_signature_message(edge).is_some_and(|msg| key.verify(&msg, &signature).is_ok())
}

pub fn evaluate_social_graph(
    subject: &str,
    edges: &[TrustEdge],
    trusted_roots: &[String],
    now: u64,
    config: &ScoringConfig,
) -> ScoringResult {
    let mut reasons = Vec::new();
    let mut valid = Vec::new();
    for edge in edges {
        if !verify_edge_signature(edge) {
            return ScoringResult::Fail {
                reasons: vec!["bad_signature".into()],
                weighted_score: 0.0,
                independent_edges: 0,
            };
        }
        if (!edge.revoked && edge.weight < 0.1) || edge.weight > 1.0 {
            return ScoringResult::Fail {
                reasons: vec!["invalid_weight".into()],
                weighted_score: 0.0,
                independent_edges: 0,
            };
        }
        if !edge.revoked {
            valid.push(edge);
        }
    }
    let mut out_degree: HashMap<&str, usize> = HashMap::new();
    for e in &valid {
        *out_degree.entry(e.truster.as_str()).or_default() += 1;
    }
    let age_ok =
        |e: &TrustEdge| now.saturating_sub(e.timestamp) / 86_400 > config.min_edge_age_days;
    let aged: Vec<&TrustEdge> = valid.iter().copied().filter(|e| age_ok(e)).collect();
    if !has_path(trusted_roots, subject, &aged) {
        reasons.push("no_seed_rooted_path".into());
    }
    let inbound: Vec<&TrustEdge> = valid
        .iter()
        .copied()
        .filter(|e| e.trustee == subject)
        .collect();
    if inbound.is_empty() {
        reasons.push("no_inbound_trust_edges".into());
    }
    let eligible: Vec<&TrustEdge> = inbound.iter().copied().filter(|e| age_ok(e)).collect();
    if eligible.len() < inbound.len() {
        reasons.push("edge_too_young".into());
    }
    let mut best: HashMap<&str, f64> = HashMap::new();
    for e in eligible {
        let degree = *out_degree.get(e.truster.as_str()).unwrap_or(&0);
        if degree == 0 {
            continue;
        }
        let factor = (config.fanout_cap as f64 / degree as f64).min(1.0);
        best.entry(e.truster.as_str())
            .and_modify(|w| *w = w.max(e.weight * factor))
            .or_insert(e.weight * factor);
    }
    let independent_edges = best.len();
    if independent_edges < config.min_independent_edges {
        reasons.push("insufficient_independent_edges".into());
    }
    let weighted_score = if independent_edges == 0 {
        0.0
    } else {
        best.values().sum::<f64>() / independent_edges as f64
    };
    if weighted_score < config.min_weighted_score {
        reasons.push("weighted_score_below_threshold".into());
    }
    let level = if weighted_score >= 0.5 {
        3
    } else if weighted_score >= 0.3 {
        2
    } else if weighted_score >= 0.1 {
        1
    } else {
        0
    };
    if level == 0
        && !reasons
            .iter()
            .any(|r| r == "weighted_score_below_threshold")
    {
        reasons.push("weighted_score_below_threshold".into());
    }
    if reasons.is_empty() {
        ScoringResult::Pass {
            weighted_score,
            independent_edges,
            eligibility_level: level,
        }
    } else {
        ScoringResult::Fail {
            reasons,
            weighted_score,
            independent_edges,
        }
    }
}

fn has_path(roots: &[String], subject: &str, edges: &[&TrustEdge]) -> bool {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in edges {
        adj.entry(&e.truster).or_default().push(&e.trustee);
    }
    let mut seen = HashSet::new();
    let mut q: VecDeque<&str> = roots.iter().map(String::as_str).collect();
    while let Some(n) = q.pop_front() {
        if n == subject {
            return true;
        }
        if !seen.insert(n) {
            continue;
        }
        if let Some(ns) = adj.get(n) {
            for next in ns {
                q.push_back(next);
            }
        }
    }
    false
}
