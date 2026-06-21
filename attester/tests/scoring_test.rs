// SPDX-License-Identifier: Apache-2.0 OR MIT

use attester::{
    scoring::{clout_signature_message, evaluate_social_graph, ScoringConfig, ScoringResult},
    types::TrustEdge,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::collections::HashMap;

const NOW: u64 = 1_760_000_000;

struct G {
    keys: HashMap<String, SigningKey>,
    edges: Vec<TrustEdge>,
}
impl G {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            edges: vec![],
        }
    }
    fn pk(&mut self, name: &str) -> String {
        hex::encode(
            self.keys
                .entry(name.into())
                .or_insert_with(|| SigningKey::generate(&mut OsRng))
                .verifying_key()
                .as_bytes(),
        )
    }
    fn edge(&mut self, a: &str, b: &str, weight: f64, age: u64) {
        self.edge_rev(a, b, weight, age, false);
    }
    fn edge_rev(&mut self, a: &str, b: &str, weight: f64, age: u64, revoked: bool) {
        let truster = self.pk(a);
        let trustee = self.pk(b);
        let mut e = TrustEdge {
            truster: truster.clone(),
            trustee,
            weight,
            timestamp: NOW - age * 86_400,
            revoked,
            signature: String::new(),
        };
        let msg = clout_signature_message(&e).unwrap();
        e.signature = hex::encode(self.keys[a].sign(&msg).to_bytes());
        self.edges.push(e);
    }
    fn root(&mut self) -> Vec<String> {
        vec![self.pk("R0")]
    }
    fn sub(&mut self, name: &str) -> String {
        self.pk(name)
    }
}
fn pass(r: ScoringResult) -> bool {
    matches!(r, ScoringResult::Pass { .. })
}
fn reasons(r: ScoringResult) -> Vec<String> {
    match r {
        ScoringResult::Fail { reasons, .. } => reasons,
        _ => vec![],
    }
}
fn eval(g: &mut G, s: &str) -> ScoringResult {
    let sub = g.sub(s);
    let roots = g.root();
    evaluate_social_graph(&sub, &g.edges, &roots, NOW, &ScoringConfig::default())
}

#[test]
fn healthy_community_passes() {
    let mut g = G::new();
    g.edge("R0", "A", 0.9, 365);
    g.edge("R0", "B", 0.8, 300);
    g.edge("A", "C", 0.7, 180);
    g.edge("B", "D", 0.6, 120);
    g.edge("A", "T", 0.8, 90);
    g.edge("B", "T", 0.6, 45);
    g.edge("C", "T", 0.4, 20);
    assert!(pass(eval(&mut g, "T")));
}
#[test]
fn cold_start_fails() {
    let mut g = G::new();
    g.edge("R0", "E", 0.8, 100);
    g.edge("E", "T", 0.7, 2);
    let rs = reasons(eval(&mut g, "T"));
    assert!(rs.contains(&"insufficient_independent_edges".into()));
    assert!(rs.contains(&"edge_too_young".into()));
}
#[test]
fn minimum_viable_passes() {
    let mut g = G::new();
    g.edge("R0", "M", 0.8, 120);
    g.edge("R0", "N", 0.8, 120);
    g.edge("M", "T", 0.4, 8);
    g.edge("N", "T", 0.3, 8);
    assert!(pass(eval(&mut g, "T")));
}
#[test]
fn collusion_ring_fails_without_seed_root() {
    let mut g = G::new();
    for i in 1..=10 {
        for j in 1..=10 {
            if i != j {
                g.edge(&format!("F{i}"), &format!("F{j}"), 0.9, 1)
            }
        }
    }
    let rs = reasons(eval(&mut g, "F1"));
    assert!(rs.contains(&"no_seed_rooted_path".into()));
    assert!(rs.contains(&"edge_too_young".into()));
}
#[test]
fn bridge_farming_fails_when_edges_too_young() {
    let mut g = G::new();
    for i in 1..=3 {
        g.edge("R0", &format!("H{i}"), 0.9, 300);
        g.edge(&format!("H{i}"), "T", 0.9 - (i as f64 / 10.0), 2);
    }
    assert!(reasons(eval(&mut g, "T")).contains(&"edge_too_young".into()));
}
#[test]
fn aged_farmer_passes_known_false_negative() {
    let mut g = G::new();
    for (i, w) in [(4, 0.5), (5, 0.4), (6, 0.4)] {
        g.edge("R0", &format!("H{i}"), 0.9, 300);
        g.edge(&format!("H{i}"), "T", w, 30);
    }
    assert!(pass(eval(&mut g, "T")));
}
#[test]
fn whaling_fails_due_to_fanout_discount() {
    let mut g = G::new();
    g.edge("R0", "W", 1.0, 365);
    g.edge("R0", "L", 0.8, 365);
    for i in 1..=35 {
        g.edge("W", &format!("Legacy{i}"), 0.6, 100)
    }
    for i in 1..=15 {
        g.edge("W", &format!("S{i}"), 1.0, 10);
        g.edge("L", &format!("S{i}"), 0.1, 10)
    }
    assert!(reasons(eval(&mut g, "S1")).contains(&"weighted_score_below_threshold".into()));
}
#[test]
fn revoked_edges_are_ignored() {
    let mut g = G::new();
    g.edge("R0", "A", 0.8, 100);
    g.edge_rev("A", "T", 0.0, 30, true);
    assert!(reasons(eval(&mut g, "T")).contains(&"no_inbound_trust_edges".into()));
}
#[test]
fn bad_signature_rejects_evidence() {
    let mut g = G::new();
    g.edge("R0", "A", 0.8, 100);
    g.edges[0].signature = "00".repeat(64);
    assert!(reasons(eval(&mut g, "A")).contains(&"bad_signature".into()));
}
#[test]
fn duplicate_edges_from_same_truster_count_once() {
    let mut g = G::new();
    g.edge("R0", "A", 0.8, 100);
    g.edge("R0", "B", 0.8, 100);
    g.edge("A", "T", 0.3, 30);
    g.edge("A", "T", 0.9, 30);
    let r = eval(&mut g, "T");
    match r {
        ScoringResult::Fail {
            independent_edges, ..
        } => assert_eq!(independent_edges, 1),
        _ => panic!("expected fail"),
    }
}
