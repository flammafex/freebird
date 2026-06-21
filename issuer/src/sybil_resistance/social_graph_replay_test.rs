// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use crate::sybil_resistance::replay_store::{InMemoryReplayStore, ReplayStore};
    use std::time::Duration;

    #[derive(Debug)]
    struct MockSocialGraphAttestation {
        attester_id: String,
        jti: String,
        quota_nullifier: Option<String>,
    }

    impl MockSocialGraphAttestation {
        fn jti_replay_key(&self) -> String {
            format!("{}:{}", self.attester_id, self.jti)
        }

        fn quota_replay_key(&self) -> Option<String> {
            self.quota_nullifier
                .as_ref()
                .map(|quota_nullifier| format!("{}:{}", self.attester_id, quota_nullifier))
        }
    }

    fn mock_attestation() -> MockSocialGraphAttestation {
        MockSocialGraphAttestation {
            attester_id: "attester:example:v1".to_string(),
            jti: "jti-1".to_string(),
            quota_nullifier: Some(
                "c2d0e3f4a5b697887766554433221100ffeeddccbbaa99887766554433221100".to_string(),
            ),
        }
    }

    #[test]
    fn social_graph_replay_store_rejects_reused_jti() {
        let store = InMemoryReplayStore::default();
        let attestation = mock_attestation();
        let replay_key = attestation.jti_replay_key();

        assert!(store
            .mark_once("social_graph:jti", &replay_key, Duration::from_secs(300))
            .is_ok());
        assert!(store
            .mark_once("social_graph:jti", &replay_key, Duration::from_secs(300))
            .is_err());
    }

    #[test]
    fn social_graph_replay_store_enforces_quota_nullifier() {
        let store = InMemoryReplayStore::default();
        let quota_key = mock_attestation()
            .quota_replay_key()
            .expect("mock attestation includes quota nullifier");

        assert!(store
            .mark_once("social_graph:quota", &quota_key, Duration::from_secs(3600))
            .is_ok());
        assert!(store
            .mark_once("social_graph:quota", &quota_key, Duration::from_secs(3600))
            .is_err());
    }

    #[test]
    fn social_graph_replay_store_allows_reuse_after_ttl_expiry() {
        let store = InMemoryReplayStore::default();
        let replay_key = mock_attestation().jti_replay_key();

        store
            .mark_once("social_graph:jti", &replay_key, Duration::from_secs(1))
            .unwrap();
        std::thread::sleep(Duration::from_secs(2));

        assert!(store
            .mark_once("social_graph:jti", &replay_key, Duration::from_secs(300))
            .is_ok());
    }
}
