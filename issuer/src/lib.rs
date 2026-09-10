pub mod audit;
pub mod config;
pub mod exchange;
pub mod graph_issuance;
pub mod keys;
pub mod multi_key_voprf;
pub mod native_bearer_v7;
pub mod readiness;
pub mod replay_authority;
pub mod routes;
pub mod shutdown;
pub mod startup;
pub mod sybil_resistance;
pub mod v7_registry;
pub mod v7_signers;
pub mod voprf_core;
pub mod webauthn;

// Re-export for convenience
pub use main_state::AppStateWithSybil;

// We need to move AppStateWithSybil out of main.rs to a shared place.
// Let's create a small internal module for it or put it in lib.rs directly.
pub mod main_state {
    use crate::sybil_resistance::{invitation::InvitationSystem, SybilResistance};
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct AppStateWithSybil {
        pub issuer_id: String,
        pub kid: String,
        pub pubkey_b64: String,
        pub require_tls: bool,
        pub behind_proxy: bool,
        pub sybil_checker: Option<Arc<dyn SybilResistance>>,
        pub admission: crate::sybil_resistance::admission::AdmissionExecutor,
        pub invitation_system: Option<Arc<InvitationSystem>>,
        /// The mandatory active V7 native bearer signer. Startup initializes
        /// this field before the HTTP listener is bound.
        pub native_bearer_v7: Arc<crate::native_bearer_v7::NativeBearerV7Issuer>,
        /// Immutable retained V7 discovery records published with the active key.
        pub native_bearer_v7_retained: Vec<freebird_common::api::NativeBearerV7KeyInfo>,
        /// Active V7 exchange engine and immutable discovery.
        pub native_exchange_v7: Option<Arc<crate::exchange::v7::V7ExchangeEngine>>,
        pub native_exchange_v7_discovery: Option<freebird_common::api::NativeExchangeV3Discovery>,
        /// Active V7 graph-issuance engine and immutable discovery.
        pub native_graph_issuance_v7: Option<Arc<crate::graph_issuance::V7GraphIssuanceEngine>>,
        pub native_graph_issuance_v7_discovery:
            Option<freebird_common::api::NativeGraphIssuanceV7Discovery>,
        pub replay_authority: Option<Arc<crate::replay_authority::ReplayAuthority>>,
        /// Duration of each epoch in seconds (default: 86400 = 1 day)
        pub epoch_duration_sec: u64,
        /// Number of previous epochs to accept (for graceful rotation)
        pub epoch_retention: u32,
        /// Admin API key used to authenticate privileged endpoints
        /// (e.g. the `/v1/oprf/renew` route). `None` means admin auth is
        /// disabled and such endpoints return 503.
        pub admin_api_key: Option<String>,
        /// Sanitized Sybil resistance configuration summary, published in the
        /// `/.well-known/issuer` metadata so clients can auto-select PoW
        /// difficulty and know which sybil mechanisms are required.
        pub sybil_summary: Option<crate::routes::admin::SybilConfigSummary>,
    }

    impl AppStateWithSybil {
        /// Calculate current epoch based on Unix timestamp
        pub fn current_epoch(&self) -> u32 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            (now / self.epoch_duration_sec) as u32
        }

        /// Get list of currently valid epochs (current and recent past)
        pub fn valid_epochs(&self) -> Vec<u32> {
            let current = self.current_epoch();
            let start = current.saturating_sub(self.epoch_retention);
            (start..=current).collect()
        }
    }

    #[cfg(test)]
    pub fn test_native_bearer_v7() -> Arc<crate::native_bearer_v7::NativeBearerV7Issuer> {
        let root = tempfile::tempdir().expect("temporary V7 test directory");
        Arc::new(
            crate::native_bearer_v7::NativeBearerV7Issuer::load_or_generate(
                &crate::config::NativeBearerV7Config {
                    sk_path: root.path().join("v7.der"),
                    metadata_path: root.path().join("v7.json"),
                    registry_path: root.path().join("registry.json"),
                    profile_id: freebird_common::api::NATIVE_BEARER_V7_PROFILE_ID.into(),
                    descriptor_id: String::new(),
                    token_key_id: "01".repeat(32),
                    asset_id: "USD".into(),
                    amount_minor: 1,
                    validity_secs: 3600,
                },
                "test-issuer",
            )
            .expect("test V7 issuer"),
        )
    }
}
