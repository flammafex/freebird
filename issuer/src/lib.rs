pub mod audit;
pub mod config;
pub mod federation_store;
pub mod keys;
pub mod multi_key_voprf;
pub mod routes;
pub mod startup;
pub mod sybil_resistance;
pub mod voprf_core;
pub mod webauthn;

// Re-export for convenience
pub use main_state::AppStateWithSybil;

// We need to move AppStateWithSybil out of main.rs to a shared place.
// Let's create a small internal module for it or put it in lib.rs directly.
pub mod main_state {
    use std::sync::Arc;
    use crate::federation_store::FederationStore;
    use crate::sybil_resistance::{invitation::InvitationSystem, SybilResistance};

    #[derive(Clone)]
    pub struct AppStateWithSybil {
        pub issuer_id: String,
        pub kid: String,
        pub exp_sec: u64,
        pub pubkey_b64: String,
        pub require_tls: bool,
        pub behind_proxy: bool,
        pub sybil_checker: Option<Arc<dyn SybilResistance>>,
        pub invitation_system: Option<Arc<InvitationSystem>>,
        /// Duration of each epoch in seconds (default: 86400 = 1 day)
        pub epoch_duration_sec: u64,
        /// Number of previous epochs to accept (for graceful rotation)
        pub epoch_retention: u32,
        /// Federation storage for vouches and revocations
        pub federation_store: FederationStore,
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
}
