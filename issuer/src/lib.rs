pub mod config;
pub mod keys;
pub mod multi_key_voprf;
pub mod routes;
pub mod startup;
pub mod sybil_resistance;
pub mod voprf_core;

#[cfg(feature = "human-gate-webauthn")]
pub mod webauthn_ctx;
#[cfg(feature = "human-gate-webauthn")]
pub mod webauthn_store;

// Re-export for convenience
pub use main_state::AppStateWithSybil;

// We need to move AppStateWithSybil out of main.rs to a shared place.
// Let's create a small internal module for it or put it in lib.rs directly.
pub mod main_state {
    use std::sync::Arc;
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
    }
}