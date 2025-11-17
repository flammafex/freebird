// issuer/src/sybil_resistance/invitation.rs
//! Invitation-based Sybil resistance mechanism with persistence
//!
//! This system provides a trust-based approach where existing users can invite new users.
//! Key features:
//! - Cryptographically signed invitation codes (ECDSA P-256)
//! - Invite quotas and cooldown periods
//! - Reputation tracking
//! - Ban tree propagation (banning a user can ban their invitees)
//! - JSON-based persistence (survives restarts)

use super::{current_timestamp, verify_timestamp_recent, SybilProof, SybilResistance};
use anyhow::{anyhow, bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

/// Configuration for the invitation system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvitationConfig {
    /// How many invites each user gets by default
    pub invites_per_user: u32,
    /// Minimum time between sending invites (seconds)
    pub invite_cooldown_secs: u64,
    /// How long an invitation is valid (seconds)
    pub invite_expires_secs: u64,
    /// How long a new user must wait before they can invite (seconds)
    pub new_user_can_invite_after_secs: u64,
    /// Path to persistence file
    #[serde(default = "default_persistence_path")]
    pub persistence_path: PathBuf,
    /// Auto-save interval (seconds), 0 = only on shutdown
    #[serde(default = "default_autosave_interval")]
    pub autosave_interval_secs: u64,
}

fn default_persistence_path() -> PathBuf {
    PathBuf::from("invitations.json")
}

fn default_autosave_interval() -> u64 {
    300 // 5 minutes
}

impl Default for InvitationConfig {
    fn default() -> Self {
        Self {
            invites_per_user: 5,
            invite_cooldown_secs: 3600,              // 1 hour
            invite_expires_secs: 30 * 24 * 3600,     // 30 days
            new_user_can_invite_after_secs: 30 * 24 * 3600, // 30 days
            persistence_path: default_persistence_path(),
            autosave_interval_secs: default_autosave_interval(),
        }
    }
}

/// Represents a single invitation
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Invitation {
    /// Unique invitation code
    code: String,
    /// User ID who created this invite
    inviter_id: String,
    /// User ID who redeemed it (if used)
    invitee_id: Option<String>,
    /// When the invitation was created (Unix timestamp)
    created_at: u64,
    /// When the invitation expires (Unix timestamp)
    expires_at: u64,
    /// ECDSA signature of the code (hex encoded for JSON)
    #[serde(with = "hex_serde")]
    signature: Vec<u8>,
    /// Whether this invitation has been redeemed
    redeemed: bool,
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// State tracking for a user who can send invites
#[derive(Clone, Debug, Serialize, Deserialize)]
struct InviterState {
    /// User's identifier
    user_id: String,
    /// How many invites they have left
    invites_remaining: u32,
    /// List of invitation codes they've created
    invites_sent: Vec<String>,
    /// List of invitation codes that were redeemed
    invites_used: Vec<String>,
    /// When this user joined (Unix timestamp)
    joined_at: u64,
    /// Last time they sent an invite (Unix timestamp)
    last_invite_at: u64,
    /// Trust score (0.0 = banned, 1.0 = perfect)
    reputation: f64,
    /// Whether this user is banned
    banned: bool,
}

impl InviterState {
    fn new(user_id: String, invites: u32, joined_at: u64) -> Self {
        Self {
            user_id,
            invites_remaining: invites,
            invites_sent: Vec::new(),
            invites_used: Vec::new(),
            joined_at,
            last_invite_at: 0,
            reputation: 1.0,
            banned: false,
        }
    }
}

/// Persisted state of the invitation system
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedState {
    invitations: HashMap<String, Invitation>,
    inviters: HashMap<String, InviterState>,
    version: u32,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            invitations: HashMap::new(),
            inviters: HashMap::new(),
            version: 1,
        }
    }
}

/// The main invitation system with persistence
pub struct InvitationSystem {
    /// ECDSA signing key for signing invitation codes
    issuer_key: SigningKey,
    /// Public key for verification
    issuer_pubkey: VerifyingKey,
    /// Storage for invitations and inviters (in-memory cache)
    state: Arc<RwLock<PersistedState>>,
    /// Configuration
    config: InvitationConfig,
    /// Flag to track if state has been modified since last save
    dirty: Arc<RwLock<bool>>,
}

impl InvitationSystem {
    /// Create a new invitation system
    pub fn new(issuer_key: SigningKey, config: InvitationConfig) -> Self {
        let issuer_pubkey = VerifyingKey::from(&issuer_key);
        
        Self {
            issuer_key,
            issuer_pubkey,
            state: Arc::new(RwLock::new(PersistedState::default())),
            config,
            dirty: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Create and load from persistence file
    pub async fn load_or_create(
        issuer_key: SigningKey,
        config: InvitationConfig,
    ) -> Result<Self> {
        let issuer_pubkey = VerifyingKey::from(&issuer_key);
        
        let state = if config.persistence_path.exists() {
            info!("Loading invitation state from {:?}", config.persistence_path);
            let data = tokio::fs::read_to_string(&config.persistence_path)
                .await
                .context("read persistence file")?;
            let loaded: PersistedState = serde_json::from_str(&data)
                .context("deserialize invitation state")?;
            info!(
                "Loaded {} invitations and {} users",
                loaded.invitations.len(),
                loaded.inviters.len()
            );
            loaded
        } else {
            info!("No persistence file found, starting fresh");
            PersistedState::default()
        };
        
        let system = Self {
            issuer_key,
            issuer_pubkey,
            state: Arc::new(RwLock::new(state)),
            config,
            dirty: Arc::new(RwLock::new(false)),
        };
        
        // Start autosave task if configured
        if system.config.autosave_interval_secs > 0 {
            system.start_autosave_task();
        }
        
        Ok(system)
    }
    
    /// Start background autosave task
    fn start_autosave_task(&self) {
        let state = self.state.clone();
        let dirty = self.dirty.clone();
        let path = self.config.persistence_path.clone();
        let interval = self.config.autosave_interval_secs;
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(
                std::time::Duration::from_secs(interval)
            );
            
            loop {
                interval_timer.tick().await;
                
                // Only save if dirty
                let is_dirty = *dirty.read().await;
                if !is_dirty {
                    continue;
                }
                
                let state_snapshot = state.read().await.clone();
                
                match Self::save_to_file(&state_snapshot, &path).await {
                    Ok(_) => {
                        *dirty.write().await = false;
                        debug!("Autosaved invitation state");
                    }
                    Err(e) => {
                        error!("Autosave failed: {:?}", e);
                    }
                }
            }
        });
    }
    
    /// Save state to file
    async fn save_to_file(state: &PersistedState, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(state)
            .context("serialize state")?;
        
        // Atomic write: write to temp file, then rename
        let temp_path = path.with_extension("tmp");
        tokio::fs::write(&temp_path, json)
            .await
            .context("write temp file")?;
        tokio::fs::rename(&temp_path, path)
            .await
            .context("rename temp file")?;
        
        Ok(())
    }
    
    /// Explicitly save current state
    pub async fn save(&self) -> Result<()> {
        let state_snapshot = self.state.read().await.clone();
        Self::save_to_file(&state_snapshot, &self.config.persistence_path).await?;
        *self.dirty.write().await = false;
        info!("Saved invitation state to {:?}", self.config.persistence_path);
        Ok(())
    }
    
    /// Mark state as dirty
    async fn mark_dirty(&self) {
        *self.dirty.write().await = true;
    }

    /// Generate a random invitation code
    fn generate_code() -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 16] = rng.gen();
        Base64UrlUnpadded::encode_string(&bytes)
    }

    /// Sign an invitation code
    fn sign_code(&self, code: &str) -> Vec<u8> {
        let signature: Signature = self.issuer_key.sign(code.as_bytes());
        signature.to_bytes().to_vec()
    }

    /// Verify a signature on an invitation code
    fn verify_signature(&self, code: &str, sig: &[u8]) -> Result<()> {
        let signature = Signature::from_bytes(sig.into())
            .context("invalid signature format")?;
        self.issuer_pubkey
            .verify(code.as_bytes(), &signature)
            .context("signature verification failed")?;
        Ok(())
    }

    /// Add a bootstrap user with invite privileges
    pub async fn add_bootstrap_user(&self, user_id: String, invites: u32) {
        let mut state = self.state.write().await;
        
        if state.inviters.contains_key(&user_id) {
            warn!(user_id = %user_id, "bootstrap user already exists");
            return;
        }

        let inviter_state = InviterState::new(user_id.clone(), invites, current_timestamp());
        state.inviters.insert(user_id.clone(), inviter_state);
        drop(state);
        
        self.mark_dirty().await;
        info!(user_id = %user_id, invites = invites, "added bootstrap user");
    }

    /// Check if a user can send invites right now
    async fn can_invite(&self, user_id: &str) -> Result<()> {
        let state = self.state.read().await;
        
        let inviter = state.inviters
            .get(user_id)
            .ok_or_else(|| anyhow!("user not found"))?;

        if inviter.banned {
            bail!("user is banned");
        }

        if inviter.invites_remaining == 0 {
            bail!("no invites remaining");
        }

        let now = current_timestamp();

        // Check if new user needs to wait before inviting
        if now < inviter.joined_at + self.config.new_user_can_invite_after_secs {
            let wait_time = inviter.joined_at + self.config.new_user_can_invite_after_secs - now;
            bail!("new user must wait {} more seconds before inviting", wait_time);
        }

        // Check cooldown period
        if inviter.last_invite_at > 0 {
            let cooldown_until = inviter.last_invite_at + self.config.invite_cooldown_secs;
            if now < cooldown_until {
                let remaining = cooldown_until - now;
                bail!("cooldown period: please wait {} more seconds", remaining);
            }
        }

        Ok(())
    }

    /// Generate a new invitation code
    pub async fn generate_invite(&self, inviter_id: &str) -> Result<(String, Vec<u8>, u64)> {
        // Check if user can invite
        self.can_invite(inviter_id).await?;

        let code = Self::generate_code();
        let signature = self.sign_code(&code);
        let now = current_timestamp();
        let expires_at = now + self.config.invite_expires_secs;

        let invitation = Invitation {
            code: code.clone(),
            inviter_id: inviter_id.to_string(),
            invitee_id: None,
            created_at: now,
            expires_at,
            signature: signature.clone(),
            redeemed: false,
        };

        // Store invitation and update inviter state
        {
            let mut state = self.state.write().await;
            state.invitations.insert(code.clone(), invitation);
            
            if let Some(inviter) = state.inviters.get_mut(inviter_id) {
                inviter.invites_remaining -= 1;
                inviter.invites_sent.push(code.clone());
                inviter.last_invite_at = now;
            }
        }
        
        self.mark_dirty().await;

        info!(
            inviter_id = %inviter_id,
            code = %code,
            expires_at = expires_at,
            "generated invitation"
        );

        Ok((code, signature, expires_at))
    }

    /// Verify an invitation is valid (doesn't redeem it)
    async fn verify_invitation(&self, code: &str, signature: &[u8]) -> Result<String> {
        // Verify signature
        self.verify_signature(code, signature)?;

        let state = self.state.read().await;
        let invitation = state.invitations
            .get(code)
            .ok_or_else(|| anyhow!("invitation not found"))?;

        let now = current_timestamp();

        // Check expiry
        if now > invitation.expires_at {
            bail!("invitation expired");
        }

        // Check if already redeemed
        if invitation.redeemed {
            bail!("invitation already used");
        }

        Ok(invitation.inviter_id.clone())
    }

    /// Redeem an invitation - FIXED: Better invitee ID generation
    async fn redeem_invitation(&self, code: &str, client_data: &str) -> Result<String> {
        let now = current_timestamp();

        // Generate invitee ID with more entropy
        let invitee_id = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"freebird:invitee:");
            hasher.update(code.as_bytes());
            hasher.update(b":");
            hasher.update(client_data.as_bytes()); // Include client-provided data
            hasher.update(b":");
            hasher.update(now.to_le_bytes()); // Include redemption timestamp
            let hash = hasher.finalize();
            Base64UrlUnpadded::encode_string(&hash[..24]) // Use 192 bits
        };

        let inviter_id = {
            let mut state = self.state.write().await;
            let invitation = state.invitations
                .get_mut(code)
                .ok_or_else(|| anyhow!("invitation not found"))?;

            if invitation.redeemed {
                bail!("invitation already redeemed");
            }

            invitation.redeemed = true;
            invitation.invitee_id = Some(invitee_id.clone());
            
            let inviter_id = invitation.inviter_id.clone();
            
            // Update inviter's used list
            if let Some(inviter) = state.inviters.get_mut(&inviter_id) {
                inviter.invites_used.push(code.to_string());
            }

            // Create new user with 0 invites initially (earn them later)
            let invitee_state = InviterState::new(invitee_id.clone(), 0, now);
            state.inviters.insert(invitee_id.clone(), invitee_state);
            
            inviter_id
        };
        
        self.mark_dirty().await;

        info!(
            code = %code,
            invitee_id = %invitee_id,
            inviter_id = %inviter_id,
            "redeemed invitation"
        );

        Ok(invitee_id)
    }

    /// Ban a user and optionally their entire invite tree
    pub async fn ban_user(&self, user_id: &str, ban_tree: bool) {
        let mut state = self.state.write().await;

        if let Some(inviter) = state.inviters.get_mut(user_id) {
            inviter.banned = true;
            inviter.reputation = 0.0;
            info!(user_id = %user_id, "banned user");
        }

        if ban_tree {
            // Find all users invited by this user (recursively)
            let mut to_ban = Vec::new();
            
            for invitation in state.invitations.values() {
                if invitation.inviter_id == user_id {
                    if let Some(ref invitee_id) = invitation.invitee_id {
                        to_ban.push(invitee_id.clone());
                    }
                }
            }

            // Ban invitees
            for invitee_id in to_ban {
                if let Some(inviter) = state.inviters.get_mut(&invitee_id) {
                    inviter.banned = true;
                    inviter.reputation = 0.0;
                    warn!(user_id = %invitee_id, "banned user (tree ban)");
                }
            }
        }
        
        drop(state);
        self.mark_dirty().await;
    }

    /// Grant invites to a user (for reputation rewards, etc.)
    pub async fn grant_invites(&self, user_id: &str, count: u32) -> Result<()> {
        let mut state = self.state.write().await;
        
        let inviter = state.inviters
            .get_mut(user_id)
            .ok_or_else(|| anyhow!("user not found"))?;

        if inviter.banned {
            bail!("cannot grant invites to banned user");
        }

        inviter.invites_remaining += count;
        drop(state);
        
        self.mark_dirty().await;
        info!(user_id = %user_id, count = count, "granted invites");
        
        Ok(())
    }

    /// Get invitation statistics
    pub async fn get_stats(&self) -> InvitationStats {
        let state = self.state.read().await;

        let total_invitations = state.invitations.len();
        let redeemed_invitations = state.invitations.values().filter(|i| i.redeemed).count();
        let total_users = state.inviters.len();
        let banned_users = state.inviters.values().filter(|i| i.banned).count();

        InvitationStats {
            total_invitations,
            redeemed_invitations,
            pending_invitations: total_invitations - redeemed_invitations,
            total_users,
            banned_users,
        }
    }
}

/// Statistics about the invitation system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationStats {
    pub total_invitations: usize,
    pub redeemed_invitations: usize,
    pub pending_invitations: usize,
    pub total_users: usize,
    pub banned_users: usize,
}

// ============================================================================
// SybilResistance Trait Implementation
// ============================================================================

impl SybilResistance for InvitationSystem {
    fn verify(&self, proof: &SybilProof) -> Result<()> {
        // Make async context available
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let (code, signature_b64) = match proof {
                SybilProof::Invitation { code, signature } => (code, signature),
                _ => bail!("expected Invitation proof"),
            };

            // Decode signature from base64
            let signature = Base64UrlUnpadded::decode_vec(signature_b64)
                .context("invalid signature encoding")?;

            // Verify invitation is valid
            let _inviter_id = self.verify_invitation(code, &signature).await?;

            // Use code as client_data for now (could be enhanced with IP, fingerprint, etc.)
            let _invitee_id = self.redeem_invitation(code, code).await?;

            debug!(code = %code, "invitation verified and redeemed");
            Ok(())
        })
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::Invitation { .. })
    }

    fn cost(&self) -> u64 {
        self.config.invite_cooldown_secs
    }
}

// Make sure to add hex crate to dependencies
// In Cargo.toml: hex = "0.4"

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    async fn setup() -> InvitationSystem {
        let key = SigningKey::random(&mut OsRng);
        let config = InvitationConfig {
            invites_per_user: 5,
            invite_cooldown_secs: 1,
            invite_expires_secs: 3600,
            new_user_can_invite_after_secs: 1,
            persistence_path: PathBuf::from("/tmp/test_invitations.json"),
            autosave_interval_secs: 0, // Disable autosave in tests
        };
        InvitationSystem::new(key, config)
    }

    #[tokio::test]
    async fn test_generate_invite() {
        let system = setup().await;
        system.add_bootstrap_user("admin".into(), 10).await;

        let result = system.generate_invite("admin").await;
        assert!(result.is_ok());

        let (code, signature, expires_at) = result.unwrap();
        assert!(!code.is_empty());
        assert!(!signature.is_empty());
        assert!(expires_at > current_timestamp());
    }

    #[tokio::test]
    async fn test_persistence() {
        let path = PathBuf::from("/tmp/test_persistence.json");
        let _ = std::fs::remove_file(&path); // Clean up
        
        let key = SigningKey::random(&mut OsRng);
        let config = InvitationConfig {
            persistence_path: path.clone(),
            autosave_interval_secs: 0,
            ..Default::default()
        };
        
        // Create system and add user
        {
            let system = InvitationSystem::load_or_create(key.clone(), config.clone())
                .await
                .unwrap();
            system.add_bootstrap_user("admin".into(), 10).await;
            system.save().await.unwrap();
        }
        
        // Load and verify
        {
            let system = InvitationSystem::load_or_create(key, config)
                .await
                .unwrap();
            let stats = system.get_stats().await;
            assert_eq!(stats.total_users, 1);
        }
        
        let _ = std::fs::remove_file(&path);
    }
}