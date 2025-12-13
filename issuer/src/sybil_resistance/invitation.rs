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
//! - Strong invitee ID generation with cryptographic random nonce

use super::{current_timestamp, SybilProof, SybilResistance};
use anyhow::{anyhow, bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

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
            invite_cooldown_secs: 3600,                     // 1 hour
            invite_expires_secs: 30 * 24 * 3600,            // 30 days
            new_user_can_invite_after_secs: 30 * 24 * 3600, // 30 days
            persistence_path: default_persistence_path(),
            autosave_interval_secs: default_autosave_interval(),
        }
    }
}

/// Represents a single invitation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invitation {
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

impl Invitation {
    /// Get the invitation code
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Get the inviter user ID
    pub fn inviter_id(&self) -> &str {
        &self.inviter_id
    }

    /// Get the invitee user ID (if redeemed)
    pub fn invitee_id(&self) -> Option<&str> {
        self.invitee_id.as_deref()
    }

    /// Get the creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the expiration timestamp
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Check if the invitation has been redeemed
    pub fn redeemed(&self) -> bool {
        self.redeemed
    }
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
pub struct InviterState {
    /// User's identifier
    pub user_id: String,
    /// How many invites they have left
    pub invites_remaining: u32,
    /// List of invitation codes they've created
    pub invites_sent: Vec<String>,
    /// List of invitation codes that were redeemed
    pub invites_used: Vec<String>,
    /// When this user joined (Unix timestamp)
    pub joined_at: u64,
    /// Last time they sent an invite (Unix timestamp)
    pub last_invite_at: u64,
    /// Trust score (0.0 = banned, 1.0 = perfect)
    pub reputation: f64,
    /// Whether this user is banned
    pub banned: bool,
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
    /// Owner of this Freebird instance (public key of the admin user)
    #[serde(default)]
    owner: Option<String>,
    version: u32,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            invitations: HashMap::new(),
            inviters: HashMap::new(),
            owner: None,
            version: 1,
        }
    }
}

/// Client-specific data used for invitee ID generation
///
/// This provides additional entropy beyond just the invitation code,
/// making invitee IDs more unique and harder to predict.
#[derive(Debug, Clone, Default)]
pub struct ClientData {
    /// Client IP address (hashed, not stored directly)
    pub ip_addr: Option<String>,
    /// Browser/client fingerprint (e.g., User-Agent hash)
    pub fingerprint: Option<String>,
    /// Any additional context data
    pub extra: Option<String>,
}

impl ClientData {
    /// Create ClientData from just an IP address
    pub fn from_ip(ip: impl Into<String>) -> Self {
        Self {
            ip_addr: Some(ip.into()),
            fingerprint: None,
            extra: None,
        }
    }

    /// Create ClientData from IP and fingerprint
    pub fn from_ip_and_fingerprint(ip: impl Into<String>, fingerprint: impl Into<String>) -> Self {
        Self {
            ip_addr: Some(ip.into()),
            fingerprint: Some(fingerprint.into()),
            extra: None,
        }
    }

    /// Serialize for hashing (consistent ordering)
    fn to_hash_input(&self) -> Vec<u8> {
        let mut result = Vec::new();

        if let Some(ref ip) = self.ip_addr {
            result.extend_from_slice(b"ip:");
            result.extend_from_slice(ip.as_bytes());
            result.push(b'|');
        }

        if let Some(ref fp) = self.fingerprint {
            result.extend_from_slice(b"fp:");
            result.extend_from_slice(fp.as_bytes());
            result.push(b'|');
        }

        if let Some(ref extra) = self.extra {
            result.extend_from_slice(b"extra:");
            result.extend_from_slice(extra.as_bytes());
            result.push(b'|');
        }

        result
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

/// Filter criteria for listing invitations
#[derive(Debug, Clone, Default)]
pub struct InvitationFilter {
    /// Filter by status: Some(true) = redeemed only, Some(false) = pending only, None = all
    pub redeemed: Option<bool>,
    /// Filter by inviter user ID
    pub inviter_id: Option<String>,
    /// Filter by minimum creation date (Unix timestamp)
    pub date_from: Option<u64>,
    /// Filter by maximum creation date (Unix timestamp)
    pub date_to: Option<u64>,
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
    pub async fn load_or_create(issuer_key: SigningKey, config: InvitationConfig) -> Result<Self> {
        let issuer_pubkey = VerifyingKey::from(&issuer_key);

        let state = if config.persistence_path.exists() {
            info!(
                "Loading invitation state from {:?}",
                config.persistence_path
            );
            let data = tokio::fs::read_to_string(&config.persistence_path)
                .await
                .context("read persistence file")?;
            let loaded: PersistedState =
                serde_json::from_str(&data).context("deserialize invitation state")?;
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

    /// List invitations with pagination support
    ///
    /// # Arguments
    /// * `limit` - Maximum number of invitations to return
    /// * `offset` - Number of invitations to skip (for pagination)
    ///
    /// # Returns
    /// A vector of invitations sorted by creation time (newest first)
    pub async fn list_invitations(&self, limit: usize, offset: usize) -> Vec<Invitation> {
        self.list_invitations_filtered(limit, offset, None).await
    }

    /// List invitations with pagination and filtering support
    ///
    /// # Arguments
    /// * `limit` - Maximum number of invitations to return
    /// * `offset` - Number of invitations to skip (for pagination)
    /// * `filter` - Optional filter criteria
    ///
    /// # Returns
    /// A vector of invitations sorted by creation time (newest first)
    pub async fn list_invitations_filtered(
        &self,
        limit: usize,
        offset: usize,
        filter: Option<InvitationFilter>,
    ) -> Vec<Invitation> {
        let state = self.state.read().await;
        let mut invites: Vec<Invitation> = state.invitations.values().cloned().collect();

        // Apply filters if provided
        if let Some(ref f) = filter {
            invites.retain(|invite| {
                // Filter by redeemed status
                if let Some(redeemed) = f.redeemed {
                    if invite.redeemed != redeemed {
                        return false;
                    }
                }
                // Filter by inviter ID
                if let Some(ref inviter_id) = f.inviter_id {
                    if &invite.inviter_id != inviter_id {
                        return false;
                    }
                }
                // Filter by date range
                if let Some(date_from) = f.date_from {
                    if invite.created_at < date_from {
                        return false;
                    }
                }
                if let Some(date_to) = f.date_to {
                    if invite.created_at > date_to {
                        return false;
                    }
                }
                true
            });
        }

        // Sort by creation time descending
        invites.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply offset and limit
        invites.into_iter().skip(offset).take(limit).collect()
    }

    /// Get the total count of invitations (optionally filtered)
    ///
    /// Useful for pagination to show "Page X of Y"
    pub async fn count_invitations(&self) -> usize {
        self.count_invitations_filtered(None).await
    }

    /// Get the count of invitations matching a filter
    pub async fn count_invitations_filtered(&self, filter: Option<InvitationFilter>) -> usize {
        let state = self.state.read().await;

        if filter.is_none() {
            return state.invitations.len();
        }

        let f = filter.unwrap();
        state.invitations.values().filter(|invite| {
            // Filter by redeemed status
            if let Some(redeemed) = f.redeemed {
                if invite.redeemed != redeemed {
                    return false;
                }
            }
            // Filter by inviter ID
            if let Some(ref inviter_id) = f.inviter_id {
                if &invite.inviter_id != inviter_id {
                    return false;
                }
            }
            // Filter by date range
            if let Some(date_from) = f.date_from {
                if invite.created_at < date_from {
                    return false;
                }
            }
            if let Some(date_to) = f.date_to {
                if invite.created_at > date_to {
                    return false;
                }
            }
            true
        }).count()
    }

    /// Get all invitations (for export - no pagination)
    pub async fn get_all_invitations(&self) -> Vec<Invitation> {
        let state = self.state.read().await;
        let mut invites: Vec<Invitation> = state.invitations.values().cloned().collect();
        invites.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        invites
    }

    /// Get all users (for export - no pagination)
    pub async fn get_all_users(&self) -> Vec<(String, u32, bool, u64, f64)> {
        let state = self.state.read().await;
        let mut users: Vec<_> = state
            .inviters
            .values()
            .map(|inviter| {
                (
                    inviter.user_id.clone(),
                    inviter.invites_remaining,
                    inviter.banned,
                    inviter.joined_at,
                    inviter.reputation,
                )
            })
            .collect();
        users.sort_by(|a, b| b.3.cmp(&a.3)); // Sort by joined_at descending
        users
    }

    /// Start background autosave task
    fn start_autosave_task(&self) {
        let state = self.state.clone();
        let dirty = self.dirty.clone();
        let path = self.config.persistence_path.clone();
        let interval = self.config.autosave_interval_secs;

        tokio::spawn(async move {
            let mut interval_timer =
                tokio::time::interval(std::time::Duration::from_secs(interval));

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
        let json = serde_json::to_string_pretty(state).context("serialize state")?;

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
        info!(
            "Saved invitation state to {:?}",
            self.config.persistence_path
        );
        Ok(())
    }

    /// Mark state as dirty
    async fn mark_dirty(&self) {
        *self.dirty.write().await = true;
    }

    /// Generate a random invitation code
    fn generate_code() -> String {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Base64UrlUnpadded::encode_string(&bytes)
    }

    /// Sign an invitation code
    fn sign_code(&self, code: &str) -> Vec<u8> {
        let signature: Signature = self.issuer_key.sign(code.as_bytes());
        signature.to_bytes().to_vec()
    }

    /// Verify a signature on an invitation code
    fn verify_signature(&self, code: &str, sig: &[u8]) -> Result<()> {
        let signature = Signature::from_bytes(sig.into()).context("invalid signature format")?;
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
    async fn can_invite(&self, user_id: &str, skip_rate_limits: bool) -> Result<()> {
        let state = self.state.read().await;

        let inviter = state
            .inviters
            .get(user_id)
            .ok_or_else(|| anyhow!("user not found"))?;

        if inviter.banned {
            bail!("user is banned");
        }

        if inviter.invites_remaining == 0 {
            bail!("no invites remaining");
        }

        // Skip rate limit checks for admin API calls
        if skip_rate_limits {
            return Ok(());
        }

        let now = current_timestamp();

        // Check if new user needs to wait before inviting
        if now < inviter.joined_at + self.config.new_user_can_invite_after_secs {
            let wait_time = inviter.joined_at + self.config.new_user_can_invite_after_secs - now;
            bail!(
                "new user must wait {} more seconds before inviting",
                wait_time
            );
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
        self.generate_invite_internal(inviter_id, false).await
    }

    /// Generate a new invitation code (admin mode - bypasses rate limits)
    ///
    /// This should only be called from admin API endpoints that are already
    /// protected by the admin API key.
    pub async fn generate_invite_admin(&self, inviter_id: &str) -> Result<(String, Vec<u8>, u64)> {
        self.generate_invite_internal(inviter_id, true).await
    }

    /// Internal implementation for generating invitations
    async fn generate_invite_internal(&self, inviter_id: &str, skip_rate_limits: bool) -> Result<(String, Vec<u8>, u64)> {
        // Check if user can invite
        self.can_invite(inviter_id, skip_rate_limits).await?;

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
        debug!(code = %code, "verifying invitation");

        // Verify signature
        self.verify_signature(code, signature)?;

        let state = self.state.read().await;
        let invitation = state
            .invitations
            .get(code)
            .ok_or_else(|| anyhow!("invitation not found"))?;

        let now = current_timestamp();

        // Check expiry
        if now > invitation.expires_at {
            warn!(code = %code, "invitation expired");
            bail!("invitation expired");
        }

        // Check if already redeemed
        if invitation.redeemed {
            warn!(code = %code, "invitation already used - rejecting");
            bail!("invitation already used");
        }

        debug!(code = %code, inviter = %invitation.inviter_id, "invitation valid");
        Ok(invitation.inviter_id.clone())
    }

    /// Redeem an invitation and create a new user
    ///
    /// # Security Properties
    ///
    /// The invitee ID is generated by hashing:
    /// 1. Invitation code (ensures different codes → different IDs)
    /// 2. Redemption timestamp (prevents pre-computation)
    /// 3. Client-specific data (IP, fingerprint - adds entropy)
    /// 4. Cryptographic random nonce (guarantees uniqueness)
    ///
    /// This provides ~192 bits of entropy and prevents:
    /// - ID collisions (random nonce)
    /// - Pre-computation attacks (timestamp)
    /// - Linkability across sessions (each redemption is unique)
    ///
    /// # Arguments
    ///
    /// * `code` - The invitation code being redeemed
    /// * `client_data` - Optional client-specific information for entropy
    ///
    /// # Returns
    ///
    /// The newly generated invitee user ID
    async fn redeem_invitation(
        &self,
        code: &str,
        client_data: Option<ClientData>,
    ) -> Result<String> {
        let now = current_timestamp();

        // Generate invitee ID with strong entropy
        let invitee_id = {
            use sha2::{Digest, Sha256};

            let mut hasher = Sha256::new();

            // Domain separation
            hasher.update(b"freebird:invitee:v2:");

            // Invitation code (uniqueness per code)
            hasher.update(code.as_bytes());
            hasher.update(b":");

            // Redemption timestamp (prevents pre-computation)
            hasher.update(now.to_le_bytes());
            hasher.update(b":");

            // Client-specific data (optional additional entropy)
            if let Some(ref data) = client_data {
                hasher.update(data.to_hash_input());
                hasher.update(b":");
            }

            // Cryptographic random nonce (guarantees uniqueness)
            let mut nonce = [0u8; 16];
            OsRng.fill_bytes(&mut nonce);
            hasher.update(nonce);

            let hash = hasher.finalize();
            Base64UrlUnpadded::encode_string(&hash[..24]) // 192 bits
        };

        let inviter_id = {
            let mut state = self.state.write().await;
            let invitation = state
                .invitations
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
            has_client_data = client_data.is_some(),
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

        let inviter = state
            .inviters
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

    /// Get the owner of this Freebird instance
    pub async fn get_owner(&self) -> Option<String> {
        let state = self.state.read().await;
        state.owner.clone()
    }

    /// Set the owner of this Freebird instance (only works once - first registration wins)
    ///
    /// This also creates a bootstrap user record for the owner if they don't already exist,
    /// allowing them to create the initial invitation pool.
    ///
    /// Returns Ok(()) if the owner was set successfully, or Err if an owner already exists
    pub async fn set_owner(&self, user_id: String) -> Result<()> {
        let mut state = self.state.write().await;

        if state.owner.is_some() {
            bail!("owner already registered");
        }

        state.owner = Some(user_id.clone());

        // Auto-create a bootstrap user record for the owner if they don't exist
        // This allows the owner to create the initial invitation pool
        // We set joined_at to 0 so the owner bypasses the new-user waiting period
        if !state.inviters.contains_key(&user_id) {
            let inviter_state = InviterState::new(
                user_id.clone(),
                self.config.invites_per_user,
                0, // Epoch time - owner bypasses waiting period
            );
            state.inviters.insert(user_id.clone(), inviter_state);
            info!(owner = %user_id, invites = self.config.invites_per_user, "created bootstrap user for owner");
        }

        drop(state);

        self.mark_dirty().await;
        info!(owner = %user_id, "registered instance owner");

        Ok(())
    }

    /// Get the count of unique users who have redeemed invitations
    pub async fn get_redeemed_user_count(&self) -> usize {
        let state = self.state.read().await;
        state
            .invitations
            .values()
            .filter_map(|i| i.invitee_id.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    /// Get detailed information about a user
    ///
    /// Returns user state and list of their invitees
    pub async fn get_user_details(&self, user_id: &str) -> Result<(InviterState, Vec<String>)> {
        let state = self.state.read().await;

        let inviter = state
            .inviters
            .get(user_id)
            .ok_or_else(|| anyhow!("user not found"))?
            .clone();

        // Find all users invited by this user
        let mut invitees = Vec::new();
        for invitation in state.invitations.values() {
            if invitation.inviter_id == user_id {
                if let Some(ref invitee_id) = invitation.invitee_id {
                    invitees.push(invitee_id.clone());
                }
            }
        }

        Ok((inviter, invitees))
    }

    /// Get detailed information about an invitation
    pub async fn get_invitation_details(&self, code: &str) -> Result<Invitation> {
        let state = self.state.read().await;

        state
            .invitations
            .get(code)
            .cloned()
            .ok_or_else(|| anyhow!("invitation not found"))
    }

    /// Get the current invite count for a user (for admin responses)
    pub async fn get_user_invite_count(&self, user_id: &str) -> Result<u32> {
        let state = self.state.read().await;

        state
            .inviters
            .get(user_id)
            .map(|inviter| inviter.invites_remaining)
            .ok_or_else(|| anyhow!("user not found"))
    }

    /// List all users (for admin dashboard) with pagination support
    ///
    /// # Arguments
    /// * `limit` - Maximum number of users to return
    /// * `offset` - Number of users to skip (for pagination)
    ///
    /// # Returns
    /// A vector of (user_id, invites_remaining, banned) sorted by join date (newest first)
    pub async fn list_users(&self, limit: usize, offset: usize) -> Vec<(String, u32, bool)> {
        let state = self.state.read().await;

        let mut users: Vec<_> = state
            .inviters
            .values()
            .map(|inviter| {
                (
                    inviter.user_id.clone(),
                    inviter.invites_remaining,
                    inviter.banned,
                    inviter.joined_at,
                )
            })
            .collect();

        // Sort by joined_at descending (newest first)
        users.sort_by(|a, b| b.3.cmp(&a.3));

        // Apply pagination and remove join timestamp from result
        users
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(user_id, invites, banned, _)| (user_id, invites, banned))
            .collect()
    }

    /// Get the total count of users
    ///
    /// Useful for pagination to show "Page X of Y"
    pub async fn count_users(&self) -> usize {
        let state = self.state.read().await;
        state.inviters.len()
    }

    /// Count how many users would be affected by a ban tree
    ///
    /// Returns the number of users that would be banned (including the target)
    pub async fn count_ban_tree_size(&self, user_id: &str) -> usize {
        let state = self.state.read().await;

        // Start with the target user
        let mut count = 1;

        // Find all users invited by this user (recursively)
        let mut to_check = vec![user_id.to_string()];
        let mut checked = std::collections::HashSet::new();

        while let Some(current_id) = to_check.pop() {
            if !checked.insert(current_id.clone()) {
                continue; // Already checked this user
            }

            for invitation in state.invitations.values() {
                if invitation.inviter_id == current_id {
                    if let Some(ref invitee_id) = invitation.invitee_id {
                        count += 1;
                        to_check.push(invitee_id.clone());
                    }
                }
            }
        }
        count
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
        // Use block_in_place to allow blocking from within an async context
        // This is safe because we're in a multi-threaded runtime
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                match proof {
                    SybilProof::Invitation { code, signature } => {
                        // Decode signature from base64
                        let signature = Base64UrlUnpadded::decode_vec(signature)
                            .context("invalid signature encoding")?;

                        debug!(code = %code, "processing invitation proof");

                        // Verify invitation is valid
                        let _inviter_id = self.verify_invitation(code, &signature).await?;

                        // For now, no client data available in this context
                        // In production, this should be enhanced to extract IP/fingerprint
                        // from the HTTP request context
                        let _invitee_id = self.redeem_invitation(code, None).await?;

                        // Persist the redemption immediately to prevent replay attacks
                        // if the server restarts before the autosave runs
                        if let Err(e) = self.save().await {
                            // Log error but don't fail the request - state is still in memory
                            // and will be persisted by the autosave task
                            error!("Failed to persist invitation redemption: {:?}", e);
                        } else {
                            info!(code = %code, "invitation redeemed and persisted to disk");
                        }

                        debug!(code = %code, "invitation verified and redeemed");
                        Ok(())
                    }
                    SybilProof::RegisteredUser { user_id } => {
                        // Verify user exists in the users table
                        // This is for users who have already been registered (e.g., instance owner)
                        let state = self.state.read().await;

                        if !state.inviters.contains_key(user_id) {
                            bail!("user not found: {}", user_id);
                        }

                        // Check user is not banned
                        if let Some(inviter) = state.inviters.get(user_id) {
                            if inviter.banned {
                                bail!("user is banned");
                            }
                        }

                        debug!(user_id = %user_id, "registered user verified");
                        Ok(())
                    }
                    _ => bail!("expected Invitation or RegisteredUser proof"),
                }
            })
        })
    }

    fn supports(&self, proof: &SybilProof) -> bool {
        matches!(proof, SybilProof::Invitation { .. } | SybilProof::RegisteredUser { .. })
    }

    fn cost(&self) -> u64 {
        self.config.invite_cooldown_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    async fn setup() -> InvitationSystem {
        let key = SigningKey::random(&mut OsRng);
        let config = InvitationConfig {
            invites_per_user: 5,
            invite_cooldown_secs: 0, // Disable cooldown in tests
            invite_expires_secs: 3600,
            new_user_can_invite_after_secs: 0, // Disable new user wait in tests
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
            let system = InvitationSystem::load_or_create(key, config).await.unwrap();
            let stats = system.get_stats().await;
            assert_eq!(stats.total_users, 1);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_invitee_id_uniqueness() {
        let system = setup().await;
        system.add_bootstrap_user("admin".into(), 10).await;

        // Generate one invitation
        let (code, sig, _) = system.generate_invite("admin").await.unwrap();

        // Verify it
        system.verify_invitation(&code, &sig).await.unwrap();

        // Redeem twice with same code - should fail on second attempt
        let id1 = system.redeem_invitation(&code, None).await.unwrap();
        let result2 = system.redeem_invitation(&code, None).await;

        assert!(result2.is_err()); // Should fail - already redeemed
        assert!(!id1.is_empty());
    }

    #[tokio::test]
    async fn test_invitee_id_with_client_data() {
        let system = setup().await;
        system.add_bootstrap_user("admin".into(), 10).await;

        let (code1, sig1, _) = system.generate_invite("admin").await.unwrap();
        let (code2, sig2, _) = system.generate_invite("admin").await.unwrap();

        system.verify_invitation(&code1, &sig1).await.unwrap();
        system.verify_invitation(&code2, &sig2).await.unwrap();

        let client_data1 = ClientData::from_ip("192.168.1.1");
        let client_data2 = ClientData::from_ip("192.168.1.2");

        let id1 = system
            .redeem_invitation(&code1, Some(client_data1))
            .await
            .unwrap();
        let id2 = system
            .redeem_invitation(&code2, Some(client_data2))
            .await
            .unwrap();

        // IDs should be different (different codes + different IPs + random nonces)
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn test_invitee_id_entropy() {
        // Test that even with same parameters, random nonce makes IDs unique
        let system = setup().await;
        system.add_bootstrap_user("admin".into(), 10).await;

        // Generate multiple invitations
        let mut ids = Vec::new();
        for _ in 0..5 {
            let (code, sig, _) = system.generate_invite("admin").await.unwrap();
            system.verify_invitation(&code, &sig).await.unwrap();
            let id = system.redeem_invitation(&code, None).await.unwrap();
            ids.push(id);

            // Small delay to ensure timestamp changes (if needed)
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // All IDs should be unique
        let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique_ids.len(), 5, "All invitee IDs should be unique");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sybil_resistance_verify_redeems_invitation() {
        // This test verifies that calling SybilResistance::verify() properly
        // marks the invitation as redeemed (the full production code path)
        // Note: requires multi_thread runtime because SybilResistance::verify uses block_in_place
        let system = setup().await;
        system.add_bootstrap_user("admin".into(), 10).await;

        // Generate an invitation
        let (code, sig, _) = system.generate_invite("admin").await.unwrap();

        // Create a SybilProof::Invitation from the code and signature
        let signature_b64 = Base64UrlUnpadded::encode_string(&sig);
        let proof = SybilProof::Invitation {
            code: code.clone(),
            signature: signature_b64,
        };

        // Verify that the invitation is NOT redeemed before calling verify
        let details_before = system.get_invitation_details(&code).await.unwrap();
        assert!(!details_before.redeemed(), "invitation should not be redeemed yet");

        // Call SybilResistance::verify - this is what /v1/oprf/issue handler uses
        let result = system.verify(&proof);
        assert!(result.is_ok(), "first verify should succeed");

        // Verify that the invitation IS redeemed after calling verify
        let details_after = system.get_invitation_details(&code).await.unwrap();
        assert!(details_after.redeemed(), "invitation should be redeemed after verify");
        assert!(details_after.invitee_id().is_some(), "invitee_id should be set");

        // Calling verify again with the same invitation should fail
        let result2 = system.verify(&proof);
        assert!(result2.is_err(), "second verify should fail - invitation already used");
        let err_msg = result2.unwrap_err().to_string();
        assert!(
            err_msg.contains("already used") || err_msg.contains("already redeemed"),
            "error should indicate invitation was already used, got: {}",
            err_msg
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sybil_resistance_verify_persists_redemption() {
        // This test verifies that invitation redemption is persisted to disk
        // immediately after verification, surviving app restarts
        let path = PathBuf::from("/tmp/test_verify_persistence.json");
        let _ = std::fs::remove_file(&path); // Clean up

        let key = SigningKey::random(&mut OsRng);
        let config = InvitationConfig {
            invites_per_user: 5,
            invite_cooldown_secs: 0,
            invite_expires_secs: 3600,
            new_user_can_invite_after_secs: 0,
            persistence_path: path.clone(),
            autosave_interval_secs: 0, // Disable autosave
        };

        let code: String;
        let signature_b64: String;

        // Phase 1: Create invitation and redeem it
        {
            let system = InvitationSystem::load_or_create(key.clone(), config.clone())
                .await
                .unwrap();
            system.add_bootstrap_user("admin".into(), 10).await;

            // Generate and redeem invitation
            let (c, sig, _) = system.generate_invite("admin").await.unwrap();
            code = c;
            signature_b64 = Base64UrlUnpadded::encode_string(&sig);

            let proof = SybilProof::Invitation {
                code: code.clone(),
                signature: signature_b64.clone(),
            };

            // This should redeem AND persist
            let result = system.verify(&proof);
            assert!(result.is_ok(), "verify should succeed");

            // Verify it's redeemed in memory
            let details = system.get_invitation_details(&code).await.unwrap();
            assert!(details.redeemed(), "invitation should be redeemed");
        }
        // System is dropped here - simulates app restart

        // Phase 2: Load from disk and verify redemption persisted
        {
            let system = InvitationSystem::load_or_create(key, config)
                .await
                .unwrap();

            // Verify the invitation is STILL redeemed after "restart"
            let details = system.get_invitation_details(&code).await.unwrap();
            assert!(
                details.redeemed(),
                "invitation should still be redeemed after reload from disk"
            );
            assert!(
                details.invitee_id().is_some(),
                "invitee_id should still be set after reload"
            );

            // Trying to redeem again should fail
            let proof = SybilProof::Invitation {
                code: code.clone(),
                signature: signature_b64,
            };
            let result = system.verify(&proof);
            assert!(
                result.is_err(),
                "should not be able to reuse invitation after reload"
            );
        }

        let _ = std::fs::remove_file(&path);
    }
}
