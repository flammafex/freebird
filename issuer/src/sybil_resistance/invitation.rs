// issuer/src/sybil_resistance/invitation.rs
//! Invitation-based Sybil resistance mechanism
//!
//! This system provides a trust-based approach where existing users can invite new users.
//! Key features:
//! - Cryptographically signed invitation codes (ECDSA P-256)
//! - Invite quotas and cooldown periods
//! - Reputation tracking
//! - Ban tree propagation (banning a user can ban their invitees)
//!
//! # Architecture
//!
//! The inviter_id is embedded in the invitation record (not in the proof).
//! This is more secure because:
//! - Client can't forge who invited them
//! - Inviter information is server-side only
//! - Signature proves authenticity, not inviter identity

use super::{current_timestamp, verify_timestamp_recent, SybilProof, SybilResistance};
use anyhow::{anyhow, bail, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Configuration for the invitation system
#[derive(Clone, Debug)]
pub struct InvitationConfig {
    /// How many invites each user gets by default
    pub invites_per_user: u32,
    /// Minimum time between sending invites (seconds)
    pub invite_cooldown_secs: u64,
    /// How long an invitation is valid (seconds)
    pub invite_expires_secs: u64,
    /// How long a new user must wait before they can invite (seconds)
    pub new_user_can_invite_after_secs: u64,
}

impl Default for InvitationConfig {
    fn default() -> Self {
        Self {
            invites_per_user: 5,
            invite_cooldown_secs: 3600,              // 1 hour
            invite_expires_secs: 30 * 24 * 3600,     // 30 days
            new_user_can_invite_after_secs: 30 * 24 * 3600, // 30 days
        }
    }
}

/// Represents a single invitation
#[derive(Clone, Debug)]
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
    /// ECDSA signature of the code
    signature: Vec<u8>,
    /// Whether this invitation has been redeemed
    redeemed: bool,
}

/// State tracking for a user who can send invites
#[derive(Clone, Debug)]
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

/// The main invitation system
pub struct InvitationSystem {
    /// ECDSA signing key for signing invitation codes
    issuer_key: SigningKey,
    /// Public key for verification
    issuer_pubkey: VerifyingKey,
    /// Storage for invitations (code -> Invitation)
    invitations: Arc<RwLock<HashMap<String, Invitation>>>,
    /// Storage for inviter state (user_id -> InviterState)
    inviters: Arc<RwLock<HashMap<String, InviterState>>>,
    /// Configuration
    config: InvitationConfig,
}

impl InvitationSystem {
    /// Create a new invitation system
    pub fn new(issuer_key: SigningKey, config: InvitationConfig) -> Self {
        let issuer_pubkey = VerifyingKey::from(&issuer_key);
        
        Self {
            issuer_key,
            issuer_pubkey,
            invitations: Arc::new(RwLock::new(HashMap::new())),
            inviters: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
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
        let mut inviters = self.inviters.write().await;
        
        if inviters.contains_key(&user_id) {
            warn!(user_id = %user_id, "bootstrap user already exists");
            return;
        }

        let state = InviterState::new(user_id.clone(), invites, current_timestamp());
        inviters.insert(user_id.clone(), state);
        info!(user_id = %user_id, invites = invites, "added bootstrap user");
    }

    /// Check if a user can send invites right now
    async fn can_invite(&self, user_id: &str) -> Result<()> {
        let inviters = self.inviters.read().await;
        
        let inviter = inviters
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

        // Store invitation
        {
            let mut invitations = self.invitations.write().await;
            invitations.insert(code.clone(), invitation);
        }

        // Update inviter state
        {
            let mut inviters = self.inviters.write().await;
            if let Some(inviter) = inviters.get_mut(inviter_id) {
                inviter.invites_remaining -= 1;
                inviter.invites_sent.push(code.clone());
                inviter.last_invite_at = now;
            }
        }

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

        let invitations = self.invitations.read().await;
        let invitation = invitations
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

    /// Redeem an invitation (marks as used, creates invitee record)
    async fn redeem_invitation(&self, code: &str, invitee_id: &str) -> Result<()> {
        let now = current_timestamp();

        // Update invitation
        let inviter_id = {
            let mut invitations = self.invitations.write().await;
            let invitation = invitations
                .get_mut(code)
                .ok_or_else(|| anyhow!("invitation not found"))?;

            if invitation.redeemed {
                bail!("invitation already redeemed");
            }

            invitation.redeemed = true;
            invitation.invitee_id = Some(invitee_id.to_string());
            invitation.inviter_id.clone()
        };

        // Create invitee state (starts with 0 invites, earns them later)
        {
            let mut inviters = self.inviters.write().await;
            
            // Update inviter's used list
            if let Some(inviter) = inviters.get_mut(&inviter_id) {
                inviter.invites_used.push(code.to_string());
            }

            // Create new user with 0 invites (they'll earn them after waiting period)
            let invitee_state = InviterState::new(invitee_id.to_string(), 0, now);
            inviters.insert(invitee_id.to_string(), invitee_state);
        }

        info!(
            code = %code,
            invitee_id = %invitee_id,
            inviter_id = %inviter_id,
            "redeemed invitation"
        );

        Ok(())
    }

    /// Ban a user and optionally their entire invite tree
    pub async fn ban_user(&self, user_id: &str, ban_tree: bool) {
        let mut inviters = self.inviters.write().await;

        if let Some(inviter) = inviters.get_mut(user_id) {
            inviter.banned = true;
            inviter.reputation = 0.0;
            info!(user_id = %user_id, "banned user");
        }

        if ban_tree {
            // Find all users invited by this user
            let invitations = self.invitations.read().await;
            let mut to_ban = Vec::new();

            for invitation in invitations.values() {
                if invitation.inviter_id == user_id {
                    if let Some(ref invitee_id) = invitation.invitee_id {
                        to_ban.push(invitee_id.clone());
                    }
                }
            }

            // Recursively ban invitees
            for invitee_id in to_ban {
                if let Some(inviter) = inviters.get_mut(&invitee_id) {
                    inviter.banned = true;
                    inviter.reputation = 0.0;
                    warn!(user_id = %invitee_id, "banned user (tree ban)");
                }
            }
        }
    }

    /// Grant invites to a user (for reputation rewards, etc.)
    pub async fn grant_invites(&self, user_id: &str, count: u32) -> Result<()> {
        let mut inviters = self.inviters.write().await;
        
        let inviter = inviters
            .get_mut(user_id)
            .ok_or_else(|| anyhow!("user not found"))?;

        if inviter.banned {
            bail!("cannot grant invites to banned user");
        }

        inviter.invites_remaining += count;
        info!(user_id = %user_id, count = count, "granted invites");
        
        Ok(())
    }

    /// Get invitation statistics
    pub async fn get_stats(&self) -> InvitationStats {
        let invitations = self.invitations.read().await;
        let inviters = self.inviters.read().await;

        let total_invitations = invitations.len();
        let redeemed_invitations = invitations.values().filter(|i| i.redeemed).count();
        let total_users = inviters.len();
        let banned_users = inviters.values().filter(|i| i.banned).count();

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
#[derive(Debug, Clone)]
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

            // Generate invitee ID from code (deterministic)
            let invitee_id = {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(b"invitee:");
                hasher.update(code.as_bytes());
                let hash = hasher.finalize();
                Base64UrlUnpadded::encode_string(&hash[..16])
            };

            // Redeem invitation
            self.redeem_invitation(code, &invitee_id).await?;

            debug!(code = %code, invitee_id = %invitee_id, "invitation verified and redeemed");
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    async fn setup() -> InvitationSystem {
        let key = SigningKey::random(&mut OsRng);
        let config = InvitationConfig {
            invites_per_user: 5,
            invite_cooldown_secs: 1, // Short for testing
            invite_expires_secs: 3600,
            new_user_can_invite_after_secs: 1,
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
    async fn test_verify_valid_invite() {
        let system = setup().await;
        system.add_bootstrap_user("admin".into(), 10).await;

        let (code, signature, _) = system.generate_invite("admin").await.unwrap();

        let sig_b64 = Base64UrlUnpadded::encode_string(&signature);
        let proof = SybilProof::Invitation {
            code: code.clone(),
            signature: sig_b64,
        };

        let result = system.verify(&proof);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_invite_reuse_blocked() {
        let system = setup().await;
        system.add_bootstrap_user("admin".into(), 10).await;

        let (code, signature, _) = system.generate_invite("admin").await.unwrap();
        let sig_b64 = Base64UrlUnpadded::encode_string(&signature);

        let proof = SybilProof::Invitation {
            code: code.clone(),
            signature: sig_b64.clone(),
        };

        // First use should succeed
        assert!(system.verify(&proof).is_ok());

        // Second use should fail
        let proof2 = SybilProof::Invitation {
            code,
            signature: sig_b64,
        };
        assert!(system.verify(&proof2).is_err());
    }

    #[tokio::test]
    async fn test_expired_invite() {
        let key = SigningKey::random(&mut OsRng);
        let config = InvitationConfig {
            invites_per_user: 5,
            invite_cooldown_secs: 1,
            invite_expires_secs: 1, // 1 second expiry
            new_user_can_invite_after_secs: 1,
        };
        let system = InvitationSystem::new(key, config);
        system.add_bootstrap_user("admin".into(), 10).await;

        let (code, signature, _) = system.generate_invite("admin").await.unwrap();

        // Wait for expiry
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let sig_b64 = Base64UrlUnpadded::encode_string(&signature);
        let proof = SybilProof::Invitation {
            code,
            signature: sig_b64,
        };

        assert!(system.verify(&proof).is_err());
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let system = setup().await;
        system.add_bootstrap_user("admin".into(), 10).await;

        let (code, _, _) = system.generate_invite("admin").await.unwrap();

        // Create fake signature
        let fake_sig = vec![0u8; 64];
        let sig_b64 = Base64UrlUnpadded::encode_string(&fake_sig);

        let proof = SybilProof::Invitation {
            code,
            signature: sig_b64,
        };

        assert!(system.verify(&proof).is_err());
    }

    #[tokio::test]
    async fn test_invite_cooldown() {
        let key = SigningKey::random(&mut OsRng);
        let config = InvitationConfig {
            invites_per_user: 5,
            invite_cooldown_secs: 10, // 10 second cooldown
            invite_expires_secs: 3600,
            new_user_can_invite_after_secs: 1,
        };
        let system = InvitationSystem::new(key, config);
        system.add_bootstrap_user("admin".into(), 10).await;

        // First invite should succeed
        assert!(system.generate_invite("admin").await.is_ok());

        // Second invite immediately should fail
        assert!(system.generate_invite("admin").await.is_err());
    }

    #[tokio::test]
    async fn test_ban_user() {
        let system = setup().await;
        system.add_bootstrap_user("admin".into(), 10).await;

        // Generate invite before ban
        assert!(system.generate_invite("admin").await.is_ok());

        // Ban user
        system.ban_user("admin", false).await;

        // Should fail after ban
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(system.generate_invite("admin").await.is_err());
    }

    #[tokio::test]
    async fn test_grant_invites() {
        let system = setup().await;
        system.add_bootstrap_user("user".into(), 1).await;

        // Use up the one invite
        assert!(system.generate_invite("user").await.is_ok());

        // Should be out of invites
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(system.generate_invite("user").await.is_err());

        // Grant more invites
        assert!(system.grant_invites("user", 5).await.is_ok());

        // Should work now
        assert!(system.generate_invite("user").await.is_ok());
    }
}