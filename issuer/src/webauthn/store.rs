// issuer/src/webauthn_store.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Redis-backed credential storage for WebAuthn
//!
//! This module provides persistent storage for WebAuthn credentials using Redis.
//! Credentials are stored with the following structure:
//! - Key: `webauthn:cred:{cred_id_base64}`
//! - Value: JSON-serialized credential data
//! - TTL: Optional expiration for credential lifecycle management
//!
//! # Security Considerations
//!
//! - Credentials contain public keys only (no secrets stored)
//! - User handles are hashed to prevent enumeration
//! - Redis should be configured with authentication and encryption in transit
//! - Consider using Redis ACLs to restrict access to webauthn:* keys

use anyhow::{Context, Result};
use base64ct::Encoding;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use webauthn_rs::prelude::Passkey;

// --- Types ---

/// Device type classification for multi-device credential management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// Platform authenticator (Touch ID, Windows Hello, Face ID)
    Platform,
    /// Cross-platform authenticator (USB security key, NFC)
    CrossPlatform,
    /// Hybrid transport (phone as authenticator via QR/BLE)
    Hybrid,
    /// Unknown device type
    #[default]
    Unknown,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Platform => write!(f, "platform"),
            DeviceType::CrossPlatform => write!(f, "cross-platform"),
            DeviceType::Hybrid => write!(f, "hybrid"),
            DeviceType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Authenticator transport mechanism
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorTransport {
    /// USB transport
    Usb,
    /// NFC transport
    Nfc,
    /// Bluetooth Low Energy
    Ble,
    /// Internal/platform authenticator
    Internal,
    /// Hybrid (cross-device via QR/BLE)
    Hybrid,
    /// Smart card
    SmartCard,
    /// Unknown transport
    Unknown(String),
}

impl From<&str> for AuthenticatorTransport {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "usb" => AuthenticatorTransport::Usb,
            "nfc" => AuthenticatorTransport::Nfc,
            "ble" => AuthenticatorTransport::Ble,
            "internal" => AuthenticatorTransport::Internal,
            "hybrid" => AuthenticatorTransport::Hybrid,
            "smart-card" | "smartcard" => AuthenticatorTransport::SmartCard,
            other => AuthenticatorTransport::Unknown(other.to_string()),
        }
    }
}

/// Serializable credential data for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Credential ID (raw bytes)
    pub cred_id: Vec<u8>,
    /// Full PasskeyRegistration data from webauthn-rs
    pub credential: Passkey,
    /// User handle (hashed for privacy)
    pub user_id_hash: String,
    /// Registration timestamp (Unix seconds)
    pub registered_at: i64,
    /// Last used timestamp (Unix seconds, optional)
    pub last_used_at: Option<i64>,
    /// Device type (platform, cross-platform, hybrid)
    #[serde(default)]
    pub device_type: DeviceType,
    /// Backup eligibility flag (BE) - can this credential be backed up?
    #[serde(default)]
    pub backup_eligible: bool,
    /// Backup state flag (BS) - is this credential currently backed up/synced?
    #[serde(default)]
    pub backup_state: bool,
    /// Transports supported by this credential
    #[serde(default)]
    pub transports: Vec<AuthenticatorTransport>,
    /// Attestation format used during registration
    #[serde(default)]
    pub attestation_format: Option<String>,
    /// AAGUID of the authenticator (if available)
    #[serde(default)]
    pub aaguid: Option<String>,
    /// Whether this is a discoverable/resident credential
    #[serde(default)]
    pub is_discoverable: bool,
    /// User handle for discoverable credential lookup (base64url encoded)
    #[serde(default)]
    pub user_handle: Option<String>,
    /// Friendly name for the credential (e.g., "MacBook Pro Touch ID")
    #[serde(default)]
    pub friendly_name: Option<String>,
}

impl StoredCredential {
    /// Check if this credential is synced across devices
    pub fn is_synced(&self) -> bool {
        self.backup_eligible && self.backup_state
    }

    /// Check if this is a hardware-bound credential
    pub fn is_hardware_bound(&self) -> bool {
        !self.backup_eligible
    }

    /// Get a summary for admin display
    pub fn summary(&self) -> CredentialSummary {
        CredentialSummary {
            cred_id: base64ct::Base64UrlUnpadded::encode_string(&self.cred_id),
            device_type: self.device_type,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            is_discoverable: self.is_discoverable,
            registered_at: self.registered_at,
            last_used_at: self.last_used_at,
            transports: self.transports.clone(),
            aaguid: self.aaguid.clone(),
            friendly_name: self.friendly_name.clone(),
        }
    }
}

/// Credential summary for admin display (without sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub cred_id: String,
    pub device_type: DeviceType,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub is_discoverable: bool,
    pub registered_at: i64,
    pub last_used_at: Option<i64>,
    pub transports: Vec<AuthenticatorTransport>,
    pub aaguid: Option<String>,
    pub friendly_name: Option<String>,
}

/// Extended credential creation options
#[derive(Debug, Clone, Default)]
pub struct CredentialCreateOptions {
    pub device_type: DeviceType,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Vec<AuthenticatorTransport>,
    pub attestation_format: Option<String>,
    pub aaguid: Option<String>,
    pub is_discoverable: bool,
    pub user_handle: Option<String>,
    pub friendly_name: Option<String>,
}

// --- Abstraction ---

/// Unified wrapper for storage backends
#[derive(Clone)]
pub enum CredentialStore {
    Redis(RedisCredStore),
    InMemory(InMemoryCredStore),
}

impl CredentialStore {
    pub async fn save(&self, cred_id: Vec<u8>, credential: Passkey, user_id_hash: String) -> Result<()> {
        match self {
            Self::Redis(s) => s.save(cred_id, credential, user_id_hash).await,
            Self::InMemory(s) => s.save(cred_id, credential, user_id_hash).await,
        }
    }

    /// Save credential with extended options (device metadata, etc.)
    pub async fn save_with_options(
        &self,
        cred_id: Vec<u8>,
        credential: Passkey,
        user_id_hash: String,
        username: String,
        options: CredentialCreateOptions,
    ) -> Result<()> {
        match self {
            Self::Redis(s) => s.save_with_options(cred_id, credential, user_id_hash, username, options).await,
            Self::InMemory(s) => s.save_with_options(cred_id, credential, user_id_hash, username, options).await,
        }
    }

    pub async fn load(&self, cred_id: &[u8]) -> Result<Option<StoredCredential>> {
        match self {
            Self::Redis(s) => s.load(cred_id).await,
            Self::InMemory(s) => s.load(cred_id).await,
        }
    }

    pub async fn load_user_credentials(&self, user_id_hash: &str) -> Result<Vec<StoredCredential>> {
        match self {
            Self::Redis(s) => s.load_user_credentials(user_id_hash).await,
            Self::InMemory(s) => s.load_user_credentials(user_id_hash).await,
        }
    }

    /// Look up username by user handle (for discoverable credentials)
    pub async fn lookup_username_by_handle(&self, user_handle: &str) -> Result<Option<String>> {
        match self {
            Self::Redis(s) => s.lookup_username_by_handle(user_handle).await,
            Self::InMemory(s) => s.lookup_username_by_handle(user_handle).await,
        }
    }

    /// Load all discoverable credentials for a user handle
    pub async fn load_discoverable_credentials(&self, user_handle: &str) -> Result<Vec<StoredCredential>> {
        match self {
            Self::Redis(s) => s.load_discoverable_credentials(user_handle).await,
            Self::InMemory(s) => s.load_discoverable_credentials(user_handle).await,
        }
    }

    pub async fn update_last_used(&self, cred_id: &[u8]) -> Result<()> {
        match self {
            Self::Redis(s) => s.update_last_used(cred_id).await,
            Self::InMemory(s) => s.update_last_used(cred_id).await,
        }
    }

    /// Update backup state after authenticator signals a change
    pub async fn update_backup_state(&self, cred_id: &[u8], backup_state: bool) -> Result<()> {
        match self {
            Self::Redis(s) => s.update_backup_state(cred_id, backup_state).await,
            Self::InMemory(s) => s.update_backup_state(cred_id, backup_state).await,
        }
    }

    pub async fn delete(&self, cred_id: &[u8]) -> Result<bool> {
        match self {
            Self::Redis(s) => s.delete(cred_id).await,
            Self::InMemory(s) => s.delete(cred_id).await,
        }
    }

    pub async fn list_all(&self) -> Result<Vec<StoredCredential>> {
        match self {
            Self::Redis(s) => s.list_all().await,
            Self::InMemory(s) => s.list_all().await,
        }
    }

    /// List all credentials with their summaries (for admin)
    pub async fn list_all_summaries(&self) -> Result<Vec<CredentialSummary>> {
        let creds = self.list_all().await?;
        Ok(creds.iter().map(|c| c.summary()).collect())
    }

    pub async fn count_credentials(&self) -> Result<usize> {
        match self {
            Self::Redis(s) => s.count_credentials().await,
            Self::InMemory(s) => s.count_credentials().await,
        }
    }

    /// Count credentials for a specific user
    pub async fn count_user_credentials(&self, user_id_hash: &str) -> Result<usize> {
        let creds = self.load_user_credentials(user_id_hash).await?;
        Ok(creds.len())
    }
}

// --- Redis Backend ---

#[derive(Clone)]
pub struct RedisCredStore {
    client: redis::Client,
    credential_ttl: Option<u64>,
}


impl RedisCredStore {
    pub fn new(redis_url: &str, credential_ttl: Option<u64>) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .with_context(|| format!("Failed to connect to Redis at {}", redis_url))?;
        Ok(Self { client, credential_ttl })
    }

    /// Get async connection with retry logic
    async fn get_connection(&self) -> Result<redis::aio::Connection> {
        let mut backoff_ms = 100u64;
        for attempt in 1..=3 {
            match self.client.get_async_connection().await {
                Ok(conn) => return Ok(conn),
                Err(e) if attempt < 3 => {
                    warn!(
                        attempt,
                        backoff_ms, "Redis connection failed, retrying: {}", e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                }
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!()
    }

    /// Generate Redis key for credential
    fn credential_key(cred_id: &[u8]) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        format!(
            "webauthn:cred:{}",
            Base64UrlUnpadded::encode_string(cred_id)
        )
    }

    /// Generate Redis key for user's credential list
    fn user_creds_key(user_id_hash: &str) -> String {
        format!("webauthn:user:{}", user_id_hash)
    }

    /// Generate Redis key for user handle → username mapping
    fn handle_key(user_handle: &str) -> String {
        format!("webauthn:handle:{}", user_handle)
    }

    /// Generate Redis key for discoverable credentials by user handle
    fn discoverable_creds_key(user_handle: &str) -> String {
        format!("webauthn:discoverable:{}", user_handle)
    }

    /// Save a credential to Redis (basic version for backwards compatibility)
    ///
    /// This stores:
    /// 1. The credential itself at `webauthn:cred:{cred_id}`
    /// 2. A reference in the user's credential set at `webauthn:user:{user_id_hash}`
    pub async fn save(
        &self,
        cred_id: Vec<u8>,
        credential: Passkey,
        user_id_hash: String,
    ) -> Result<()> {
        let mut conn = self.get_connection().await?;

        let stored = StoredCredential {
            cred_id: cred_id.clone(),
            credential,
            user_id_hash: user_id_hash.clone(),
            registered_at: chrono::Utc::now().timestamp(),
            last_used_at: None,
            device_type: DeviceType::Unknown,
            backup_eligible: false,
            backup_state: false,
            transports: Vec::new(),
            attestation_format: None,
            aaguid: None,
            is_discoverable: false,
            user_handle: None,
            friendly_name: None,
        };

        let cred_json = serde_json::to_string(&stored).context("Failed to serialize credential")?;

        let cred_key = Self::credential_key(&cred_id);
        let user_key = Self::user_creds_key(&user_id_hash);

        // Store credential
        if let Some(ttl) = self.credential_ttl {
            conn.set_ex::<_, _, ()>(&cred_key, cred_json, ttl).await?;
        } else {
            conn.set::<_, _, ()>(&cred_key, cred_json).await?;
        }

        // Add to user's credential set
        conn.sadd::<_, _, ()>(&user_key, &cred_key).await?;

        // Optionally set TTL on user set as well
        if let Some(ttl) = self.credential_ttl {
            conn.expire::<_, ()>(&user_key, ttl as i64).await?;
        }

        info!(
            cred_key = %cred_key,
            user_key = %user_key,
            "Saved WebAuthn credential"
        );

        Ok(())
    }

    /// Save a credential with extended options (device metadata, discoverable, etc.)
    ///
    /// This stores:
    /// 1. The credential itself at `webauthn:cred:{cred_id}`
    /// 2. A reference in the user's credential set at `webauthn:user:{user_id_hash}`
    /// 3. For discoverable credentials: user handle → username mapping
    /// 4. For discoverable credentials: credential reference in discoverable set
    pub async fn save_with_options(
        &self,
        cred_id: Vec<u8>,
        credential: Passkey,
        user_id_hash: String,
        username: String,
        options: CredentialCreateOptions,
    ) -> Result<()> {
        let mut conn = self.get_connection().await?;

        let stored = StoredCredential {
            cred_id: cred_id.clone(),
            credential,
            user_id_hash: user_id_hash.clone(),
            registered_at: chrono::Utc::now().timestamp(),
            last_used_at: None,
            device_type: options.device_type,
            backup_eligible: options.backup_eligible,
            backup_state: options.backup_state,
            transports: options.transports,
            attestation_format: options.attestation_format,
            aaguid: options.aaguid,
            is_discoverable: options.is_discoverable,
            user_handle: options.user_handle.clone(),
            friendly_name: options.friendly_name,
        };

        let cred_json = serde_json::to_string(&stored).context("Failed to serialize credential")?;

        let cred_key = Self::credential_key(&cred_id);
        let user_key = Self::user_creds_key(&user_id_hash);

        // Store credential
        if let Some(ttl) = self.credential_ttl {
            conn.set_ex::<_, _, ()>(&cred_key, &cred_json, ttl).await?;
        } else {
            conn.set::<_, _, ()>(&cred_key, &cred_json).await?;
        }

        // Add to user's credential set
        conn.sadd::<_, _, ()>(&user_key, &cred_key).await?;

        // Optionally set TTL on user set as well
        if let Some(ttl) = self.credential_ttl {
            conn.expire::<_, ()>(&user_key, ttl as i64).await?;
        }

        // For discoverable credentials, also store the handle → username mapping
        if options.is_discoverable {
            if let Some(ref user_handle) = options.user_handle {
                let handle_key = Self::handle_key(user_handle);
                let discoverable_key = Self::discoverable_creds_key(user_handle);

                // Store handle → username mapping
                if let Some(ttl) = self.credential_ttl {
                    conn.set_ex::<_, _, ()>(&handle_key, &username, ttl).await?;
                } else {
                    conn.set::<_, _, ()>(&handle_key, &username).await?;
                }

                // Add to discoverable credentials set
                conn.sadd::<_, _, ()>(&discoverable_key, &cred_key).await?;
                if let Some(ttl) = self.credential_ttl {
                    conn.expire::<_, ()>(&discoverable_key, ttl as i64).await?;
                }

                debug!(
                    handle_key = %handle_key,
                    discoverable_key = %discoverable_key,
                    "Stored discoverable credential mapping"
                );
            }
        }

        info!(
            cred_key = %cred_key,
            user_key = %user_key,
            device_type = %stored.device_type,
            backup_eligible = stored.backup_eligible,
            is_discoverable = stored.is_discoverable,
            "Saved WebAuthn credential with extended options"
        );

        Ok(())
    }

    /// Load a credential by credential ID
    pub async fn load(&self, cred_id: &[u8]) -> Result<Option<StoredCredential>> {
        let mut conn = self.get_connection().await?;
        let cred_key = Self::credential_key(cred_id);

        let cred_json: Option<String> = conn.get(&cred_key).await?;

        match cred_json {
            Some(json) => {
                let stored: StoredCredential =
                    serde_json::from_str(&json).context("Failed to deserialize credential")?;
                debug!(cred_key = %cred_key, "Loaded WebAuthn credential");
                Ok(Some(stored))
            }
            None => {
                debug!(cred_key = %cred_key, "Credential not found");
                Ok(None)
            }
        }
    }

    /// Load all credentials for a user
    pub async fn load_user_credentials(&self, user_id_hash: &str) -> Result<Vec<StoredCredential>> {
        let mut conn = self.get_connection().await?;
        let user_key = Self::user_creds_key(user_id_hash);

        // Get all credential keys for this user
        let cred_keys: Vec<String> = conn.smembers(&user_key).await?;

        if cred_keys.is_empty() {
            debug!(user_key = %user_key, "No credentials found for user");
            return Ok(Vec::new());
        }

        // Load all credentials
        let mut credentials = Vec::new();
        for cred_key in cred_keys {
            let cred_json: Option<String> = conn.get(&cred_key).await?;
            if let Some(json) = cred_json {
                match serde_json::from_str::<StoredCredential>(&json) {
                    Ok(stored) => credentials.push(stored),
                    Err(e) => warn!(
                        cred_key = %cred_key,
                        error = %e,
                        "Failed to deserialize credential, skipping"
                    ),
                }
            }
        }

        debug!(
            user_key = %user_key,
            count = credentials.len(),
            "Loaded user credentials"
        );

        Ok(credentials)
    }

    /// Update last_used_at timestamp for a credential
    pub async fn update_last_used(&self, cred_id: &[u8]) -> Result<()> {
        let mut stored = match self.load(cred_id).await? {
            Some(s) => s,
            None => return Ok(()), // Credential doesn't exist, nothing to update
        };

        stored.last_used_at = Some(chrono::Utc::now().timestamp());

        let cred_json = serde_json::to_string(&stored)?;
        let cred_key = Self::credential_key(cred_id);

        let mut conn = self.get_connection().await?;
        if let Some(ttl) = self.credential_ttl {
            conn.set_ex::<_, _, ()>(&cred_key, cred_json, ttl).await?;
        } else {
            conn.set::<_, _, ()>(&cred_key, cred_json).await?;
        }

        debug!(cred_key = %cred_key, "Updated credential last_used_at");
        Ok(())
    }

    /// Update backup state for a credential
    pub async fn update_backup_state(&self, cred_id: &[u8], backup_state: bool) -> Result<()> {
        let mut stored = match self.load(cred_id).await? {
            Some(s) => s,
            None => return Ok(()), // Credential doesn't exist, nothing to update
        };

        stored.backup_state = backup_state;

        let cred_json = serde_json::to_string(&stored)?;
        let cred_key = Self::credential_key(cred_id);

        let mut conn = self.get_connection().await?;
        if let Some(ttl) = self.credential_ttl {
            conn.set_ex::<_, _, ()>(&cred_key, cred_json, ttl).await?;
        } else {
            conn.set::<_, _, ()>(&cred_key, cred_json).await?;
        }

        debug!(cred_key = %cred_key, backup_state = backup_state, "Updated credential backup_state");
        Ok(())
    }

    /// Look up username by user handle (for discoverable credential authentication)
    pub async fn lookup_username_by_handle(&self, user_handle: &str) -> Result<Option<String>> {
        let mut conn = self.get_connection().await?;
        let handle_key = Self::handle_key(user_handle);

        let username: Option<String> = conn.get(&handle_key).await?;

        debug!(
            handle_key = %handle_key,
            found = username.is_some(),
            "Looked up username by handle"
        );

        Ok(username)
    }

    /// Load all discoverable credentials for a user handle
    pub async fn load_discoverable_credentials(&self, user_handle: &str) -> Result<Vec<StoredCredential>> {
        let mut conn = self.get_connection().await?;
        let discoverable_key = Self::discoverable_creds_key(user_handle);

        // Get all credential keys for this user handle
        let cred_keys: Vec<String> = conn.smembers(&discoverable_key).await?;

        if cred_keys.is_empty() {
            debug!(discoverable_key = %discoverable_key, "No discoverable credentials found");
            return Ok(Vec::new());
        }

        // Load all credentials
        let mut credentials = Vec::new();
        for cred_key in cred_keys {
            let cred_json: Option<String> = conn.get(&cred_key).await?;
            if let Some(json) = cred_json {
                match serde_json::from_str::<StoredCredential>(&json) {
                    Ok(stored) if stored.is_discoverable => credentials.push(stored),
                    Ok(_) => warn!(
                        cred_key = %cred_key,
                        "Credential in discoverable set but not marked discoverable"
                    ),
                    Err(e) => warn!(
                        cred_key = %cred_key,
                        error = %e,
                        "Failed to deserialize credential, skipping"
                    ),
                }
            }
        }

        debug!(
            discoverable_key = %discoverable_key,
            count = credentials.len(),
            "Loaded discoverable credentials"
        );

        Ok(credentials)
    }

    /// Delete a credential and clean up all associated data
    pub async fn delete(&self, cred_id: &[u8]) -> Result<bool> {
        let mut conn = self.get_connection().await?;
        let cred_key = Self::credential_key(cred_id);

        // Load credential to get user_id_hash and user_handle before deleting
        if let Some(stored) = self.load(cred_id).await? {
            let user_key = Self::user_creds_key(&stored.user_id_hash);

            // Remove from user's set
            conn.srem::<_, _, ()>(&user_key, &cred_key).await?;

            // Clean up discoverable credential mappings if applicable
            if stored.is_discoverable {
                if let Some(ref user_handle) = stored.user_handle {
                    let discoverable_key = Self::discoverable_creds_key(user_handle);
                    conn.srem::<_, _, ()>(&discoverable_key, &cred_key).await?;

                    // Check if this was the last credential for this handle
                    let remaining: usize = conn.scard(&discoverable_key).await.unwrap_or(0);
                    if remaining == 0 {
                        // Remove the handle → username mapping
                        let handle_key = Self::handle_key(user_handle);
                        conn.del::<_, ()>(&handle_key).await?;
                        debug!(handle_key = %handle_key, "Removed orphaned handle mapping");
                    }
                }
            }

            // Delete credential
            let deleted: bool = conn.del(&cred_key).await?;

            info!(
                cred_key = %cred_key,
                user_key = %user_key,
                is_discoverable = stored.is_discoverable,
                "Deleted WebAuthn credential"
            );

            Ok(deleted)
        } else {
            debug!(cred_key = %cred_key, "Credential not found for deletion");
            Ok(false)
        }
    }

    /// Count total credentials in system
    pub async fn count_credentials(&self) -> Result<usize> {
        let mut conn = self.get_connection().await?;
        let keys: Vec<String> = conn.keys("webauthn:cred:*").await?;
        Ok(keys.len())
    }

    /// List all credentials in the system
    pub async fn list_all(&self) -> Result<Vec<StoredCredential>> {
        let mut conn = self.get_connection().await?;
        let keys: Vec<String> = conn.keys("webauthn:cred:*").await?;

        let mut credentials = Vec::new();
        for cred_key in keys {
            let cred_json: Option<String> = conn.get(&cred_key).await?;
            if let Some(json) = cred_json {
                match serde_json::from_str::<StoredCredential>(&json) {
                    Ok(stored) => credentials.push(stored),
                    Err(e) => warn!(
                        cred_key = %cred_key,
                        error = %e,
                        "Failed to deserialize credential, skipping"
                    ),
                }
            }
        }

        // Sort by registered_at descending (newest first)
        credentials.sort_by(|a, b| b.registered_at.cmp(&a.registered_at));

        debug!(count = credentials.len(), "Listed all WebAuthn credentials");
        Ok(credentials)
    }
}

/// In-memory credential store (for development/testing)
#[derive(Default, Clone)]
pub struct InMemoryCredStore {
    credentials: Arc<RwLock<std::collections::HashMap<Vec<u8>, StoredCredential>>>,
    /// User handle → username mappings for discoverable credentials
    handle_mappings: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

impl InMemoryCredStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn save(
        &self,
        cred_id: Vec<u8>,
        credential: Passkey,
        user_id_hash: String,
    ) -> Result<()> {
        let stored = StoredCredential {
            cred_id: cred_id.clone(),
            credential,
            user_id_hash,
            registered_at: chrono::Utc::now().timestamp(),
            last_used_at: None,
            device_type: DeviceType::Unknown,
            backup_eligible: false,
            backup_state: false,
            transports: Vec::new(),
            attestation_format: None,
            aaguid: None,
            is_discoverable: false,
            user_handle: None,
            friendly_name: None,
        };

        self.credentials.write().await.insert(cred_id, stored);
        Ok(())
    }

    pub async fn save_with_options(
        &self,
        cred_id: Vec<u8>,
        credential: Passkey,
        user_id_hash: String,
        username: String,
        options: CredentialCreateOptions,
    ) -> Result<()> {
        let stored = StoredCredential {
            cred_id: cred_id.clone(),
            credential,
            user_id_hash,
            registered_at: chrono::Utc::now().timestamp(),
            last_used_at: None,
            device_type: options.device_type,
            backup_eligible: options.backup_eligible,
            backup_state: options.backup_state,
            transports: options.transports,
            attestation_format: options.attestation_format,
            aaguid: options.aaguid,
            is_discoverable: options.is_discoverable,
            user_handle: options.user_handle.clone(),
            friendly_name: options.friendly_name,
        };

        // Store handle → username mapping for discoverable credentials
        if options.is_discoverable {
            if let Some(ref user_handle) = options.user_handle {
                self.handle_mappings
                    .write()
                    .await
                    .insert(user_handle.clone(), username);
            }
        }

        self.credentials.write().await.insert(cred_id, stored);
        Ok(())
    }

    pub async fn load(&self, cred_id: &[u8]) -> Result<Option<StoredCredential>> {
        Ok(self.credentials.read().await.get(cred_id).cloned())
    }

    pub async fn load_user_credentials(&self, user_id_hash: &str) -> Result<Vec<StoredCredential>> {
        let creds = self.credentials.read().await;
        Ok(creds
            .values()
            .filter(|c| c.user_id_hash == user_id_hash)
            .cloned()
            .collect())
    }

    pub async fn lookup_username_by_handle(&self, user_handle: &str) -> Result<Option<String>> {
        Ok(self.handle_mappings.read().await.get(user_handle).cloned())
    }

    pub async fn load_discoverable_credentials(&self, user_handle: &str) -> Result<Vec<StoredCredential>> {
        let creds = self.credentials.read().await;
        Ok(creds
            .values()
            .filter(|c| {
                c.is_discoverable
                    && c.user_handle
                        .as_ref()
                        .map(|h| h == user_handle)
                        .unwrap_or(false)
            })
            .cloned()
            .collect())
    }

    pub async fn update_last_used(&self, cred_id: &[u8]) -> Result<()> {
        if let Some(stored) = self.credentials.write().await.get_mut(cred_id) {
            stored.last_used_at = Some(chrono::Utc::now().timestamp());
        }
        Ok(())
    }

    pub async fn update_backup_state(&self, cred_id: &[u8], backup_state: bool) -> Result<()> {
        if let Some(stored) = self.credentials.write().await.get_mut(cred_id) {
            stored.backup_state = backup_state;
        }
        Ok(())
    }

    pub async fn delete(&self, cred_id: &[u8]) -> Result<bool> {
        let mut creds = self.credentials.write().await;
        if let Some(stored) = creds.remove(cred_id) {
            // Clean up handle mapping if this was a discoverable credential
            if stored.is_discoverable {
                if let Some(ref user_handle) = stored.user_handle {
                    // Check if there are other discoverable credentials with this handle
                    let has_others = creds.values().any(|c| {
                        c.is_discoverable
                            && c.user_handle
                                .as_ref()
                                .map(|h| h == user_handle)
                                .unwrap_or(false)
                    });
                    if !has_others {
                        self.handle_mappings.write().await.remove(user_handle);
                    }
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn count_credentials(&self) -> Result<usize> {
        Ok(self.credentials.read().await.len())
    }

    pub async fn list_all(&self) -> Result<Vec<StoredCredential>> {
        let creds = self.credentials.read().await;
        let mut credentials: Vec<StoredCredential> = creds.values().cloned().collect();
        // Sort by registered_at descending (newest first)
        credentials.sort_by(|a, b| b.registered_at.cmp(&a.registered_at));
        Ok(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_store() {
        let store = InMemoryCredStore::new();

        // Create a mock credential
        let cred_id = vec![1, 2, 3, 4];
        let user_id_hash = "user123".to_string();

        // Note: Creating a real Passkey requires complex setup, so this is just a structure test
        // In real tests, you'd use webauthn-rs test utilities
        assert_eq!(store.count_credentials().await.unwrap(), 0);
    }
}
