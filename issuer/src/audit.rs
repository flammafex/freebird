// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! Audit logging system for admin operations
//!
//! This module provides audit logging functionality for tracking admin actions:
//! - User bans and grants
//! - Invitation creation
//! - Key rotations
//! - Owner registration
//! - Other administrative operations
//!
//! Logs are persisted to disk and can be queried with pagination support.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Audit log entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix timestamp when the action occurred
    pub timestamp: u64,
    /// Log level: "info", "warning", "error", "success"
    pub level: String,
    /// Action type (e.g., "user_banned", "invitations_created", "key_rotated")
    pub action: String,
    /// User ID associated with the action (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Additional details about the action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Admin who performed the action (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_id: Option<String>,
}

impl AuditEntry {
    /// Create a new info-level audit entry
    pub fn info(action: impl Into<String>) -> Self {
        Self {
            timestamp: current_timestamp(),
            level: "info".to_string(),
            action: action.into(),
            user_id: None,
            details: None,
            admin_id: None,
        }
    }

    /// Create a new success-level audit entry
    pub fn success(action: impl Into<String>) -> Self {
        Self {
            timestamp: current_timestamp(),
            level: "success".to_string(),
            action: action.into(),
            user_id: None,
            details: None,
            admin_id: None,
        }
    }

    /// Create a new warning-level audit entry
    pub fn warning(action: impl Into<String>) -> Self {
        Self {
            timestamp: current_timestamp(),
            level: "warning".to_string(),
            action: action.into(),
            user_id: None,
            details: None,
            admin_id: None,
        }
    }

    /// Create a new error-level audit entry
    pub fn error(action: impl Into<String>) -> Self {
        Self {
            timestamp: current_timestamp(),
            level: "error".to_string(),
            action: action.into(),
            user_id: None,
            details: None,
            admin_id: None,
        }
    }

    /// Set the user ID
    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set the details
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Set the admin ID
    pub fn with_admin(mut self, admin_id: impl Into<String>) -> Self {
        self.admin_id = Some(admin_id.into());
        self
    }
}

/// Configuration for the audit log system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Path to persistence file
    #[serde(default = "default_audit_path")]
    pub persistence_path: PathBuf,
    /// Maximum number of entries to keep (0 = unlimited)
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// Auto-save interval in seconds (0 = only on shutdown)
    #[serde(default = "default_autosave_interval")]
    pub autosave_interval_secs: u64,
}

fn default_audit_path() -> PathBuf {
    PathBuf::from("audit_log.json")
}

fn default_max_entries() -> usize {
    10000
}

fn default_autosave_interval() -> u64 {
    60 // 1 minute
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            persistence_path: default_audit_path(),
            max_entries: default_max_entries(),
            autosave_interval_secs: default_autosave_interval(),
        }
    }
}

/// Persisted state of the audit log
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    entries: Vec<AuditEntry>,
    version: u32,
}

/// The main audit log system with persistence
pub struct AuditLog {
    /// In-memory log entries
    state: Arc<RwLock<PersistedState>>,
    /// Configuration
    config: AuditConfig,
    /// Flag to track if state has been modified since last save
    dirty: Arc<RwLock<bool>>,
}

impl AuditLog {
    /// Create a new audit log system
    pub fn new(config: AuditConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(PersistedState::default())),
            config,
            dirty: Arc::new(RwLock::new(false)),
        }
    }

    /// Create and load from persistence file
    pub async fn load_or_create(config: AuditConfig) -> Result<Self> {
        let state = if config.persistence_path.exists() {
            info!("Loading audit log from {:?}", config.persistence_path);
            let data = tokio::fs::read_to_string(&config.persistence_path)
                .await
                .context("read audit log file")?;
            let loaded: PersistedState =
                serde_json::from_str(&data).context("deserialize audit log")?;
            info!("Loaded {} audit entries", loaded.entries.len());
            loaded
        } else {
            info!("No audit log file found, starting fresh");
            PersistedState::default()
        };

        let system = Self {
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
                        debug!("Autosaved audit log");
                    }
                    Err(e) => {
                        error!("Audit log autosave failed: {:?}", e);
                    }
                }
            }
        });
    }

    /// Save state to file
    async fn save_to_file(state: &PersistedState, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(state).context("serialize audit log")?;

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
        info!("Saved audit log to {:?}", self.config.persistence_path);
        Ok(())
    }

    /// Mark state as dirty
    async fn mark_dirty(&self) {
        *self.dirty.write().await = true;
    }

    /// Log an audit entry
    pub async fn log(&self, entry: AuditEntry) {
        let mut state = self.state.write().await;

        // Add entry
        state.entries.push(entry.clone());

        // Trim if over max entries
        if self.config.max_entries > 0 && state.entries.len() > self.config.max_entries {
            let excess = state.entries.len() - self.config.max_entries;
            state.entries.drain(0..excess);
        }

        drop(state);
        self.mark_dirty().await;

        debug!(
            action = %entry.action,
            level = %entry.level,
            "Audit log entry added"
        );
    }

    /// Get audit entries with pagination
    ///
    /// Returns entries sorted by timestamp descending (newest first)
    pub async fn get_entries(&self, limit: usize, offset: usize) -> Vec<AuditEntry> {
        let state = self.state.read().await;

        // Return entries in reverse order (newest first)
        state
            .entries
            .iter()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get total count of entries
    pub async fn count(&self) -> usize {
        let state = self.state.read().await;
        state.entries.len()
    }

    /// Get entries filtered by level
    pub async fn get_entries_by_level(
        &self,
        level: &str,
        limit: usize,
        offset: usize,
    ) -> Vec<AuditEntry> {
        let state = self.state.read().await;

        state
            .entries
            .iter()
            .rev()
            .filter(|e| e.level == level)
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_log_basic() {
        let config = AuditConfig {
            persistence_path: PathBuf::from("/tmp/test_audit.json"),
            max_entries: 100,
            autosave_interval_secs: 0,
        };

        let audit = AuditLog::new(config);

        // Log some entries
        audit
            .log(AuditEntry::info("test_action").with_user("user1"))
            .await;
        audit
            .log(AuditEntry::success("another_action").with_details("some details"))
            .await;

        // Check count
        assert_eq!(audit.count().await, 2);

        // Get entries
        let entries = audit.get_entries(10, 0).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "another_action"); // Newest first
        assert_eq!(entries[1].action, "test_action");
    }

    #[tokio::test]
    async fn test_audit_log_max_entries() {
        let config = AuditConfig {
            persistence_path: PathBuf::from("/tmp/test_audit_max.json"),
            max_entries: 3,
            autosave_interval_secs: 0,
        };

        let audit = AuditLog::new(config);

        // Log more entries than max
        for i in 0..5 {
            audit
                .log(AuditEntry::info(format!("action_{}", i)))
                .await;
        }

        // Should only have max entries
        assert_eq!(audit.count().await, 3);

        // Should have the newest entries
        let entries = audit.get_entries(10, 0).await;
        assert_eq!(entries[0].action, "action_4");
        assert_eq!(entries[1].action, "action_3");
        assert_eq!(entries[2].action, "action_2");
    }

    #[tokio::test]
    async fn test_audit_entry_builder() {
        let entry = AuditEntry::warning("user_banned")
            .with_user("bad_user")
            .with_details("Spam behavior detected")
            .with_admin("admin1");

        assert_eq!(entry.level, "warning");
        assert_eq!(entry.action, "user_banned");
        assert_eq!(entry.user_id, Some("bad_user".to_string()));
        assert_eq!(entry.details, Some("Spam behavior detected".to_string()));
        assert_eq!(entry.admin_id, Some("admin1".to_string()));
    }
}
