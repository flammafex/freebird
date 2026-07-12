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
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
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
    PathBuf::from("/var/lib/freebird/issuer/audit_log.json")
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

struct RuntimeState {
    persisted: PersistedState,
    generation: u64,
}

/// The main audit log system with persistence
pub struct AuditLog {
    /// In-memory log entries
    state: Arc<RwLock<RuntimeState>>,
    /// Configuration
    config: AuditConfig,
    /// Flag to track if state has been modified since last save
    save_lock: Arc<Mutex<()>>,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn ensure_storage_path(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).context("create audit parent directory")?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe = parent.join(format!(
        ".audit-writable.{}.{}",
        std::process::id(),
        counter
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&probe)
        .context("audit directory is not writable")?;
    use std::io::Write;
    file.write_all(b"audit path probe")
        .context("write audit path probe")?;
    file.sync_all().context("sync audit path probe")?;
    fs::remove_file(&probe).context("remove audit path probe")?;
    Ok(())
}

impl AuditLog {
    /// Create a new audit log system
    pub fn new(config: AuditConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(RuntimeState {
                persisted: PersistedState::default(),
                generation: 0,
            })),
            config,
            save_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Create and load from persistence file
    pub async fn load_or_create(config: AuditConfig) -> Result<Self> {
        ensure_storage_path(&config.persistence_path).context("validate audit storage path")?;
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
            state: Arc::new(RwLock::new(RuntimeState {
                persisted: state,
                generation: 0,
            })),
            config,
            save_lock: Arc::new(Mutex::new(())),
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
        let save_lock = self.save_lock.clone();
        let path = self.config.persistence_path.clone();
        let interval = self.config.autosave_interval_secs;

        tokio::spawn(async move {
            let mut interval_timer =
                tokio::time::interval(std::time::Duration::from_secs(interval));

            loop {
                interval_timer.tick().await;

                // Serialize the complete snapshot with the final shutdown
                // flush. The lock must precede both snapshot and generation
                // capture, otherwise autosave can overwrite a final flush.
                let _save_guard = save_lock.lock().await;
                let (state_snapshot, generation) = {
                    let state = state.read().await;
                    (state.persisted.clone(), state.generation)
                };
                if generation == 0 {
                    continue;
                }
                match Self::save_to_file(&state_snapshot, &path).await {
                    Ok(_) => {
                        let mut current = state.write().await;
                        if current.generation == generation {
                            current.generation = 0;
                        }
                        debug!(generation, "Autosaved audit log");
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
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = path.with_file_name(format!(
            ".{}.tmp.{}.{}",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("audit"),
            std::process::id(),
            counter
        ));
        #[cfg(unix)]
        let parent = crate::shutdown::persistence_parent(path);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        options.create_new(true);
        let mut file = options.open(&temp_path).context("open audit temp file")?;
        use std::io::Write;
        file.write_all(json.as_bytes()).context("write temp file")?;
        file.sync_all().context("sync audit temp file")?;
        if let Err(error) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(error).context("rename temp file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .context("set audit file permissions")?;
        }
        // Directory sync makes the rename durable on Unix filesystems.
        #[cfg(unix)]
        std::fs::File::open(parent)
            .context("open audit directory for sync")?
            .sync_all()
            .context("sync audit directory")?;

        Ok(())
    }

    /// Explicitly save current state
    pub async fn save(&self) -> Result<()> {
        let _save_guard = self.save_lock.lock().await;
        let (state_snapshot, generation) = {
            let state = self.state.read().await;
            (state.persisted.clone(), state.generation)
        };
        Self::save_to_file(&state_snapshot, &self.config.persistence_path).await?;
        let mut state = self.state.write().await;
        if state.generation == generation {
            state.generation = 0;
        }
        info!("Saved audit log to {:?}", self.config.persistence_path);
        Ok(())
    }

    /// Mark state as dirty
    /// Log an audit entry
    pub async fn log(&self, entry: AuditEntry) {
        let mut state = self.state.write().await;

        // Add entry
        state.persisted.entries.push(entry.clone());

        // Trim if over max entries
        if self.config.max_entries > 0 && state.persisted.entries.len() > self.config.max_entries {
            let excess = state.persisted.entries.len() - self.config.max_entries;
            state.persisted.entries.drain(0..excess);
        }
        state.generation = state.generation.wrapping_add(1).max(1);
        drop(state);

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
            .persisted
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
        state.persisted.entries.len()
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
            .persisted
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
            audit.log(AuditEntry::info(format!("action_{}", i))).await;
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

    #[tokio::test]
    async fn corrupt_audit_log_is_a_startup_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        tokio::fs::write(&path, b"not-json").await.unwrap();
        let result = AuditLog::load_or_create(AuditConfig {
            persistence_path: path,
            ..AuditConfig::default()
        })
        .await;
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("deserialize audit log"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persisted_audit_log_has_restrictive_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        let audit = AuditLog::new(AuditConfig {
            persistence_path: path.clone(),
            ..AuditConfig::default()
        });
        audit.log(AuditEntry::info("permission_test")).await;
        audit.save().await.unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn audit_storage_rejects_unwritable_parent() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_directory = dir.path().join("parent");
        tokio::fs::write(&not_a_directory, b"file").await.unwrap();
        let result = AuditLog::load_or_create(AuditConfig {
            persistence_path: not_a_directory.join("audit.json"),
            ..AuditConfig::default()
        })
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn late_appends_remain_dirty_after_a_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        let audit = AuditLog::new(AuditConfig {
            persistence_path: path.clone(),
            ..AuditConfig::default()
        });
        audit.log(AuditEntry::info("before_save")).await;
        audit.save().await.unwrap();
        audit.log(AuditEntry::info("after_snapshot")).await;
        audit.save().await.unwrap();

        let loaded = AuditLog::load_or_create(AuditConfig {
            persistence_path: path,
            autosave_interval_secs: 0,
            ..AuditConfig::default()
        })
        .await
        .unwrap();
        assert_eq!(loaded.count().await, 2);
    }

    #[tokio::test]
    async fn concurrent_appends_survive_serialized_saves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        let audit = Arc::new(AuditLog::new(AuditConfig {
            persistence_path: path.clone(),
            ..AuditConfig::default()
        }));
        let mut tasks = Vec::new();
        for index in 0..8 {
            let audit = Arc::clone(&audit);
            tasks.push(tokio::spawn(async move {
                audit
                    .log(AuditEntry::info(format!("concurrent_{}", index)))
                    .await;
            }));
        }
        let saver = {
            let audit = Arc::clone(&audit);
            tokio::spawn(async move { audit.save().await.unwrap() })
        };
        for task in tasks {
            task.await.unwrap();
        }
        saver.await.unwrap();
        audit.save().await.unwrap();

        let loaded = AuditLog::load_or_create(AuditConfig {
            persistence_path: path,
            autosave_interval_secs: 0,
            ..AuditConfig::default()
        })
        .await
        .unwrap();
        assert_eq!(loaded.count().await, 8);
    }

    #[tokio::test]
    async fn final_save_snapshots_after_waiting_for_autosave_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        let audit = Arc::new(AuditLog::new(AuditConfig {
            persistence_path: path.clone(),
            autosave_interval_secs: 0,
            ..AuditConfig::default()
        }));
        let guard = audit.save_lock.lock().await;
        let pending = {
            let audit = Arc::clone(&audit);
            tokio::spawn(async move { audit.save().await.unwrap() })
        };
        audit.log(AuditEntry::info("after-autosave-snapshot")).await;
        drop(guard);
        pending.await.unwrap();
        let loaded = AuditLog::load_or_create(AuditConfig {
            persistence_path: path,
            autosave_interval_secs: 0,
            ..AuditConfig::default()
        })
        .await
        .unwrap();
        assert_eq!(
            loaded.get_entries(1, 0).await[0].action,
            "after-autosave-snapshot"
        );
    }
}
