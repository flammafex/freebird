//! Freebird Admin CLI
//!
//! A command-line tool for managing Freebird issuer instances.
//!
//! # Usage
//!
//! ```bash
//! # Set environment variables
//! export FREEBIRD_ISSUER_URL=http://localhost:8081
//! export FREEBIRD_ADMIN_KEY=your-admin-key
//!
//! # Or pass via CLI
//! freebird-cli --url http://localhost:8081 --key your-admin-key health
//!
//! # Commands
//! freebird-cli health              # Check issuer health
//! freebird-cli stats               # Show issuer statistics
//! freebird-cli config              # Show configuration
//! freebird-cli users list          # List users
//! freebird-cli users get <id>      # Get user details
//! freebird-cli users ban <id>      # Ban a user
//! freebird-cli invites revoke <c>  # Revoke a pending invitation
//! freebird-cli vouching list       # List trusted vouchers
//! freebird-cli webauthn policy     # Show WebAuthn attestation policy
//! freebird-cli keys list           # List signing keys
//! freebird-cli keys rotate         # Rotate signing key
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fmt::Write as FmtWrite;

/// Freebird Admin CLI - Manage your Freebird issuer instance
#[derive(Parser)]
#[command(name = "freebird-cli")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Issuer URL (or set FREEBIRD_ISSUER_URL)
    #[arg(short, long, env = "FREEBIRD_ISSUER_URL")]
    url: Option<String>,

    /// Admin API key (or set FREEBIRD_ADMIN_KEY)
    #[arg(short, long, env = "FREEBIRD_ADMIN_KEY")]
    key: Option<String>,

    /// Output format: table, json, or compact
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Compact,
}

#[derive(Subcommand)]
enum Commands {
    /// Check issuer health status
    Health,

    /// Show issuer statistics
    Stats,

    /// Show issuer configuration
    Config,

    /// Show Prometheus metrics
    Metrics,

    /// User management commands
    #[command(subcommand)]
    Users(UsersCommands),

    /// Invitation management commands
    #[command(subcommand)]
    Invites(InvitesCommands),

    /// Multi-party vouching management commands
    #[command(subcommand)]
    Vouching(VouchingCommands),

    /// WebAuthn management commands
    #[command(subcommand)]
    WebAuthn(WebAuthnCommands),

    /// Signing key management commands
    #[command(subcommand)]
    Keys(KeysCommands),

    /// Export data commands
    #[command(subcommand)]
    Export(ExportCommands),

    /// View audit log
    Audit {
        /// Maximum number of entries to show
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum UsersCommands {
    /// List all users
    List {
        /// Maximum number of users to show
        #[arg(short, long, default_value = "50")]
        limit: usize,

        /// Offset for pagination
        #[arg(short, long, default_value = "0")]
        offset: usize,
    },

    /// Get details for a specific user
    Get {
        /// User ID
        user_id: String,
    },

    /// Ban a user (and optionally their invite tree)
    Ban {
        /// User ID to ban
        user_id: String,

        /// Also ban all users invited by this user
        #[arg(long)]
        tree: bool,
    },

    /// Unban a user
    Unban {
        /// User ID to unban
        user_id: String,
    },

    /// Add a bootstrap user with an initial invite quota
    Bootstrap {
        /// User ID to add
        user_id: String,

        /// Initial invite quota
        #[arg(short, long, default_value = "5")]
        invites: u32,
    },

    /// Register the instance owner user
    RegisterOwner {
        /// Owner user ID
        user_id: String,
    },
}

#[derive(Subcommand)]
enum InvitesCommands {
    /// List all invitations
    List {
        /// Maximum number to show
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Create new invitations for a user
    Create {
        /// User ID who will own the invitations
        inviter_id: String,

        /// Number of invitations to create
        #[arg(short, long, default_value = "1")]
        count: usize,
    },

    /// Get details of a specific invitation
    Get {
        /// Invitation code
        code: String,
    },

    /// Revoke a pending invitation
    Revoke {
        /// Invitation code
        code: String,
    },

    /// Grant additional invite slots to a user
    Grant {
        /// User ID to grant invites to
        user_id: String,

        /// Number of invite slots to grant
        #[arg(short, long, default_value = "1")]
        count: usize,
    },
}

#[derive(Subcommand)]
enum VouchingCommands {
    /// List trusted vouchers
    List,

    /// Add a trusted voucher P-256 public key
    Add {
        /// Voucher user ID
        user_id: String,

        /// P-256 SEC1 public key, base64url without padding
        public_key_b64: String,
    },

    /// Remove a trusted voucher
    Remove {
        /// Voucher user ID
        user_id: String,
    },

    /// Submit a signed vouch
    Submit {
        /// Voucher user ID
        voucher_id: String,

        /// Vouchee user ID
        vouchee_id: String,

        /// P-256 ECDSA signature, base64url without padding
        signature_b64: String,

        /// Unix timestamp used in the signed vouch message
        timestamp: i64,
    },

    /// List pending vouches
    Pending,

    /// Clear pending vouches for a user
    ClearPending {
        /// Vouchee user ID
        vouchee_id: String,
    },

    /// Mark a vouched user as successful for voucher reputation
    MarkSuccessful {
        /// Vouchee user ID
        vouchee_id: String,
    },

    /// Mark a vouched user as problematic for voucher reputation
    MarkProblematic {
        /// Vouchee user ID
        vouchee_id: String,
    },
}

#[derive(Subcommand)]
enum WebAuthnCommands {
    /// Show active WebAuthn attestation/AAGUID policy
    Policy,

    /// Show WebAuthn credential statistics
    Stats,

    /// List registered WebAuthn credentials
    List,

    /// Delete a registered WebAuthn credential by credential ID
    Delete {
        /// Credential ID, base64url without padding
        credential_id: String,
    },
}

#[derive(Subcommand)]
enum KeysCommands {
    /// List all signing keys
    List,

    /// Rotate the signing key (create new epoch)
    Rotate {
        /// New key ID
        new_kid: String,

        /// Grace period for the old key in seconds
        #[arg(long)]
        grace_period_secs: Option<u64>,
    },

    /// Clean up old keys beyond retention period
    Cleanup,
}

#[derive(Subcommand)]
enum ExportCommands {
    /// Export users to JSON
    Users,

    /// Export invitations to JSON
    Invitations,

    /// Export audit log to JSON
    Audit,
}

// API response types

#[derive(Debug, Deserialize, Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    uptime_seconds: u64,
    invitation_system_status: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct StatsResponse {
    stats: InvitationStats,
    timestamp: u64,
    owner: Option<String>,
    user_count: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct InvitationStats {
    total_invitations: usize,
    redeemed_invitations: usize,
    pending_invitations: usize,
    total_users: usize,
    banned_users: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct ConfigResponse {
    issuer_id: String,
    epoch_duration: String,
    epoch_retention: u32,
    require_tls: bool,
    behind_proxy: bool,
    webauthn_enabled: bool,
    sybil: SybilConfig,
}

#[derive(Debug, Deserialize, Serialize)]
struct SybilConfig {
    mode: String,
    mode_description: String,
    settings: Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct UsersResponse {
    users: Vec<UserSummary>,
    total: u64,
    limit: usize,
    offset: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct UserSummary {
    user_id: String,
    invites_remaining: u32,
    banned: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct UserDetails {
    user_id: String,
    invites_remaining: u32,
    invites_sent: Vec<String>,
    invites_used: Vec<String>,
    joined_at: u64,
    last_invite_at: u64,
    reputation: f64,
    banned: bool,
    invitees: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct InvitationsResponse {
    invitations: Vec<InvitationSummary>,
    total: usize,
    offset: usize,
    limit: usize,
    has_more: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct InvitationSummary {
    code: String,
    inviter_id: String,
    invitee_id: Option<String>,
    created_at: u64,
    expires_at: u64,
    redeemed: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeySummary {
    kid: String,
    status: Value,
    pubkey_b64: String,
    deprecated_at: Option<u64>,
    expires_at: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeysResponse {
    keys: Vec<KeySummary>,
    stats: Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuditEntry {
    timestamp: u64,
    level: String,
    action: String,
    user_id: Option<String>,
    details: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuditResponse {
    entries: Vec<AuditEntry>,
    total: usize,
}

#[derive(Debug, Serialize)]
struct BanRequest {
    user_id: String,
    ban_tree: bool,
}

#[derive(Debug, Serialize)]
struct UnbanRequest {
    user_id: String,
}

#[derive(Debug, Serialize)]
struct CreateInvitationsRequest {
    inviter_id: String,
    count: usize,
}

#[derive(Debug, Serialize)]
struct GrantInvitesRequest {
    user_id: String,
    count: usize,
}

#[derive(Debug, Serialize)]
struct RotateKeyRequest {
    new_kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    grace_period_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BootstrapUserRequest {
    user_id: String,
    invite_count: u32,
}

#[derive(Debug, Serialize)]
struct RegisterOwnerRequest {
    user_id: String,
}

#[derive(Debug, Serialize)]
struct AddVoucherRequest {
    user_id: String,
    public_key_b64: String,
}

#[derive(Debug, Serialize)]
struct SubmitVouchRequest {
    voucher_id: String,
    vouchee_id: String,
    signature_b64: String,
    timestamp: i64,
}

#[derive(Debug, Serialize)]
struct VoucheeRequest {
    vouchee_id: String,
}

struct ApiClient {
    client: Client,
    base_url: String,
    admin_key: String,
}

impl ApiClient {
    fn new(base_url: String, admin_key: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            admin_key,
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}/admin{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .header("X-Admin-Key", &self.admin_key)
            .send()
            .await
            .context("Failed to connect to issuer")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error ({}): {}", status, body);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}/admin{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .header("X-Admin-Key", &self.admin_key)
            .json(body)
            .send()
            .await
            .context("Failed to connect to issuer")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error ({}): {}", status, body);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}/admin{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .header("X-Admin-Key", &self.admin_key)
            .send()
            .await
            .context("Failed to connect to issuer")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error ({}): {}", status, body);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}/admin{}", self.base_url, path);
        let resp = self
            .client
            .delete(&url)
            .header("X-Admin-Key", &self.admin_key)
            .send()
            .await
            .context("Failed to connect to issuer")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error ({}): {}", status, body);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn delete_json<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = format!("{}/admin{}", self.base_url, path);
        let resp = self
            .client
            .delete(&url)
            .header("X-Admin-Key", &self.admin_key)
            .json(body)
            .send()
            .await
            .context("Failed to connect to issuer")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error ({}): {}", status, body);
        }

        resp.json().await.context("Failed to parse response")
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

// Simple table rendering without external dependency issues
fn print_table<T: TableRow>(headers: &[&str], rows: &[T]) {
    if rows.is_empty() {
        return;
    }

    // Calculate column widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        let values = row.values();
        for (i, v) in values.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(strip_ansi(v).len());
            }
        }
    }

    // Print header
    let mut header_line = String::new();
    let mut separator = String::new();
    for (i, h) in headers.iter().enumerate() {
        if i > 0 {
            header_line.push_str(" │ ");
            separator.push_str("─┼─");
        }
        let _ = write!(header_line, "{:width$}", h.bold(), width = widths[i]);
        separator.push_str(&"─".repeat(widths[i]));
    }
    println!("{}", header_line);
    println!("{}", separator);

    // Print rows
    for row in rows {
        let values = row.values();
        let mut line = String::new();
        for (i, v) in values.iter().enumerate() {
            if i > 0 {
                line.push_str(" │ ");
            }
            let stripped_len = strip_ansi(v).len();
            let padding = widths[i].saturating_sub(stripped_len);
            line.push_str(v);
            line.push_str(&" ".repeat(padding));
        }
        println!("{}", line);
    }
}

fn strip_ansi(s: &str) -> String {
    // Simple ANSI escape sequence stripper
    let mut result = String::new();
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else {
            result.push(c);
        }
    }
    result
}

trait TableRow {
    fn values(&self) -> Vec<String>;
}

impl TableRow for UserSummary {
    fn values(&self) -> Vec<String> {
        vec![
            self.user_id.clone(),
            self.invites_remaining.to_string(),
            if self.banned {
                "Yes".red().to_string()
            } else {
                "No".green().to_string()
            },
        ]
    }
}

impl TableRow for InvitationSummary {
    fn values(&self) -> Vec<String> {
        vec![
            self.code.clone(),
            self.inviter_id.clone(),
            self.invitee_id.clone().unwrap_or_else(|| "-".to_string()),
            if self.redeemed {
                "Redeemed".green().to_string()
            } else {
                "Pending".yellow().to_string()
            },
            self.created_at.to_string(),
            self.expires_at.to_string(),
        ]
    }
}

impl TableRow for KeySummary {
    fn values(&self) -> Vec<String> {
        vec![
            self.kid.clone(),
            self.status.to_string(),
            self.deprecated_at
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            self.expires_at
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ]
    }
}

impl TableRow for AuditEntry {
    fn values(&self) -> Vec<String> {
        vec![
            self.timestamp.to_string(),
            self.level.clone(),
            self.action.clone(),
            self.user_id.clone().unwrap_or_else(|| "-".to_string()),
            self.details.clone().unwrap_or_else(|| "-".to_string()),
        ]
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Get URL and key from args or environment
    let url = cli
        .url
        .or_else(|| env::var("FREEBIRD_ISSUER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8081".to_string());

    let key = cli
        .key
        .or_else(|| env::var("FREEBIRD_ADMIN_KEY").ok())
        .context("Admin key required. Set FREEBIRD_ADMIN_KEY or use --key")?;

    let api = ApiClient::new(url, key);
    let format = cli.format;

    match cli.command {
        Commands::Health => {
            let health: HealthResponse = api.get("/health").await?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&health)?);
            } else {
                let status_colored = if health.status == "healthy" || health.status == "ok" {
                    health.status.green()
                } else {
                    health.status.red()
                };
                println!("{} {}", "Status:".bold(), status_colored);
                println!("{} {}", "Service:".bold(), health.service);
                println!(
                    "{} {}",
                    "Invitation State:".bold(),
                    health.invitation_system_status
                );
                println!(
                    "{} {}",
                    "Uptime:".bold(),
                    format_uptime(health.uptime_seconds)
                );
            }
        }

        Commands::Stats => {
            let stats: StatsResponse = api.get("/stats").await?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!("{}", "Issuer Statistics".bold().underline());
                println!();
                println!("{:.<25} {}", "Total Users", stats.stats.total_users);
                println!("{:.<25} {}", "Redeemed Users", stats.user_count);
                println!("{:.<25} {}", "Banned Users", stats.stats.banned_users);
                println!(
                    "{:.<25} {}",
                    "Total Invitations", stats.stats.total_invitations
                );
                println!(
                    "{:.<25} {}",
                    "Pending Invitations", stats.stats.pending_invitations
                );
                println!(
                    "{:.<25} {}",
                    "Redeemed Invitations", stats.stats.redeemed_invitations
                );
                if let Some(owner) = stats.owner {
                    println!("{:.<25} {}", "Owner", owner);
                }
            }
        }

        Commands::Config => {
            let config: ConfigResponse = api.get("/config").await?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&config)?);
            } else {
                println!("{}", "Issuer Configuration".bold().underline());
                println!();
                println!("{:.<25} {}", "Issuer ID", config.issuer_id);
                println!("{:.<25} {}", "Epoch Duration", config.epoch_duration);
                println!("{:.<25} {}", "Epoch Retention", config.epoch_retention);
                println!(
                    "{:.<25} {}",
                    "Require TLS",
                    if config.require_tls {
                        "Yes".green()
                    } else {
                        "No".yellow()
                    }
                );
                println!(
                    "{:.<25} {}",
                    "Behind Proxy",
                    if config.behind_proxy { "Yes" } else { "No" }
                );
                println!(
                    "{:.<25} {}",
                    "WebAuthn",
                    if config.webauthn_enabled {
                        "Enabled".green()
                    } else {
                        "Disabled".dimmed()
                    }
                );
                println!();
                println!("{}", "Sybil Resistance".bold());
                println!("{:.<25} {}", "Mode", config.sybil.mode.cyan());
                println!("{:.<25} {}", "Description", config.sybil.mode_description);
                if !config.sybil.settings.is_null() {
                    println!("{:.<25}", "Settings");
                    println!("{}", serde_json::to_string_pretty(&config.sybil.settings)?);
                }
            }
        }

        Commands::Metrics => {
            // Metrics endpoint returns plain text, not JSON
            let url = format!("{}/admin/metrics", api.base_url);
            let resp = api
                .client
                .get(&url)
                .header("X-Admin-Key", &api.admin_key)
                .send()
                .await
                .context("Failed to connect to issuer")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("API error ({}): {}", status, body);
            }

            let metrics = resp.text().await.context("Failed to read response")?;
            println!("{}", metrics);
        }

        Commands::Users(cmd) => match cmd {
            UsersCommands::List { limit, offset } => {
                let users: UsersResponse = api
                    .get(&format!("/users?limit={}&offset={}", limit, offset))
                    .await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&users)?);
                } else {
                    println!(
                        "{} (showing {}-{} of {})",
                        "Users".bold().underline(),
                        offset + 1,
                        (offset + users.users.len()).min(users.total as usize),
                        users.total
                    );
                    println!();
                    if users.users.is_empty() {
                        println!("{}", "No users found.".dimmed());
                    } else {
                        print_table(&["User ID", "Invites Remaining", "Banned"], &users.users);
                    }
                }
            }

            UsersCommands::Get { user_id } => {
                let user: UserDetails = api.get(&format!("/users/{}", user_id)).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&user)?);
                } else {
                    println!("{}", "User Details".bold().underline());
                    println!();
                    println!("{:.<25} {}", "User ID", user.user_id);
                    println!("{:.<25} {}", "Joined At", user.joined_at);
                    println!("{:.<25} {}", "Last Invite At", user.last_invite_at);
                    println!(
                        "{:.<25} {}",
                        "Status",
                        if user.banned {
                            "Banned".red()
                        } else {
                            "Active".green()
                        }
                    );
                    println!("{:.<25} {:.2}", "Reputation", user.reputation);
                    println!("{:.<25} {}", "Invites Remaining", user.invites_remaining);
                    println!("{:.<25} {}", "Invites Sent", user.invites_sent.len());
                    println!("{:.<25} {}", "Invites Used", user.invites_used.len());
                    println!("{:.<25} {}", "Invitees", user.invitees.len());
                }
            }

            UsersCommands::Ban { user_id, tree } => {
                let req = BanRequest {
                    user_id: user_id.clone(),
                    ban_tree: tree,
                };
                let resp: Value = api.post("/users/ban", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!(
                        "{} User {} has been banned{}",
                        "✓".green(),
                        user_id.bold(),
                        if tree { " (including invite tree)" } else { "" }
                    );
                }
            }

            UsersCommands::Unban { user_id } => {
                let req = UnbanRequest {
                    user_id: user_id.clone(),
                };
                let resp: Value = api.post("/users/unban", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} User {} has been unbanned", "✓".green(), user_id.bold());
                }
            }

            UsersCommands::Bootstrap { user_id, invites } => {
                let req = BootstrapUserRequest {
                    user_id: user_id.clone(),
                    invite_count: invites,
                };
                let resp: Value = api.post("/bootstrap/add", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!(
                        "{} Added bootstrap user {} with {} invite slot(s)",
                        "✓".green(),
                        user_id.bold(),
                        invites
                    );
                }
            }

            UsersCommands::RegisterOwner { user_id } => {
                let req = RegisterOwnerRequest {
                    user_id: user_id.clone(),
                };
                let resp: Value = api.post("/register-owner", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Registered owner {}", "✓".green(), user_id.bold());
                }
            }
        },

        Commands::Invites(cmd) => match cmd {
            InvitesCommands::List { limit } => {
                let invites: InvitationsResponse =
                    api.get(&format!("/invitations?limit={}", limit)).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&invites)?);
                } else {
                    println!(
                        "{} ({} total)",
                        "Invitations".bold().underline(),
                        invites.total
                    );
                    println!();
                    if invites.invitations.is_empty() {
                        println!("{}", "No invitations found.".dimmed());
                    } else {
                        print_table(
                            &["Code", "Inviter", "Invitee", "Status", "Created", "Expires"],
                            &invites.invitations,
                        );
                    }
                }
            }

            InvitesCommands::Create { inviter_id, count } => {
                let req = CreateInvitationsRequest {
                    inviter_id: inviter_id.clone(),
                    count,
                };
                let resp: Value = api.post("/invitations/create", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!(
                        "{} Created {} invitation(s) for user {}",
                        "✓".green(),
                        count,
                        inviter_id.bold()
                    );
                    if let Some(codes) = resp.get("invitations").and_then(|c| c.as_array()) {
                        println!();
                        println!("{}", "Invitation Codes:".bold());
                        for invite in codes {
                            if let Some(s) = invite.get("code").and_then(|v| v.as_str()) {
                                println!("  {}", s.cyan());
                            }
                        }
                    }
                }
            }

            InvitesCommands::Get { code } => {
                let invite: Value = api.get(&format!("/invitations/{}", code)).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&invite)?);
                } else {
                    println!("{}", "Invitation Details".bold().underline());
                    println!();
                    println!("{}", serde_json::to_string_pretty(&invite)?);
                }
            }

            InvitesCommands::Revoke { code } => {
                let resp: Value = api.delete(&format!("/invitations/{}", code)).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Revoked invitation {}", "✓".green(), code.bold());
                }
            }

            InvitesCommands::Grant { user_id, count } => {
                let req = GrantInvitesRequest {
                    user_id: user_id.clone(),
                    count,
                };
                let resp: Value = api.post("/invites/grant", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!(
                        "{} Granted {} invite slot(s) to user {}",
                        "✓".green(),
                        count,
                        user_id.bold()
                    );
                }
            }
        },

        Commands::Vouching(cmd) => match cmd {
            VouchingCommands::List => {
                let resp: Value = api.get("/vouching/vouchers").await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{}", "Trusted Vouchers".bold().underline());
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
            }

            VouchingCommands::Add {
                user_id,
                public_key_b64,
            } => {
                let req = AddVoucherRequest {
                    user_id: user_id.clone(),
                    public_key_b64,
                };
                let resp: Value = api.post("/vouching/vouchers", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Added voucher {}", "✓".green(), user_id.bold());
                }
            }

            VouchingCommands::Remove { user_id } => {
                let resp: Value = api
                    .delete(&format!("/vouching/vouchers/{}", user_id))
                    .await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Removed voucher {}", "✓".green(), user_id.bold());
                }
            }

            VouchingCommands::Submit {
                voucher_id,
                vouchee_id,
                signature_b64,
                timestamp,
            } => {
                let req = SubmitVouchRequest {
                    voucher_id: voucher_id.clone(),
                    vouchee_id: vouchee_id.clone(),
                    signature_b64,
                    timestamp,
                };
                let resp: Value = api.post("/vouching/vouches", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!(
                        "{} Submitted vouch from {} for {}",
                        "✓".green(),
                        voucher_id.bold(),
                        vouchee_id.bold()
                    );
                }
            }

            VouchingCommands::Pending => {
                let resp: Value = api.get("/vouching/pending").await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{}", "Pending Vouches".bold().underline());
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                }
            }

            VouchingCommands::ClearPending { vouchee_id } => {
                let req = VoucheeRequest {
                    vouchee_id: vouchee_id.clone(),
                };
                let resp: Value = api.delete_json("/vouching/pending", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!(
                        "{} Cleared pending vouches for {}",
                        "✓".green(),
                        vouchee_id.bold()
                    );
                }
            }

            VouchingCommands::MarkSuccessful { vouchee_id } => {
                let req = VoucheeRequest {
                    vouchee_id: vouchee_id.clone(),
                };
                let resp: Value = api.post("/vouching/mark-successful", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Marked {} successful", "✓".green(), vouchee_id.bold());
                }
            }

            VouchingCommands::MarkProblematic { vouchee_id } => {
                let req = VoucheeRequest {
                    vouchee_id: vouchee_id.clone(),
                };
                let resp: Value = api.post("/vouching/mark-problematic", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Marked {} problematic", "✓".green(), vouchee_id.bold());
                }
            }
        },

        Commands::WebAuthn(cmd) => match cmd {
            WebAuthnCommands::Policy => {
                let resp: Value = api.get("/webauthn/policy").await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            WebAuthnCommands::Stats => {
                let resp: Value = api.get("/webauthn/stats").await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            WebAuthnCommands::List => {
                let resp: Value = api.get("/webauthn/credentials").await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            WebAuthnCommands::Delete { credential_id } => {
                let resp: Value = api
                    .delete(&format!("/webauthn/credentials/{}", credential_id))
                    .await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!(
                        "{} Deleted WebAuthn credential {}",
                        "✓".green(),
                        credential_id
                    );
                }
            }
        },

        Commands::Keys(cmd) => match cmd {
            KeysCommands::List => {
                let keys: KeysResponse = api.get("/keys").await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&keys)?);
                } else {
                    println!("{}", "Signing Keys".bold().underline());
                    println!("{}", serde_json::to_string_pretty(&keys.stats)?);
                    println!();
                    if keys.keys.is_empty() {
                        println!("{}", "No keys found.".dimmed());
                    } else {
                        print_table(
                            &["Key ID", "Status", "Deprecated At", "Expires At"],
                            &keys.keys,
                        );
                    }
                }
            }

            KeysCommands::Rotate {
                new_kid,
                grace_period_secs,
            } => {
                let req = RotateKeyRequest {
                    new_kid,
                    grace_period_secs,
                };
                let resp: Value = api.post("/keys/rotate", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Key rotation complete", "✓".green());
                    if let Some(kid) = resp.get("new_kid").and_then(|k| k.as_str()) {
                        println!("  New key ID: {}", kid);
                    }
                }
            }

            KeysCommands::Cleanup => {
                let resp: Value = api.post_empty("/keys/cleanup").await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Key cleanup complete", "✓".green());
                    if let Some(removed) = resp.get("removed_count").and_then(|r| r.as_u64()) {
                        println!("  Removed {} old key(s)", removed);
                    }
                }
            }
        },

        Commands::Export(cmd) => {
            let data: Value = match cmd {
                ExportCommands::Users => api.get("/export/users").await?,
                ExportCommands::Invitations => api.get("/export/invitations").await?,
                ExportCommands::Audit => api.get("/export/audit").await?,
            };

            // Export always outputs JSON
            println!("{}", serde_json::to_string_pretty(&data)?);
        }

        Commands::Audit { limit } => {
            let audit: AuditResponse = api.get(&format!("/audit?limit={}", limit)).await?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&audit)?);
            } else {
                println!(
                    "{} ({} total entries)",
                    "Audit Log".bold().underline(),
                    audit.total
                );
                println!();
                if audit.entries.is_empty() {
                    println!("{}", "No audit entries found.".dimmed());
                } else {
                    print_table(
                        &["Timestamp", "Level", "Action", "User", "Details"],
                        &audit.entries,
                    );
                }
            }
        }
    }

    Ok(())
}
