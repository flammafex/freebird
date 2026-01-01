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
//! freebird-cli keys list           # List signing keys
//! freebird-cli keys rotate         # Rotate signing key
//! freebird-cli federation vouches  # List federation vouches
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

    /// Signing key management commands
    #[command(subcommand)]
    Keys(KeysCommands),

    /// Federation management commands
    #[command(subcommand)]
    Federation(FederationCommands),

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
enum KeysCommands {
    /// List all signing keys
    List,

    /// Rotate the signing key (create new epoch)
    Rotate,

    /// Clean up old keys beyond retention period
    Cleanup,
}

#[derive(Subcommand)]
enum FederationCommands {
    /// List vouches for other issuers
    Vouches,

    /// Add a vouch for another issuer
    Vouch {
        /// Issuer ID to vouch for
        issuer_id: String,

        /// Trust level (1-10)
        #[arg(short, long, default_value = "5")]
        level: u8,

        /// Optional note
        #[arg(short, long)]
        note: Option<String>,
    },

    /// Remove a vouch for an issuer
    Unvouch {
        /// Issuer ID to remove vouch for
        issuer_id: String,
    },

    /// List revocations
    Revocations,

    /// Add a revocation for an issuer
    Revoke {
        /// Issuer ID to revoke
        issuer_id: String,

        /// Reason for revocation
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Remove a revocation
    Unrevoke {
        /// Issuer ID to unrevoke
        issuer_id: String,
    },
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
    version: String,
    uptime_secs: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct StatsResponse {
    total_users: u64,
    active_users_24h: u64,
    tokens_issued_24h: u64,
    current_epoch: u32,
    invitations_pending: u64,
    invitations_redeemed: u64,
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
    created_at: String,
    last_seen: Option<String>,
    tokens_issued: u64,
    is_banned: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct UserDetails {
    user_id: String,
    created_at: String,
    last_seen: Option<String>,
    tokens_issued: u64,
    is_banned: bool,
    invited_by: Option<String>,
    invites_remaining: u32,
    invites_used: u32,
    trust_level: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
struct InvitationsResponse {
    invitations: Vec<InvitationSummary>,
    total: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct InvitationSummary {
    code: String,
    inviter_id: String,
    status: String,
    created_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeySummary {
    epoch: u32,
    kid: String,
    created_at: String,
    is_active: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeysResponse {
    keys: Vec<KeySummary>,
    current_epoch: u32,
}

#[derive(Debug, Deserialize, Serialize)]
struct VouchSummary {
    issuer_id: String,
    trust_level: u8,
    created_at: String,
    note: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VouchesResponse {
    vouches: Vec<VouchSummary>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RevocationSummary {
    issuer_id: String,
    reason: Option<String>,
    created_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RevocationsResponse {
    revocations: Vec<RevocationSummary>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuditEntry {
    timestamp: String,
    action: String,
    actor: Option<String>,
    details: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuditResponse {
    entries: Vec<AuditEntry>,
    total: u64,
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
struct AddVouchRequest {
    issuer_id: String,
    trust_level: u8,
    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct AddRevocationRequest {
    issuer_id: String,
    reason: Option<String>,
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
            self.created_at.clone(),
            self.last_seen.clone().unwrap_or_else(|| "-".to_string()),
            self.tokens_issued.to_string(),
            if self.is_banned { "Yes".red().to_string() } else { "No".green().to_string() },
        ]
    }
}

impl TableRow for InvitationSummary {
    fn values(&self) -> Vec<String> {
        vec![
            self.code.clone(),
            self.inviter_id.clone(),
            self.status.clone(),
            self.created_at.clone(),
        ]
    }
}

impl TableRow for KeySummary {
    fn values(&self) -> Vec<String> {
        vec![
            self.epoch.to_string(),
            self.kid.clone(),
            self.created_at.clone(),
            if self.is_active { "Yes".green().to_string() } else { "No".dimmed().to_string() },
        ]
    }
}

impl TableRow for VouchSummary {
    fn values(&self) -> Vec<String> {
        vec![
            self.issuer_id.clone(),
            self.trust_level.to_string(),
            self.created_at.clone(),
            self.note.clone().unwrap_or_else(|| "-".to_string()),
        ]
    }
}

impl TableRow for RevocationSummary {
    fn values(&self) -> Vec<String> {
        vec![
            self.issuer_id.clone(),
            self.reason.clone().unwrap_or_else(|| "-".to_string()),
            self.created_at.clone(),
        ]
    }
}

impl TableRow for AuditEntry {
    fn values(&self) -> Vec<String> {
        vec![
            self.timestamp.clone(),
            self.action.clone(),
            self.actor.clone().unwrap_or_else(|| "-".to_string()),
            self.details.clone().unwrap_or_else(|| "-".to_string()),
        ]
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Get URL and key from args or environment
    let url = cli.url.or_else(|| env::var("FREEBIRD_ISSUER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8081".to_string());

    let key = cli.key.or_else(|| env::var("FREEBIRD_ADMIN_KEY").ok())
        .context("Admin key required. Set FREEBIRD_ADMIN_KEY or use --key")?;

    let api = ApiClient::new(url, key);
    let format = cli.format;

    match cli.command {
        Commands::Health => {
            let health: HealthResponse = api.get("/health").await?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&health)?);
            } else {
                let status_colored = if health.status == "healthy" {
                    health.status.green()
                } else {
                    health.status.red()
                };
                println!("{} {}", "Status:".bold(), status_colored);
                println!("{} {}", "Service:".bold(), health.service);
                println!("{} {}", "Version:".bold(), health.version);
                println!("{} {}", "Uptime:".bold(), format_uptime(health.uptime_secs));
            }
        }

        Commands::Stats => {
            let stats: StatsResponse = api.get("/stats").await?;
            if format == OutputFormat::Json {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!("{}", "Issuer Statistics".bold().underline());
                println!();
                println!("{:.<25} {}", "Total Users", stats.total_users);
                println!("{:.<25} {}", "Active (24h)", stats.active_users_24h);
                println!("{:.<25} {}", "Tokens Issued (24h)", stats.tokens_issued_24h);
                println!("{:.<25} {}", "Current Epoch", stats.current_epoch);
                println!("{:.<25} {}", "Pending Invitations", stats.invitations_pending);
                println!("{:.<25} {}", "Redeemed Invitations", stats.invitations_redeemed);
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
                println!("{:.<25} {}", "Require TLS", if config.require_tls { "Yes".green() } else { "No".yellow() });
                println!("{:.<25} {}", "Behind Proxy", if config.behind_proxy { "Yes" } else { "No" });
                println!("{:.<25} {}", "WebAuthn", if config.webauthn_enabled { "Enabled".green() } else { "Disabled".dimmed() });
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
            let resp = api.client
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
                let users: UsersResponse = api.get(&format!("/users?limit={}&offset={}", limit, offset)).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&users)?);
                } else {
                    println!("{} (showing {}-{} of {})",
                        "Users".bold().underline(),
                        offset + 1,
                        (offset + users.users.len()).min(users.total as usize),
                        users.total
                    );
                    println!();
                    if users.users.is_empty() {
                        println!("{}", "No users found.".dimmed());
                    } else {
                        print_table(
                            &["User ID", "Created", "Last Seen", "Tokens", "Banned"],
                            &users.users,
                        );
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
                    println!("{:.<25} {}", "Created", user.created_at);
                    println!("{:.<25} {}", "Last Seen", user.last_seen.unwrap_or_else(|| "Never".to_string()));
                    println!("{:.<25} {}", "Tokens Issued", user.tokens_issued);
                    println!("{:.<25} {}", "Status", if user.is_banned { "Banned".red() } else { "Active".green() });
                    println!("{:.<25} {}", "Invited By", user.invited_by.unwrap_or_else(|| "N/A".to_string()));
                    println!("{:.<25} {}", "Invites Remaining", user.invites_remaining);
                    println!("{:.<25} {}", "Invites Used", user.invites_used);
                    if let Some(level) = user.trust_level {
                        println!("{:.<25} {}", "Trust Level", level);
                    }
                }
            }

            UsersCommands::Ban { user_id, tree } => {
                let req = BanRequest { user_id: user_id.clone(), ban_tree: tree };
                let resp: Value = api.post("/users/ban", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} User {} has been banned{}",
                        "✓".green(),
                        user_id.bold(),
                        if tree { " (including invite tree)" } else { "" }
                    );
                }
            }

            UsersCommands::Unban { user_id } => {
                let req = UnbanRequest { user_id: user_id.clone() };
                let resp: Value = api.post("/users/unban", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} User {} has been unbanned", "✓".green(), user_id.bold());
                }
            }
        },

        Commands::Invites(cmd) => match cmd {
            InvitesCommands::List { limit } => {
                let invites: InvitationsResponse = api.get(&format!("/invitations?limit={}", limit)).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&invites)?);
                } else {
                    println!("{} ({} total)", "Invitations".bold().underline(), invites.total);
                    println!();
                    if invites.invitations.is_empty() {
                        println!("{}", "No invitations found.".dimmed());
                    } else {
                        print_table(
                            &["Code", "Inviter", "Status", "Created"],
                            &invites.invitations,
                        );
                    }
                }
            }

            InvitesCommands::Create { inviter_id, count } => {
                let req = CreateInvitationsRequest { inviter_id: inviter_id.clone(), count };
                let resp: Value = api.post("/invitations/create", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Created {} invitation(s) for user {}",
                        "✓".green(), count, inviter_id.bold());
                    if let Some(codes) = resp.get("codes").and_then(|c| c.as_array()) {
                        println!();
                        println!("{}", "Invitation Codes:".bold());
                        for code in codes {
                            if let Some(s) = code.as_str() {
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

            InvitesCommands::Grant { user_id, count } => {
                let req = GrantInvitesRequest { user_id: user_id.clone(), count };
                let resp: Value = api.post("/invites/grant", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Granted {} invite slot(s) to user {}",
                        "✓".green(), count, user_id.bold());
                }
            }
        },

        Commands::Keys(cmd) => match cmd {
            KeysCommands::List => {
                let keys: KeysResponse = api.get("/keys").await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&keys)?);
                } else {
                    println!("{} (current epoch: {})",
                        "Signing Keys".bold().underline(),
                        keys.current_epoch.to_string().cyan()
                    );
                    println!();
                    if keys.keys.is_empty() {
                        println!("{}", "No keys found.".dimmed());
                    } else {
                        print_table(
                            &["Epoch", "Key ID", "Created", "Active"],
                            &keys.keys,
                        );
                    }
                }
            }

            KeysCommands::Rotate => {
                let resp: Value = api.post_empty("/keys/rotate").await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Key rotation complete", "✓".green());
                    if let Some(epoch) = resp.get("new_epoch").and_then(|e| e.as_u64()) {
                        println!("  New epoch: {}", epoch.to_string().cyan());
                    }
                    if let Some(kid) = resp.get("kid").and_then(|k| k.as_str()) {
                        println!("  Key ID: {}", kid);
                    }
                }
            }

            KeysCommands::Cleanup => {
                let resp: Value = api.post_empty("/keys/cleanup").await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Key cleanup complete", "✓".green());
                    if let Some(removed) = resp.get("removed").and_then(|r| r.as_u64()) {
                        println!("  Removed {} old key(s)", removed);
                    }
                }
            }
        },

        Commands::Federation(cmd) => match cmd {
            FederationCommands::Vouches => {
                let vouches: VouchesResponse = api.get("/federation/vouches").await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&vouches)?);
                } else {
                    println!("{}", "Federation Vouches".bold().underline());
                    println!();
                    if vouches.vouches.is_empty() {
                        println!("{}", "No vouches configured.".dimmed());
                    } else {
                        print_table(
                            &["Issuer ID", "Level", "Created", "Note"],
                            &vouches.vouches,
                        );
                    }
                }
            }

            FederationCommands::Vouch { issuer_id, level, note } => {
                let req = AddVouchRequest { issuer_id: issuer_id.clone(), trust_level: level, note };
                let resp: Value = api.post("/federation/vouches", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Added vouch for {} (level {})",
                        "✓".green(), issuer_id.bold(), level);
                }
            }

            FederationCommands::Unvouch { issuer_id } => {
                let resp: Value = api.delete(&format!("/federation/vouches/{}", issuer_id)).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Removed vouch for {}", "✓".green(), issuer_id.bold());
                }
            }

            FederationCommands::Revocations => {
                let revocations: RevocationsResponse = api.get("/federation/revocations").await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&revocations)?);
                } else {
                    println!("{}", "Federation Revocations".bold().underline());
                    println!();
                    if revocations.revocations.is_empty() {
                        println!("{}", "No revocations configured.".dimmed());
                    } else {
                        print_table(
                            &["Issuer ID", "Reason", "Created"],
                            &revocations.revocations,
                        );
                    }
                }
            }

            FederationCommands::Revoke { issuer_id, reason } => {
                let req = AddRevocationRequest { issuer_id: issuer_id.clone(), reason };
                let resp: Value = api.post("/federation/revocations", &req).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Added revocation for {}", "✓".green(), issuer_id.bold());
                }
            }

            FederationCommands::Unrevoke { issuer_id } => {
                let resp: Value = api.delete(&format!("/federation/revocations/{}", issuer_id)).await?;
                if format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    println!("{} Removed revocation for {}", "✓".green(), issuer_id.bold());
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
                println!("{} ({} total entries)", "Audit Log".bold().underline(), audit.total);
                println!();
                if audit.entries.is_empty() {
                    println!("{}", "No audit entries found.".dimmed());
                } else {
                    print_table(
                        &["Timestamp", "Action", "Actor", "Details"],
                        &audit.entries,
                    );
                }
            }
        }
    }

    Ok(())
}
