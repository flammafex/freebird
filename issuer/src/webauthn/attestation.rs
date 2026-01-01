// issuer/src/webauthn/attestation.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! WebAuthn Attestation Policy Enforcement
//!
//! This module provides comprehensive attestation validation including:
//! - Policy levels: none, indirect, direct, enterprise
//! - AAGUID allowlisting for specific authenticator models
//! - Attestation format detection (packed, tpm, android-key, etc.)
//! - Audit logging for compliance

use axum::http::StatusCode;
use base64ct::Encoding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;
use tracing::{debug, info, warn};
use webauthn_rs::prelude::*;

// --- AAGUID Constants ---

/// Well-known AAGUIDs for reference
pub mod known_aaguids {
    /// YubiKey 5 Series
    pub const YUBIKEY_5: &str = "fa2b99dc-9e39-4257-8f92-4a30d23c4118";
    /// YubiKey 5Ci
    pub const YUBIKEY_5CI: &str = "c5ef55ff-ad9a-4b9f-b580-adebafe026d0";
    /// YubiKey Bio
    pub const YUBIKEY_BIO: &str = "d8522d9f-575b-4866-88a9-ba99fa02f35b";
    /// Apple Secure Enclave (typically uses self/none attestation)
    pub const APPLE_SECURE_ENCLAVE: &str = "00000000-0000-0000-0000-000000000000";
    /// Google Titan Security Key
    pub const GOOGLE_TITAN: &str = "42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3";
    /// Feitian ePass FIDO
    pub const FEITIAN_EPASS: &str = "833b721a-ff5f-4d00-bb2e-bdda3ec01e29";
    /// SoloKeys Solo 2
    pub const SOLOKEYS_SOLO2: &str = "8876631b-d4a0-427f-5773-0ec71c9e0279";
}

// --- Configuration ---

/// Attestation policy configuration loaded from environment
#[derive(Debug, Clone)]
pub struct AttestationConfig {
    /// Policy level (none, indirect, direct, enterprise)
    pub policy: AttestationPolicy,
    /// Set of allowed AAGUIDs (empty means allow all)
    pub allowed_aaguids: HashSet<String>,
    /// Whether to log attestation details for audit
    pub audit_logging: bool,
    /// Maximum credentials per user
    pub max_credentials_per_user: usize,
    /// Whether to require resident keys by default
    pub require_resident_key: bool,
    /// Whether to allow credential revocation
    pub allow_credential_revocation: bool,
}

impl AttestationConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let policy = match std::env::var("WEBAUTHN_ATTESTATION_POLICY")
            .unwrap_or_else(|_| "none".to_string())
            .to_lowercase()
            .as_str()
        {
            "none" => AttestationPolicy::None,
            "indirect" => AttestationPolicy::Indirect,
            "direct" => AttestationPolicy::Direct,
            "enterprise" => AttestationPolicy::Enterprise,
            other => {
                warn!(
                    "Unknown attestation policy '{}', defaulting to 'none'",
                    other
                );
                AttestationPolicy::None
            }
        };

        let allowed_aaguids = std::env::var("WEBAUTHN_ALLOWED_AAGUIDS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let audit_logging = std::env::var("WEBAUTHN_AUDIT_LOGGING")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true); // Default to true for security

        let max_credentials_per_user = std::env::var("WEBAUTHN_MAX_CREDENTIALS_PER_USER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        let require_resident_key = std::env::var("WEBAUTHN_REQUIRE_RESIDENT_KEY")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let allow_credential_revocation = std::env::var("WEBAUTHN_ALLOW_CREDENTIAL_REVOCATION")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);

        let config = Self {
            policy,
            allowed_aaguids,
            audit_logging,
            max_credentials_per_user,
            require_resident_key,
            allow_credential_revocation,
        };

        info!(
            policy = ?config.policy,
            allowed_aaguids = ?config.allowed_aaguids,
            audit_logging = config.audit_logging,
            max_credentials_per_user = config.max_credentials_per_user,
            "Loaded attestation configuration"
        );

        config
    }

    /// Get global attestation config (lazy loaded)
    pub fn global() -> &'static AttestationConfig {
        static CONFIG: OnceLock<AttestationConfig> = OnceLock::new();
        CONFIG.get_or_init(AttestationConfig::from_env)
    }
}

/// Attestation policy level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationPolicy {
    /// Accept any attestation including none
    None,
    /// Accept self-attestation and anonymized attestation
    Indirect,
    /// Require verifiable attestation from authenticator
    Direct,
    /// Require enterprise attestation (for managed devices)
    Enterprise,
}

impl AttestationPolicy {
    /// Convert to the corresponding string value for webauthn-rs
    pub fn to_string_value(&self) -> &'static str {
        match self {
            AttestationPolicy::None => "none",
            AttestationPolicy::Indirect => "indirect",
            AttestationPolicy::Direct => "direct",
            AttestationPolicy::Enterprise => "enterprise",
        }
    }
}

// --- Attestation Parsing ---

/// Parsed attestation information from a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationInfo {
    /// Attestation format (packed, tpm, android-key, none, etc.)
    pub format: String,
    /// AAGUID (Authenticator Attestation GUID)
    pub aaguid: Option<String>,
    /// Whether attestation is self-signed (no certificate chain)
    pub self_attestation: bool,
    /// Attestation certificate subject (if available)
    pub cert_subject: Option<String>,
    /// Raw attestation object size
    pub attestation_size: usize,
    /// Authenticator data flags
    pub flags: AuthenticatorFlags,
}

/// Authenticator data flags parsed from attestation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthenticatorFlags {
    /// User present flag (UP)
    pub user_present: bool,
    /// User verified flag (UV)
    pub user_verified: bool,
    /// Backup eligible flag (BE)
    pub backup_eligible: bool,
    /// Backup state flag (BS) - credential is currently backed up
    pub backup_state: bool,
    /// Attested credential data present (AT)
    pub attested_credential_data: bool,
    /// Extension data present (ED)
    pub extension_data: bool,
}

impl AuthenticatorFlags {
    /// Parse flags from a byte
    pub fn from_byte(flags: u8) -> Self {
        Self {
            user_present: (flags & 0x01) != 0,
            user_verified: (flags & 0x04) != 0,
            backup_eligible: (flags & 0x08) != 0,
            backup_state: (flags & 0x10) != 0,
            attested_credential_data: (flags & 0x40) != 0,
            extension_data: (flags & 0x80) != 0,
        }
    }
}

/// Parse attestation information from a RegisterPublicKeyCredential
///
/// This extracts the attestation format, AAGUID, and flags from the
/// attestation object by parsing its CBOR structure.
pub fn parse_attestation_info(credential: &RegisterPublicKeyCredential) -> AttestationInfo {
    let attestation_bytes = credential.response.attestation_object.to_vec();
    let attestation_size = attestation_bytes.len();

    // Default values for when parsing fails
    let mut format = "unknown".to_string();
    let mut aaguid: Option<String> = None;
    let mut self_attestation = true;
    let mut cert_subject: Option<String> = None;
    let mut flags = AuthenticatorFlags::default();

    // Parse CBOR attestation object
    // Structure: { "fmt": string, "attStmt": map, "authData": bytes }
    if attestation_size > 37 {
        // Minimum size for CBOR header + authData
        // Try to extract format from the beginning of CBOR
        // The format is typically a short string after the initial map tag

        // Simple CBOR parsing for attestation format
        // Look for common format signatures in the raw bytes
        let data = &attestation_bytes;

        // Check for "packed" format
        if contains_cbor_string(data, "packed") {
            format = "packed".to_string();
            self_attestation = false;
        } else if contains_cbor_string(data, "tpm") {
            format = "tpm".to_string();
            self_attestation = false;
        } else if contains_cbor_string(data, "android-key") {
            format = "android-key".to_string();
            self_attestation = false;
        } else if contains_cbor_string(data, "android-safetynet") {
            format = "android-safetynet".to_string();
            self_attestation = false;
        } else if contains_cbor_string(data, "fido-u2f") {
            format = "fido-u2f".to_string();
            self_attestation = false;
        } else if contains_cbor_string(data, "apple") {
            format = "apple".to_string();
            self_attestation = false;
        } else if contains_cbor_string(data, "none") {
            format = "none".to_string();
            self_attestation = true;
        }

        // Extract authData which follows a known structure
        // authData starts after the CBOR map structure
        // The authData contains: rpIdHash (32) + flags (1) + signCount (4) + attestedCredData
        // attestedCredData contains: aaguid (16) + credIdLen (2) + credId + publicKey

        // Find authData by looking for the "authData" key in CBOR
        if let Some(auth_data_start) = find_auth_data_offset(data) {
            if auth_data_start + 37 <= data.len() {
                // Parse flags (at offset 32)
                flags = AuthenticatorFlags::from_byte(data[auth_data_start + 32]);

                // Parse AAGUID (at offset 37, after rpIdHash + flags + signCount)
                if auth_data_start + 53 <= data.len() && flags.attested_credential_data {
                    let aaguid_bytes = &data[auth_data_start + 37..auth_data_start + 53];
                    aaguid = Some(format_aaguid(aaguid_bytes));
                }
            }
        }

        // Try to extract certificate subject if present
        // Certificates are typically in the attStmt under "x5c" key
        if let Some(subject) = extract_cert_subject(data) {
            cert_subject = Some(subject);
            self_attestation = false;
        }
    }

    AttestationInfo {
        format,
        aaguid,
        self_attestation,
        cert_subject,
        attestation_size,
        flags,
    }
}

/// Check if the CBOR data contains a specific string value
fn contains_cbor_string(data: &[u8], needle: &str) -> bool {
    // CBOR text strings are encoded as: 0x60 + length (for len < 24) or 0x78 + 1-byte length
    let needle_bytes = needle.as_bytes();
    let len = needle_bytes.len();

    // Look for short string encoding (len < 24)
    if len < 24 {
        let header = 0x60 + len as u8;
        for i in 0..data.len().saturating_sub(len + 1) {
            if data[i] == header && &data[i + 1..i + 1 + len] == needle_bytes {
                return true;
            }
        }
    }

    // Look for 1-byte length encoding
    if len < 256 {
        for i in 0..data.len().saturating_sub(len + 2) {
            if data[i] == 0x78 && data[i + 1] == len as u8 && &data[i + 2..i + 2 + len] == needle_bytes {
                return true;
            }
        }
    }

    false
}

/// Find the offset of authData in the CBOR attestation object
fn find_auth_data_offset(data: &[u8]) -> Option<usize> {
    // Look for "authData" string in CBOR (0x68 + "authData" = 8 bytes string)
    let auth_data_key = b"authData";
    let key_len = auth_data_key.len();

    for i in 0..data.len().saturating_sub(key_len + 3) {
        // Check for CBOR string header (0x68 for 8-char string)
        if data[i] == 0x68 && &data[i + 1..i + 1 + key_len] == auth_data_key {
            // The value follows the key - it's a byte string
            let value_start = i + 1 + key_len;
            if value_start < data.len() {
                let header = data[value_start];
                // Check for byte string headers
                if header >= 0x40 && header < 0x58 {
                    // Short byte string (length in header)
                    return Some(value_start + 1);
                } else if header == 0x58 && value_start + 2 < data.len() {
                    // 1-byte length prefix
                    return Some(value_start + 2);
                } else if header == 0x59 && value_start + 3 < data.len() {
                    // 2-byte length prefix
                    return Some(value_start + 3);
                }
            }
        }
    }
    None
}

/// Format AAGUID bytes as a UUID string
fn format_aaguid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return "invalid".to_string();
    }

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Extract certificate subject from attestation statement (simplified)
fn extract_cert_subject(data: &[u8]) -> Option<String> {
    // Look for "x5c" key which indicates a certificate chain
    // This is a simplified check - full parsing would require ASN.1/X.509 parsing
    let x5c_key = b"x5c";
    for i in 0..data.len().saturating_sub(x5c_key.len() + 1) {
        if data[i] == 0x63 && &data[i + 1..i + 1 + x5c_key.len()] == x5c_key {
            // Found x5c key, certificate chain is present
            return Some("Certificate chain present".to_string());
        }
    }
    None
}

// --- Policy Enforcement ---

/// Result of attestation policy check
#[derive(Debug, Clone, Serialize)]
pub struct PolicyCheckResult {
    pub allowed: bool,
    pub reason: String,
    pub attestation_info: AttestationInfo,
}

/// Enforce attestation policy on a credential
///
/// Returns Ok(()) if the credential passes policy, or an error with the rejection reason.
pub fn enforce_policy(
    credential: &RegisterPublicKeyCredential,
    config: &AttestationConfig,
) -> Result<PolicyCheckResult, (StatusCode, String)> {
    let info = parse_attestation_info(credential);

    // Log for audit if enabled
    if config.audit_logging {
        info!(
            format = %info.format,
            aaguid = ?info.aaguid,
            self_attestation = info.self_attestation,
            backup_eligible = info.flags.backup_eligible,
            backup_state = info.flags.backup_state,
            attestation_size = info.attestation_size,
            "Attestation audit log"
        );
    }

    // Check AAGUID allowlist first (if configured)
    if !config.allowed_aaguids.is_empty() {
        match &info.aaguid {
            Some(aaguid) if config.allowed_aaguids.contains(&aaguid.to_lowercase()) => {
                debug!(aaguid = %aaguid, "AAGUID allowed by allowlist");
            }
            Some(aaguid) => {
                warn!(aaguid = %aaguid, "AAGUID not in allowlist");
                return Err((
                    StatusCode::FORBIDDEN,
                    format!(
                        "Authenticator not allowed. AAGUID {} is not in the approved list.",
                        aaguid
                    ),
                ));
            }
            None => {
                // No AAGUID available (self/none attestation)
                // For allowlist mode, this typically means rejection
                warn!("No AAGUID available but allowlist is configured");
                return Err((
                    StatusCode::FORBIDDEN,
                    "Authenticator attestation required but not provided.".to_string(),
                ));
            }
        }
    }

    // Check policy level
    match config.policy {
        AttestationPolicy::None => {
            // Accept everything
            Ok(PolicyCheckResult {
                allowed: true,
                reason: "No attestation policy enforced".to_string(),
                attestation_info: info,
            })
        }
        AttestationPolicy::Indirect => {
            // Accept self-attestation and indirect
            // Reject only if we can verify it's a completely invalid format
            if info.format == "unknown" && info.attestation_size < 100 {
                Err((
                    StatusCode::BAD_REQUEST,
                    "Invalid attestation format".to_string(),
                ))
            } else {
                Ok(PolicyCheckResult {
                    allowed: true,
                    reason: format!("Indirect policy: accepted {} attestation", info.format),
                    attestation_info: info,
                })
            }
        }
        AttestationPolicy::Direct => {
            // Require non-self attestation
            if info.self_attestation && info.format == "none" {
                Err((
                    StatusCode::FORBIDDEN,
                    "Direct attestation required. Self/none attestation not accepted.".to_string(),
                ))
            } else if info.attestation_size < 200 {
                // Heuristic: very small attestation objects are likely "none" format
                warn!(
                    size = info.attestation_size,
                    "Attestation object too small for direct policy"
                );
                Err((
                    StatusCode::FORBIDDEN,
                    "Hardware authenticator with attestation required.".to_string(),
                ))
            } else {
                Ok(PolicyCheckResult {
                    allowed: true,
                    reason: format!("Direct policy: accepted {} attestation", info.format),
                    attestation_info: info,
                })
            }
        }
        AttestationPolicy::Enterprise => {
            // Require attestation with certificate chain
            if info.cert_subject.is_none() {
                Err((
                    StatusCode::FORBIDDEN,
                    "Enterprise attestation with certificate chain required.".to_string(),
                ))
            } else {
                Ok(PolicyCheckResult {
                    allowed: true,
                    reason: format!(
                        "Enterprise policy: accepted {} attestation with certificate",
                        info.format
                    ),
                    attestation_info: info,
                })
            }
        }
    }
}

/// Quick check if policy enforcement is enabled
pub fn is_policy_enabled() -> bool {
    std::env::var("WEBAUTHN_REQUIRE_ATTESTATION")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

// --- Audit Metadata ---

/// Extended registration metadata for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationAuditMetadata {
    pub username: String,
    pub registered_at: i64,
    pub policy: String,
    pub attestation_format: String,
    pub aaguid: Option<String>,
    pub self_attestation: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Store registration audit metadata to Redis
pub async fn store_audit_metadata(
    redis_url: &str,
    cred_id: &[u8],
    metadata: &RegistrationAuditMetadata,
) {
    if let Ok(client) = redis::Client::open(redis_url) {
        if let Ok(mut conn) = client.get_async_connection().await {
            if let Ok(json) = serde_json::to_string(metadata) {
                let key = format!(
                    "webauthn:audit:{}",
                    base64ct::Base64UrlUnpadded::encode_string(cred_id)
                );

                // Store with longer TTL for audit purposes (30 days)
                let _: Result<(), _> = redis::cmd("SET")
                    .arg(&key)
                    .arg(&json)
                    .arg("EX")
                    .arg(30 * 24 * 3600) // 30 days
                    .query_async(&mut conn)
                    .await;

                debug!(key = %key, "Stored registration audit metadata");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_aaguid() {
        let bytes = [
            0xfa, 0x2b, 0x99, 0xdc, 0x9e, 0x39, 0x42, 0x57, 0x8f, 0x92, 0x4a, 0x30, 0xd2, 0x3c,
            0x41, 0x18,
        ];
        let formatted = format_aaguid(&bytes);
        assert_eq!(formatted, "fa2b99dc-9e39-4257-8f92-4a30d23c4118");
    }

    #[test]
    fn test_authenticator_flags() {
        // Test UP + UV + BE flags
        let flags = AuthenticatorFlags::from_byte(0x0D); // 0b00001101
        assert!(flags.user_present);
        assert!(flags.user_verified);
        assert!(flags.backup_eligible);
        assert!(!flags.backup_state);

        // Test all flags set
        let flags = AuthenticatorFlags::from_byte(0xFF);
        assert!(flags.user_present);
        assert!(flags.user_verified);
        assert!(flags.backup_eligible);
        assert!(flags.backup_state);
        assert!(flags.attested_credential_data);
        assert!(flags.extension_data);
    }

    #[test]
    fn test_contains_cbor_string() {
        // CBOR string "packed" = 0x66 + "packed"
        let data = [0xa3, 0x66, b'p', b'a', b'c', b'k', b'e', b'd'];
        assert!(contains_cbor_string(&data, "packed"));
        assert!(!contains_cbor_string(&data, "none"));
    }
}
