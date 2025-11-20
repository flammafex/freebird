// issuer/src/webauthn_ctx.rs
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! WebAuthn context and configuration
//!
//! This module provides a configured WebAuthn instance for the Freebird issuer.
//! Configuration is done via environment variables for production deployments.

use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::info;
use webauthn_rs::prelude::*;

/// WebAuthn context with configuration
pub struct WebAuthnCtx {
    pub webauthn: Webauthn,
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
}

impl WebAuthnCtx {
    /// Create a new WebAuthn context from environment variables
    ///
    /// # Environment Variables
    ///
    /// - `WEBAUTHN_RP_ID`: Relying Party ID (e.g., "example.com")
    /// - `WEBAUTHN_RP_NAME`: Relying Party name (e.g., "Freebird")
    /// - `WEBAUTHN_RP_ORIGIN`: Origin URL (e.g., "https://issuer.example.com")
    ///
    /// # Example
    ///
    /// ```bash
    /// export WEBAUTHN_RP_ID=localhost
    /// export WEBAUTHN_RP_NAME="Freebird Dev"
    /// export WEBAUTHN_RP_ORIGIN=http://localhost:8081
    /// ```
    pub fn from_env() -> Result<Arc<Self>> {
        let rp_id = std::env::var("WEBAUTHN_RP_ID").context("WEBAUTHN_RP_ID not set")?;

        let rp_name = std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Freebird".to_string());

        let rp_origin =
            std::env::var("WEBAUTHN_RP_ORIGIN").context("WEBAUTHN_RP_ORIGIN not set")?;

        Self::new(rp_id, rp_name, rp_origin)
    }

    /// Create a new WebAuthn context with explicit configuration
    pub fn new(rp_id: String, rp_name: String, rp_origin: String) -> Result<Arc<Self>> {
        // Parse origin URL to validate it
        let _origin_url = url::Url::parse(&rp_origin)
            .with_context(|| format!("Invalid WEBAUTHN_RP_ORIGIN: {}", rp_origin))?;

        // Create WebAuthn builder
        let rp_origin_parsed =
            Url::parse(&rp_origin).with_context(|| format!("Invalid origin URL: {}", rp_origin))?;

        let mut builder = WebauthnBuilder::new(&rp_id, &rp_origin_parsed)
            .with_context(|| format!("Failed to create WebAuthn builder for RP ID: {}", rp_id))?;

        // Set RP name
        builder = builder.rp_name(&rp_name);

        // Build WebAuthn instance
        let webauthn = builder
            .build()
            .context("Failed to build WebAuthn instance")?;

        info!(
            rp_id = %rp_id,
            rp_name = %rp_name,
            rp_origin = %rp_origin,
            "Initialized WebAuthn context"
        );

        Ok(Arc::new(Self {
            webauthn,
            rp_id,
            rp_name,
            rp_origin,
        }))
    }

    /// Create a development/test context (localhost)
    ///
    /// Only use this for local development!
    #[cfg(test)]
    pub fn test_context() -> Arc<Self> {
        Self::new(
            "localhost".to_string(),
            "Freebird Test".to_string(),
            "http://localhost:8081".to_string(),
        )
        .expect("Failed to create test WebAuthn context")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_context() {
        let ctx = WebAuthnCtx::test_context();
        assert_eq!(ctx.rp_id, "localhost");
        assert_eq!(ctx.rp_name, "Freebird Test");
        assert_eq!(ctx.rp_origin, "http://localhost:8081");
    }
}
