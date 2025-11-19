// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use tracing::{debug, error, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crypto::vendor::voprf_p256::oprf::Server;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IssuerSecret(pub [u8; 32]);

pub struct VoprfCore {
    server: Server,
    ctx: Vec<u8>,
    _sk: IssuerSecret,
    pub pubkey_b64: String,
    pub kid: String,
}

impl VoprfCore {
    pub fn new(sk: [u8; 32], pubkey_b64: String, kid: String, ctx: &[u8]) -> Result<Self> {
        let server = Server::from_secret_key(sk, ctx).map_err(|_| anyhow!("invalid secret key"))?;
        Ok(Self {
            server,
            ctx: ctx.to_vec(),
            _sk: IssuerSecret(sk),
            pubkey_b64,
            kid,
        })
    }

    /// Safe wrapper for VOPRF evaluation with panic protection
    ///
    /// # Panic Safety
    ///
    /// The underlying VOPRF library may panic in rare edge cases:
    /// - Invalid curve points that pass initial validation
    /// - Arithmetic overflow in scalar operations (extremely rare with P-256)
    /// - Malformed proof generation (should never happen with correct implementation)
    ///
    /// We use `catch_unwind` as a last line of defense. This should NEVER trigger
    /// in production with valid inputs, but prevents a single malicious request
    /// from crashing the entire server.
    ///
    /// # Known Issues
    ///
    /// If this function returns "panicked" errors frequently, it indicates:
    /// 1. Bug in the VOPRF implementation (crypto/vendor/voprf_p256/)
    /// 2. Malicious inputs bypassing validation
    /// 3. Memory corruption (very unlikely in safe Rust)
    ///
    /// Monitor logs for "💥 Server::evaluate() panicked" messages and investigate.
    ///
    /// # Arguments
    ///
    /// * `blinded_b64` - Base64url-encoded SEC1 compressed point (33 bytes)
    ///
    /// # Returns
    ///
    /// Base64url-encoded evaluation token (130 bytes: 33 + 33 + 64)
    ///
    /// # Errors
    ///
    /// - Invalid base64 encoding
    /// - Wrong length (must be 33 bytes after decoding)
    /// - Invalid curve point
    /// - VOPRF evaluation failure
    /// - Panic in underlying library (logged and converted to error)
    pub fn evaluate_b64(&self, blinded_b64: &str) -> Result<String> {
        use std::panic;

        debug!("🔍 evaluate_b64 called ({} chars)", blinded_b64.len());

        // Decode the blinded element
        let blinded =
            Base64UrlUnpadded::decode_vec(blinded_b64).context("invalid base64 encoding")?;

        if blinded.len() != 33 {
            error!("❌ invalid blinded_element length: {}", blinded.len());
            return Err(anyhow!(
                "expected 33-byte SEC1-compressed point, got {} bytes",
                blinded.len()
            ));
        }

        // PANIC SAFETY: Catch panics from the underlying VOPRF library
        //
        // This is defensive programming. The VOPRF implementation should handle
        // all error cases gracefully, but we protect the server from crashes.
        //
        // If you see this triggering, it's a bug that needs investigation.
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            debug!("🧮 calling Server::evaluate()");
            self.server.evaluate(&blinded)
        }));

        match result {
            Ok(Ok(token)) => {
                // Sanity check the output size
                // Expected: 33 (A) + 33 (B) + 64 (DLEQ proof) = 130 bytes
                if token.len() != 130 {
                    error!(
                        "❌ token size mismatch: got {} bytes, expected 130",
                        token.len()
                    );
                    return Err(anyhow!(
                        "internal error: token size mismatch (got {}, expected 130)",
                        token.len()
                    ));
                }

                let encoded = Base64UrlUnpadded::encode_string(&token);
                debug!("✅ evaluate_b64 succeeded (encoded len={})", encoded.len());
                Ok(encoded)
            }
            Ok(Err(e)) => {
                error!("❌ Server::evaluate() returned error: {:?}", e);
                Err(anyhow!("VOPRF evaluation failed: {:?}", e))
            }
            Err(panic_info) => {
                // CRITICAL: This should NEVER happen in production
                error!("💥 CRITICAL: Server::evaluate() panicked!");
                error!("Panic info: {:?}", panic_info);
                warn!("This indicates a bug in the VOPRF implementation");
                warn!(
                    "Please report this with the blinded input length: {}",
                    blinded.len()
                );

                Err(anyhow!(
                    "internal error: VOPRF evaluation panicked (this is a bug)"
                ))
            }
        }
    }

    pub fn suite_id(&self) -> &'static str {
        "OPRF(P-256, SHA-256)-verifiable"
    }

    pub fn context(&self) -> &[u8] {
        &self.ctx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voprf_core_creation() {
        let sk = [0x42u8; 32];
        let pubkey = "test_pubkey".to_string();
        let kid = "test_kid".to_string();
        let ctx = b"test_context";

        let result = VoprfCore::new(sk, pubkey.clone(), kid.clone(), ctx);
        assert!(result.is_ok());

        let voprf = result.unwrap();
        assert_eq!(voprf.pubkey_b64, pubkey);
        assert_eq!(voprf.kid, kid);
        assert_eq!(voprf.context(), ctx);
    }

    #[test]
    fn test_evaluate_b64_invalid_length() {
        let sk = [0x42u8; 32];
        let voprf = VoprfCore::new(sk, "pk".into(), "kid".into(), b"ctx").unwrap();

        // Too short
        let result = voprf.evaluate_b64("aGVsbG8"); // "hello" in base64
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("33-byte"));

        // Too long
        let long_input = Base64UrlUnpadded::encode_string(&[0u8; 64]);
        let result = voprf.evaluate_b64(&long_input);
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_b64_invalid_base64() {
        let sk = [0x42u8; 32];
        let voprf = VoprfCore::new(sk, "pk".into(), "kid".into(), b"ctx").unwrap();

        let result = voprf.evaluate_b64("not!!!valid!!!base64");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64"));
    }
}
