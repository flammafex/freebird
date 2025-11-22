// issuer/src/voprf_core.rs

use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use tracing::{debug, error};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::sync::Arc;

// Ensure IssuerSecret is defined if not imported
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IssuerSecret(pub [u8; 32]);

/// VOPRF core using pluggable crypto provider (software or HSM)
pub struct VoprfCore {
    /// Crypto provider (software or HSM)
    provider: Arc<dyn crypto::provider::CryptoProvider>,

    /// Context (cached from provider)
    ctx: Vec<u8>,

    /// Public key base64 (cached)
    pub pubkey_b64: String,

    /// Key ID (cached)
    pub kid: String,
}

impl VoprfCore {
    /// Create a new VoprfCore with a software crypto provider
    ///
    /// This is the default constructor that uses software-based cryptography.
    /// For HSM support, use `from_provider` instead.
    pub fn new(sk: [u8; 32], pubkey_b64: String, kid: String, ctx: &[u8]) -> Result<Self> {
        // Create software provider
        let provider = crypto::provider::software::SoftwareCryptoProvider::new(
            sk,
            kid.clone(),
            ctx.to_vec(),
        )?;

        Ok(Self {
            provider: Arc::new(provider),
            ctx: ctx.to_vec(),
            pubkey_b64,
            kid,
        })
    }

    /// Create a new VoprfCore from a crypto provider
    ///
    /// This allows using HSM-backed providers or custom implementations.
    pub fn from_provider(provider: Arc<dyn crypto::provider::CryptoProvider>, pubkey_b64: String) -> Result<Self> {
        let kid = provider.key_id().to_string();
        let ctx = provider.context().to_vec();

        Ok(Self {
            provider,
            ctx,
            pubkey_b64,
            kid,
        })
    }

    /// Derive MAC key for a specific epoch
    pub fn derive_mac_key_for_epoch(&self, issuer_id: &str, epoch: u32) -> [u8; 32] {
        // Use async runtime to call async provider method
        let provider = self.provider.clone();
        let issuer_id = issuer_id.to_string();
        let kid = self.kid.clone();

        // Block on async call (we're in a sync context)
        tokio::runtime::Handle::current().block_on(async move {
            provider.derive_mac_key(&issuer_id, &kid, epoch)
                .await
                .expect("MAC key derivation should not fail")
        })
    }

    pub fn evaluate_b64(&self, blinded_b64: &str) -> Result<String> {
        debug!("🔍 evaluate_b64 called ({} chars)", blinded_b64.len());

        // 1. Decode the blinded element
        let blinded = Base64UrlUnpadded::decode_vec(blinded_b64)
            .context("invalid base64 encoding")?;

        // 2. Validate input length (P-256 compressed point = 33 bytes)
        if blinded.len() != 33 {
            error!("❌ invalid blinded_element length: {}", blinded.len());
            return Err(anyhow!(
                "expected 33-byte SEC1-compressed point, got {} bytes",
                blinded.len()
            ));
        }

        // 3. Perform Evaluation using provider
        let provider = self.provider.clone();
        let token = tokio::runtime::Handle::current().block_on(async move {
            provider.voprf_evaluate(&blinded).await
        }).map_err(|e| {
            error!("❌ VOPRF evaluation failed: {:?}", e);
            anyhow!("VOPRF evaluation failed")
        })?;

        // 4. Sanity check the output size
        // Expected: 1 (VERSION) + 33 (A) + 33 (B) + 64 (DLEQ proof) = 131 bytes
        if token.len() != 131 {
            error!(
                "❌ token size mismatch: got {} bytes, expected 131",
                token.len()
            );
            return Err(anyhow!(
                "internal error: token size mismatch (got {}, expected 131)",
                token.len()
            ));
        }

        // 5. Encode and Return
        let encoded = Base64UrlUnpadded::encode_string(&token);
        debug!("✅ evaluate_b64 succeeded (encoded len={})", encoded.len());

        Ok(encoded)
    }

    pub fn suite_id(&self) -> &'static str {
        "OPRF(P-256, SHA-256)-verifiable"
    }

    pub fn context(&self) -> &[u8] {
        &self.ctx
    }
}