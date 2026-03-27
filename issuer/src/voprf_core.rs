// issuer/src/voprf_core.rs

use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::sync::Arc;
use tracing::{debug, error};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Ensure IssuerSecret is defined if not imported
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IssuerSecret(pub [u8; 32]);

/// VOPRF core using pluggable crypto provider (software or HSM)
pub struct VoprfCore {
    /// Crypto provider (software or HSM)
    provider: Arc<dyn freebird_crypto::provider::CryptoProvider>,

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
        let provider = freebird_crypto::provider::software::SoftwareCryptoProvider::new(
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
    pub fn from_provider(
        provider: Arc<dyn freebird_crypto::provider::CryptoProvider>,
        pubkey_b64: String,
    ) -> Result<Self> {
        let kid = provider.key_id().to_string();
        let ctx = provider.context().to_vec();

        Ok(Self {
            provider,
            ctx,
            pubkey_b64,
            kid,
        })
    }

    /// Sign token metadata using ECDSA (for federation support)
    pub async fn sign_token_metadata(
        &self,
        kid: &str,
        exp: i64,
        issuer_id: &str,
    ) -> Result<[u8; 64]> {
        self.provider
            .sign_token_metadata(kid, exp, issuer_id)
            .await
    }

    pub async fn evaluate_b64(&self, blinded_b64: &str) -> Result<String> {
        debug!("🔍 evaluate_b64 called ({} chars)", blinded_b64.len());

        // 1. Decode the blinded element
        let blinded =
            Base64UrlUnpadded::decode_vec(blinded_b64).context("invalid base64 encoding")?;

        // 2. Validate input length (P-256 compressed point = 33 bytes)
        if blinded.len() != 33 {
            error!("❌ invalid blinded_element length: {}", blinded.len());
            return Err(anyhow!(
                "expected 33-byte SEC1-compressed point, got {} bytes",
                blinded.len()
            ));
        }

        // 3. Perform Evaluation using provider
        let token = self.provider.voprf_evaluate(&blinded).await.map_err(|e| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};

    fn make_core() -> VoprfCore {
        let sk = [1u8; 32];
        let ctx = b"freebird:v1";
        let server = freebird_crypto::Server::from_secret_key(sk, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();
        let pubkey_b64 = Base64UrlUnpadded::encode_string(&pk);
        let kid = "test-kid-001".to_string();
        VoprfCore::new(sk, pubkey_b64, kid, ctx).unwrap()
    }

    #[test]
    fn test_new_creates_valid_core() {
        let core = make_core();
        assert_eq!(core.kid, "test-kid-001");
        assert!(!core.pubkey_b64.is_empty());
    }

    #[test]
    fn test_new_zero_key_fails() {
        let sk = [0u8; 32];
        let ctx = b"freebird:v1";
        let pubkey_b64 = "dummy".to_string();
        let kid = "kid".to_string();
        let result = VoprfCore::new(sk, pubkey_b64, kid, ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_suite_id() {
        let core = make_core();
        assert_eq!(core.suite_id(), "OPRF(P-256, SHA-256)-verifiable");
    }

    #[test]
    fn test_context_roundtrip() {
        let core = make_core();
        assert_eq!(core.context(), b"freebird:v1");
    }

    #[tokio::test]
    async fn test_evaluate_b64_valid() {
        let sk = [1u8; 32];
        let ctx = b"freebird:v1";
        let server = freebird_crypto::Server::from_secret_key(sk, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();
        let pubkey_b64 = Base64UrlUnpadded::encode_string(&pk);
        let kid = "test-kid-001".to_string();
        let core = VoprfCore::new(sk, pubkey_b64, kid, ctx).unwrap();

        let mut client = freebird_crypto::Client::new(ctx);
        let (blinded_b64, _state) = client.blind(b"test input").unwrap();

        let result = core.evaluate_b64(&blinded_b64).await;
        assert!(result.is_ok(), "evaluate_b64 failed: {:?}", result.err());
        let eval_b64 = result.unwrap();
        assert!(!eval_b64.is_empty());
        let decoded = Base64UrlUnpadded::decode_vec(&eval_b64).unwrap();
        assert_eq!(decoded.len(), 131);
    }

    #[tokio::test]
    async fn test_evaluate_b64_invalid_base64() {
        let core = make_core();
        let result = core.evaluate_b64("not!valid!base64!!").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_evaluate_b64_wrong_size() {
        let core = make_core();
        let bad_input = Base64UrlUnpadded::encode_string(&[0xAAu8; 10]);
        let result = core.evaluate_b64(&bad_input).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sign_token_metadata_returns_64_bytes() {
        let core = make_core();
        let sig = core
            .sign_token_metadata("test-kid-001", 1700000000, "test-issuer")
            .await
            .unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test]
    async fn test_sign_token_metadata_verifiable() {
        let sk = [1u8; 32];
        let ctx = b"freebird:v1";
        let server = freebird_crypto::Server::from_secret_key(sk, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();
        let pubkey_b64 = Base64UrlUnpadded::encode_string(&pk);
        let kid = "test-kid-001".to_string();
        let core = VoprfCore::new(sk, pubkey_b64, kid, ctx).unwrap();

        let kid = "test-kid-001";
        let exp = 1700000000i64;
        let issuer_id = "test-issuer";

        let sig = core.sign_token_metadata(kid, exp, issuer_id).await.unwrap();
        let valid = freebird_crypto::verify_token_signature(&pk, &sig, kid, exp, issuer_id);
        assert!(valid, "signature should verify against issuer public key");
    }
}
