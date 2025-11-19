// issuer/src/voprf_core.rs

use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use tracing::{debug, error};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crypto::vendor::voprf_p256::oprf::Server;

// Ensure IssuerSecret is defined if not imported
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
        // Initialize the server with the secret key and context
        let server = Server::from_secret_key(sk, ctx)
            .map_err(|_| anyhow!("invalid secret key"))?;

        Ok(Self {
            server,
            ctx: ctx.to_vec(),
            _sk: IssuerSecret(sk),
            pubkey_b64,
            kid,
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

        // 3. Perform Evaluation (No panic catching needed)
        // We map the internal crypto error to a generic anyhow error to avoid leaking details.
        let token = self.server.evaluate(&blinded)
            .map_err(|e| {
                error!("❌ VOPRF evaluation failed: {:?}", e);
                anyhow!("VOPRF evaluation failed")
            })?;

        // 4. Sanity check the output size
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