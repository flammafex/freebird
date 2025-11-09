// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2024 The Carpocratian Church of Commonality and Equality, Inc.
use anyhow::{anyhow, Context, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use zeroize::{Zeroize, ZeroizeOnDrop};
use tracing::{debug, error};

use crypto::vendor::voprf_p256::oprf::{self, Server};

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

    /// Safe wrapper — never panics
   pub fn evaluate_b64(&self, blinded_b64: &str) -> Result<String> {
    use std::panic;
    use tracing::{debug, error};

    debug!("🔍 evaluate_b64 called ({} chars)", blinded_b64.len());

    // Decode the blinded element
    let blinded = match Base64UrlUnpadded::decode_vec(blinded_b64) {
        Ok(b) => b,
        Err(e) => {
            error!("❌ base64 decode failed: {:?}", e);
            return Err(anyhow!("invalid base64: {:?}", e));
        }
    };

    if blinded.len() != 33 {
        error!("❌ invalid blinded_element length: {}", blinded.len());
        return Err(anyhow!("expected 33-byte SEC1-compressed element"));
    }

    // Safely call evaluate()
    let result = panic::catch_unwind(|| {
        tracing::debug!("🧮 calling Server::evaluate()");
        self.server.evaluate(&blinded)
    });

    match result {
        Ok(Ok(token)) => {
            if token.len() != 130 {
                error!("❌ token size mismatch: got {}", token.len());
                return Err(anyhow!("internal error: token size mismatch"));
            }
            let encoded = Base64UrlUnpadded::encode_string(&token);
            debug!("✅ evaluate_b64 succeeded (encoded len={})", encoded.len());
            Ok(encoded)
        }
        Ok(Err(e)) => {
            error!("❌ Server::evaluate() returned Err: {:?}", e);
            Err(anyhow!("oprf evaluate failed: {:?}", e))
        }
        Err(e) => {
            error!("💥 Server::evaluate() panicked: {:?}", e);
            Err(anyhow!("server.evaluate() panicked"))
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

use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::AppState;

#[derive(Deserialize)]
pub struct IssueRequest {
    #[serde(alias = "blinded")]
    pub blinded_element_b64: String,
    pub proof_type: Option<String>,
    pub proof_payload: Option<String>,
}

#[derive(Serialize)]
pub struct IssueResponse {
    pub issuer_id: String,
    pub suite: String,
    pub kid: String,
    pub pubkey: String,
    pub token: String,
}

/// Adapter used by main.rs (still available for backward compatibility)
pub async fn issue_token(
    voprf: Arc<VoprfCore>,
    req: IssueRequest,
) -> Result<Json<IssueResponse>, (StatusCode, String)> {
    debug!("🌀 issue_token entered");
    let token_b64 = match voprf.evaluate_b64(&req.blinded_element_b64) {
        Ok(t) => t,
        Err(e) => {
            error!("❌ evaluate_b64 failed: {:?}", e);
            return Err((StatusCode::BAD_REQUEST, "invalid blinded_element".into()));
        }
    };

    Ok(Json(IssueResponse {
        issuer_id: "issuer:freebird:v1".to_string(),
        suite: voprf.suite_id().to_string(),
        kid: voprf.kid.clone(),
        pubkey: voprf.pubkey_b64.clone(),
        token: token_b64,
    }))
}
