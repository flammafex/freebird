// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//./crypto/src/libs.rs
//! crypto: real VOPRF(P-256, SHA-256)-verifiable façade (no mocks).
//! - Binary wire = raw bytes, encoded for JSON as base64url (no padding).
//! - Opaque token format (from vendor): A(33) || B(33) || proof(c||s, 64) = 130 bytes.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

pub mod vendor;
use vendor::voprf_p256 as v;

#[derive(Debug)]
pub enum Error {
    Decode,
    Verify,
    Internal,
}

pub struct Client(v::Client);
pub struct Server(v::Server);
pub struct Verifier(v::Verifier);

pub struct BlindState {
    inner: v::BlindState,
}

/// Deterministic nullifier seed for anti-double-spend.
pub fn nullifier_key(issuer_id: &str, token_output_b64: &str) -> String {
    let mut h = Sha256::new();
    h.update(issuer_id.as_bytes());
    h.update(token_output_b64.as_bytes());
    Base64UrlUnpadded::encode_string(&h.finalize())
}

impl Client {
    pub fn new(ctx: &[u8]) -> Self {
        Self(v::Client::new(ctx))
    }

    /// Blind caller-provided input bytes. Returns (blinded_b64, state).
    pub fn blind(&mut self, input: &[u8]) -> Result<(String, BlindState), Error> {
        let (blinded_raw, st) = self.0.blind(input).map_err(|_| Error::Internal)?;
        Ok((
            Base64UrlUnpadded::encode_string(&blinded_raw),
            BlindState { inner: st },
        ))
    }

    /// Finalize with issuer evaluation token (base64url) and issuer pubkey (SEC1 compressed).
    /// Returns (token_b64, token_output_b64).
    pub fn finalize(
        self,
        state: BlindState,
        evaluation_b64: &str,
        issuer_pubkey_sec1_compressed: &[u8],
    ) -> Result<(String, String), Error> {
        let eval_raw =
            Base64UrlUnpadded::decode_vec(evaluation_b64).map_err(|_| Error::Decode)?;
        let (token_raw, out_raw) = self
            .0
            .finalize(state.inner, &eval_raw, issuer_pubkey_sec1_compressed)
            .map_err(|_| Error::Verify)?;
        Ok((
            Base64UrlUnpadded::encode_string(&token_raw),
            Base64UrlUnpadded::encode_string(&out_raw),
        ))
    }
}

impl Server {
    pub fn from_secret_key(sk_bytes: [u8; 32], ctx: &[u8]) -> Result<Self, Error> {
        v::Server::from_secret_key(sk_bytes, ctx)
            .map(Self)
            .map_err(|_| Error::Internal)
    }

    pub fn public_key_sec1_compressed(&self) -> [u8; 33] {
        self.0.public_key_sec1_compressed()
    }

    /// Evaluate a single blinded element (base64url), return evaluation/token bytes (base64url).
    pub fn evaluate_with_proof(&self, blinded_b64: &str) -> Result<String, Error> {
        let blinded_raw =
            Base64UrlUnpadded::decode_vec(blinded_b64).map_err(|_| Error::Decode)?;
        let eval_raw = self.0.evaluate(&blinded_raw).map_err(|_| Error::Internal)?;
        Ok(Base64UrlUnpadded::encode_string(&eval_raw))
    }
}

impl Verifier {
    pub fn new(ctx: &[u8]) -> Self {
        Self(v::Verifier::new(ctx))
    }

    /// Verify opaque token locally and derive token_output used for nullifier.
    pub fn verify(
        &self,
        token_b64: &str,
        issuer_pubkey_sec1_compressed: &[u8],
    ) -> Result<String, Error> {
        let tok_raw = Base64UrlUnpadded::decode_vec(token_b64).map_err(|_| Error::Decode)?;
        let out_raw = self
            .0
            .verify(&tok_raw, issuer_pubkey_sec1_compressed)
            .map_err(|_| Error::Verify)?;
        Ok(Base64UrlUnpadded::encode_string(&out_raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end() {
        let ctx = b"presence-v1";
        let sk = [7u8; 32];

        let server = Server::from_secret_key(sk, ctx).unwrap();
        let pk = server.public_key_sec1_compressed();

        // client blinds input
        let mut client = Client::new(ctx);
        let (blinded_b64, st) = client.blind(b"hello world").unwrap();

        // server evaluates
        let eval_b64 = server.evaluate_with_proof(&blinded_b64).unwrap();

        // client finalizes
        let (token_b64, out_cli_b64) = client.finalize(st, &eval_b64, &pk).unwrap();

        // verifier derives same output
        let verifier = Verifier::new(ctx);
        let out_ver_b64 = verifier.verify(&token_b64, &pk).unwrap();

        assert_eq!(out_cli_b64, out_ver_b64);

        // nullifier determinism
        let n1 = nullifier_key("issuer:presence:v1", &out_ver_b64);
        let n2 = nullifier_key("issuer:presence:v1", &out_ver_b64);
        assert_eq!(n1, n2);
        assert!(!n1.is_empty());
    }
}
