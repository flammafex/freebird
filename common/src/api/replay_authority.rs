// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Dedicated V4 replay-authority discovery metadata.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const V4_REPLAY_AUTHORITY_MAX_TOMBSTONES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V4ReplayAuthorityDiscovery {
    pub issuer_id: String,
    pub authority_id: String,
    pub v4_scope_digest_tombstones: Vec<String>,
}

impl V4ReplayAuthorityDiscovery {
    pub fn validate(&self) -> Result<(), String> {
        if self.issuer_id.is_empty() || self.issuer_id.len() > 128 || !self.issuer_id.is_ascii() {
            return Err("invalid replay-authority issuer id".into());
        }
        decode_canonical_32(&self.authority_id, "authority id")?;
        if self.v4_scope_digest_tombstones.len() > V4_REPLAY_AUTHORITY_MAX_TOMBSTONES {
            return Err("too many replay-authority tombstones".into());
        }
        let mut seen = HashSet::new();
        for tombstone in &self.v4_scope_digest_tombstones {
            decode_canonical_32(tombstone, "V4 scope tombstone")?;
            if !seen.insert(tombstone) {
                return Err("duplicate replay-authority tombstone".into());
            }
        }
        Ok(())
    }
}

pub fn decode_canonical_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.contains('=') {
        return Err(format!("{label} is padded"));
    }
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| format!("invalid {label}"))?;
    if bytes.len() != 32 || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(format!("invalid {label}"));
    }
    bytes.try_into().map_err(|_| format!("invalid {label}"))
}
