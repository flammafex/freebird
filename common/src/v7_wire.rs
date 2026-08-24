// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Small canonical wire helpers shared by the native V7 HTTP paths.

use base64ct::{Base64UrlUnpadded, Encoding};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V7WireError(pub &'static str);

impl std::fmt::Display for V7WireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for V7WireError {}

pub fn decode_base64url(value: &str, max: usize) -> Result<Vec<u8>, V7WireError> {
    if value.contains('=') || value.len() > max.div_ceil(3) * 4 {
        return Err(V7WireError("invalid base64url"));
    }
    let bytes =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| V7WireError("invalid base64url"))?;
    if bytes.len() > max || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(V7WireError("non-canonical base64url"));
    }
    Ok(bytes)
}

pub fn parse_operation_id(value: &str) -> Result<[u8; 16], V7WireError> {
    decode_base64url(value, 16)?
        .try_into()
        .map_err(|_| V7WireError("operation id must be 16 bytes"))
}

pub const MAX_ARTIFACT: usize = 16 * 1024;
