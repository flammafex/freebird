// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The common operation-status capability contract.
//!
//! Operation identifiers and capabilities are deliberately represented as
//! canonical base64url strings on the wire.  The digest helper takes the
//! decoded values so callers cannot accidentally hash a textual encoding.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const OPERATION_STATUS_V1_VERSION: u8 = 1;
pub const OPERATION_STATUS_CAPABILITY_HEADER: &str = "operation-status-capability";
pub const OPERATION_STATUS_CAPABILITY_HEADER_NAME: &str = OPERATION_STATUS_CAPABILITY_HEADER;
pub const STATUS_CAPABILITY_HEADER: &str = OPERATION_STATUS_CAPABILITY_HEADER;
pub const OPERATION_STATUS_CAPABILITY_DOMAIN: &[u8] = b"freebird operation status capability v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationStatusV1Error(pub &'static str);

impl std::fmt::Display for OperationStatusV1Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for OperationStatusV1Error {}

/// Decode a canonical raw 16-byte value.
pub fn parse_raw16(value: &str) -> Result<[u8; 16], OperationStatusV1Error> {
    parse_exact::<16>(value, "value must be canonical raw16")
}

/// Decode a canonical raw 32-byte value.
pub fn parse_raw32(value: &str) -> Result<[u8; 32], OperationStatusV1Error> {
    parse_exact::<32>(value, "value must be canonical raw32")
}

/// Decode a public lowercase hexadecimal raw32 digest.  This is deliberately
/// separate from [`parse_raw32`], which is the secret base64url header codec.
pub fn parse_hex32(value: &str) -> Result<[u8; 32], OperationStatusV1Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(OperationStatusV1Error(
            "value must be lowercase hexadecimal raw32",
        ));
    }
    hex::decode(value)
        .map_err(|_| OperationStatusV1Error("value must be lowercase hexadecimal raw32"))?
        .try_into()
        .map_err(|_| OperationStatusV1Error("value must be lowercase hexadecimal raw32"))
}

/// Explicit aliases used at operation/status boundaries.
pub fn decode_raw16(value: &str) -> Result<[u8; 16], OperationStatusV1Error> {
    parse_raw16(value)
}

pub fn decode_raw32(value: &str) -> Result<[u8; 32], OperationStatusV1Error> {
    parse_raw32(value)
}

pub fn decode_operation_id(value: &str) -> Result<[u8; 16], OperationStatusV1Error> {
    parse_raw16(value)
}

pub fn decode_status_capability(value: &str) -> Result<[u8; 32], OperationStatusV1Error> {
    parse_raw32(value)
}

pub fn encode_raw16(value: &[u8; 16]) -> String {
    Base64UrlUnpadded::encode_string(value)
}

pub fn encode_raw32(value: &[u8; 32]) -> String {
    Base64UrlUnpadded::encode_string(value)
}

/// Compute the status capability digest from already decoded fixed-width
/// values.  The transcript is domain || LP32(profile) || raw16(operation) ||
/// raw32(capability).
pub fn operation_status_capability_digest_raw(
    profile_id: &str,
    public_operation_id: &[u8; 16],
    capability: &[u8; 32],
) -> [u8; 32] {
    let mut transcript = Vec::with_capacity(profile_id.len() + 4 + 16 + 32);
    transcript.extend_from_slice(&(profile_id.len() as u32).to_be_bytes());
    transcript.extend_from_slice(profile_id.as_bytes());
    transcript.extend_from_slice(public_operation_id);
    transcript.extend_from_slice(capability);
    Sha256::digest([OPERATION_STATUS_CAPABILITY_DOMAIN, transcript.as_slice()].concat()).into()
}

/// Compute the status capability digest from its strict wire encodings.
pub fn operation_status_capability_digest(
    profile_id: &str,
    public_operation_id: &str,
    capability: &str,
) -> Result<[u8; 32], OperationStatusV1Error> {
    let profile_id = ascii_text(profile_id, "invalid status profile")?;
    let operation_id = parse_raw16(public_operation_id)?;
    let capability = parse_raw32(capability)?;
    Ok(operation_status_capability_digest_raw(
        profile_id,
        &operation_id,
        &capability,
    ))
}

pub fn status_capability_digest(
    profile_id: &str,
    public_operation_id: &str,
    capability: &str,
) -> Result<[u8; 32], OperationStatusV1Error> {
    operation_status_capability_digest(profile_id, public_operation_id, capability)
}

pub fn operation_status_capability_digest_hex(
    profile_id: &str,
    public_operation_id: &str,
    capability: &str,
) -> Result<String, OperationStatusV1Error> {
    Ok(hex::encode(operation_status_capability_digest(
        profile_id,
        public_operation_id,
        capability,
    )?))
}

/// Validate a stored/requested digest against the exact capability which was
/// presented by the operation owner.
pub fn validate_status_capability_digest(
    profile_id: &str,
    public_operation_id: &str,
    capability: &str,
    expected_digest: &str,
) -> Result<(), OperationStatusV1Error> {
    let expected = parse_hex32(expected_digest)?;
    let actual = operation_status_capability_digest(profile_id, public_operation_id, capability)?;
    if actual.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(OperationStatusV1Error("status capability digest mismatch"));
    }
    Ok(())
}

fn parse_exact<const N: usize>(
    value: &str,
    error: &'static str,
) -> Result<[u8; N], OperationStatusV1Error> {
    if value.contains('=') {
        return Err(OperationStatusV1Error(error));
    }
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| OperationStatusV1Error(error))?;
    if bytes.len() != N || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(OperationStatusV1Error(error));
    }
    bytes.try_into().map_err(|_| OperationStatusV1Error(error))
}

fn ascii_text<'a>(value: &'a str, error: &'static str) -> Result<&'a str, OperationStatusV1Error> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(OperationStatusV1Error(error));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw16_and_raw32_are_strict() {
        let raw16 = [7; 16];
        let raw32 = [8; 32];
        assert_eq!(parse_raw16(&encode_raw16(&raw16)).unwrap(), raw16);
        assert_eq!(parse_raw32(&encode_raw32(&raw32)).unwrap(), raw32);
        assert!(parse_raw16(&encode_raw16(&raw16).replace('A', "a")).is_ok());
        assert!(parse_raw16("AAAAAAAAAAAAAAAAAAAAAA==").is_err());
        assert!(parse_raw16(&encode_raw32(&raw32)).is_err());
        assert!(parse_raw32(&format!("{}=", encode_raw32(&raw32))).is_err());
    }

    #[test]
    fn capability_digest_binds_profile_operation_and_raw_capability() {
        let operation = encode_raw16(&[1; 16]);
        let capability = encode_raw32(&[2; 32]);
        let digest =
            operation_status_capability_digest("freebird/test/v1", &operation, &capability)
                .unwrap();
        assert_ne!(digest, [0; 32]);
        assert_ne!(
            digest,
            operation_status_capability_digest("freebird/other/v1", &operation, &capability)
                .unwrap()
        );
        assert_ne!(
            digest,
            operation_status_capability_digest(
                "freebird/test/v1",
                &encode_raw16(&[3; 16]),
                &capability
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            operation_status_capability_digest(
                "freebird/test/v1",
                &operation,
                &encode_raw32(&[3; 32])
            )
            .unwrap()
        );
    }

    #[test]
    fn capability_validation_rejects_noncanonical_and_tampered_values() {
        let operation = encode_raw16(&[1; 16]);
        let capability = encode_raw32(&[2; 32]);
        let digest =
            operation_status_capability_digest("freebird/test/v1", &operation, &capability)
                .unwrap();
        let digest_text = hex::encode(digest);
        assert!(validate_status_capability_digest(
            "freebird/test/v1",
            &operation,
            &capability,
            &digest_text
        )
        .is_ok());
        assert!(validate_status_capability_digest(
            "freebird/test/v1",
            &operation,
            &capability,
            &hex::encode([0; 32])
        )
        .is_err());
        assert!(operation_status_capability_digest(
            "freebird/test/v1",
            &format!("{}=", operation),
            &capability
        )
        .is_err());
    }

    #[test]
    fn public_digest_is_lowercase_hex_but_header_is_base64url() {
        let operation = encode_raw16(&[1; 16]);
        let capability = encode_raw32(&[2; 32]);
        let digest =
            operation_status_capability_digest_hex("freebird/test/v1", &operation, &capability)
                .unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert_eq!(parse_raw32(&capability).unwrap(), [2; 32]);
        assert!(parse_hex32(&format!("{}A", &digest[..63])).is_err());
        assert_eq!(
            digest,
            "f1a07a7d7ca9de6f427a009410941fa04f85207bc4ecb799018cdf55df8428d6"
        );
    }
}
