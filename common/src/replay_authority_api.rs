// SPDX-License-Identifier: Apache-2.0 OR MIT
//! V4 replay-authority probe wire types and proof framing.

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const REPLAY_AUTHORITY_VERSION_V1: u8 = 1;
const DOMAIN_REPLAY_AUTHORITY_PROBE_V1: &[u8] = b"freebird v4 replay authority probe v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayAuthorityError(pub &'static str);

impl std::fmt::Display for ReplayAuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ReplayAuthorityError {}

fn decode_32(value: &str, error: &'static str) -> Result<[u8; 32], ReplayAuthorityError> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| ReplayAuthorityError(error))?;
    if bytes.len() != 32 || Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(ReplayAuthorityError(error));
    }
    bytes.try_into().map_err(|_| ReplayAuthorityError(error))
}

pub fn decode_authority_id(value: &str) -> Result<[u8; 32], ReplayAuthorityError> {
    decode_32(value, "invalid authority id")
}

pub fn decode_probe_id(value: &str) -> Result<[u8; 32], ReplayAuthorityError> {
    decode_32(value, "invalid probe id")
}

pub fn decode_proof(value: &str) -> Result<[u8; 32], ReplayAuthorityError> {
    decode_32(value, "invalid replay authority proof")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAuthorityProbeV1 {
    pub version: u8,
    pub authority_id: String,
    pub probe_id: String,
}

impl ReplayAuthorityProbeV1 {
    pub fn authority_id(&self) -> Result<[u8; 32], ReplayAuthorityError> {
        decode_authority_id(&self.authority_id)
    }

    pub fn probe_id(&self) -> Result<[u8; 32], ReplayAuthorityError> {
        decode_probe_id(&self.probe_id)
    }

    pub fn validate(&self) -> Result<(), ReplayAuthorityError> {
        if self.version != REPLAY_AUTHORITY_VERSION_V1 {
            return Err(ReplayAuthorityError("unsupported replay authority version"));
        }
        self.authority_id()?;
        self.probe_id()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAuthorityProofV1 {
    pub version: u8,
    pub authority_id: String,
    pub probe_id: String,
    pub proof: String,
}

impl ReplayAuthorityProofV1 {
    pub fn validate_against(
        &self,
        challenge: &[u8; 32],
        issuer_id: &str,
        expected_authority_id: &str,
        expected_probe_id: &str,
    ) -> Result<(), ReplayAuthorityError> {
        if self.version != REPLAY_AUTHORITY_VERSION_V1 {
            return Err(ReplayAuthorityError("unsupported replay authority version"));
        }
        let authority = decode_authority_id(expected_authority_id)?;
        let probe = decode_probe_id(expected_probe_id)?;
        if decode_authority_id(&self.authority_id)?
            .ct_eq(&authority)
            .unwrap_u8()
            != 1
            || decode_probe_id(&self.probe_id)?.ct_eq(&probe).unwrap_u8() != 1
        {
            return Err(ReplayAuthorityError(
                "replay authority response selector mismatch",
            ));
        }
        let expected = replay_authority_proof_v1(challenge, &authority, &probe, issuer_id)?;
        if decode_proof(&self.proof)?.ct_eq(&expected).unwrap_u8() != 1 {
            return Err(ReplayAuthorityError("replay authority proof mismatch"));
        }
        Ok(())
    }
}

pub fn replay_authority_proof_v1(
    challenge: &[u8; 32],
    authority_id: &[u8; 32],
    probe_id: &[u8; 32],
    issuer_id: &str,
) -> Result<[u8; 32], ReplayAuthorityError> {
    let issuer_len = u32::try_from(issuer_id.len())
        .map_err(|_| ReplayAuthorityError("issuer id is too large"))?;
    let mut transcript =
        Vec::with_capacity(DOMAIN_REPLAY_AUTHORITY_PROBE_V1.len() + 68 + issuer_id.len());
    transcript.extend_from_slice(DOMAIN_REPLAY_AUTHORITY_PROBE_V1);
    transcript.extend_from_slice(authority_id);
    transcript.extend_from_slice(probe_id);
    transcript.extend_from_slice(&issuer_len.to_be_bytes());
    transcript.extend_from_slice(issuer_id.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(challenge)
        .map_err(|_| ReplayAuthorityError("invalid replay authority challenge"))?;
    mac.update(&transcript);
    Ok(mac.finalize().into_bytes().into())
}

pub type ReplayAuthorityProbe = ReplayAuthorityProbeV1;
pub type ReplayAuthorityProof = ReplayAuthorityProofV1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_proof_rejects_selector_tampering() {
        let authority = Base64UrlUnpadded::encode_string(&[1; 32]);
        let probe = Base64UrlUnpadded::encode_string(&[2; 32]);
        let challenge = [3; 32];
        let proof = Base64UrlUnpadded::encode_string(
            &replay_authority_proof_v1(&challenge, &[1; 32], &[2; 32], "issuer").unwrap(),
        );
        let response = ReplayAuthorityProofV1 {
            version: REPLAY_AUTHORITY_VERSION_V1,
            authority_id: authority.clone(),
            probe_id: probe.clone(),
            proof,
        };
        assert!(response
            .validate_against(&challenge, "issuer", &authority, &probe)
            .is_ok());
        assert!(response
            .validate_against(&challenge, "issuer", &probe, &authority)
            .is_err());
    }
}
