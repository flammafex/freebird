//! This experimental adapter provides blind signing and verification for token type `0x0002`.
//!
//! The adapter implements RFC 9578 with RSA-2048 and the `SHA384/PSS/Deterministic` profile
//! from RFC 9474. This profile uses a 48-byte salt.
//! The pinned blind RSA implementation has not been audited for production use or resistance
//! to side-channel attacks.
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, Deterministic, KeyPair,
    PublicKeySha384PSSDeterministic, SecretKeySha384PSSDeterministic, Sha384, Signature, PSS,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidKey,
    InvalidInput,
    Crypto,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Privacy Pass cryptographic error: {self:?}")
    }
}
impl std::error::Error for Error {}

pub struct PublicKey {
    inner: PublicKeySha384PSSDeterministic,
    spki: Vec<u8>,
}

/// This key type omits `Debug` to keep secret key material out of debug output.
pub struct SecretKey(SecretKeySha384PSSDeterministic);

/// Finalization consumes this state, which keeps the blinding secret and token input private.
pub struct BlindState {
    inner: BlindingResult,
    input: [u8; 98],
    key_id: [u8; 32],
}

impl PublicKey {
    fn checked(inner: PublicKeySha384PSSDeterministic) -> Result<Self, Error> {
        let n = inner.components().n();
        if n.len() != 256 || n[0] & 0x80 == 0 {
            return Err(Error::InvalidKey);
        }
        let spki = inner.to_spki().map_err(|_| Error::InvalidKey)?;
        Ok(Self { inner, spki })
    }

    pub fn from_spki(bytes: &[u8]) -> Result<Self, Error> {
        let inner =
            PublicKeySha384PSSDeterministic::from_spki(bytes).map_err(|_| Error::InvalidKey)?;
        let key = Self::checked(inner)?;
        // Compare the input with the canonical encoding to check the PSS parameters and DER
        // lengths and to reject trailing bytes. The upstream parser checks the algorithm OID
        // but does not enforce SHA-384, MGF1 with SHA-384, or the 48-byte salt.
        if key.spki != bytes {
            return Err(Error::InvalidKey);
        }
        Ok(key)
    }

    pub fn to_spki(&self) -> &[u8] {
        &self.spki
    }

    pub fn key_id(&self) -> [u8; 32] {
        Sha256::digest(&self.spki).into()
    }

    pub fn blind(&self, input: &[u8; 98]) -> Result<([u8; 256], BlindState), Error> {
        if input[..2] != [0, 2] {
            return Err(Error::InvalidInput);
        }
        let inner = self
            .inner
            .blind(&mut DefaultRng, input)
            .map_err(|_| Error::Crypto)?;
        let request = inner
            .blind_message
            .0
            .as_slice()
            .try_into()
            .map_err(|_| Error::Crypto)?;
        Ok((
            request,
            BlindState {
                inner,
                input: *input,
                key_id: self.key_id(),
            },
        ))
    }

    pub fn finalize(&self, state: BlindState, response: &[u8; 256]) -> Result<[u8; 256], Error> {
        if state.key_id != self.key_id() {
            return Err(Error::InvalidKey);
        }
        let signature = self
            .inner
            .finalize(
                &BlindSignature(response.to_vec()),
                &state.inner,
                state.input,
            )
            .map_err(|_| Error::Crypto)?;
        signature.0.try_into().map_err(|_| Error::Crypto)
    }

    pub fn verify(&self, input: &[u8; 98], signature: &[u8; 256]) -> Result<(), Error> {
        if input[..2] != [0, 2] {
            return Err(Error::InvalidInput);
        }
        self.inner
            .verify(&Signature(signature.to_vec()), None, input)
            .map_err(|_| Error::Crypto)
    }
}

impl SecretKey {
    pub fn generate() -> Result<Self, Error> {
        let pair = KeyPair::<Sha384, PSS, Deterministic>::generate(&mut DefaultRng, 2048)
            .map_err(|_| Error::Crypto)?;
        Ok(Self(pair.sk))
    }

    /// Import a private key only if its bytes match the canonical PKCS#8 DER encoding.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, Error> {
        let inner =
            SecretKeySha384PSSDeterministic::from_der(bytes).map_err(|_| Error::InvalidKey)?;
        if inner.to_der().map_err(|_| Error::InvalidKey)? != bytes {
            return Err(Error::InvalidKey);
        }
        let key = Self(inner);
        key.public_key()?;
        Ok(key)
    }

    /// Store the exported key bytes securely and erase them after use.
    pub fn to_pkcs8(&self) -> Result<Vec<u8>, Error> {
        self.0.to_der().map_err(|_| Error::Crypto)
    }

    pub fn public_key(&self) -> Result<PublicKey, Error> {
        PublicKey::checked(self.0.public_key().map_err(|_| Error::InvalidKey)?)
    }

    pub fn blind_sign(&self, request: &[u8; 256]) -> Result<[u8; 256], Error> {
        self.0
            .blind_sign(request)
            .map_err(|_| Error::Crypto)?
            .0
            .try_into()
            .map_err(|_| Error::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_pass_rejects_malformed_keys() {
        for len in [0, 1, 18, 70, 71, 256, 342, 801] {
            assert!(PublicKey::from_spki(&vec![0; len]).is_err());
            assert!(SecretKey::from_pkcs8(&vec![0; len]).is_err());
        }
    }
}
