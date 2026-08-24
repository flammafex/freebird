// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2025 The Carpocratian Church of Commonality and Equality, Inc.

//! The native amount-bearing V7 public-bearer body.
//!
//! This module is intentionally separate from the legacy V5 bearer types.  The
//! body transcript is the canonical input to the V7 application digest; JSON
//! serialization and V5 framing are not involved.

use blind_rsa_signatures::reexports::rand::rng;
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, MessageRandomizer, PublicKeySha384PSSRandomized, Signature,
};
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;

use crate::Error;

pub const V7_VERSION: u32 = 7;
/// The dispatch byte for a complete native V7 bearer envelope.
pub const V7_ENVELOPE_VERSION: u8 = 0x07;
/// The retired public-bearer dispatch byte.  It is not a V7 compatibility path.
pub const V7_RETIRED_ENVELOPE_VERSION: u8 = 0x05;
/// The reserved even-version dispatch byte.
pub const V7_RESERVED_ENVELOPE_VERSION: u8 = 0x06;
pub const V7_ARTIFACT_TYPE: &str = "scarcity/native-bearer/v7";
pub const V7_TOKEN_KEY_ID_LEN: usize = 32;
pub const V7_NONCE_LEN: usize = 32;
pub const V7_NULLIFIER_LEN: usize = 32;
pub const V7_OWNER_COMMITMENT_LEN: usize = 32;
pub const V7_APPLICATION_MESSAGE_LEN: usize = 48;
pub const V7_MESSAGE_RANDOMIZER_LEN: usize = 32;
pub const V7_SIGNATURE_LEN: usize = 384;
pub const V7_RFC9474_VARIANT: &str = "RSABSSA-SHA384-PSS-Randomized-V7";
pub const V7_NULLIFIER_DOMAIN: &[u8] = b"scarcity native bearer nullifier v7\0";
pub const V7_BLIND_MESSAGE_DOMAIN: &[u8] = b"scarcity native bearer blind message v7\0";
pub const V7_ARTIFACT_DOMAIN: &[u8] = b"scarcity native bearer artifact v7\0";

const MAX_TEXT_LEN: usize = 128;
const BODY_MIN_LEN: usize = 4
    + 4
    + V7_ARTIFACT_TYPE.len()
    + 4
    + 1
    + 8
    + 4
    + 1
    + V7_TOKEN_KEY_ID_LEN
    + V7_NONCE_LEN
    + V7_NULLIFIER_LEN
    + V7_OWNER_COMMITMENT_LEN;
const BODY_MAX_LEN: usize = 4
    + 4
    + V7_ARTIFACT_TYPE.len()
    + 4
    + MAX_TEXT_LEN
    + 8
    + 4
    + MAX_TEXT_LEN
    + V7_TOKEN_KEY_ID_LEN
    + V7_NONCE_LEN
    + V7_NULLIFIER_LEN
    + V7_OWNER_COMMITMENT_LEN;
const V7_ENVELOPE_SUFFIX_LEN: usize = V7_MESSAGE_RANDOMIZER_LEN + V7_SIGNATURE_LEN;
const V7_ENVELOPE_MIN_LEN: usize = 1 + BODY_MIN_LEN + V7_ENVELOPE_SUFFIX_LEN;
const V7_ENVELOPE_MAX_LEN: usize = 1 + BODY_MAX_LEN + V7_ENVELOPE_SUFFIX_LEN;

/// A V7 token key identifier.  Its nominal type prevents accidental reuse of
/// a V5 key identifier in a V7 transcript.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct V7TokenKeyId([u8; V7_TOKEN_KEY_ID_LEN]);

impl V7TokenKeyId {
    pub const fn new(bytes: [u8; V7_TOKEN_KEY_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; V7_TOKEN_KEY_ID_LEN] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; V7_TOKEN_KEY_ID_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        fixed_from_slice(bytes, "V7 token_key_id").map(Self::new)
    }
}

impl From<[u8; V7_TOKEN_KEY_ID_LEN]> for V7TokenKeyId {
    fn from(bytes: [u8; V7_TOKEN_KEY_ID_LEN]) -> Self {
        Self::new(bytes)
    }
}

/// The deployment identity carried by a V7 body and registry binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V7KeyIdentity {
    issuer_id: String,
    token_key_id: V7TokenKeyId,
}

impl V7KeyIdentity {
    /// Construct a V7 issuer/key-id identity.
    pub fn new(issuer_id: impl Into<String>, token_key_id: V7TokenKeyId) -> Result<Self, Error> {
        let issuer_id = issuer_id.into();
        validate_text("issuer_id", &issuer_id)?;
        Ok(Self {
            issuer_id,
            token_key_id,
        })
    }

    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    pub const fn token_key_id(&self) -> &V7TokenKeyId {
        &self.token_key_id
    }
}

/// Exact V7 registry binding for one issuer key.
///
/// The canonical SPKI and its SHA-256 fingerprint are retained together with
/// the deployment identity. Callers cannot construct this type without
/// passing strict V7 RSA-3072 validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V7PublicKeyBinding {
    identity: V7KeyIdentity,
    public_key_spki: Vec<u8>,
    spki_fingerprint: [u8; 32],
}

impl V7PublicKeyBinding {
    /// Construct and strictly validate a V7 binding from SPKI bytes.
    pub fn new(identity: V7KeyIdentity, public_key_spki: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::from_identity_and_spki(identity, public_key_spki.as_ref())
    }

    /// Construct a binding from an identity and V7 SPKI bytes.
    pub fn from_identity_and_spki(
        identity: V7KeyIdentity,
        public_key_spki: &[u8],
    ) -> Result<Self, Error> {
        let canonical = canonical_v7_public_bearer_spki(public_key_spki)?;
        let spki_fingerprint: [u8; 32] = Sha256::digest(&canonical).into();
        Ok(Self {
            identity,
            public_key_spki: canonical,
            spki_fingerprint,
        })
    }

    pub fn identity(&self) -> &V7KeyIdentity {
        &self.identity
    }

    pub fn issuer_id(&self) -> &str {
        self.identity.issuer_id()
    }

    pub const fn token_key_id(&self) -> &V7TokenKeyId {
        self.identity.token_key_id()
    }

    pub fn public_key_spki(&self) -> &[u8] {
        &self.public_key_spki
    }

    pub const fn spki_fingerprint(&self) -> &[u8; 32] {
        &self.spki_fingerprint
    }

    /// Validate a V7 body against this key identity and its fixed body policy.
    ///
    /// The policy is deliberately supplied separately from the public-key
    /// material.  This lets a common layer retain the per-key policy without
    /// making the crypto crate depend on that layer.
    pub fn validate_body_policy(
        &self,
        body: &PublicBearerV7Body,
        policy: &V7BodyPolicy,
    ) -> Result<(), Error> {
        if body.identity() != self.identity() {
            return Err(Error::InvalidInput(
                "V7 body identity does not match key binding".to_string(),
            ));
        }
        policy.validate_body(body)
    }
}

/// The SHA-384 V7 application message supplied to RFC 9474 preparation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct V7ApplicationMessage([u8; V7_APPLICATION_MESSAGE_LEN]);

impl V7ApplicationMessage {
    pub const fn new(bytes: [u8; V7_APPLICATION_MESSAGE_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; V7_APPLICATION_MESSAGE_LEN] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; V7_APPLICATION_MESSAGE_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        fixed_from_slice(bytes, "V7 application message").map(Self::new)
    }
}

/// The serialized 32-byte RFC 9474 V7 preparation randomizer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct V7MessageRandomizer([u8; V7_MESSAGE_RANDOMIZER_LEN]);

impl V7MessageRandomizer {
    pub const fn new(bytes: [u8; V7_MESSAGE_RANDOMIZER_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; V7_MESSAGE_RANDOMIZER_LEN] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; V7_MESSAGE_RANDOMIZER_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        fixed_from_slice(bytes, "V7 message randomizer").map(Self::new)
    }
}

/// A finalized V7 RSA-BSSA signature.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct V7Signature([u8; V7_SIGNATURE_LEN]);

impl V7Signature {
    pub const fn new(bytes: [u8; V7_SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; V7_SIGNATURE_LEN] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; V7_SIGNATURE_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        fixed_from_slice(bytes, "V7 signature").map(Self::new)
    }
}

/// A raw 384-byte V7 blinded RSA message.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct V7BlindMessage([u8; V7_SIGNATURE_LEN]);

impl V7BlindMessage {
    pub const fn new(bytes: [u8; V7_SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; V7_SIGNATURE_LEN] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; V7_SIGNATURE_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        fixed_from_slice(bytes, "V7 blind message").map(Self::new)
    }
}

/// A raw 384-byte V7 blind RSA signature returned by an issuer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct V7BlindSignature([u8; V7_SIGNATURE_LEN]);

impl V7BlindSignature {
    pub const fn new(bytes: [u8; V7_SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; V7_SIGNATURE_LEN] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; V7_SIGNATURE_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        fixed_from_slice(bytes, "V7 blind signature").map(Self::new)
    }
}

/// The canonical V7 bearer body, without the randomizer or signature.
///
/// All fields are private so callers cannot construct a body without passing
/// the string bounds and supplied-nullifier consistency checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicBearerV7Body {
    asset_id: String,
    amount_minor: u64,
    identity: V7KeyIdentity,
    nonce: [u8; V7_NONCE_LEN],
    nullifier: [u8; V7_NULLIFIER_LEN],
    owner_commitment: [u8; V7_OWNER_COMMITMENT_LEN],
}

impl PublicBearerV7Body {
    /// Construct a body from all body fields, checking the supplied nullifier.
    pub fn new(
        asset_id: impl Into<String>,
        amount_minor: u64,
        issuer_id: impl Into<String>,
        token_key_id: V7TokenKeyId,
        nonce: [u8; V7_NONCE_LEN],
        nullifier: [u8; V7_NULLIFIER_LEN],
        owner_commitment: [u8; V7_OWNER_COMMITMENT_LEN],
    ) -> Result<Self, Error> {
        let identity = V7KeyIdentity::new(issuer_id, token_key_id)?;
        Self::new_with_identity(
            asset_id,
            amount_minor,
            identity,
            nonce,
            nullifier,
            owner_commitment,
        )
    }

    /// Construct a body from an explicit issuer/key-id identity.
    pub fn new_with_identity(
        asset_id: impl Into<String>,
        amount_minor: u64,
        identity: V7KeyIdentity,
        nonce: [u8; V7_NONCE_LEN],
        nullifier: [u8; V7_NULLIFIER_LEN],
        owner_commitment: [u8; V7_OWNER_COMMITMENT_LEN],
    ) -> Result<Self, Error> {
        let asset_id = asset_id.into();
        validate_amount_minor(amount_minor)?;
        validate_text("asset_id", &asset_id)?;
        validate_text("issuer_id", identity.issuer_id())?;

        let expected = derive_v7_nullifier(identity.issuer_id(), &nonce, &owner_commitment)?;
        if !bool::from(expected.ct_eq(&nullifier)) {
            return Err(Error::InvalidInput(
                "V7 supplied nullifier does not match body fields".to_string(),
            ));
        }

        Ok(Self {
            asset_id,
            amount_minor,
            identity,
            nonce,
            nullifier,
            owner_commitment,
        })
    }

    /// Revalidate all semantic body invariants before a body is consumed by a
    /// wire, digest, or cryptographic operation.
    pub fn validate(&self) -> Result<(), Error> {
        validate_amount_minor(self.amount_minor)?;
        validate_text("asset_id", &self.asset_id)?;
        validate_text("issuer_id", self.issuer_id())?;

        let expected = derive_v7_nullifier(self.issuer_id(), &self.nonce, &self.owner_commitment)?;
        if !bool::from(expected.ct_eq(&self.nullifier)) {
            return Err(Error::InvalidInput(
                "V7 supplied nullifier does not match body fields".to_string(),
            ));
        }
        Ok(())
    }

    /// Construct a body from a registry binding while retaining only identity.
    pub fn new_with_binding(
        asset_id: impl Into<String>,
        amount_minor: u64,
        binding: &V7PublicKeyBinding,
        nonce: [u8; V7_NONCE_LEN],
        nullifier: [u8; V7_NULLIFIER_LEN],
        owner_commitment: [u8; V7_OWNER_COMMITMENT_LEN],
    ) -> Result<Self, Error> {
        Self::new_with_identity(
            asset_id,
            amount_minor,
            binding.identity.clone(),
            nonce,
            nullifier,
            owner_commitment,
        )
    }

    /// Construct a body while deriving its nullifier from issuer, nonce, and owner.
    pub fn new_derived(
        asset_id: impl Into<String>,
        amount_minor: u64,
        issuer_id: impl Into<String>,
        token_key_id: V7TokenKeyId,
        nonce: [u8; V7_NONCE_LEN],
        owner_commitment: [u8; V7_OWNER_COMMITMENT_LEN],
    ) -> Result<Self, Error> {
        let issuer_id = issuer_id.into();
        let nullifier = derive_v7_nullifier(&issuer_id, &nonce, &owner_commitment)?;
        Self::new(
            asset_id,
            amount_minor,
            issuer_id,
            token_key_id,
            nonce,
            nullifier,
            owner_commitment,
        )
    }

    /// Alias for the explicit, derived-nullifier constructor.
    pub fn try_new_derived(
        asset_id: impl Into<String>,
        amount_minor: u64,
        issuer_id: impl Into<String>,
        token_key_id: V7TokenKeyId,
        nonce: [u8; V7_NONCE_LEN],
        owner_commitment: [u8; V7_OWNER_COMMITMENT_LEN],
    ) -> Result<Self, Error> {
        Self::new_derived(
            asset_id,
            amount_minor,
            issuer_id,
            token_key_id,
            nonce,
            owner_commitment,
        )
    }

    /// Parse exactly one canonical V7 body transcript.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < BODY_MIN_LEN {
            return Err(Error::InvalidInput("V7 body too short".to_string()));
        }
        if bytes.len() > BODY_MAX_LEN {
            return Err(Error::InvalidInput("V7 body too large".to_string()));
        }

        let mut position = 0;
        let version = take_u32be(bytes, &mut position, "V7 version")?;
        if version != V7_VERSION {
            return Err(Error::InvalidInput(
                "unsupported V7 body version".to_string(),
            ));
        }

        let artifact_type = take_lp32(bytes, &mut position, "V7 artifact_type")?;
        if artifact_type != V7_ARTIFACT_TYPE.as_bytes() {
            return Err(Error::InvalidInput("invalid V7 artifact_type".to_string()));
        }

        let asset_id = parse_text(take_lp32(bytes, &mut position, "V7 asset_id")?, "asset_id")?;
        let amount_minor = take_u64be(bytes, &mut position, "V7 amount_minor")?;
        validate_amount_minor(amount_minor)?;
        let issuer_id = parse_text(
            take_lp32(bytes, &mut position, "V7 issuer_id")?,
            "issuer_id",
        )?;
        let token_key_id = V7TokenKeyId::new(take_fixed::<V7_TOKEN_KEY_ID_LEN>(
            bytes,
            &mut position,
            "V7 token_key_id",
        )?);
        let nonce = take_fixed::<V7_NONCE_LEN>(bytes, &mut position, "V7 nonce")?;
        let nullifier = take_fixed::<V7_NULLIFIER_LEN>(bytes, &mut position, "V7 nullifier")?;
        let owner_commitment =
            take_fixed::<V7_OWNER_COMMITMENT_LEN>(bytes, &mut position, "V7 owner_commitment")?;

        if position != bytes.len() {
            return Err(Error::InvalidInput("trailing V7 body bytes".to_string()));
        }

        Self::new(
            asset_id,
            amount_minor,
            issuer_id,
            token_key_id,
            nonce,
            nullifier,
            owner_commitment,
        )
    }

    /// Serialize the body into its canonical binary transcript.
    pub fn body_transcript(&self) -> Vec<u8> {
        let mut transcript = Vec::with_capacity(
            4 + 4
                + V7_ARTIFACT_TYPE.len()
                + 4
                + self.asset_id.len()
                + 8
                + 4
                + self.issuer_id().len()
                + V7_TOKEN_KEY_ID_LEN
                + V7_NONCE_LEN
                + V7_NULLIFIER_LEN
                + V7_OWNER_COMMITMENT_LEN,
        );
        push_u32be(&mut transcript, V7_VERSION);
        push_lp32(&mut transcript, V7_ARTIFACT_TYPE.as_bytes());
        push_lp32(&mut transcript, self.asset_id.as_bytes());
        transcript.extend_from_slice(&self.amount_minor.to_be_bytes());
        push_lp32(&mut transcript, self.issuer_id().as_bytes());
        transcript.extend_from_slice(self.token_key_id().as_bytes());
        transcript.extend_from_slice(&self.nonce);
        transcript.extend_from_slice(&self.nullifier);
        transcript.extend_from_slice(&self.owner_commitment);
        transcript
    }

    /// Alias for [`Self::body_transcript`].
    pub fn transcript(&self) -> Vec<u8> {
        self.body_transcript()
    }

    /// Return the V7 SHA-384 application message for this body.
    pub fn application_message(&self) -> V7ApplicationMessage {
        let mut digest = Sha384::new();
        digest.update(V7_BLIND_MESSAGE_DOMAIN);
        digest.update(self.body_transcript());
        V7ApplicationMessage::new(digest.finalize().into())
    }

    /// Alias naming the SHA-384 output as an application digest.
    pub fn application_digest(&self) -> V7ApplicationMessage {
        self.application_message()
    }

    pub fn asset_id(&self) -> &str {
        &self.asset_id
    }

    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }

    pub fn issuer_id(&self) -> &str {
        self.identity.issuer_id()
    }

    pub const fn token_key_id(&self) -> &V7TokenKeyId {
        self.identity.token_key_id()
    }

    pub const fn identity(&self) -> &V7KeyIdentity {
        &self.identity
    }

    pub const fn nonce(&self) -> &[u8; V7_NONCE_LEN] {
        &self.nonce
    }

    pub const fn nullifier(&self) -> &[u8; V7_NULLIFIER_LEN] {
        &self.nullifier
    }

    pub const fn owner_commitment(&self) -> &[u8; V7_OWNER_COMMITMENT_LEN] {
        &self.owner_commitment
    }

    /// Derive the supplied nullifier for a V7 body.
    pub fn derive_nullifier(
        issuer_id: &str,
        nonce: &[u8; V7_NONCE_LEN],
        owner_commitment: &[u8; V7_OWNER_COMMITMENT_LEN],
    ) -> Result<[u8; V7_NULLIFIER_LEN], Error> {
        derive_v7_nullifier(issuer_id, nonce, owner_commitment)
    }
}

/// Fixed per-key policy for V7 body fields that are not identity material.
///
/// A policy is intentionally independent of the key bytes.  Common can bind
/// one policy to a key registry entry and call
/// [`V7PublicKeyBinding::validate_body_policy`] without introducing a common
/// crate dependency here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V7BodyPolicy {
    asset_id: String,
    amount_minor: u64,
}

impl V7BodyPolicy {
    /// Construct a policy for one nonzero amount of one asset.
    pub fn new(asset_id: impl Into<String>, amount_minor: u64) -> Result<Self, Error> {
        let asset_id = asset_id.into();
        validate_amount_minor(amount_minor)?;
        validate_text("asset_id", &asset_id)?;
        Ok(Self {
            asset_id,
            amount_minor,
        })
    }

    pub fn asset_id(&self) -> &str {
        &self.asset_id
    }

    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }

    /// Validate the body against this policy, including the body's own
    /// semantic invariants.
    pub fn validate_body(&self, body: &PublicBearerV7Body) -> Result<(), Error> {
        body.validate()?;
        if body.asset_id() != self.asset_id {
            return Err(Error::InvalidInput(
                "V7 body asset_id does not match key policy".to_string(),
            ));
        }
        if body.amount_minor() != self.amount_minor {
            return Err(Error::InvalidInput(
                "V7 body amount_minor does not match key policy".to_string(),
            ));
        }
        Ok(())
    }
}

/// A complete, nominal V7 bearer artifact.
///
/// The body remains the canonical V7 body transcript.  The preparation
/// randomizer is retained beside the finalized raw384 signature because
/// randomized RFC 9474 verification cannot be performed without it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeBearerV7Token {
    body: PublicBearerV7Body,
    message_randomizer: V7MessageRandomizer,
    signature: V7Signature,
}

impl NativeBearerV7Token {
    /// Build a nominal complete V7 artifact from its three wire components.
    pub fn build(
        body: PublicBearerV7Body,
        message_randomizer: V7MessageRandomizer,
        signature: V7Signature,
    ) -> Result<Self, Error> {
        body.validate()?;
        Ok(Self::new(body, message_randomizer, signature))
    }

    /// Construct a complete V7 artifact from its nominal components.
    pub const fn new(
        body: PublicBearerV7Body,
        message_randomizer: V7MessageRandomizer,
        signature: V7Signature,
    ) -> Self {
        Self {
            body,
            message_randomizer,
            signature,
        }
    }

    pub const fn body(&self) -> &PublicBearerV7Body {
        &self.body
    }

    pub const fn message_randomizer(&self) -> &V7MessageRandomizer {
        &self.message_randomizer
    }

    pub const fn randomizer(&self) -> &V7MessageRandomizer {
        self.message_randomizer()
    }

    pub const fn signature(&self) -> &V7Signature {
        &self.signature
    }

    /// Serialize exactly one canonical V7 final envelope.
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.body.validate()?;
        let body = self.body.body_transcript();
        let mut output = Vec::with_capacity(1 + body.len() + V7_ENVELOPE_SUFFIX_LEN);
        output.push(V7_ENVELOPE_VERSION);
        output.extend_from_slice(&body);
        output.extend_from_slice(self.message_randomizer.as_bytes());
        output.extend_from_slice(self.signature.as_bytes());
        Ok(output)
    }

    /// Alias for [`Self::serialize`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.serialize()
    }

    /// Parse exactly one complete V7 final envelope.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        parse_native_bearer_v7_token(bytes)
    }

    /// Compute the digest of the authenticated final-envelope presentation.
    ///
    /// This digest authenticates the serialized presentation data. It is not a
    /// spend identity; replay identity is the external issuer/federation
    /// namespace paired with this token body's nullifier.
    pub fn artifact_digest(&self) -> Result<[u8; 32], Error> {
        v7_artifact_digest(self)
    }

    /// Verify this artifact against its bound V7 key and serialized randomizer.
    pub fn verify(&self, binding: &V7PublicKeyBinding, policy: &V7BodyPolicy) -> Result<(), Error> {
        if self.body.identity() != binding.identity() {
            return Err(Error::InvalidInput(
                "V7 body identity does not match key binding".to_string(),
            ));
        }
        binding.validate_body_policy(&self.body, policy)?;
        self.verify_checked(binding)
    }

    fn verify_checked(&self, binding: &V7PublicKeyBinding) -> Result<(), Error> {
        verify_v7(
            binding,
            &self.body,
            &self.signature,
            *self.message_randomizer(),
        )
    }
}

/// Build and serialize one complete V7 final envelope.
pub fn build_native_bearer_v7_token(
    body: &PublicBearerV7Body,
    message_randomizer: V7MessageRandomizer,
    signature: V7Signature,
) -> Result<Vec<u8>, Error> {
    body.validate()?;
    NativeBearerV7Token::new(body.clone(), message_randomizer, signature).serialize()
}

/// Serialize a nominal complete V7 token.
pub fn serialize_native_bearer_v7_token(token: &NativeBearerV7Token) -> Result<Vec<u8>, Error> {
    token.serialize()
}

/// Parse exactly one complete V7 final envelope.
pub fn parse_native_bearer_v7_token(bytes: &[u8]) -> Result<NativeBearerV7Token, Error> {
    let dispatch = bytes
        .first()
        .copied()
        .ok_or_else(|| Error::InvalidInput("V7 envelope is empty".to_string()))?;
    match dispatch {
        V7_ENVELOPE_VERSION => {}
        V7_RETIRED_ENVELOPE_VERSION => {
            return Err(Error::InvalidInput(
                "retired V5 public-bearer envelope".to_string(),
            ));
        }
        V7_RESERVED_ENVELOPE_VERSION => {
            return Err(Error::InvalidInput(
                "reserved V6 public-bearer envelope".to_string(),
            ));
        }
        _ => {
            return Err(Error::InvalidInput(
                "unsupported V7 envelope version".to_string(),
            ))
        }
    }

    if bytes.len() < V7_ENVELOPE_MIN_LEN {
        return Err(Error::InvalidInput("V7 envelope too short".to_string()));
    }
    if bytes.len() > V7_ENVELOPE_MAX_LEN {
        return Err(Error::InvalidInput("V7 envelope too large".to_string()));
    }

    let body_end = bytes.len() - V7_ENVELOPE_SUFFIX_LEN;
    let body = PublicBearerV7Body::parse(&bytes[1..body_end])?;
    let randomizer = V7MessageRandomizer::new(
        bytes[body_end..body_end + V7_MESSAGE_RANDOMIZER_LEN]
            .try_into()
            .map_err(|_| Error::InvalidInput("invalid V7 message randomizer".to_string()))?,
    );
    let signature = V7Signature::new(
        bytes[body_end + V7_MESSAGE_RANDOMIZER_LEN..]
            .try_into()
            .map_err(|_| Error::InvalidInput("invalid V7 signature".to_string()))?,
    );

    Ok(NativeBearerV7Token::new(body, randomizer, signature))
}

/// Compute the canonical SHA-256 digest of the authenticated presentation.
///
/// The digest covers the exact final envelope, including the serialized
/// message randomizer and raw384 signature. It is presentation data only;
/// callers must use `(issuer_or_federation_id, body.nullifier())` for global
/// spend identity.
pub fn v7_artifact_digest(token: &NativeBearerV7Token) -> Result<[u8; 32], Error> {
    let envelope = token.serialize()?;
    let mut digest = Sha256::new();
    digest.update(V7_ARTIFACT_DOMAIN);
    digest.update(envelope);
    Ok(digest.finalize().into())
}

/// Verify a complete V7 artifact using its bound key and serialized randomizer.
pub fn verify_native_bearer_v7_token(
    binding: &V7PublicKeyBinding,
    token: &NativeBearerV7Token,
    policy: &V7BodyPolicy,
) -> Result<(), Error> {
    if token.body.identity() != binding.identity() {
        return Err(Error::InvalidInput(
            "V7 body identity does not match key binding".to_string(),
        ));
    }
    binding.validate_body_policy(token.body(), policy)?;
    token.verify_checked(binding)
}

/// State retained by the V7 client between blinding and local finalization.
pub struct V7BlindState {
    result: BlindingResult,
    application_message: V7ApplicationMessage,
    randomizer: V7MessageRandomizer,
    binding_identity: V7KeyIdentity,
    binding_fingerprint: [u8; 32],
}

impl V7BlindState {
    /// Return the randomizer generated during blinding.
    pub const fn randomizer(&self) -> &V7MessageRandomizer {
        &self.randomizer
    }

    pub const fn binding_fingerprint(&self) -> &[u8; 32] {
        &self.binding_fingerprint
    }

    pub fn binding_identity(&self) -> &V7KeyIdentity {
        &self.binding_identity
    }
}

/// Validate a V7 public key using the exact randomized RSA-3072 profile.
pub fn validate_public_bearer_spki_v7(pubkey_spki: &[u8]) -> Result<(), Error> {
    canonical_v7_public_bearer_spki(pubkey_spki).map(|_| ())
}

fn canonical_v7_public_bearer_spki(pubkey_spki: &[u8]) -> Result<Vec<u8>, Error> {
    let key = PublicKeySha384PSSRandomized::from_spki(pubkey_spki)
        .map_err(|_| Error::InvalidInput("invalid V7 public token key".to_string()))?;
    let modulus = key.components().n();
    let exponent = key.components().e();
    let first_nonzero = exponent
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(exponent.len());
    let exponent = &exponent[first_nonzero..];
    if modulus.len() != V7_SIGNATURE_LEN
        || modulus.first().map_or(true, |byte| byte & 0x80 == 0)
        || exponent != [1, 0, 1]
    {
        return Err(Error::InvalidInput(
            "V7 public token key must be RSA-3072 with high bit set and e=65537".to_string(),
        ));
    }
    let canonical = key
        .to_spki()
        .map_err(|_| Error::InvalidInput("failed to encode V7 public token key".to_string()))?;
    if canonical != pubkey_spki {
        return Err(Error::InvalidInput(
            "V7 public token key SPKI is not canonical".to_string(),
        ));
    }
    Ok(canonical)
}

fn parse_v7_public_key(
    binding: &V7PublicKeyBinding,
) -> Result<PublicKeySha384PSSRandomized, Error> {
    PublicKeySha384PSSRandomized::from_spki(binding.public_key_spki())
        .map_err(|_| Error::InvalidInput("invalid V7 public token key".to_string()))
}

/// Blind a V7 application message using a validated registry binding.
pub fn blind_v7(
    binding: &V7PublicKeyBinding,
    body: &PublicBearerV7Body,
) -> Result<(V7BlindMessage, V7MessageRandomizer, V7BlindState), Error> {
    body.validate()?;
    if body.identity() != binding.identity() {
        return Err(Error::InvalidInput(
            "V7 body identity does not match key binding".to_string(),
        ));
    }
    let key = parse_v7_public_key(binding)?;
    let application_message = body.application_message();
    let mut rng = rng();
    let result = key
        .blind(&mut rng, application_message.as_bytes())
        .map_err(|_| Error::Internal)?;
    if result.blind_message.len() != V7_SIGNATURE_LEN {
        return Err(Error::Internal);
    }
    let randomizer = result
        .msg_randomizer
        .map(|randomizer| V7MessageRandomizer::new(randomizer.0))
        .ok_or_else(|| Error::Internal)?;
    let blind_message = V7BlindMessage::new(
        result
            .blind_message
            .0
            .clone()
            .try_into()
            .map_err(|_| Error::Internal)?,
    );
    Ok((
        blind_message,
        randomizer,
        V7BlindState {
            result,
            application_message,
            randomizer,
            binding_identity: binding.identity().clone(),
            binding_fingerprint: *binding.spki_fingerprint(),
        },
    ))
}

/// Locally finalize a V7 blind signature using the binding retained by the caller.
pub fn finalize_v7(
    binding: &V7PublicKeyBinding,
    state: V7BlindState,
    blind_signature: &V7BlindSignature,
) -> Result<V7Signature, Error> {
    if !bool::from(state.binding_fingerprint.ct_eq(binding.spki_fingerprint())) {
        return Err(Error::Verify);
    }
    if state.binding_identity != *binding.identity() {
        return Err(Error::Verify);
    }
    let key = parse_v7_public_key(binding)?;
    let randomizer = MessageRandomizer(state.randomizer.into_bytes());
    if state.result.msg_randomizer != Some(randomizer) {
        return Err(Error::Verify);
    }
    let signature = key
        .finalize(
            &BlindSignature(blind_signature.as_bytes().to_vec()),
            &state.result,
            state.application_message.as_bytes(),
        )
        .map_err(|_| Error::Verify)?;
    if signature.len() != V7_SIGNATURE_LEN {
        return Err(Error::Verify);
    }
    Ok(V7Signature::new(
        signature.0.try_into().map_err(|_| Error::Verify)?,
    ))
}

/// Verify a V7 signature against a matching body identity and key binding.
pub fn verify_v7(
    binding: &V7PublicKeyBinding,
    body: &PublicBearerV7Body,
    signature: &V7Signature,
    randomizer: V7MessageRandomizer,
) -> Result<(), Error> {
    body.validate()?;
    if body.identity() != binding.identity() {
        return Err(Error::InvalidInput(
            "V7 body identity does not match key binding".to_string(),
        ));
    }
    let key = parse_v7_public_key(binding)?;
    key.verify(
        &Signature(signature.as_bytes().to_vec()),
        Some(MessageRandomizer(randomizer.into_bytes())),
        body.application_message().as_bytes(),
    )
    .map_err(|_| Error::Verify)
}

/// Derive the V7 nullifier from exactly the fields specified by the contract.
pub fn derive_v7_nullifier(
    issuer_id: &str,
    nonce: &[u8; V7_NONCE_LEN],
    owner_commitment: &[u8; V7_OWNER_COMMITMENT_LEN],
) -> Result<[u8; V7_NULLIFIER_LEN], Error> {
    validate_text("issuer_id", issuer_id)?;
    let mut transcript = Vec::with_capacity(
        V7_NULLIFIER_DOMAIN.len() + 4 + issuer_id.len() + V7_NONCE_LEN + V7_OWNER_COMMITMENT_LEN,
    );
    transcript.extend_from_slice(V7_NULLIFIER_DOMAIN);
    transcript.extend_from_slice(&(issuer_id.len() as u32).to_be_bytes());
    transcript.extend_from_slice(issuer_id.as_bytes());
    transcript.extend_from_slice(nonce);
    transcript.extend_from_slice(owner_commitment);
    Ok(Sha256::digest(transcript).into())
}

fn validate_text(name: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > MAX_TEXT_LEN {
        return Err(Error::InvalidInput(format!(
            "V7 {name} must be 1-{MAX_TEXT_LEN} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn validate_amount_minor(amount_minor: u64) -> Result<(), Error> {
    if amount_minor == 0 {
        return Err(Error::InvalidInput(
            "V7 amount_minor must be nonzero".to_string(),
        ));
    }
    Ok(())
}

fn parse_text(bytes: &[u8], name: &str) -> Result<String, Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::InvalidInput(format!("V7 {name} is not UTF-8")))?;
    validate_text(name, text)?;
    Ok(text.to_owned())
}

fn fixed_from_slice<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::InvalidInput(format!("{name} must be exactly {N} bytes")))
}

fn push_u32be(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_lp32(output: &mut Vec<u8>, bytes: &[u8]) {
    push_u32be(output, bytes.len() as u32);
    output.extend_from_slice(bytes);
}

fn take_u32be(bytes: &[u8], position: &mut usize, name: &str) -> Result<u32, Error> {
    let raw = take_fixed::<4>(bytes, position, name)?;
    Ok(u32::from_be_bytes(raw))
}

fn take_u64be(bytes: &[u8], position: &mut usize, name: &str) -> Result<u64, Error> {
    let raw = take_fixed::<8>(bytes, position, name)?;
    Ok(u64::from_be_bytes(raw))
}

fn take_lp32<'a>(bytes: &'a [u8], position: &mut usize, name: &str) -> Result<&'a [u8], Error> {
    let length = take_u32be(bytes, position, name)? as usize;
    let end = position
        .checked_add(length)
        .ok_or_else(|| Error::InvalidInput(format!("invalid {name} length")))?;
    if end > bytes.len() {
        return Err(Error::InvalidInput(format!("truncated {name}")));
    }
    let value = &bytes[*position..end];
    *position = end;
    Ok(value)
}

fn take_fixed<const N: usize>(
    bytes: &[u8],
    position: &mut usize,
    name: &str,
) -> Result<[u8; N], Error> {
    let end = position
        .checked_add(N)
        .ok_or_else(|| Error::InvalidInput(format!("invalid {name} length")))?;
    if end > bytes.len() {
        return Err(Error::InvalidInput(format!("truncated {name}")));
    }
    let value = bytes[*position..end]
        .try_into()
        .map_err(|_| Error::InvalidInput(format!("invalid {name} length")))?;
    *position = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::reexports::{crypto_bigint::BoxedUint, rsa::RsaPrivateKey};
    use blind_rsa_signatures::{
        DefaultRng, KeyPairSha384PSSRandomized, SecretKeySha384PSSRandomized,
    };

    const BODY: &[u8] = b"\x00\x00\x00\x07\x00\x00\x00\x19scarcity/native-bearer/v7\x00\x00\x00\x03USD\x00\x00\x00\x00\x00\x00\x00*\x00\x00\x00\x09issuer:v7\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?Z\xd7\x9f\xe6\x93)\xbf\x92\x7f\xf4\xd4\xfc\xa1Rz\xf7#T\xb4;\xb4\xc4d\xaeY\xab\x0a\xab\x7f\x99\xfe\xba@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";
    const NULLIFIER: [u8; 32] = [
        0x5a, 0xd7, 0x9f, 0xe6, 0x93, 0x29, 0xbf, 0x92, 0x7f, 0xf4, 0xd4, 0xfc, 0xa1, 0x52, 0x7a,
        0xf7, 0x23, 0x54, 0xb4, 0x3b, 0xb4, 0xc4, 0x64, 0xae, 0x59, 0xab, 0x0a, 0xab, 0x7f, 0x99,
        0xfe, 0xba,
    ];
    const APPLICATION_MESSAGE: [u8; 48] = [
        0x80, 0x46, 0x53, 0x56, 0x30, 0x69, 0x7e, 0x78, 0x76, 0x1c, 0xe8, 0x4a, 0xd2, 0xf1, 0x64,
        0x98, 0xe0, 0x04, 0x40, 0xcf, 0x86, 0x22, 0xa2, 0x59, 0xfc, 0x04, 0xf1, 0x50, 0xf8, 0xc9,
        0x70, 0xef, 0xc9, 0x82, 0xf9, 0xb1, 0x91, 0x04, 0x00, 0x4a, 0x94, 0xb5, 0x81, 0x70, 0xe1,
        0x96, 0x30, 0xde,
    ];

    fn fixture() -> PublicBearerV7Body {
        PublicBearerV7Body::new(
            "USD",
            42,
            "issuer:v7",
            V7TokenKeyId::new(core::array::from_fn(|i| i as u8)),
            core::array::from_fn(|i| 32 + i as u8),
            NULLIFIER,
            core::array::from_fn(|i| 64 + i as u8),
        )
        .unwrap()
    }

    #[test]
    fn canonical_body_transcript_and_application_message() {
        let body = fixture();
        assert_eq!(body.body_transcript(), BODY);
        assert_eq!(body.application_message().into_bytes(), APPLICATION_MESSAGE);
        assert_eq!(PublicBearerV7Body::parse(BODY).unwrap(), body);
    }

    #[test]
    fn zero_amount_is_rejected_at_body_construction_and_parsing() {
        let nonce = [1; V7_NONCE_LEN];
        let owner_commitment = [2; V7_OWNER_COMMITMENT_LEN];
        let nullifier = derive_v7_nullifier("issuer:v7", &nonce, &owner_commitment).unwrap();

        assert!(PublicBearerV7Body::new(
            "USD",
            0,
            "issuer:v7",
            V7TokenKeyId::new([3; V7_TOKEN_KEY_ID_LEN]),
            nonce,
            nullifier,
            owner_commitment,
        )
        .is_err());
        assert!(V7BodyPolicy::new("USD", 0).is_err());

        let mut zero_amount = BODY.to_vec();
        let amount_offset = 4 + 4 + V7_ARTIFACT_TYPE.len() + 4 + 3;
        zero_amount[amount_offset..amount_offset + 8].fill(0);
        assert!(PublicBearerV7Body::parse(&zero_amount).is_err());
    }

    #[test]
    fn zero_amount_is_rejected_at_envelope_and_crypto_boundaries() {
        let mut envelope = envelope_fixture().serialize().unwrap();
        let amount_offset = 1 + 4 + 4 + V7_ARTIFACT_TYPE.len() + 4 + 3;
        envelope[amount_offset..amount_offset + 8].fill(0);
        assert!(parse_native_bearer_v7_token(&envelope).is_err());

        let identity = V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([3; 32])).unwrap();
        let nonce = [1; V7_NONCE_LEN];
        let owner_commitment = [2; V7_OWNER_COMMITMENT_LEN];
        let nullifier =
            derive_v7_nullifier(identity.issuer_id(), &nonce, &owner_commitment).unwrap();
        let invalid_body = PublicBearerV7Body {
            asset_id: "USD".to_owned(),
            amount_minor: 0,
            identity: identity.clone(),
            nonce,
            nullifier,
            owner_commitment,
        };
        let (spki, _) = rsa_fixture();
        let binding = V7PublicKeyBinding::from_identity_and_spki(identity, &spki).unwrap();
        assert!(blind_v7(&binding, &invalid_body).is_err());
        assert!(verify_v7(
            &binding,
            &invalid_body,
            &V7Signature::new([0; V7_SIGNATURE_LEN]),
            V7MessageRandomizer::new([0; V7_MESSAGE_RANDOMIZER_LEN]),
        )
        .is_err());
    }

    #[test]
    fn v7_body_policy_is_fixed_to_asset_and_nonzero_amount() {
        let body = fixture();
        let policy = V7BodyPolicy::new("USD", 42).unwrap();
        assert_eq!(policy.asset_id(), "USD");
        assert_eq!(policy.amount_minor(), 42);
        policy.validate_body(&body).unwrap();

        assert!(V7BodyPolicy::new("EUR", 42)
            .unwrap()
            .validate_body(&body)
            .is_err());
        assert!(V7BodyPolicy::new("USD", 43)
            .unwrap()
            .validate_body(&body)
            .is_err());
    }

    fn envelope_fixture() -> NativeBearerV7Token {
        NativeBearerV7Token::new(
            fixture(),
            V7MessageRandomizer::new(core::array::from_fn(|i| 0xa0 + i as u8)),
            V7Signature::new(core::array::from_fn(|i| (i % 256) as u8)),
        )
    }

    #[test]
    fn v7_final_envelope_is_exact_and_round_trips() {
        let token = envelope_fixture();
        let mut expected = vec![V7_ENVELOPE_VERSION];
        expected.extend_from_slice(BODY);
        expected.extend_from_slice(token.message_randomizer().as_bytes());
        expected.extend_from_slice(token.signature().as_bytes());

        let encoded = token.serialize().unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(encoded.len(), 606);
        assert_eq!(parse_native_bearer_v7_token(&encoded).unwrap(), token);
        assert_eq!(NativeBearerV7Token::parse(&encoded).unwrap(), token);
        assert_eq!(serialize_native_bearer_v7_token(&token).unwrap(), encoded);
        assert_eq!(
            build_native_bearer_v7_token(
                token.body(),
                *token.message_randomizer(),
                *token.signature(),
            )
            .unwrap(),
            encoded
        );
    }

    #[test]
    fn v7_final_envelope_rejects_malformed_truncated_and_trailing_bytes() {
        let encoded = envelope_fixture().serialize().unwrap();

        for length in 0..encoded.len() {
            assert!(
                parse_native_bearer_v7_token(&encoded[..length]).is_err(),
                "truncated envelope of length {length} was accepted"
            );
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(parse_native_bearer_v7_token(&trailing).is_err());

        let mut retired = encoded.clone();
        retired[0] = V7_RETIRED_ENVELOPE_VERSION;
        assert!(matches!(
            parse_native_bearer_v7_token(&retired),
            Err(Error::InvalidInput(_))
        ));

        let mut reserved = encoded.clone();
        reserved[0] = V7_RESERVED_ENVELOPE_VERSION;
        assert!(matches!(
            parse_native_bearer_v7_token(&reserved),
            Err(Error::InvalidInput(_))
        ));

        let mut wrong_dispatch = encoded;
        wrong_dispatch[0] = 0x04;
        assert!(parse_native_bearer_v7_token(&wrong_dispatch).is_err());
    }

    #[test]
    fn v7_artifact_digest_fixture_covers_authenticated_presentation() {
        let token = envelope_fixture();
        const DIGEST: [u8; 32] = [
            0x96, 0xf5, 0xc1, 0x3e, 0xee, 0x5b, 0xfa, 0xcd, 0xa4, 0x24, 0x84, 0x5d, 0xe1, 0xd0,
            0x32, 0x45, 0x3e, 0xa6, 0x9c, 0xb4, 0x55, 0x81, 0x37, 0x99, 0xee, 0x27, 0x14, 0x16,
            0x89, 0xc5, 0xea, 0x65,
        ];

        assert_eq!(v7_artifact_digest(&token).unwrap(), DIGEST);
        assert_eq!(token.artifact_digest().unwrap(), DIGEST);
    }

    #[test]
    fn v7_nullifier_fixture() {
        let body = fixture();
        assert_eq!(body.nullifier(), &NULLIFIER);
        assert_eq!(
            derive_v7_nullifier(body.issuer_id(), body.nonce(), body.owner_commitment()).unwrap(),
            NULLIFIER
        );
    }

    #[test]
    fn supplied_nullifier_tampering_is_rejected() {
        let mut nullifier = NULLIFIER;
        nullifier[0] ^= 1;
        assert!(PublicBearerV7Body::new(
            "USD",
            42,
            "issuer:v7",
            V7TokenKeyId::new([0; 32]),
            [1; 32],
            nullifier,
            [2; 32],
        )
        .is_err());

        let mut tampered = BODY.to_vec();
        tampered[4 + 4 + V7_ARTIFACT_TYPE.len() + 4 + 3 + 8 + 4 + 9 + 32 + 32] ^= 1;
        assert!(PublicBearerV7Body::parse(&tampered).is_err());
    }

    #[test]
    fn text_bounds_are_strict() {
        let key = V7TokenKeyId::new([0; 32]);
        let nonce = [1; 32];
        let owner = [2; 32];
        let nullifier = derive_v7_nullifier("issuer", &nonce, &owner).unwrap();
        assert!(PublicBearerV7Body::new("", 42, "issuer", key, nonce, nullifier, owner).is_err());
        assert!(PublicBearerV7Body::new(
            "a".repeat(MAX_TEXT_LEN + 1),
            42,
            "issuer",
            key,
            nonce,
            nullifier,
            owner,
        )
        .is_err());
        assert!(PublicBearerV7Body::new(
            "asset",
            42,
            "i".repeat(MAX_TEXT_LEN + 1),
            key,
            nonce,
            nullifier,
            owner,
        )
        .is_err());
    }

    fn rsa_fixture() -> (Vec<u8>, SecretKeySha384PSSRandomized) {
        let mut rng = DefaultRng;
        let key_pair = KeyPairSha384PSSRandomized::generate(&mut rng, 3072).unwrap();
        let spki = key_pair.pk.to_spki().unwrap();
        (spki, key_pair.sk)
    }

    #[test]
    fn randomized_v7_roundtrip_and_randomizer_required() {
        let (spki, secret_key) = rsa_fixture();
        let body = fixture();
        let binding =
            V7PublicKeyBinding::from_identity_and_spki(body.identity().clone(), &spki).unwrap();
        let (blinded, randomizer, state) = blind_v7(&binding, &body).unwrap();
        assert_eq!(blinded.as_bytes().len(), V7_SIGNATURE_LEN);
        assert_eq!(state.randomizer(), &randomizer);
        assert_eq!(state.binding_identity(), binding.identity());
        assert_eq!(state.binding_fingerprint(), binding.spki_fingerprint());

        let blind_signature =
            V7BlindSignature::from_bytes(&secret_key.blind_sign(blinded.as_bytes()).unwrap().0)
                .unwrap();
        let signature = finalize_v7(&binding, state, &blind_signature).unwrap();
        verify_v7(&binding, &body, &signature, randomizer).unwrap();

        let token = NativeBearerV7Token::new(body.clone(), randomizer, signature);
        let policy = V7BodyPolicy::new("USD", 42).unwrap();
        token.verify(&binding, &policy).unwrap();
        verify_native_bearer_v7_token(&binding, &token, &policy).unwrap();

        assert!(token
            .verify(&binding, &V7BodyPolicy::new("EUR", 42).unwrap())
            .is_err());
        assert!(verify_native_bearer_v7_token(
            &binding,
            &token,
            &V7BodyPolicy::new("USD", 43).unwrap(),
        )
        .is_err());

        let mut wrong_randomizer = randomizer.into_bytes();
        wrong_randomizer[0] ^= 1;
        let corrupted_randomizer = NativeBearerV7Token::new(
            body.clone(),
            V7MessageRandomizer::new(wrong_randomizer),
            signature,
        );
        assert!(corrupted_randomizer.verify(&binding, &policy).is_err());

        let mut wrong_signature = signature.into_bytes();
        wrong_signature[0] ^= 1;
        let corrupted_signature =
            NativeBearerV7Token::new(body, randomizer, V7Signature::new(wrong_signature));
        assert!(corrupted_signature.verify(&binding, &policy).is_err());
    }

    #[test]
    fn v7_provider_trait_is_distinct_from_v5_provider() {
        fn accepts_v7_provider<P: crate::provider::V7BlindRsaProvider>(_: &P) {}

        let identity = V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([0x42; 32])).unwrap();
        let provider =
            crate::provider::software::SoftwareV7BlindRsaProvider::generate(identity).unwrap();
        accepts_v7_provider(&provider);
    }

    #[test]
    fn noncanonical_v7_spki_is_rejected() {
        let (spki, _) = rsa_fixture();
        let mut noncanonical = spki;
        noncanonical[3] = noncanonical[3].wrapping_sub(1);
        assert!(validate_public_bearer_spki_v7(&noncanonical).is_err());
    }

    #[test]
    fn v7_3071_bit_spki_is_rejected() {
        let mut rng = DefaultRng;
        let key_pair = KeyPairSha384PSSRandomized::generate(&mut rng, 3071).unwrap();
        let spki = key_pair.pk.to_spki().unwrap();
        let identity = V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([0x42; 32])).unwrap();

        assert!(V7PublicKeyBinding::new(identity, spki).is_err());
    }

    #[test]
    fn v7_non_65537_exponent_spki_is_rejected() {
        let mut rng = DefaultRng;
        let private_key =
            RsaPrivateKey::new_with_exp(&mut rng, 3072, BoxedUint::from(3u64)).unwrap();
        let spki = PublicKeySha384PSSRandomized::new(private_key.to_public_key())
            .to_spki()
            .unwrap();
        let identity = V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([0x42; 32])).unwrap();

        let error = V7PublicKeyBinding::new(identity, spki).unwrap_err();
        match error {
            Error::InvalidInput(message) => assert!(message.contains("e=65537")),
            other => panic!("unexpected V7 SPKI rejection: {other:?}"),
        }
    }

    #[test]
    fn v7_binding_retains_canonical_spki_and_fingerprint() {
        let (spki, _) = rsa_fixture();
        let identity = V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([0x42; 32])).unwrap();
        let binding = V7PublicKeyBinding::new(identity.clone(), spki.clone()).unwrap();
        let fingerprint: [u8; 32] = Sha256::digest(&spki).into();

        assert_eq!(binding.identity(), &identity);
        assert_eq!(binding.public_key_spki(), spki.as_slice());
        assert_eq!(binding.spki_fingerprint(), &fingerprint);
    }

    #[test]
    fn v7_binding_rejects_noncanonical_spki() {
        let (spki, _) = rsa_fixture();
        let identity = V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([0x42; 32])).unwrap();
        let mut noncanonical = spki;
        noncanonical[3] = noncanonical[3].wrapping_sub(1);
        assert!(V7PublicKeyBinding::new(identity, noncanonical).is_err());
    }

    #[test]
    fn v7_nominal_blind_types_check_slice_lengths() {
        assert!(V7BlindMessage::from_bytes(&[0; V7_SIGNATURE_LEN]).is_ok());
        assert!(V7BlindSignature::from_bytes(&[0; V7_SIGNATURE_LEN]).is_ok());
        assert!(V7BlindMessage::from_bytes(&[0; V7_SIGNATURE_LEN - 1]).is_err());
        assert!(V7BlindSignature::from_bytes(&[0; V7_SIGNATURE_LEN + 1]).is_err());
    }

    #[test]
    fn v7_binding_identity_is_required_before_crypto() {
        let (spki, _) = rsa_fixture();
        let binding = V7PublicKeyBinding::from_identity_and_spki(
            V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([0x42; 32])).unwrap(),
            &spki,
        )
        .unwrap();
        let wrong_identity =
            V7KeyIdentity::new("issuer:other", V7TokenKeyId::new([0x42; 32])).unwrap();
        let nonce = [1; 32];
        let owner = [2; 32];
        let nullifier = derive_v7_nullifier("issuer:other", &nonce, &owner).unwrap();
        let body = PublicBearerV7Body::new_with_identity(
            "USD",
            42,
            wrong_identity,
            nonce,
            nullifier,
            owner,
        )
        .unwrap();
        assert!(blind_v7(&binding, &body).is_err());
        assert!(verify_v7(
            &binding,
            &body,
            &V7Signature::new([0; V7_SIGNATURE_LEN]),
            V7MessageRandomizer::new([0; V7_MESSAGE_RANDOMIZER_LEN]),
        )
        .is_err());
    }

    #[test]
    fn v7_distinct_token_key_id_is_rejected_before_crypto() {
        let (spki, _) = rsa_fixture();
        let binding = V7PublicKeyBinding::from_identity_and_spki(
            V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([0x42; 32])).unwrap(),
            &spki,
        )
        .unwrap();
        let wrong_identity =
            V7KeyIdentity::new("issuer:v7", V7TokenKeyId::new([0x43; 32])).unwrap();
        let nonce = [1; 32];
        let owner = [2; 32];
        let nullifier = derive_v7_nullifier("issuer:v7", &nonce, &owner).unwrap();
        let body = PublicBearerV7Body::new_with_identity(
            "USD",
            42,
            wrong_identity,
            nonce,
            nullifier,
            owner,
        )
        .unwrap();

        assert!(blind_v7(&binding, &body).is_err());
        assert!(verify_v7(
            &binding,
            &body,
            &V7Signature::new([0; V7_SIGNATURE_LEN]),
            V7MessageRandomizer::new([0; V7_MESSAGE_RANDOMIZER_LEN]),
        )
        .is_err());
    }

    #[test]
    fn v7_finalization_rejects_same_spki_with_different_identity() {
        let (spki, secret_key) = rsa_fixture();
        let body = fixture();
        let binding =
            V7PublicKeyBinding::from_identity_and_spki(body.identity().clone(), &spki).unwrap();
        let other_identity = V7KeyIdentity::new("issuer:other", *body.token_key_id()).unwrap();
        let other_binding =
            V7PublicKeyBinding::from_identity_and_spki(other_identity, &spki).unwrap();
        let (blinded, _, state) = blind_v7(&binding, &body).unwrap();
        let blind_signature =
            V7BlindSignature::from_bytes(&secret_key.blind_sign(blinded.as_bytes()).unwrap().0)
                .unwrap();

        assert!(finalize_v7(&other_binding, state, &blind_signature).is_err());
    }
}
