use std::fmt;

use ed25519_dalek::Signer;
use rand_core::OsRng;
use thiserror::Error;

use crate::{Address, Signature};

/// Why a signature check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// The 32 address bytes do not decode to an Ed25519 point.
    #[error("address is not a valid Ed25519 public key")]
    InvalidPublicKey,
    /// The signature is malformed or does not match the message and key.
    #[error("signature does not verify")]
    BadSignature,
}

/// An Ed25519 secret key (32-byte seed).
#[derive(Clone)]
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// Draws a fresh key from the operating system's random source.
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut OsRng))
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// The 32-byte seed. It is the secret: never log it.
    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The public key, which is the address.
    pub fn address(&self) -> Address {
        Address(self.0.verifying_key().to_bytes())
    }

    /// Ed25519 signature over `message` as given, with no prefix added.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message).to_bytes())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey({})", self.address())
    }
}

/// Strict Ed25519 verification (RFC 8032, no malleable signatures).
pub fn verify(address: &Address, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
    #[expect(
        clippy::map_err_ignore,
        reason = "ed25519-dalek reports one opaque error for every rejection"
    )]
    let key = ed25519_dalek::VerifyingKey::from_bytes(&address.0)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature.0);
    #[expect(
        clippy::map_err_ignore,
        reason = "ed25519-dalek reports one opaque error for every rejection"
    )]
    let verdict = key
        .verify_strict(message, &signature)
        .map_err(|_| CryptoError::BadSignature);
    verdict
}
