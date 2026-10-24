use std::{fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{FIELD_INPUT_BYTES, serde_base64, text};

/// Why the text form of an id, hash or blob does not parse.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum ParseError {
    /// The type prefix, such as `addr:`, is absent or wrong.
    #[error("missing prefix `{0}`")]
    MissingPrefix(&'static str),
    /// The text or the decoded bytes have the wrong length.
    #[error("expected {expected} characters or bytes, found {found}")]
    BadLength {
        /// Length the type requires.
        expected: usize,
        /// Length of the input.
        found: usize,
    },
    #[error("invalid hex: {0}")]
    BadHex(#[from] hex::FromHexError),
    /// The input is not standard base64 with padding.
    #[error("invalid base64: {0}")]
    BadBase64(#[from] base64::DecodeError),
}

/// A SHA-256 digest. Text form is 64 lowercase hex digits.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// All zero bytes, the `parent` of the genesis block.
    pub const ZERO: Hash32 = Hash32([0; 32]);
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", text::Hex(&self.0))
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&text::Hex(&self.0), f)
    }
}

impl FromStr for Hash32 {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        text::decode_fixed(s).map(Hash32)
    }
}

/// An Ed25519 public key. Text form is `addr:` plus 64 lowercase hex digits.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Prefix of the text form.
    pub const PREFIX: &'static str = "addr:";
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        text::write_prefixed(f, Self::PREFIX, &self.0)
    }
}

impl FromStr for Address {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        text::decode_prefixed(Self::PREFIX, s).map(Address)
    }
}

/// An Ed25519 signature. Text form is base64.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct Signature(pub [u8; 64]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&serde_base64::display(&self.0), f)
    }
}

impl FromStr for Signature {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        serde_base64::decode_fixed(s).map(Signature)
    }
}

/// A 248-bit little-endian integer (byte 0 is least significant) given to a circuit as a
/// public input. Text form is the 62 lowercase hex digits of the bytes in order.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct FieldInput(pub [u8; FIELD_INPUT_BYTES]);

impl fmt::Debug for FieldInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for FieldInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&text::Hex(&self.0), f)
    }
}

impl FromStr for FieldInput {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        text::decode_fixed(s).map(FieldInput)
    }
}

macro_rules! serde_via_text {
    ($($ty:ty),* $(,)?) => {$(
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                text::deserialize_from_str(deserializer)
            }
        }
    )*};
}

serde_via_text!(Hash32, Address, Signature, FieldInput);
