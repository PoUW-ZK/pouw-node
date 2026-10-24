//! `#[serde(with = "...")]` adapter that writes byte blobs as base64 strings.

use std::fmt;

use base64::{Engine, display::Base64Display, engine::general_purpose::STANDARD};
use serde::{
    Deserializer, Serializer,
    de::{Error, Visitor},
};

/// Writes `bytes` as a standard base64 string.
pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&display(bytes))
}

/// The standard base64 text of `bytes`, written without an intermediate string.
pub fn display(bytes: &[u8]) -> Base64Display<'_, 'static, base64::engine::GeneralPurpose> {
    Base64Display::new(bytes, &STANDARD)
}

struct BlobVisitor;

impl Visitor<'_> for BlobVisitor {
    type Value = Box<[u8]>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a base64 string")
    }

    fn visit_str<E: Error>(self, text: &str) -> Result<Self::Value, E> {
        STANDARD
            .decode(text)
            .map(Vec::into_boxed_slice)
            .map_err(E::custom)
    }
}

/// Reads a standard base64 string into bytes.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Box<[u8]>, D::Error> {
    deserializer.deserialize_str(BlobVisitor)
}

/// Standard base64 with padding, the text form of [`crate::Signature`].
pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes base64 into exactly `N` bytes.
pub fn decode_fixed<const N: usize>(text: &str) -> Result<[u8; N], crate::ParseError> {
    let bytes = STANDARD.decode(text)?;
    let found = bytes.len();
    #[expect(
        clippy::map_err_ignore,
        reason = "the error hands back the rejected bytes, their length is `found`"
    )]
    let fixed = bytes
        .try_into()
        .map_err(|_| crate::ParseError::BadLength { expected: N, found });
    fixed
}
