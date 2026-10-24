//! Text forms shared by the JSON representation of ids and byte blobs.

use std::{fmt, marker::PhantomData, str::FromStr};

use serde::{
    Deserializer,
    de::{Error, Visitor},
};

use crate::newtypes::ParseError;

/// Lowercase hex of the bytes, written without an intermediate string.
pub struct Hex<'a>(pub &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut digits = [0u8; 64];
        for chunk in self.0.chunks(32) {
            let out = chunk
                .len()
                .checked_mul(2)
                .and_then(|len| digits.get_mut(..len))
                .ok_or(fmt::Error)?;
            #[expect(
                clippy::map_err_ignore,
                reason = "fmt::Error carries no detail, so the source has nowhere to go"
            )]
            {
                hex::encode_to_slice(chunk, out).map_err(|_| fmt::Error)?;
                f.write_str(std::str::from_utf8(out).map_err(|_| fmt::Error)?)?;
            }
        }
        Ok(())
    }
}

/// `prefix` followed by lowercase hex of `bytes`.
pub fn write_prefixed(f: &mut fmt::Formatter<'_>, prefix: &str, bytes: &[u8]) -> fmt::Result {
    f.write_str(prefix)?;
    fmt::Display::fmt(&Hex(bytes), f)
}

struct FromStrVisitor<T>(PhantomData<T>);

impl<T: FromStr> Visitor<'_> for FromStrVisitor<T>
where
    T::Err: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: Error>(self, text: &str) -> Result<T, E> {
        text.parse().map_err(E::custom)
    }
}

/// Parses a JSON string with `T::from_str`, borrowing the text from the input.
pub fn deserialize_from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    T::Err: fmt::Display,
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(FromStrVisitor(PhantomData))
}

/// Inverse of [`write_prefixed`] for exactly `N` bytes.
pub fn decode_prefixed<const N: usize>(
    prefix: &'static str,
    text: &str,
) -> Result<[u8; N], ParseError> {
    let digits = text
        .strip_prefix(prefix)
        .ok_or(ParseError::MissingPrefix(prefix))?;
    decode_fixed(digits)
}

/// Lowercase or uppercase hex of exactly `N` bytes.
pub fn decode_fixed<const N: usize>(digits: &str) -> Result<[u8; N], ParseError> {
    let expected = const { N * 2 };
    if digits.len() != expected {
        return Err(ParseError::BadLength {
            expected,
            found: digits.len(),
        });
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(digits, &mut out)?;
    Ok(out)
}
