//! Cryptographic primitives of the PoUW-ZK node: SHA-256 hashing, the fixed-size
//! byte newtypes that appear on the wire, and Ed25519 signatures.
//! Every other crate takes hashes, addresses and signatures from here. The protocol
//! constants that use these primitives (domain prefixes, limits) are in
//! `pouw_types::protocol`.

#![forbid(unsafe_code)]

mod keys;
mod newtypes;
pub mod serde_base64;
pub mod text;

pub use keys::{CryptoError, SigningKey, verify};
pub use newtypes::{Address, FieldInput, Hash32, ParseError, Signature};

use sha2::{Digest, Sha256};

/// Number of bytes in a [`FieldInput`].
pub const FIELD_INPUT_BYTES: usize = 31;

/// SHA-256 over the concatenation of `parts`.
pub fn sha256(parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    Hash32(hasher.finalize().into())
}

/// SHA-256 of whatever is written to it, so a value is hashed without first being
/// collected into a buffer.
#[derive(Default)]
pub struct Sha256Writer(Sha256);

impl Sha256Writer {
    /// The digest of everything written so far.
    pub fn finish(self) -> Hash32 {
        Hash32(self.0.finalize().into())
    }
}

impl std::io::Write for Sha256Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Keeps bytes 0..31 of the digest verbatim and drops byte 31.
pub fn hash_to_field(hash: &Hash32) -> FieldInput {
    let mut out = [0u8; FIELD_INPUT_BYTES];
    out.copy_from_slice(&hash.0[..FIELD_INPUT_BYTES]);
    FieldInput(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_abc_matches_rfc_vector() {
        let digest = sha256(&[b"abc"]);
        assert_eq!(
            hex::encode(digest.0),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_concatenates_parts() {
        assert_eq!(sha256(&[b"a", b"bc"]), sha256(&[b"abc"]));
    }

    #[test]
    fn hash_to_field_takes_bytes_0_to_31() {
        let mut bytes = [0u8; 32];
        for (b, value) in bytes.iter_mut().zip(1u8..) {
            *b = value;
        }
        let field = hash_to_field(&Hash32(bytes));
        assert_eq!(field.0[..], bytes[..31]);
        assert_eq!(field.0[30], 31);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = SigningKey::generate();
        let signature = key.sign(b"message");
        assert_eq!(verify(&key.address(), b"message", &signature), Ok(()));
    }

    #[test]
    fn tampered_message_fails() {
        let key = SigningKey::generate();
        let signature = key.sign(b"message");
        assert_eq!(
            verify(&key.address(), b"messagE", &signature),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let signature = SigningKey::from_seed([1; 32]).sign(b"m");
        let other = SigningKey::from_seed([2; 32]).address();
        assert_eq!(
            verify(&other, b"m", &signature),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn json_forms() {
        let hash = Hash32([0xab; 32]);
        assert_eq!(
            serde_json::to_string(&hash).unwrap(),
            format!("\"{}\"", "ab".repeat(32))
        );
        let address = Address([0x11; 32]);
        let json = serde_json::to_string(&address).unwrap();
        assert_eq!(json, format!("\"addr:{}\"", "11".repeat(32)));
        assert_eq!(serde_json::from_str::<Address>(&json).unwrap(), address);
        let mut bytes = [0u8; 31];
        bytes[0] = 0x01;
        bytes[30] = 0xff;
        let json = serde_json::to_string(&FieldInput(bytes)).unwrap();
        assert_eq!(json, format!("\"01{}ff\"", "00".repeat(29)));
        assert_eq!(
            serde_json::from_str::<FieldInput>(&json).unwrap(),
            FieldInput(bytes)
        );
        let signature = Signature([7; 64]);
        let json = serde_json::to_string(&signature).unwrap();
        assert_eq!(serde_json::from_str::<Signature>(&json).unwrap(), signature);
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let text = format!("tx:{}", "00".repeat(32));
        assert!("addr:00".parse::<Address>().is_err());
        assert!(text.parse::<Address>().is_err());
    }
}
