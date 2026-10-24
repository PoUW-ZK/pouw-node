use std::{fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use pouw_crypto::{Hash32, ParseError, text};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

macro_rules! prefixed_id {
    ($(#[$meta:meta])* $name:ident($inner:ty), $prefix:literal, |$s:ident| $get:expr, |$h:ident| $make:expr) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
            FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
        )]
        #[repr(transparent)]
        pub struct $name(pub $inner);

        impl $name {
            /// Prefix of the text form.
            pub const PREFIX: &'static str = $prefix;

            /// The 32 hash bytes, without the type.
            pub fn hash(&self) -> Hash32 {
                let $s = self;
                $get
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                text::write_prefixed(f, Self::PREFIX, &self.hash().0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self}")
            }
        }

        impl FromStr for $name {
            type Err = ParseError;
            fn from_str(s: &str) -> Result<Self, ParseError> {
                let $h = Hash32(text::decode_prefixed(Self::PREFIX, s)?);
                Ok($make)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                text::deserialize_from_str(deserializer)
            }
        }
    };
}

prefixed_id! {
    /// `sha256(borsh(SignedTx))`. Text form `tx:<64 hex>`.
    TxId(Hash32), "tx:", |s| s.0, |h| TxId(h)
}

prefixed_id! {
    /// `sha256(DOMAIN_HEADER || header bytes)`, see [`crate::block_id`]. In header v1 it
    /// is also the proof-of-work hash. Text form `blk:<64 hex>`.
    BlockId(Hash32), "blk:", |s| s.0, |h| BlockId(h)
}

prefixed_id! {
    /// The txid of the `RegisterCircuit` transaction. Text form `circ:<64 hex>`.
    CircuitId(TxId), "circ:", |s| s.0.0, |h| CircuitId(TxId(h))
}

prefixed_id! {
    /// `sha256(borsh(ProofTx))`, the Merkle leaf id of a proof tx. Text form
    /// `proof:<64 hex>`.
    ProofHash(Hash32), "proof:", |s| s.0, |h| ProofHash(h)
}

impl BlockId {
    /// The `parent` of the genesis block.
    pub const ZERO: BlockId = BlockId(Hash32::ZERO);
}
