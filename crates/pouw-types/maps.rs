//! Hash maps chosen by the kind of their key. Ordered or consensus-serialized data
//! stays in `BTreeMap` and `BTreeSet` (a `StateDiff`, anything iterated into output or
//! a hash), and node-local counters live in a `Vec`. The rest is a point lookup in one
//! of two hashed maps.
//!
//! - `TxId`, `Address` and `CircuitId` keys use [`FastMap`], because an attacker grinds
//!   them for the price of a signature or a key.
//! - `BlockId` keys that passed the header proof-of-work check use [`BlockMap`], because
//!   each id costs a proof of work.
//!
//! A txid cannot use the identity hash: about 20 bits of a txid can be ground with about
//! a million signatures, around 15 s on one core, enough to pile entries into one bucket.

use std::{
    collections::HashMap,
    hash::{BuildHasher, BuildHasherDefault, Hasher},
    sync::OnceLock,
};

use foldhash::{
    SharedSeed,
    fast::{FoldHasher, SeedableRandomState},
};
use rand_core::{OsRng, RngCore};

use crate::BlockId;

/// A `HashMap` for keys an attacker can grind, hashed by foldhash under a seed the
/// operating system draws once per process.
pub type FastMap<K, V> = HashMap<K, V, FastState>;

/// The [`BuildHasher`] of [`FastMap`]. Every state of a process carries the same seed,
/// so maps and their clones agree on the hash of a key. foldhash's own `RandomState`
/// derives its seed from address-space layout and the clock, which is no defence against
/// a peer who can try many keys. This one draws 128 bits from the operating system.
#[derive(Clone, Debug)]
pub struct FastState(SeedableRandomState);

static PROCESS_SEED: OnceLock<(u64, SharedSeed)> = OnceLock::new();

impl Default for FastState {
    /// # Panics
    ///
    /// When the operating system has no randomness, as a key generation would.
    fn default() -> Self {
        let (per_hasher, shared) =
            PROCESS_SEED.get_or_init(|| (OsRng.next_u64(), SharedSeed::from_u64(OsRng.next_u64())));
        Self(SeedableRandomState::with_seed(*per_hasher, shared))
    }
}

impl BuildHasher for FastState {
    type Hasher = FoldHasher<'static>;

    fn build_hasher(&self) -> FoldHasher<'static> {
        self.0.build_hasher()
    }
}

/// A `HashMap` keyed by [`BlockId`]s that passed the header proof-of-work check.
///
/// The identity hash is safe only for such ids. A valid id is a hash output at most
/// the target, so each key an attacker adds costs a proof of work. A map that can hold
/// an id the node did not check (a gossiped announcement before `pow::check`, an id a
/// peer names in a request) uses [`FastMap`] instead.
///
/// With a trivial target (the devnet spec allows `0xff..ff`) the proof of work costs
/// nothing and so does grinding the hashed bytes, so the chain spec of a network that
/// takes untrusted peers needs a target that is hard.
pub type BlockMap<V> = HashMap<BlockId, V, BuildHasherDefault<BlockIdHasher>>;

/// The identity hash of a [`BlockId`]: its last 8 bytes. The id is compared with the
/// target as a big-endian number, so a valid id starts with zero bytes and only the
/// tail is random.
#[derive(Debug, Default)]
pub struct BlockIdHasher(u64);

impl Hasher for BlockIdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let tail = bytes
            .get(bytes.len().saturating_sub(8)..)
            .unwrap_or_default();
        let mut word = [0u8; 8];
        if let Some(head) = word.get_mut(..tail.len()) {
            head.copy_from_slice(tail);
        }
        self.0 = u64::from_le_bytes(word);
    }

    /// `Hash for [u8; 32]` writes the length first, the bytes of the id follow.
    fn write_usize(&mut self, _len: usize) {}
}

#[cfg(test)]
mod tests;
