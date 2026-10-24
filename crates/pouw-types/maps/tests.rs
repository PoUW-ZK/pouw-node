use std::hash::{BuildHasher, BuildHasherDefault, Hash};

use foldhash::fast::SeedableRandomState;
use pouw_crypto::Hash32;

use super::*;
use crate::{BlockId, TxId};

fn finish<S: BuildHasher, K: Hash>(state: &S, key: &K) -> u64 {
    state.hash_one(key)
}

/// An id as a proof of work leaves it: leading zero bytes, a random tail.
fn work_id(tail: u64) -> BlockId {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&tail.to_be_bytes());
    BlockId(Hash32(bytes))
}

#[test]
fn a_block_id_hashes_to_its_last_eight_bytes() {
    let state = BuildHasherDefault::<BlockIdHasher>::default();
    let id = work_id(0x0102_0304_0506_0708);
    assert_eq!(
        finish(&state, &id),
        u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8])
    );
}

#[test]
fn proof_of_work_ids_spread_over_the_hash_space() {
    let state = BuildHasherDefault::<BlockIdHasher>::default();
    let hashes: std::collections::BTreeSet<u64> = (1..=1000u64)
        .map(|n| finish(&state, &work_id(n.wrapping_mul(0x9e37_79b9_7f4a_7c15))))
        .collect();
    assert_eq!(hashes.len(), 1000);
}

#[test]
fn a_block_map_finds_what_it_holds() {
    let mut map = BlockMap::default();
    for n in 0..100u64 {
        map.insert(work_id(n), n);
    }
    for n in 0..100u64 {
        assert_eq!(map.get(&work_id(n)), Some(&n));
    }
    assert_eq!(map.get(&work_id(100)), None);
}

#[test]
fn the_fast_state_is_not_the_fixed_seed() {
    let key = TxId(Hash32([7; 32]));
    let seeded = finish(&FastState::default(), &key);
    assert_ne!(seeded, finish(&SeedableRandomState::fixed(), &key));
    assert_ne!(
        seeded,
        finish(
            &SeedableRandomState::with_seed(0, foldhash::SharedSeed::global_fixed()),
            &key
        )
    );
}

#[test]
fn every_fast_state_of_a_process_hashes_alike() {
    let key = TxId(Hash32([9; 32]));
    assert_eq!(
        finish(&FastState::default(), &key),
        finish(&FastState::default(), &key)
    );
}

#[test]
fn a_fast_map_finds_what_it_holds_and_compares_by_content() {
    let mut a: FastMap<TxId, u32> = FastMap::default();
    let mut b: FastMap<TxId, u32> = FastMap::default();
    for n in 0..50u8 {
        a.insert(TxId(Hash32([n; 32])), u32::from(n));
    }
    for n in (0..50u8).rev() {
        b.insert(TxId(Hash32([n; 32])), u32::from(n));
    }
    assert_eq!(a, b);
    assert_eq!(a.get(&TxId(Hash32([3; 32]))), Some(&3));
}
