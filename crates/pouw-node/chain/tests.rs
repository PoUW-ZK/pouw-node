use pouw_consensus::StateView;
use pouw_types::{Account, Height, Nonce, PowNonce, block_id, genesis_block};

use super::*;
use crate::{config::load_chain, store};

#[test]
fn genesis_seeds_the_allocations() {
    let (spec, block) = load_chain(None).unwrap();
    let mut store = store::memory();
    let tip = genesis(&mut store, &spec, &block).unwrap();
    assert_eq!(tip.height, Height(0));
    assert_eq!(tip.id, spec.expected_genesis_id);
    let reader = store::read(&store).unwrap();
    for allocation in &spec.allocations {
        assert_eq!(
            reader.account(&allocation.address).unwrap(),
            Some(Account {
                balance: allocation.amount,
                nonce: Nonce(0)
            })
        );
    }
    assert_eq!(store::tip(&reader).unwrap(), Some(tip));
}

#[test]
fn genesis_on_a_started_store_keeps_the_tip() {
    let (spec, block) = load_chain(None).unwrap();
    let mut store = store::memory();
    let first = genesis(&mut store, &spec, &block).unwrap();
    assert_eq!(genesis(&mut store, &spec, &block).unwrap(), first);
}

#[test]
fn a_store_of_another_chain_is_refused() {
    let (spec, block) = load_chain(None).unwrap();
    let mut store = store::memory();
    genesis(&mut store, &spec, &block).unwrap();
    let mut other = spec.clone();
    other.genesis.nonce = PowNonce(1);
    let other_block = genesis_block(&other);
    let error = genesis(&mut store, &other, &other_block).unwrap_err();
    assert!(matches!(
        error,
        GenesisError::ForeignChain { expected, .. } if expected == block_id(&other_block.header)
    ));
}
