use pouw_types::{Amount, ChainId, ConsensusParams, Height, Target};

use super::subsidy;

fn params() -> ConsensusParams {
    ConsensusParams {
        chain_id: ChainId(1),
        initial_subsidy: Amount(50),
        halving_interval: 10,
        target_block_secs: 10,
        half_life_secs: 100,
        initial_target: Target([0xff; 32]),
        pow_limit: Target([0xff; 32]),
        max_future_secs: 300,
        fee_per_public_input: Amount(0),
        fee_per_witness_kib: Amount(0),
    }
}

#[test]
fn genesis_pays_nothing() {
    assert_eq!(subsidy(&params(), Height(0)), Amount(0));
}

#[test]
fn the_first_interval_pays_the_initial_subsidy() {
    assert_eq!(subsidy(&params(), Height(1)), Amount(50));
    assert_eq!(subsidy(&params(), Height(9)), Amount(50));
}

#[test]
fn the_subsidy_halves_at_the_interval() {
    assert_eq!(subsidy(&params(), Height(10)), Amount(25));
    assert_eq!(subsidy(&params(), Height(19)), Amount(25));
    assert_eq!(subsidy(&params(), Height(20)), Amount(12));
    assert_eq!(subsidy(&params(), Height(30)), Amount(6));
}

#[test]
fn the_subsidy_is_zero_after_sixty_four_halvings() {
    let mut params = params();
    params.initial_subsidy = Amount(u64::MAX);
    assert_eq!(subsidy(&params, Height(63 * 10)), Amount(1));
    assert_eq!(subsidy(&params, Height(64 * 10 - 1)), Amount(1));
    assert_eq!(subsidy(&params, Height(64 * 10)), Amount(0));
    assert_eq!(subsidy(&params, Height(u64::MAX)), Amount(0));
}

#[test]
fn a_zero_interval_pays_nothing_instead_of_dividing_by_zero() {
    let mut params = params();
    params.halving_interval = 0;
    assert_eq!(subsidy(&params, Height(5)), Amount(0));
}
