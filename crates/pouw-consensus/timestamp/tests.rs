use pouw_crypto::{Address, Hash32};
use pouw_types::{
    Amount, BlockHeader, BlockId, ChainId, ConsensusParams, Target, Timestamp, U32, U64,
};

use super::{MTP_WINDOW, TimestampError, check, median_time_past};

fn params() -> ConsensusParams {
    ConsensusParams {
        chain_id: ChainId(1),
        initial_subsidy: Amount(0),
        halving_interval: 1,
        target_block_secs: 10,
        half_life_secs: 100,
        initial_target: Target([0xff; 32]),
        pow_limit: Target([0xff; 32]),
        max_future_secs: 300,
        fee_per_public_input: Amount(0),
        fee_per_witness_kib: Amount(0),
    }
}

fn at(timestamp: u64) -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(1),
        system_id: U64::new(0),
        height: U64::new(1),
        parent: BlockId::ZERO,
        timestamp: U64::new(timestamp),
        miner: Address([0; 32]),
        tx_root: Hash32::ZERO,
        target: Target([0xff; 32]),
        nonce: U64::new(0),
    }
}

fn times(values: &[u64]) -> Vec<Timestamp> {
    values.iter().copied().map(Timestamp).collect()
}

#[test]
fn the_median_of_eleven_is_the_sixth_smallest() {
    let recent = times(&[50, 10, 90, 20, 80, 30, 70, 40, 60, 100, 5]);
    assert_eq!(recent.len(), MTP_WINDOW);
    assert_eq!(median_time_past(&recent), Timestamp(50));
}

#[test]
fn the_median_near_genesis_uses_what_exists() {
    assert_eq!(median_time_past(&times(&[7])), Timestamp(7));
    assert_eq!(median_time_past(&times(&[9, 3, 5])), Timestamp(5));
    assert_eq!(median_time_past(&times(&[1, 2, 3, 4])), Timestamp(3));
    assert_eq!(median_time_past(&[]), Timestamp(0));
}

#[test]
fn only_the_last_eleven_count() {
    let mut recent = times(&[1000, 1000, 1000]);
    recent.extend(times(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]));
    assert_eq!(median_time_past(&recent), Timestamp(6));
}

#[test]
fn a_timestamp_equal_to_the_median_fails() {
    assert_eq!(
        check(&params(), &at(100), Timestamp(100), Timestamp(1000)),
        Err(TimestampError::NotAboveMedian {
            mtp: Timestamp(100),
            found: Timestamp(100)
        })
    );
}

#[test]
fn a_timestamp_one_above_the_median_passes() {
    assert_eq!(
        check(&params(), &at(101), Timestamp(100), Timestamp(1000)),
        Ok(())
    );
}

#[test]
fn a_timestamp_at_the_clock_plus_the_allowance_passes() {
    assert_eq!(
        check(&params(), &at(1300), Timestamp(100), Timestamp(1000)),
        Ok(())
    );
}

#[test]
fn a_timestamp_one_past_the_allowance_fails() {
    assert_eq!(
        check(&params(), &at(1301), Timestamp(100), Timestamp(1000)),
        Err(TimestampError::TooFarAhead {
            now: Timestamp(1000),
            found: Timestamp(1301),
            limit: 300
        })
    );
}

#[test]
fn the_clock_plus_the_allowance_does_not_wrap() {
    assert_eq!(
        check(
            &params(),
            &at(u64::MAX),
            Timestamp(100),
            Timestamp(u64::MAX)
        ),
        Ok(())
    );
}
