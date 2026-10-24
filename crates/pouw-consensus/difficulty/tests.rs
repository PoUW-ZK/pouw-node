//! Official aserti3-2d vectors of Bitcoin Cash Node, files `run01` to `run05` and
//! `run09` to `run11` of
//! <https://download.bitcoincashnode.org/misc/data/asert/test_vectors/>, with the
//! algorithm of
//! <https://raw.githubusercontent.com/bitcoincashorg/bitcoincash.org/master/spec/2020-11-15-asert.md>.
//! The vectors speak in nBits, so the tests carry the compact encoding of Bitcoin.

use pouw_crypto::Address;
use pouw_types::{
    Amount, BlockHeader, ChainId, ConsensusParams, Height, SystemId, Target, Timestamp, U32, U64,
    U256,
};

use super::{Anchor, DifficultyError, next_target};

const BCH_POW_LIMIT_BITS: u32 = 0x1d00_ffff;

fn bits_to_target(bits: u32) -> U256 {
    let exponent = bits >> 24;
    let mantissa = U256::from(bits & 0x007f_ffff);
    match 3u32.checked_sub(exponent) {
        Some(down) => mantissa.wrapping_shr(usize::try_from(down).unwrap_or(0).saturating_mul(8)),
        None => mantissa
            .checked_shl(
                usize::try_from(exponent.saturating_sub(3))
                    .unwrap_or(0)
                    .saturating_mul(8),
            )
            .unwrap_or(U256::MAX),
    }
}

fn target_to_bits(target: U256) -> u32 {
    let mut size = u32::try_from(target.bit_len().div_ceil(8)).unwrap_or(0);
    let mut compact = if let Some(up) = 3u32.checked_sub(size) {
        u32::try_from(target).unwrap_or(0) << up.saturating_mul(8)
    } else {
        let down = usize::try_from(size.saturating_sub(3))
            .unwrap_or(0)
            .saturating_mul(8);
        u32::try_from(target.wrapping_shr(down)).unwrap_or(0)
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size = size.saturating_add(1);
    }
    compact | (size << 24)
}

fn params(half_life_secs: u64, target_block_secs: u64, pow_limit: U256) -> ConsensusParams {
    ConsensusParams {
        chain_id: ChainId(1),
        initial_subsidy: Amount(0),
        halving_interval: 1,
        target_block_secs,
        half_life_secs,
        initial_target: Target::from_u256(pow_limit),
        pow_limit: Target::from_u256(pow_limit),
        max_future_secs: 300,
        fee_per_public_input: Amount(0),
        fee_per_witness_kib: Amount(0),
    }
}

fn bch_params() -> ConsensusParams {
    params(172_800, 600, bits_to_target(BCH_POW_LIMIT_BITS))
}

fn parent(height: u64, timestamp: u64) -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(1),
        system_id: U64::new(0),
        height: U64::new(height),
        parent: pouw_types::BlockId::ZERO,
        timestamp: U64::new(timestamp),
        miner: Address([0; 32]),
        tx_root: pouw_crypto::Hash32::ZERO,
        target: Target([0; 32]),
        nonce: U64::new(0),
    }
}

fn header_value(text: &str, key: &str) -> u64 {
    text.lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|rest| rest.trim().parse().ok())
        .unwrap_or_else(|| panic!("no {key} in the vector header"))
}

fn run_vectors(name: &str, text: &str) {
    let anchor_bits = text
        .lines()
        .find_map(|line| line.strip_prefix("##   anchor nBits: 0x"))
        .and_then(|hex| u32::from_str_radix(hex.trim(), 16).ok())
        .expect("anchor nBits");
    let anchor_parent_time = text
        .lines()
        .find_map(|line| {
            line.strip_prefix("##   anchor ancestor time:")
                .or_else(|| line.strip_prefix("##   anchor parent time:"))
        })
        .and_then(|rest| rest.trim().parse().ok())
        .expect("anchor parent time");
    let anchor = Anchor {
        height: Height(header_value(text, "##   anchor height:")),
        parent_timestamp: Timestamp(anchor_parent_time),
        target: Target::from_u256(bits_to_target(anchor_bits)),
    };
    let params = bch_params();
    let mut checked = 0usize;
    for line in text
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
    {
        let mut fields = line.split_whitespace();
        let _iteration = fields.next();
        let height: u64 = fields.next().and_then(|f| f.parse().ok()).expect("height");
        let time: u64 = fields.next().and_then(|f| f.parse().ok()).expect("time");
        let expected = fields
            .next()
            .and_then(|f| f.strip_prefix("0x"))
            .and_then(|f| u32::from_str_radix(f, 16).ok())
            .expect("target bits");
        let got = next_target(&params, SystemId(0), &anchor, &parent(height, time))
            .expect("system 0 has a rule")
            .to_u256();
        assert_eq!(
            target_to_bits(got),
            expected,
            "{name} height {height} time {time}"
        );
        checked = checked.saturating_add(1);
    }
    assert!(checked > 0, "{name} has no rows");
}

macro_rules! vector {
    ($test:ident, $file:literal) => {
        #[test]
        fn $test() {
            run_vectors(
                $file,
                include_str!(concat!("../testdata/aserti3-2d/", $file, ".txt")),
            );
        }
    };
}

vector!(bch_run01_steady_at_the_limit, "run01");
vector!(bch_run02_steady_at_an_arbitrary_target, "run02");
vector!(bch_run03_steady_at_the_hardest_target, "run03");
vector!(bch_run04_doubling_per_half_life_jump, "run04");
vector!(bch_run05_halving_per_half_life_of_height, "run05");
vector!(bch_run09_across_the_i32_height, "run09");
vector!(bch_run10_across_the_i64_height, "run10");
vector!(bch_run11_with_decreasing_time, "run11");

#[test]
fn compact_helpers_round_trip_known_values() {
    assert_eq!(target_to_bits(bits_to_target(0x1d00_ffff)), 0x1d00_ffff);
    assert_eq!(target_to_bits(bits_to_target(0x1802_aee8)), 0x1802_aee8);
    assert_eq!(target_to_bits(U256::from(1u64)), 0x0101_0000);
}

fn anchor_at_limit() -> Anchor {
    Anchor {
        height: Height(1),
        parent_timestamp: Timestamp(0),
        target: params(
            1000,
            10,
            U256::from(1u64).checked_shl(200).unwrap_or(U256::MAX),
        )
        .pow_limit,
    }
}

#[test]
fn the_anchor_parent_on_schedule_keeps_the_anchor_target() {
    let params = params(
        1000,
        10,
        U256::from(1u64).checked_shl(200).unwrap_or(U256::MAX),
    );
    let mut anchor = anchor_at_limit();
    anchor.target = Target::from_u256(U256::from(1u64).checked_shl(150).unwrap_or(U256::MAX));
    let got = next_target(&params, SystemId(0), &anchor, &parent(1, 10)).expect("rule");
    assert_eq!(got, anchor.target);
}

#[test]
fn a_long_gap_eases_the_target_and_a_fast_run_hardens_it() {
    let params = params(
        1000,
        10,
        U256::from(1u64).checked_shl(200).unwrap_or(U256::MAX),
    );
    let mut anchor = anchor_at_limit();
    let base = U256::from(1u64).checked_shl(150).unwrap_or(U256::MAX);
    anchor.target = Target::from_u256(base);
    let slow = next_target(&params, SystemId(0), &anchor, &parent(2, 1020)).expect("rule");
    assert_eq!(
        slow.to_u256(),
        base.checked_mul(U256::from(2u64)).unwrap_or(U256::MAX)
    );
    let fast = next_target(&params, SystemId(0), &anchor, &parent(102, 10)).expect("rule");
    assert!(fast.to_u256() < base);
}

#[test]
fn the_target_never_exceeds_the_pow_limit() {
    let limit = U256::from(1u64).checked_shl(200).unwrap_or(U256::MAX);
    let params = params(1000, 10, limit);
    let mut anchor = anchor_at_limit();
    anchor.target = params.pow_limit;
    let got = next_target(&params, SystemId(0), &anchor, &parent(2, 100_000)).expect("rule");
    assert_eq!(got, params.pow_limit);
}

#[test]
fn a_shift_past_the_width_clamps_to_the_pow_limit() {
    let params = params(1, 1, U256::MAX);
    let mut anchor = anchor_at_limit();
    anchor.target = Target::from_u256(U256::from(3u64));
    let got = next_target(&params, SystemId(0), &anchor, &parent(2, u64::MAX)).expect("rule");
    assert_eq!(got, params.pow_limit);
}

#[test]
fn a_huge_lead_gives_the_hardest_target_and_never_zero() {
    let params = params(1, 1, U256::MAX);
    let mut anchor = anchor_at_limit();
    anchor.target = params.pow_limit;
    let got = next_target(&params, SystemId(0), &anchor, &parent(u64::MAX, 0)).expect("rule");
    assert_eq!(got.to_u256(), U256::from(1u64));
}

#[test]
fn only_system_zero_has_a_rule() {
    let params = bch_params();
    let anchor = anchor_at_limit();
    assert_eq!(
        next_target(&params, SystemId(1), &anchor, &parent(2, 1200)),
        Err(DifficultyError::UnknownSystem(SystemId(1)))
    );
}

#[test]
fn the_first_block_gets_the_initial_target() {
    let mut params = bch_params();
    params.initial_target = Target::from_u256(bits_to_target(0x1802_aee8));
    let genesis = parent(0, 1_000);
    let anchor = Anchor::first_block(&params, &genesis);
    let got = next_target(&params, SystemId(0), &anchor, &genesis).expect("rule");
    assert_eq!(got, params.initial_target);
}

/// The devnet schedule: 10 s blocks, a half-life of 2880 s, a first target of about
/// 2^230.
fn devnet_params() -> ConsensusParams {
    let mut initial = [0xff; 32];
    initial[..3].fill(0);
    initial[3] = 0x3f;
    let mut limit = [0xff; 32];
    limit[0] = 0;
    let mut params = params(2880, 10, U256::MAX);
    params.initial_target = Target(initial);
    params.pow_limit = Target(limit);
    params
}

/// xorshift64*, enough for a seeded simulation.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// An exponential variate with the given mean.
    #[allow(clippy::cast_precision_loss, reason = "53 random bits of a float")]
    fn exponential(&mut self, mean: f64) -> f64 {
        let uniform = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        -(1.0 - uniform).ln() * mean
    }
}

fn target_as_f64(target: &Target) -> f64 {
    target
        .0
        .iter()
        .fold(0.0, |sum, byte| sum * 256.0 + f64::from(*byte))
}

/// Mines blocks from `genesis` at a hash rate `rate(time)` hashes per second: the wait
/// for a block is exponential with mean `2^256 / (target + 1) / rate`, and the target
/// of each block is `next_target`. Returns the timestamps of the blocks.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
#[allow(
    clippy::cast_sign_loss,
    reason = "the clock of the simulation is positive"
)]
fn simulate(
    params: &ConsensusParams,
    rng: &mut Rng,
    blocks: usize,
    rate: impl Fn(f64) -> f64,
) -> Vec<(f64, u64)> {
    let two_256 = 2f64.powi(256);
    let genesis = parent(0, 1_000_000);
    let mut anchor = Anchor::first_block(params, &genesis);
    let mut tip = genesis;
    let mut clock = 1_000_000.0;
    let mut found = Vec::with_capacity(blocks);
    for height in 1..=blocks {
        let target = next_target(params, SystemId(0), &anchor, &tip).expect("rule");
        let mean = two_256 / (target_as_f64(&target) + 1.0) / rate(clock);
        clock += rng.exponential(mean);
        let mut block = parent(height as u64, clock as u64);
        block.target = target;
        if height == 1 {
            anchor = Anchor::from_block(&block, &genesis);
        }
        found.push((clock, block.timestamp.get()));
        tip = block;
    }
    found
}

#[allow(clippy::cast_precision_loss)]
fn mean_interval(blocks: &[(f64, u64)]) -> f64 {
    let (Some(first), Some(last)) = (blocks.first(), blocks.last()) else {
        return 0.0;
    };
    (last.0 - first.0) / (blocks.len().saturating_sub(1)) as f64
}

/// A constant hash rate settles on the schedule, and a step of the hash rate to four
/// times is absorbed. The mean interval of 500 blocks must be within 15% of the 10 s
/// target (the standard deviation of such a mean is 4.5%), before the step and from
/// 6 half-lives after it. Right after the step the blocks come in less than half the
/// target time, so the test sees the rule respond.
#[test]
fn asert_holds_the_block_time_under_a_constant_and_a_stepped_hash_rate() {
    let params = devnet_params();
    let target_secs = 10.0;
    let rate = 2f64.powi(256) / (target_as_f64(&params.initial_target) + 1.0) / target_secs;
    let half_life = 2880.0;
    let step_at = 1_000_000.0 + 1000.0 * target_secs;
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let blocks = simulate(&params, &mut rng, 4000, |time| {
        if time < step_at { rate } else { 4.0 * rate }
    });
    let before: Vec<_> = blocks.iter().filter(|b| b.0 < step_at).copied().collect();
    let steady = &before[before.len().saturating_sub(500)..];
    let tolerance = 0.15 * target_secs;
    let steady_mean = mean_interval(steady);
    assert!(
        (steady_mean - target_secs).abs() < tolerance,
        "steady mean {steady_mean}"
    );
    let after: Vec<_> = blocks.iter().filter(|b| b.0 >= step_at).copied().collect();
    let burst = mean_interval(&after[..50]);
    assert!(
        burst < 0.5 * target_secs,
        "mean right after the step {burst}"
    );
    let settled_from = step_at + 6.0 * half_life;
    let settled: Vec<_> = after
        .iter()
        .filter(|b| b.0 >= settled_from)
        .copied()
        .collect();
    assert!(
        settled.len() >= 500,
        "only {} blocks after 6 half-lives",
        settled.len()
    );
    let settled_mean = mean_interval(&settled[..500]);
    assert!(
        (settled_mean - target_secs).abs() < tolerance,
        "settled mean {settled_mean}"
    );
}
