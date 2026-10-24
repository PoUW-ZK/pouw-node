//! Research seam: the target of the next block.
//!
//! [`next_target`] is a free function of the parameters, the proof system, the anchor
//! and the parent header. Research replaces its body to change the retarget rule, for
//! example to keep one target per proof system (`system_id`).

use pouw_types::{BlockHeader, ConsensusParams, Height, SystemId, Target, Timestamp, U256};
use ruint::aliases::U512;
use thiserror::Error;

/// The block every later target is scheduled against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    /// Height of the anchor block.
    pub height: Height,
    /// Timestamp of the parent of the anchor block.
    pub parent_timestamp: Timestamp,
    /// `header.target` of the anchor block.
    pub target: Target,
}

impl Anchor {
    /// The anchor of the chain before block 1 exists: height 1, scheduled from the
    /// timestamp of `genesis`, at `params.initial_target`. The child of genesis, block 1,
    /// then gets exactly `params.initial_target`.
    pub fn first_block(params: &ConsensusParams, genesis: &BlockHeader) -> Anchor {
        Anchor {
            height: Height(1),
            parent_timestamp: Timestamp(genesis.timestamp.get()),
            target: params.initial_target,
        }
    }

    /// The anchor once block 1 exists: `block` is block 1 and `parent` is genesis.
    pub fn from_block(block: &BlockHeader, parent: &BlockHeader) -> Anchor {
        Anchor {
            height: Height(block.height.get()),
            parent_timestamp: Timestamp(parent.timestamp.get()),
            target: block.target,
        }
    }
}

/// Why no target can be given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DifficultyError {
    /// Header v1 knows only the hash proof of work, system 0.
    #[error("proof system {} has no target rule", .0.0)]
    UnknownSystem(SystemId),
    /// `params.half_life_secs` is zero.
    #[error("half_life_secs is zero")]
    ZeroHalfLife,
}

/// Fixed-point scale of the exponent: 16 fractional bits.
const RADIX_BITS: u32 = 16;
const RADIX: i128 = 1 << RADIX_BITS;

/// Target of the child of `parent`, by aserti3-2d of Bitcoin Cash Node on a full
/// 256-bit target:
///
/// ```text
/// target = anchor.target
///        * 2^((parent.timestamp - anchor.parent_timestamp
///              - target_block_secs * (parent.height - anchor.height + 1)) / half_life_secs)
/// ```
///
/// The target is a function of the schedule alone, so every node computes the same
/// value from the anchor and the parent and a block is on schedule when its parent
/// is as late as the schedule says. The exponent has 16 fractional bits and
/// `2^fraction` is the cubic approximation of the specification. The result is clamped
/// to `1..=params.pow_limit`.
///
/// The anchor is block 1, scheduled from the timestamp of genesis. Before block 1
/// exists, [`Anchor::first_block`] stands for it and the result is
/// `params.initial_target`.
///
/// Header v1 has the one proof system 0. Another `system_id` is an error, so a block
/// of a system without a rule is invalid instead of getting a made-up target.
pub fn next_target(
    params: &ConsensusParams,
    system_id: SystemId,
    anchor: &Anchor,
    parent: &BlockHeader,
) -> Result<Target, DifficultyError> {
    if system_id != SystemId(0) {
        return Err(DifficultyError::UnknownSystem(system_id));
    }
    let pow_limit = params.pow_limit.to_u256();
    let scheduled = i128::from(parent.timestamp.get())
        .saturating_sub(i128::from(anchor.parent_timestamp.0))
        .saturating_sub(
            i128::from(params.target_block_secs).saturating_mul(
                i128::from(parent.height.get())
                    .saturating_sub(i128::from(anchor.height.0))
                    .saturating_add(1),
            ),
        );
    let exponent = scheduled
        .saturating_mul(RADIX)
        .checked_div(i128::from(params.half_life_secs))
        .ok_or(DifficultyError::ZeroHalfLife)?;
    let shifts = exponent.div_euclid(RADIX);
    let fraction = u128::try_from(exponent.rem_euclid(RADIX)).unwrap_or(0);
    let factor = cubic_two_pow(fraction);
    let scaled = U512::from(anchor.target.to_u256()).saturating_mul(U512::from(factor));
    let shifted = if shifts < 0 {
        let down = usize::try_from(shifts.unsigned_abs()).unwrap_or(usize::MAX);
        Some(scaled.wrapping_shr(down))
    } else {
        let up = usize::try_from(shifts).unwrap_or(usize::MAX);
        scaled.checked_shl(up)
    };
    let next = shifted.map(|value| value.wrapping_shr(RADIX_BITS as usize));
    let limit = U512::from(pow_limit);
    let clamped = next.map_or(limit, |value| value.min(limit));
    let [a, b, c, d, ..] = clamped.into_limbs();
    let clamped = U256::from_limbs([a, b, c, d]);
    Ok(Target::from_u256(clamped.max(U256::from(1u64))))
}

/// `2^(fraction / 2^16) * 2^16` for `0 <= fraction < 2^16`, rounded, by the cubic of
/// the specification. The sum stays below `2^64` for every fraction.
fn cubic_two_pow(fraction: u128) -> u128 {
    let linear = fraction.saturating_mul(195_766_423_245_049);
    let square = fraction.saturating_pow(2).saturating_mul(971_821_376);
    let cube = fraction.saturating_pow(3).saturating_mul(5_127);
    let sum = linear
        .saturating_add(square)
        .saturating_add(cube)
        .saturating_add(1 << 47);
    sum.wrapping_shr(48).saturating_add(RADIX.unsigned_abs())
}

#[cfg(test)]
mod tests;
