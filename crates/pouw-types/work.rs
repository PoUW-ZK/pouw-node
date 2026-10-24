//! Proof-of-work arithmetic: the 256-bit target of a header and the work it stands for.
//!
//! Place in the pipeline: the store sums the [`Work`] of each block into the
//! [`CumWork`] of a chain tip, and fork choice (`fork_choice::better` in pouw-consensus)
//! compares the sums. This module holds the number types and [`block_work`].

use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use pouw_crypto::{Hash32, text};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// 256-bit unsigned integer used for all work and target math.
pub type U256 = ruint::aliases::U256;

/// Upper bound for the block id of a header, as it sits in the header: 32 bytes,
/// big-endian, so the byte order of a hash read left to right is the numeric order.
/// A block meets its target when `block_id` read as a big-endian number is at most
/// the target. A smaller target is harder. Text form is 64 lowercase hex digits.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct Target(pub [u8; 32]);

impl Target {
    /// The number for math.
    pub fn to_u256(self) -> U256 {
        U256::from_be_bytes(self.0)
    }

    /// The wire form of `value`.
    pub fn from_u256(value: U256) -> Target {
        Target(value.to_be_bytes())
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hash32(self.0), f)
    }
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Target({self})")
    }
}

impl Serialize for Target {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        text::deserialize_from_str::<Hash32, D>(deserializer).map(|hash| Target(hash.0))
    }
}

/// Expected number of hash attempts to meet one target, see [`block_work`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Work(pub U256);

/// Sum of the [`Work`] of every block from genesis to a tip. Fork choice prefers the
/// larger sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CumWork(pub U256);

impl fmt::Display for CumWork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hash32(self.0.to_be_bytes()), f)
    }
}

impl Serialize for CumWork {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CumWork {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        text::deserialize_from_str::<Hash32, D>(deserializer)
            .map(|hash| CumWork(U256::from_be_bytes(hash.0)))
    }
}

impl CumWork {
    /// The sum of the empty chain.
    pub const ZERO: CumWork = CumWork(U256::ZERO);

    /// `None` on overflow.
    pub fn checked_add(self, work: Work) -> Option<CumWork> {
        self.0.checked_add(work.0).map(CumWork)
    }

    /// The work above `other`; `None` when `other` is larger.
    pub fn checked_sub(self, other: CumWork) -> Option<CumWork> {
        self.0.checked_sub(other.0).map(CumWork)
    }
}

/// Work of one block: `floor(2^256 / (target + 1))`, the expected number of attempts
/// to find a block id at most `target`.
///
/// `2^256` does not fit in a [`U256`], so the division uses the identity
/// `2^256 = !t + (t + 1)` where `!t = 2^256 - 1 - t` is the bitwise not. Then
/// `floor(2^256 / (t + 1)) = floor(!t / (t + 1)) + 1`, and every step fits.
///
/// Edge cases: `t = 2^256 - 1` makes `t + 1` overflow and the work is 1. `t = 0`
/// would need work `2^256`, which is saturated to [`U256::MAX`]. No hash is below an
/// all-zero target in practice, so that value only has to be larger than any other.
///
/// Seam for the research: header v2 may define the work of a block per proof system
/// (`header.system_id`), and then this function takes the header. The sum in
/// [`CumWork`] and the fork choice stay the same.
pub fn block_work(target: &Target) -> Work {
    let t = target.to_u256();
    let Some(divisor) = t.checked_add(U256::from(1u64)) else {
        return Work(U256::from(1u64));
    };
    let quotient = (!t).checked_div(divisor).unwrap_or(U256::MAX);
    Work(quotient.saturating_add(U256::from(1u64)))
}
