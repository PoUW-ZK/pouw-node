//! Research seam: the timestamp rule of a header.
//!
//! [`check`] bounds the timestamp from below by the median time past of the chain
//! and from above by the clock of the verifying node. The clock is an argument, so
//! nothing in consensus reads it and every rule stays testable.

use pouw_types::{BlockHeader, ConsensusParams, Timestamp};
use thiserror::Error;

/// Number of ancestors whose timestamps give the median time past.
pub const MTP_WINDOW: usize = 11;

/// Why a timestamp is out of bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TimestampError {
    /// The timestamp is not above the median time past.
    #[error("timestamp {} is not above the median time past {}", found.0, mtp.0)]
    NotAboveMedian {
        /// Median time past of the parent.
        mtp: Timestamp,
        /// `header.timestamp`.
        found: Timestamp,
    },
    /// The timestamp is more than `params.max_future_secs` ahead of the clock.
    #[error("timestamp {} is ahead of the clock {} by more than {limit} s", found.0, now.0)]
    TooFarAhead {
        /// Clock of the verifying node.
        now: Timestamp,
        /// `header.timestamp`.
        found: Timestamp,
        /// `params.max_future_secs`.
        limit: u64,
    },
}

/// Median of the last [`MTP_WINDOW`] entries of `recent`, which lists timestamps in
/// chain order and holds fewer than [`MTP_WINDOW`] near genesis. The upper median
/// counts for an even number of entries. An empty list gives 0.
pub fn median_time_past(recent: &[Timestamp]) -> Timestamp {
    let start = recent.len().saturating_sub(MTP_WINDOW);
    let mut window = recent.get(start..).unwrap_or_default().to_vec();
    window.sort_unstable();
    let middle = window.len() / 2;
    window.get(middle).copied().unwrap_or(Timestamp(0))
}

/// The rule: `header.timestamp > mtp` and
/// `header.timestamp <= now + params.max_future_secs`. `mtp` is the median time past of
/// the parent chain and `now` the clock of the verifying node, both passed in.
pub fn check(
    params: &ConsensusParams,
    header: &BlockHeader,
    mtp: Timestamp,
    now: Timestamp,
) -> Result<(), TimestampError> {
    let found = Timestamp(header.timestamp.get());
    if found <= mtp {
        return Err(TimestampError::NotAboveMedian { mtp, found });
    }
    if found.0 > now.0.saturating_add(params.max_future_secs) {
        return Err(TimestampError::TooFarAhead {
            now,
            found,
            limit: params.max_future_secs,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
