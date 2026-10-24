//! Research seam: fork choice.
//!
//! [`better`] is a free function of two chain tips.

use pouw_types::{BlockId, CumWork, Height};

/// A chain tip as fork choice sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    /// Id of the tip.
    pub id: BlockId,
    pub height: Height,
    /// Sum of the work of every block from genesis to the tip.
    pub cumulative_work: CumWork,
}

/// Whether `candidate` must replace `current`: strictly more cumulative work wins, and
/// a tie keeps `current`, so the chain seen first stays.
#[must_use]
pub fn better(current: &ChainTip, candidate: &ChainTip) -> bool {
    candidate.cumulative_work > current.cumulative_work
}

#[cfg(test)]
mod tests;
