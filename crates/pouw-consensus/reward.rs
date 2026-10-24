//! Research seam: the block subsidy.
//!
//! [`subsidy`] is a free function of the parameters and the height.

use pouw_types::{Amount, ConsensusParams, Height};

/// Coins the block at `height` creates for `header.miner`: `params.initial_subsidy`
/// halved once per `params.halving_interval` blocks, with the remainder dropped.
/// Height 0, the genesis block, pays nothing, and so does every height after 64
/// halvings. An interval of 0 pays nothing.
pub fn subsidy(params: &ConsensusParams, height: Height) -> Amount {
    if height.0 == 0 {
        return Amount(0);
    }
    let Some(halvings) = height.0.checked_div(params.halving_interval) else {
        return Amount(0);
    };
    let halvings = u32::try_from(halvings).unwrap_or(u32::MAX);
    Amount(params.initial_subsidy.0.checked_shr(halvings).unwrap_or(0))
}

#[cfg(test)]
mod tests;
