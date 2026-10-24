//! Research seam: the proof of work of a header.
//!
//! [`check`] is a free function dispatched on `header.version`. Version 1 is the hash
//! proof of work: the block id read as a 256-bit big-endian number must not exceed the
//! target. A version with a costly proof replaces one match arm, and the caller of
//! [`check`] then runs it away from the event loop.

use pouw_types::{
    Block, BlockHeader, BlockId, ConsensusParams, Target, Work, block_id, block_work,
    protocol::BLOCK_VERSION,
};
use thiserror::Error;

/// Why a header does not carry valid proof of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PowError {
    /// No proof of work is defined for this header version.
    #[error("no proof of work for header version {0}")]
    UnsupportedVersion(u32),
    /// A zero target cannot be met.
    #[error("the target is zero")]
    ZeroTarget,
    /// The target is easier than the chain allows.
    #[error("target {found} is above the limit {limit}")]
    TargetAboveLimit {
        /// `params.pow_limit`.
        limit: Target,
        /// `header.target`.
        found: Target,
    },
    /// The block id is above the target.
    #[error("block id {id} is above the target {target}")]
    AboveTarget {
        /// The block id of the header.
        id: BlockId,
        /// `header.target`.
        target: Target,
    },
}

/// Checks the proof of work of `header` and returns the [`Work`] it stands for, which
/// the store adds to the cumulative work of the chain.
///
/// Rules of version 1: the target is nonzero and at most `params.pow_limit`, and the
/// block id read as a 256-bit big-endian number is at most the target. The work is
/// [`block_work`] of the target.
pub fn check(params: &ConsensusParams, header: &BlockHeader) -> Result<Work, PowError> {
    match header.version.get() {
        BLOCK_VERSION => check_v1(params, header),
        other => Err(PowError::UnsupportedVersion(other)),
    }
}

/// Verifies the proof of work of a whole block: `header` is its header and `body` the
/// block it heads. Returns the [`Work`] the block stands for.
///
/// Rules of version 1: exactly [`check`] of the header. The body is not read, because
/// the hash proof of work is a claim about the header alone. A later header version
/// whose proof lives in the body (a proof over the transactions, say) checks it in the
/// matching match arm. Such a check can take long, which is why the node runs this
/// function as a work job (`miner::verify_work`) away from the event loop, while
/// [`check`] stays cheap enough for the loop.
///
/// Tests: `verifying_a_version_1_block_is_the_header_check` and
/// `verifying_an_unknown_version_has_no_proof_of_work`.
pub fn verify(
    params: &ConsensusParams,
    header: &BlockHeader,
    _body: &Block,
) -> Result<Work, PowError> {
    match header.version.get() {
        BLOCK_VERSION => check_v1(params, header),
        other => Err(PowError::UnsupportedVersion(other)),
    }
}

fn check_v1(params: &ConsensusParams, header: &BlockHeader) -> Result<Work, PowError> {
    let target = header.target;
    if target.to_u256().is_zero() {
        return Err(PowError::ZeroTarget);
    }
    if target > params.pow_limit {
        return Err(PowError::TargetAboveLimit {
            limit: params.pow_limit,
            found: target,
        });
    }
    let id = block_id(header);
    if !meets(&id, &target) {
        return Err(PowError::AboveTarget { id, target });
    }
    Ok(block_work(&target))
}

/// Whether `id` is at most `target`, the proof-of-work rule of version 1 that [`check`]
/// applies and the miner's nonce search tests. Equal-length big-endian byte strings
/// compare like the numbers they stand for.
pub fn meets(id: &BlockId, target: &Target) -> bool {
    id.0.0 <= target.0
}

#[cfg(test)]
mod tests;
