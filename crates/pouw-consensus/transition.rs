//! Research seam: the state transition of a block. [`apply_block`] is the stateful half
//! of the validity rules of `contracts/block.md`, the half that needs the account
//! state. The proof verify is a work job, `pouw-node` `miner::verify_work`.

use pouw_types::{Block, ConsensusParams, TxId};

use crate::{BlockError, StateDiff, StateView};

/// The change `block` makes to the state `view`, pouw-node#77. Until it exists a block
/// changes nothing.
///
/// To build, over a [`ChainState`](crate::ChainState) whose `base` is `view` and whose
/// `diff` is the result. `txids` are the ids of `block.txs` followed by the ids of the
/// requests of `block.proof_txs`, the order `Block::txids_into` gives.
/// 1. For each transaction in block order (`block.txs`, then the request of each of
///    `block.proof_txs`): the nonce is the account's (`InvalidTx::BadNonce`), balance
///    covers amount plus fee (`InsufficientBalance`), a proof request names a
///    registered circuit (`UnknownCircuit`). A broken rule is
///    `InvalidBlock::Tx { proof, index, source }`, `index` the position in its list.
///    The sender's nonce goes up by one. A `RegisterCircuit` becomes a `CircuitEntry`
///    whose `id` is the transaction's entry of `txids`, `owner` the sender and
///    `registered_at` the block height. Writes go through `set_account`, `set_circuit`
///    and `set_usage_counter`, so a later transaction sees an earlier one.
///    A proof tx's `usage_counter` is `UsageCounter(0)` when the miner has no counter for
///    the circuit, else `checked_next` of it (`InvalidBlock::BadUsageCounter`).
/// 2. Money moves with `Amount::checked_add` and `checked_sub`, an overflow is an
///    invalid transaction (`BalanceOverflow`).
/// 3. Credit `reward::subsidy(params, height)` plus every fee to `header.miner`.
/// 4. `BlockError::Invalid` goes to the caller's `mark_failed`, `block_rejected` and
///    `BlockOutcome::Invalid`. `BlockError::State` and `BlockError::Prover` are a
///    node fault, never held against a peer.
///
/// Test: transfers and the reward on a `MemState`, then `StateDiff::inverse` applied
/// after the diff gives the state before.
pub fn apply_block<V: StateView + ?Sized>(
    _params: &ConsensusParams,
    _view: &V,
    _block: &Block,
    _txids: &[TxId],
) -> Result<StateDiff, BlockError> {
    Ok(StateDiff::default())
}
