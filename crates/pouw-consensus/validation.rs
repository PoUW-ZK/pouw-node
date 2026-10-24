//! Validity rules of block.md as functions with typed errors. This module holds the
//! rules that need no chain state: a transaction on its own, a header against its
//! parent and the chain it extends, and a block body against its header. The rules that
//! read the state (nonce, balance, registry, usage counter, proof) run in the state
//! transition and report through the same error types.

use pouw_crypto::{CryptoError, Hash32};
use pouw_provers::ProverError;
use pouw_types::{
    Amount, Block, BlockHeader, ChainId, CircuitId, ConsensusParams, Height, Nonce, SignedTx,
    SystemId, Target, Timestamp, TxError, TxId, TxKind, UsageCounter, block_id, encoded_len,
    protocol::{BLOCK_VERSION, MAX_BLOCK_BYTES, MAX_PROOFS_PER_BLOCK, MAX_TXS_PER_BLOCK},
    verify_proof_tx_with, verify_tx_with,
};
use thiserror::Error;

use crate::{
    difficulty::{Anchor, DifficultyError, next_target},
    pow::PowError,
    state::StateError,
    timestamp::{self, TimestampError},
};

/// Why a transaction breaks a rule of block.md. Every variant makes the transaction
/// invalid everywhere: in the mempool, in a block and on every node.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidTx {
    /// Rule 1.
    #[error("the signature does not verify")]
    BadSignature,
    /// Rule 2.
    #[error("chain id {found:?}, this chain is {expected:?}")]
    BadChainId {
        /// Chain id of the node.
        expected: ChainId,
        /// Chain id of the transaction.
        found: ChainId,
    },
    /// Rule 3.
    #[error("expected nonce {}, got {}", expected.0, found.0)]
    BadNonce {
        /// Nonce of the sender's account.
        expected: Nonce,
        /// Nonce of the transaction.
        found: Nonce,
    },
    /// Rule 4.
    #[error("the transaction spends {} and the balance is {}", needed.0, available.0)]
    InsufficientBalance {
        /// Amount plus fee.
        needed: Amount,
        /// Balance of the sender.
        available: Amount,
    },
    /// Rule 5.
    #[error("circuit {0} is not registered")]
    UnknownCircuit(CircuitId),
    /// Rule 6.
    #[error("{what} has {found} items or bytes, the limit is {limit}")]
    OverLimit {
        what: &'static str,
        found: usize,
        limit: usize,
    },
    /// A kind in a place that does not take it, such as a `ProofRequest` in `txs`.
    #[error("a {kind} transaction is not allowed in {place}")]
    WrongKind {
        kind: &'static str,
        place: &'static str,
    },
    /// The fee is below the minimum for this transaction.
    #[error("fee {} is below the minimum {}", found.0, minimum.0)]
    FeeTooLow { minimum: Amount, found: Amount },
    /// Crediting the receiver would overflow its balance.
    #[error("the balance of the receiver would overflow")]
    BalanceOverflow,
}

impl InvalidTx {
    /// The `reason_code` of node-events.md and the `code` of a 422 answer.
    pub fn reason_code(&self) -> &'static str {
        match self {
            InvalidTx::BadSignature => "bad_signature",
            InvalidTx::BadChainId { .. } => "bad_chain_id",
            InvalidTx::BadNonce { .. } => "bad_nonce",
            InvalidTx::InsufficientBalance { .. } => "insufficient_balance",
            InvalidTx::UnknownCircuit(_) => "unknown_circuit",
            InvalidTx::OverLimit { .. } => "over_limit",
            InvalidTx::WrongKind { .. } => "wrong_kind",
            InvalidTx::FeeTooLow { .. } => "fee_too_low",
            InvalidTx::BalanceOverflow => "balance_overflow",
        }
    }
}

impl From<TxError> for InvalidTx {
    fn from(error: TxError) -> Self {
        match error {
            TxError::OverLimit { what, found, limit } => {
                InvalidTx::OverLimit { what, found, limit }
            }
            TxError::NotAProofRequest => InvalidTx::WrongKind {
                kind: "non proof_request",
                place: "the request of a proof tx",
            },
            TxError::Crypto(CryptoError::BadSignature | CryptoError::InvalidPublicKey) => {
                InvalidTx::BadSignature
            }
        }
    }
}

/// Why a block breaks a rule of block.md. Every variant makes the block invalid on
/// every node, so its sender may be penalized.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidBlock {
    /// Rule 1: `header.version`.
    #[error("header version {found}, expected {BLOCK_VERSION}")]
    BadVersion {
        /// Version in the header.
        found: u32,
    },
    /// Rule 1: `header.chain_id`.
    #[error("header chain id {found:?}, this chain is {expected:?}")]
    BadChainId {
        /// Chain id of the node.
        expected: ChainId,
        /// Chain id in the header.
        found: ChainId,
    },
    /// Rule 1: `header.height`.
    #[error("height {}, expected {}", found.0, expected.0)]
    BadHeight {
        /// Parent height plus one.
        expected: Height,
        /// Height in the header.
        found: Height,
    },
    /// Rule 1: `header.parent`.
    #[error("parent is not the block id of the parent block")]
    BadParent,
    /// Rule 2: the header carries another target than the target rule gives.
    #[error("target {found}, expected {expected}")]
    BadTarget {
        /// Target of the rule.
        expected: Target,
        /// Target of the header.
        found: Target,
    },
    /// Rule 2: the target rule has no answer for the proof system of the header.
    #[error(transparent)]
    Difficulty(#[from] DifficultyError),
    /// Rule 3: `header.timestamp`.
    #[error(transparent)]
    Timestamp(#[from] TimestampError),
    /// Rule 4: the proof of work of the header.
    #[error(transparent)]
    Pow(#[from] PowError),
    /// Rules 6 and 7: an entry of `txs` (`proof: false`) or a request of `proof_txs`.
    #[error("{} {index}: {source}", if *proof { "proof tx" } else { "tx" })]
    Tx {
        /// Whether the entry is in `proof_txs`.
        proof: bool,
        /// Position in its list.
        index: usize,
        /// The broken rule.
        source: InvalidTx,
    },
    /// Rule 8.
    #[error("proof tx {index} has usage counter {}, expected {}", found.0, expected.0)]
    BadUsageCounter {
        /// Position in `proof_txs`.
        index: usize,
        /// Counter the rule requires.
        expected: UsageCounter,
        /// Counter in the proof tx.
        found: UsageCounter,
    },
    /// Rule 9.
    #[error("the proof of proof tx {index} does not verify")]
    InvalidProof {
        /// Position in `proof_txs`.
        index: usize,
    },
    /// Rule 5: `tx_root` is not the bound root of the leaf count and the Merkle root of
    /// the entries.
    #[error("tx_root does not match the entries")]
    BadTxRoot,
    /// Rule 5.
    #[error("the block has {found} {what}, the limit is {limit}")]
    OverLimit {
        /// `bytes`, `entries` or `proof txs`.
        what: &'static str,
        found: usize,
        limit: usize,
    },
}

impl InvalidBlock {
    /// The `reason_code` of a `block_rejected` event.
    pub fn reason_code(&self) -> &'static str {
        match self {
            InvalidBlock::BadVersion { .. }
            | InvalidBlock::Pow(PowError::UnsupportedVersion(_)) => "bad_version",
            InvalidBlock::BadChainId { .. } => "bad_header_chain_id",
            InvalidBlock::BadHeight { .. } => "bad_height",
            InvalidBlock::BadParent => "bad_parent",
            InvalidBlock::BadTarget { .. }
            | InvalidBlock::Pow(PowError::ZeroTarget | PowError::TargetAboveLimit { .. }) => {
                "bad_target"
            }
            InvalidBlock::Difficulty(_) => "unknown_proof_system",
            InvalidBlock::Timestamp(TimestampError::NotAboveMedian { .. }) => {
                "timestamp_not_above_median"
            }
            InvalidBlock::Timestamp(TimestampError::TooFarAhead { .. }) => {
                "timestamp_too_far_ahead"
            }
            InvalidBlock::Pow(PowError::AboveTarget { .. }) => "insufficient_work",
            InvalidBlock::Tx { source, .. } => source.reason_code(),
            InvalidBlock::BadUsageCounter { .. } => "bad_usage_counter",
            InvalidBlock::InvalidProof { .. } => "invalid_proof",
            InvalidBlock::BadTxRoot => "bad_tx_root",
            InvalidBlock::OverLimit { .. } => "over_limit",
        }
    }
}

/// Result of checking a block against the state: invalid, or not checkable because of
/// a fault of this node. Only [`BlockError::Invalid`] may be held against the sender.
#[derive(Debug, Error)]
pub enum BlockError {
    #[error(transparent)]
    Invalid(#[from] InvalidBlock),
    #[error(transparent)]
    State(#[from] StateError),
    /// The prover failed for a reason other than the proof.
    #[error("prover failure: {0}")]
    Prover(ProverError),
}

/// Rules 1, 2 and 6 for transactions: signature, chain id and limits. The caller
/// checks nonce, balance and registry against the state.
pub fn check_tx(tx: &SignedTx, chain_id: ChainId) -> Result<(), InvalidTx> {
    check_tx_with(tx, chain_id, &mut Vec::new())
}

/// [`check_tx`] with the signing buffer of the caller, so a loop reuses one allocation.
pub fn check_tx_with(tx: &SignedTx, chain_id: ChainId, buf: &mut Vec<u8>) -> Result<(), InvalidTx> {
    if tx.body.chain_id != chain_id {
        return Err(InvalidTx::BadChainId {
            expected: chain_id,
            found: tx.body.chain_id,
        });
    }
    verify_tx_with(tx, buf).map_err(InvalidTx::from)
}

/// What a header is checked against besides its parent.
#[derive(Debug, Clone, Copy)]
pub struct HeaderContext<'a> {
    /// The parameters of the chain.
    pub params: &'a ConsensusParams,
    /// The anchor of the target rule, see [`Anchor`].
    pub anchor: &'a Anchor,
    /// Median time past of the chain ending in the parent, see
    /// [`timestamp::median_time_past`].
    pub mtp: Timestamp,
    /// The clock of the verifying node, read once by the caller.
    pub now: Timestamp,
}

/// The rules of a header that need the parent and the chain behind it, cheapest
/// first: version, chain id, height, parent, then the target of
/// [`next_target`] and the timestamp bounds. The proof of work is not checked here:
/// [`crate::check_pow`] runs before a block is decoded further and its result is the
/// verify-work stage of the node.
pub fn check_header(
    context: &HeaderContext<'_>,
    parent: &BlockHeader,
    header: &BlockHeader,
) -> Result<(), InvalidBlock> {
    if header.version.get() != BLOCK_VERSION {
        return Err(InvalidBlock::BadVersion {
            found: header.version.get(),
        });
    }
    let expected_chain = context.params.chain_id;
    let found_chain = ChainId(header.chain_id.get());
    if found_chain != expected_chain {
        return Err(InvalidBlock::BadChainId {
            expected: expected_chain,
            found: found_chain,
        });
    }
    let parent_height = Height(parent.height.get());
    let height = Height(header.height.get());
    let expected = parent_height
        .checked_next()
        .ok_or(InvalidBlock::BadHeight {
            expected: parent_height,
            found: height,
        })?;
    if height != expected {
        return Err(InvalidBlock::BadHeight {
            expected,
            found: height,
        });
    }
    if header.parent != block_id(parent) {
        return Err(InvalidBlock::BadParent);
    }
    let expected_target = next_target(
        context.params,
        SystemId(header.system_id.get()),
        context.anchor,
        parent,
    )?;
    if header.target != expected_target {
        return Err(InvalidBlock::BadTarget {
            expected: expected_target,
            found: header.target,
        });
    }
    timestamp::check(context.params, header, context.mtp, context.now)?;
    Ok(())
}

/// Buffers a caller keeps between checks so that none allocates: the signing message
/// of one transaction and the leaves of one Merkle tree.
#[derive(Debug, Default)]
pub struct Scratch {
    pub signing: Vec<u8>,
    pub leaves: Vec<Hash32>,
}

/// The rules of a block body that need no state, cheapest first: rule 5 (size,
/// then `tx_root` equals `Block::compute_tx_root`), then the stateless parts of rules
/// 6 and 7 (kinds, chain id, limits, signatures).
///
/// `txids` are those of [`Block::txids_into`], computed once by the caller. A list of
/// another length gives a different root and fails rule 5.
pub fn check_body(
    block: &Block,
    chain_id: ChainId,
    txids: &[TxId],
    scratch: &mut Scratch,
) -> Result<(), InvalidBlock> {
    let header = &block.header;
    let leaves = block.leaf_count();
    if leaves > MAX_TXS_PER_BLOCK {
        return Err(InvalidBlock::OverLimit {
            what: "entries",
            found: leaves,
            limit: MAX_TXS_PER_BLOCK,
        });
    }
    if block.proof_txs.len() > MAX_PROOFS_PER_BLOCK {
        return Err(InvalidBlock::OverLimit {
            what: "proof txs",
            found: block.proof_txs.len(),
            limit: MAX_PROOFS_PER_BLOCK,
        });
    }
    let bytes = encoded_len(block);
    if bytes > MAX_BLOCK_BYTES {
        return Err(InvalidBlock::OverLimit {
            what: "bytes",
            found: bytes,
            limit: MAX_BLOCK_BYTES,
        });
    }
    if block.tx_root_from(txids, &mut scratch.leaves) != header.tx_root {
        return Err(InvalidBlock::BadTxRoot);
    }
    let buf = &mut scratch.signing;
    for (index, tx) in block.txs.iter().enumerate() {
        let fail = |source| InvalidBlock::Tx {
            proof: false,
            index,
            source,
        };
        if matches!(tx.body.kind, TxKind::ProofRequest { .. }) {
            return Err(fail(InvalidTx::WrongKind {
                kind: tx.body.kind.name(),
                place: "txs",
            }));
        }
        check_tx_with(tx, chain_id, buf).map_err(fail)?;
    }
    for (index, proof_tx) in block.proof_txs.iter().enumerate() {
        let request = &proof_tx.request;
        let fail = |source| InvalidBlock::Tx {
            proof: true,
            index,
            source,
        };
        if request.body.chain_id != chain_id {
            return Err(fail(InvalidTx::BadChainId {
                expected: chain_id,
                found: request.body.chain_id,
            }));
        }
        verify_proof_tx_with(proof_tx, buf).map_err(|e| fail(e.into()))?;
    }
    Ok(())
}
