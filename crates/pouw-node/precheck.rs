//! The stateless checks that run on the transport side, before an item enters the p2p
//! channel, so the node loop sees only items that passed them. They are the
//! `CheckBlock` of Bitcoin Core: they read the item and the chain id, never the chain.
//!
//! ```text
//!  received bytes
//!    -> size limit            Oversized
//!    -> borsh decode          Malformed (borsh is canonical: an item with trailing
//!                             bytes or the wrong length does not decode)
//!    -> proof of work claim   pow::check on the header, one hash (blocks, headers)
//!    -> txids, once each      the leaves of tx_root and the transaction index
//!    -> tx_root, then the signatures, kinds, chain id and limits of every tx
//!    => CheckedBlock / CheckedTx
//! ```
//!
//! A [`CheckedAnnounce`] is a header whose chain id is ours and whose work claim holds.
//!
//! A [`CheckedBlock`] keeps the received bytes, which the store writes and the sync
//! answers and the API serve as they are. Every txid of the block is computed here, once.
//! The rules that read the chain (parent, target, timestamp, state transition) are
//! the connect stage in the loop.
//!
//! The checks run off the loop thread, each thread with its own [`Scratch`]: the
//! transport for gossip and sync answers, the API thread for a submitted transaction
//! ([`check_tx`], whose verdict travels in `ApiRequest::SubmitTx`).

use crate::p2p::{
    SyncResponse,
    limits::{MAX_BLOCKS_PER_REQUEST, MAX_HEADERS_PER_RESPONSE},
};
use pouw_consensus::{
    ConsensusParams, InvalidBlock, InvalidTx, Scratch, check_body, check_pow, check_tx_with,
};
use pouw_types::{
    Block, BlockHeader, BlockId, ChainId, SignedTx, TxId, block_id, protocol::MAX_BLOCK_BYTES, txid,
};
use thiserror::Error;

/// Why received bytes do not become a checked item.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrecheckError {
    /// The bytes are longer than the limit of the item.
    #[error("{found} bytes, the limit is {limit}")]
    Oversized { found: usize, limit: usize },
    /// The bytes are not the canonical encoding of an item.
    #[error("malformed: {0}")]
    Malformed(String),
    #[error(transparent)]
    Block(#[from] InvalidBlock),
    #[error(transparent)]
    Tx(#[from] InvalidTx),
}

/// A block that passed the stateless checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedBlock {
    /// The bytes it was decoded from.
    pub bytes: Vec<u8>,
    pub block: Block,
    /// The txid of every entry of `block.txs`, then of the request of every proof tx:
    /// the order of the transaction index, see `Block::txids_into`.
    pub txids: Vec<TxId>,
}

/// A header that passed the stateless checks: its chain id is ours and its id is at most
/// its own target, which is within the limit of the chain. It says nothing about the
/// parent, the height or the target the chain demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedAnnounce {
    pub header: BlockHeader,
    /// The id of `header`, hashed once here.
    pub id: BlockId,
}

/// A transaction that passed the stateless checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedTx {
    pub tx: SignedTx,
    pub txid: TxId,
}

/// Decodes `bytes` as a block and runs the stateless checks, cheapest first.
pub fn check_block(
    bytes: Vec<u8>,
    params: &ConsensusParams,
    scratch: &mut Scratch,
) -> Result<CheckedBlock, PrecheckError> {
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(PrecheckError::Oversized {
            found: bytes.len(),
            limit: MAX_BLOCK_BYTES,
        });
    }
    let block: Block =
        borsh::from_slice(&bytes).map_err(|error| PrecheckError::Malformed(error.to_string()))?;
    check_work(params, &block.header)?;
    let mut txids = Vec::new();
    block.txids_into(&mut txids);
    check_body(&block, params.chain_id, &txids, scratch)?;
    Ok(CheckedBlock {
        bytes,
        block,
        txids,
    })
}

/// The proof of work claim of `header`: its id is at most its own target, which is
/// within the limit of the chain.
pub fn check_work(params: &ConsensusParams, header: &BlockHeader) -> Result<(), InvalidBlock> {
    check_pow(params, header)?;
    Ok(())
}

/// Reads `bytes` as the 168 bytes of a header and runs [`check_announce`].
pub fn check_announce_bytes(
    bytes: &[u8],
    params: &ConsensusParams,
) -> Result<CheckedAnnounce, PrecheckError> {
    let header = BlockHeader::ref_from_versioned(bytes)
        .map_err(|error| PrecheckError::Malformed(error.to_string()))?;
    Ok(check_announce(header, params)?)
}

/// The chain id of `header` and its work claim, cheapest first, with one hash.
pub fn check_announce(
    header: &BlockHeader,
    params: &ConsensusParams,
) -> Result<CheckedAnnounce, InvalidBlock> {
    if header.chain_id.get() != params.chain_id.0 {
        return Err(InvalidBlock::BadChainId {
            expected: params.chain_id,
            found: ChainId(header.chain_id.get()),
        });
    }
    check_work(params, header)?;
    Ok(CheckedAnnounce {
        header: *header,
        id: block_id(header),
    })
}

/// Decodes `bytes` as a transaction and checks it, see [`check_tx`].
pub fn check_tx_bytes(
    bytes: &[u8],
    chain_id: ChainId,
    scratch: &mut Scratch,
) -> Result<CheckedTx, PrecheckError> {
    let tx: SignedTx =
        borsh::from_slice(bytes).map_err(|error| PrecheckError::Malformed(error.to_string()))?;
    Ok(check_tx(tx, chain_id, scratch)?)
}

/// Rules 1, 2 and 6 for `tx` and its txid.
pub fn check_tx(
    tx: SignedTx,
    chain_id: ChainId,
    scratch: &mut Scratch,
) -> Result<CheckedTx, InvalidTx> {
    check_tx_with(&tx, chain_id, &mut scratch.signing)?;
    let txid = txid(&tx);
    Ok(CheckedTx { tx, txid })
}

/// The answer of a peer after the precheck.
#[derive(Debug)]
pub enum Fetched {
    Headers(Vec<BlockHeader>),
    Blocks(Vec<CheckedBlock>),
}

/// Prechecks every item of `response`: the chain id and work claim of each header, each block as
/// [`check_block`], and the count against what one request may ask for.
pub fn check_response(
    response: SyncResponse,
    params: &ConsensusParams,
    scratch: &mut Scratch,
) -> Result<Fetched, PrecheckError> {
    match response {
        SyncResponse::Headers(headers) => {
            within(headers.len(), MAX_HEADERS_PER_RESPONSE)?;
            for header in &headers {
                check_announce(header, params)?;
            }
            Ok(Fetched::Headers(headers))
        }
        SyncResponse::Blocks(blocks) => {
            within(blocks.len(), MAX_BLOCKS_PER_REQUEST)?;
            let checked = blocks
                .into_iter()
                .map(|bytes| check_block(bytes, params, scratch))
                .collect::<Result<_, _>>()?;
            Ok(Fetched::Blocks(checked))
        }
    }
}

fn within(found: usize, limit: usize) -> Result<(), PrecheckError> {
    if found > limit {
        return Err(PrecheckError::Oversized { found, limit });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
