//! The chain spec: the JSON file that fixes a chain before its first block.
//!
//! The structs here are the file format. Field names are the JSON keys and unknown keys
//! are an error. Quantities are JSON integers. Ids and keys use their text forms
//! (`addr:<64 hex>`, `blk:<64 hex>`), and 256-bit numbers are 64 lowercase hex digits.
//!
//! The module lives in `pouw-types` so the light client reads the same file without
//! depending on the node or the consensus crate.
//!
//! The genesis block is derived from the spec by [`genesis_block`]:
//!
//! - `version` is `BLOCK_VERSION`, `system_id` and `height` are 0, `parent` is zero.
//! - `chain_id` is `params.chain_id`. `timestamp`, `miner`, `target` and `nonce` come
//!   from the `genesis` section.
//! - `tx_root` commits to the allocations: the [`bound_root`] of the allocation count
//!   and the [`merkle_root`] over one leaf per allocation in listed order, where a leaf is
//!   `sha256(DOMAIN_GENESIS_ALLOC || address (32 bytes) || amount (u64 little-endian))`.
//!   No allocations give the root of an empty block.
//! - `txs` and `proof_txs` are empty. The proof of work of genesis is not checked.
//!
//! So `expected_genesis_id` commits to every consensus parameter that sits in the
//! header, and to the initial balances. A node refuses to start when the id it computes
//! differs from `expected_genesis_id`, see [`check_genesis`].
//!
//! The size caps of blocks and transactions are fixed protocol constants in
//! [`crate::protocol`], they are not part of the spec.

use std::{collections::BTreeSet, fmt};

use pouw_crypto::{Address, Hash32, sha256};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Amount, Block, BlockHeader, BlockId, ChainId, CumWork, PowNonce, Target, Timestamp, U32, U64,
    block_id, bound_root, leaf_count_u32, merkle_root,
    protocol::{BLOCK_VERSION, DOMAIN_GENESIS_ALLOC},
};

/// Values every node of one chain must agree on. Each value is an open point of
/// block.md. The field says what it sets, not how it is chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusParams {
    /// Chain id signed into every transaction and carried by every header.
    pub chain_id: ChainId,
    /// New coins credited to `header.miner` per block before the first halving, see
    /// `pouw_consensus::reward::subsidy`.
    pub initial_subsidy: Amount,
    /// Blocks between two halvings of the subsidy.
    pub halving_interval: u64,
    /// Block time the target rule aims at, in seconds. Must be above zero.
    pub target_block_secs: u64,
    /// Seconds of schedule lag or lead that move the target by a factor of two, see
    /// `pouw_consensus::difficulty::next_target`. Must be above zero.
    pub half_life_secs: u64,
    /// `header.target` of the first block after genesis. Nonzero and at most
    /// `pow_limit`.
    pub initial_target: Target,
    /// The easiest target any block may carry. The target rule clamps to it and the
    /// proof of work check rejects a header above it.
    pub pow_limit: Target,
    /// How far a header timestamp may run ahead of the clock of the verifying node,
    /// in seconds, see `pouw_consensus::timestamp::check`.
    pub max_future_secs: u64,
    /// Fee coefficient per public input element of a proof request.
    pub fee_per_public_input: Amount,
    /// Fee coefficient per started KiB of witness of a proof request.
    pub fee_per_witness_kib: Amount,
}

/// The header fields of the genesis block that the spec chooses. The rest of the header
/// follows from the rules in the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisHeader {
    /// Unix seconds. The target rule schedules block 1 from this time, so a chain
    /// started long after it begins with a burst of easy blocks.
    pub timestamp: Timestamp,
    /// Recipient of nothing: genesis pays no subsidy. The key is only a header field.
    pub miner: Address,
    /// The target field of the genesis header. Not checked against the proof of work.
    pub target: Target,
    /// The nonce field of the genesis header.
    pub nonce: PowNonce,
}

/// An initial balance, credited to `address` in the state after genesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    /// The account that receives the balance, nonce 0.
    pub address: Address,
    /// Amount in the smallest coin unit, above zero.
    pub amount: Amount,
}

/// Name of a network, used in protocol ids as `/pouw/<network>/...`. One to 32
/// characters of `a-z`, `0-9` and `-`, not starting or ending with `-`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NetworkName(String);

impl NetworkName {
    /// The validated name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for NetworkName {
    type Error = SpecError;

    fn try_from(name: String) -> Result<Self, SpecError> {
        let allowed = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
        let valid = (1..=32).contains(&name.len())
            && name.chars().all(allowed)
            && !name.starts_with('-')
            && !name.ends_with('-');
        if valid {
            Ok(NetworkName(name))
        } else {
            Err(SpecError::BadNetworkName(name))
        }
    }
}

impl From<NetworkName> for String {
    fn from(name: NetworkName) -> String {
        name.0
    }
}

impl fmt::Display for NetworkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Everything that fixes a chain before its first block. This is the JSON file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainSpec {
    /// Name of the network, see [`NetworkName`].
    pub network: NetworkName,
    /// The consensus parameters.
    pub params: ConsensusParams,
    /// The header fields of the genesis block.
    pub genesis: GenesisHeader,
    /// Initial balances, committed by the genesis id. Addresses are unique.
    pub allocations: Vec<Allocation>,
    /// Cumulative work below which initial block download does not accept a chain as
    /// the best one, 64 hex digits. Read by IBD (pouw-node#90), a hint and not a rule of
    /// block validity.
    pub min_chain_work: CumWork,
    /// A block id whose ancestors initial block download may accept without checking
    /// proofs of work. Absent means every block is checked. Read by IBD
    /// (pouw-node#90).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assume_valid: Option<BlockId>,
    /// The id the genesis block built from this spec must have.
    pub expected_genesis_id: BlockId,
}

/// Why a spec is not usable.
#[derive(Debug, Error)]
pub enum SpecError {
    /// Not JSON of the spec format, or an unknown or missing field.
    #[error("chain spec is not valid: {0}")]
    Json(#[from] serde_json::Error),
    /// The network name breaks the rules of [`NetworkName`].
    #[error("network name {0:?} must be 1 to 32 characters of a-z, 0-9 and '-', not at the ends")]
    BadNetworkName(String),
    /// A consensus parameter is out of range.
    #[error("bad consensus parameters: {0}")]
    BadParams(&'static str),
    /// Two allocations name the same address.
    #[error("address {0} is allocated twice")]
    DuplicateAllocation(Address),
    /// An allocation has amount zero.
    #[error("allocation for {0} is zero")]
    ZeroAllocation(Address),
    /// The allocations sum above `u64::MAX`.
    #[error("the allocations overflow the total supply")]
    SupplyOverflow,
    /// The genesis block built from the spec has another id than the spec expects.
    #[error("genesis id is {computed} but the spec expects {expected}")]
    GenesisMismatch {
        /// The id of the block built from the spec.
        computed: BlockId,
        /// `expected_genesis_id`.
        expected: BlockId,
    },
}

/// Parses and validates a spec. Does not compare the genesis id, see [`check_genesis`].
pub fn parse_chain_spec(json: &str) -> Result<ChainSpec, SpecError> {
    let spec: ChainSpec = serde_json::from_str(json)?;
    validate(&spec)?;
    Ok(spec)
}

fn validate(spec: &ChainSpec) -> Result<(), SpecError> {
    let params = &spec.params;
    if params.target_block_secs == 0 {
        return Err(SpecError::BadParams("target_block_secs is zero"));
    }
    if params.half_life_secs == 0 {
        return Err(SpecError::BadParams("half_life_secs is zero"));
    }
    if params.initial_target.to_u256().is_zero() {
        return Err(SpecError::BadParams("initial_target is zero"));
    }
    if params.initial_target > params.pow_limit {
        return Err(SpecError::BadParams("initial_target is above pow_limit"));
    }
    let mut seen = BTreeSet::new();
    let mut total = Amount(0);
    for allocation in &spec.allocations {
        if allocation.amount.0 == 0 {
            return Err(SpecError::ZeroAllocation(allocation.address));
        }
        if !seen.insert(allocation.address) {
            return Err(SpecError::DuplicateAllocation(allocation.address));
        }
        total = total
            .checked_add(allocation.amount)
            .ok_or(SpecError::SupplyOverflow)?;
    }
    Ok(())
}

fn allocation_leaf(allocation: &Allocation) -> Hash32 {
    sha256(&[
        DOMAIN_GENESIS_ALLOC,
        &allocation.address.0,
        &allocation.amount.0.to_le_bytes(),
    ])
}

/// The genesis block of `spec`, by the rules in the module docs.
pub fn genesis_block(spec: &ChainSpec) -> Block {
    let leaves: Vec<Hash32> = spec.allocations.iter().map(allocation_leaf).collect();
    Block {
        header: BlockHeader {
            version: U32::new(BLOCK_VERSION),
            chain_id: U32::new(spec.params.chain_id.0),
            system_id: U64::new(0),
            height: U64::new(0),
            parent: BlockId::ZERO,
            timestamp: U64::new(spec.genesis.timestamp.0),
            miner: spec.genesis.miner,
            tx_root: bound_root(leaf_count_u32(leaves.len()), &merkle_root(&leaves)),
            target: spec.genesis.target,
            nonce: U64::new(spec.genesis.nonce.0),
        },
        txs: Vec::new(),
        proof_txs: Vec::new(),
    }
}

/// The id of the genesis block of `spec`. A new spec takes this value as its
/// `expected_genesis_id`.
pub fn genesis_id(spec: &ChainSpec) -> BlockId {
    block_id(&genesis_block(spec).header)
}

/// The genesis block of `spec` when its id is `expected_genesis_id`.
pub fn check_genesis(spec: &ChainSpec) -> Result<Block, SpecError> {
    let block = genesis_block(spec);
    let computed = block_id(&block.header);
    if computed == spec.expected_genesis_id {
        Ok(block)
    } else {
        Err(SpecError::GenesisMismatch {
            computed,
            expected: spec.expected_genesis_id,
        })
    }
}

#[cfg(test)]
mod tests;
