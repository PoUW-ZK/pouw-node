//! JSON views of `contracts/node-api.yaml`. The wire types of `pouw-types` plus the
//! derived fields the node adds (ADR-0007, ADR-0008).

use pouw_crypto::{Address, FieldInput, Hash32, serde_base64};
use pouw_types::{
    Account, Amount, Block, BlockHeader, BlockId, ChainId, CircuitEntry, CircuitId,
    ConstraintCount, Height, Nonce, ProofHash, ProofSystem, ProofTx, SignedTx, TxId, UsageCounter,
    block_id, proof_tx_hash, txid,
};
use serde::{Deserialize, Serialize};

/// Most blocks one `GET /v1/blocks` answers.
pub const MAX_BLOCKS_PER_CALL: u64 = 100;
/// Most headers one `GET /v1/headers` answers.
pub const MAX_HEADERS_PER_CALL: u64 = 1000;

/// A signed transaction with its `txid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTxView {
    /// `sha256(borsh(tx))`.
    pub txid: TxId,
    /// `body` and `signature`.
    #[serde(flatten)]
    pub tx: SignedTx,
}

impl From<&SignedTx> for SignedTxView {
    fn from(tx: &SignedTx) -> Self {
        Self {
            txid: txid(tx),
            tx: tx.clone(),
        }
    }
}

/// Where a transaction is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxStatus {
    Pending,
    /// In a block of the canonical chain.
    Included,
}

/// Answer of `GET /v1/txs/{txid}`. The optional fields are set once the tx is
/// included, and the proof fields only for an included proof request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxView {
    pub txid: TxId,
    pub status: TxStatus,
    /// The transaction; for a proof request, the request.
    pub tx: SignedTxView,
    /// Height of the including block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<Height>,
    /// Leaf index in the Merkle tree of that block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    /// Derived fields of an included proof request.
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<IncludedProof>,
}

/// Fields of [`TxView`] that only an included proof request has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncludedProof {
    /// The first public input.
    pub eta: FieldInput,
    /// The second public input.
    pub mask: FieldInput,
    /// From the registry entry of the circuit.
    pub proof_system: ProofSystem,
    /// Stored in the proof tx.
    pub usage_counter: UsageCounter,
    #[serde(with = "serde_base64")]
    pub proof: Box<[u8]>,
    /// The Merkle leaf id.
    pub proof_hash: ProofHash,
}

/// A proof tx with its derived fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTxView {
    /// `sha256(borsh(proof_tx))`.
    pub proof_hash: ProofHash,
    /// Txid of the request.
    pub request_txid: TxId,
    /// The request with its txid.
    pub request: SignedTxView,
    /// Stored usage counter.
    pub usage_counter: UsageCounter,
    #[serde(with = "serde_base64")]
    pub proof: Box<[u8]>,
    /// Derived, the first public input.
    pub eta: FieldInput,
    /// Derived, the second public input.
    pub mask: FieldInput,
    /// Derived from the registry entry of the circuit.
    pub proof_system: ProofSystem,
}

impl ProofTxView {
    /// The view of `proof_tx` with the derived fields the caller computed from the
    /// block and the registry.
    pub fn new(
        proof_tx: &ProofTx,
        eta: FieldInput,
        mask: FieldInput,
        proof_system: ProofSystem,
    ) -> Self {
        let request = SignedTxView::from(&proof_tx.request);
        Self {
            proof_hash: proof_tx_hash(proof_tx),
            request_txid: request.txid,
            request,
            usage_counter: proof_tx.usage_counter,
            proof: proof_tx.proof.clone(),
            eta,
            mask,
            proof_system,
        }
    }
}

/// A header with its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderView {
    /// [`block_id`] of `header`.
    pub id: BlockId,
    pub header: BlockHeader,
}

impl From<&BlockHeader> for HeaderView {
    fn from(header: &BlockHeader) -> Self {
        Self {
            id: block_id(header),
            header: *header,
        }
    }
}

/// A block with its id and the views of its entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockView {
    /// [`block_id`] of `header`.
    pub id: BlockId,
    pub header: BlockHeader,
    /// `Transfer` and `RegisterCircuit` entries.
    pub txs: Vec<SignedTxView>,
    /// Proof txs with their derived fields, in block order.
    pub proof_txs: Vec<ProofTxView>,
}

impl BlockView {
    /// The view of `block`, with `proof_txs` built by [`ProofTxView::new`] in block
    /// order.
    pub fn new(block: &Block, proof_txs: Vec<ProofTxView>) -> Self {
        Self {
            id: block_id(&block.header),
            header: block.header,
            txs: block.txs.iter().map(SignedTxView::from).collect(),
            proof_txs,
        }
    }
}

/// Answer of `GET /v1/blocks` in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocksPage {
    /// Ascending heights.
    pub blocks: Vec<BlockView>,
}

/// Answer of `GET /v1/headers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadersPage {
    /// Ascending heights.
    pub headers: Vec<HeaderView>,
}

/// A circuit registry entry, with the blobs only on `?include=keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitView {
    /// Txid of the `RegisterCircuit` transaction.
    pub id: CircuitId,
    /// Proof system of the keys.
    pub system: ProofSystem,
    /// Complexity measure of ADR-0006.
    pub constraint_count: ConstraintCount,
    /// Sender of the `RegisterCircuit` transaction.
    pub owner: Address,
    /// Height of the block that applied it.
    pub registered_at: Height,
    /// With `include=keys` only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_base64"
    )]
    pub verifying_key: Option<Box<[u8]>>,
    /// With `include=keys` only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_base64"
    )]
    pub circuit: Option<Box<[u8]>>,
}

impl CircuitView {
    /// The view of `entry`, with the blobs when `include_keys`.
    pub fn new(entry: &CircuitEntry, include_keys: bool) -> Self {
        Self {
            id: entry.id,
            system: entry.system,
            constraint_count: entry.constraint_count,
            owner: entry.owner,
            registered_at: entry.registered_at,
            verifying_key: include_keys.then(|| entry.verifying_key.clone()),
            circuit: include_keys.then(|| entry.circuit.clone()),
        }
    }
}

mod optional_base64 {
    use serde::{Deserialize, Deserializer, Serializer};

    #[expect(clippy::ref_option, reason = "the signature serde's `with` requires")]
    pub fn serialize<S: Serializer>(
        bytes: &Option<Box<[u8]>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => pouw_crypto::serde_base64::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Box<[u8]>>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapped(#[serde(with = "pouw_crypto::serde_base64")] Box<[u8]>);
        Ok(Option::<Wrapped>::deserialize(deserializer)?.map(|Wrapped(bytes)| bytes))
    }
}

/// Answer of `GET /v1/accounts/{addr}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountView {
    pub address: Address,
    pub balance: Amount,
    /// Nonce of the next transaction.
    pub nonce: Nonce,
}

impl AccountView {
    /// The view of the account of `address`.
    pub fn new(address: Address, account: &Account) -> Self {
        Self {
            address,
            balance: account.balance,
            nonce: account.nonce,
        }
    }
}

/// Answer of `GET /v1/txs/{txid}/inclusion-proof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// The including block.
    pub height: Height,
    /// Leaf position.
    pub index: u32,
    /// Leaves of the block's tree (`txs` plus `proof_txs`). The verifier reads it from
    /// the proof and the header `tx_root` binds it, so it needs no block.
    pub leaf_count: u32,
    /// Sibling hashes from the leaf up.
    pub siblings: Vec<Hash32>,
}

/// Answer of `GET /v1/mempool`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolView {
    pub tx_count: u32,
    pub proof_request_count: u32,
    pub txids: Vec<TxId>,
}

/// Answer of `GET /v1/node`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Chain id of genesis.
    pub chain_id: ChainId,
    /// Semantic version of the node.
    pub version: String,
    pub height: Height,
    pub peers: u32,
}

/// Answer of `POST /v1/txs`, HTTP 202.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    /// Handle for polling `GET /v1/txs/{txid}`.
    pub txid: TxId,
}
