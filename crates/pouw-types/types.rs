use borsh::{BorshDeserialize, BorshSerialize};
use pouw_crypto::{Address, FieldInput, Hash32, Signature, serde_base64};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use zerocopy::{
    FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned,
    little_endian::{U32, U64},
};

use crate::{
    ids::{BlockId, CircuitId},
    protocol::BLOCK_VERSION,
    work::Target,
};

macro_rules! quantity {
    ($($(#[$meta:meta])* $name:ident($inner:ty);)*) => {$(
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
            BorshSerialize, BorshDeserialize, Serialize, Deserialize,
        )]
        #[repr(transparent)]
        #[serde(transparent)]
        pub struct $name(pub $inner);
    )*};
}

quantity! {
    /// Position of a block, genesis is 0.
    Height(u64);
    /// Smallest coin unit. Fees are amounts too.
    Amount(u64);
    /// Number of transactions the sender sent before this one.
    Nonce(u64);
    /// The usage counter of a (miner, circuit) pair, ADR-0007.
    UsageCounter(u64);
    /// Unix seconds.
    Timestamp(u64);
    /// Network identifier fixed by genesis.
    ChainId(u32);
    /// Proof system that produced the work of a block. 0 is the hash proof of work of
    /// header v1, other values are reserved for the research systems.
    SystemId(u64);
    /// The number a miner varies to search for a block id under the target. It is
    /// not the transaction [`Nonce`].
    PowNonce(u64);
    /// Complexity measure of a circuit as registered on chain (ADR-0006).
    ConstraintCount(u64);
}

impl Amount {
    /// `None` on overflow.
    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    /// `None` when `other` is larger.
    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }
}

macro_rules! counter {
    ($($name:ident),*) => {$(
        impl $name {
            /// The value plus one, `None` on overflow.
            pub fn checked_next(self) -> Option<$name> {
                self.0.checked_add(1).map($name)
            }
        }
    )*};
}

counter!(Height, Nonce, UsageCounter);

/// Proof system of a registered circuit. The set follows ADR-0006 and is expected to
/// change, see the open point on `FieldInput` in block.md.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[borsh(use_discriminant = true)]
#[repr(u8)]
#[non_exhaustive]
pub enum ProofSystem {
    /// Groth16 over BN254, per-circuit setup.
    Groth16 = 0,
    /// PLONK with KZG commitments, universal setup.
    PlonkKzg = 1,
    /// Marlin, universal setup.
    Marlin = 2,
}

impl ProofSystem {
    /// The lowercase tag of the JSON view.
    pub fn as_str(self) -> &'static str {
        match self {
            ProofSystem::Groth16 => "groth16",
            ProofSystem::PlonkKzg => "plonk_kzg",
            ProofSystem::Marlin => "marlin",
        }
    }
}

/// A transaction as a client signs it and as it sits in the mempool.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct SignedTx {
    /// The signed part.
    pub body: TxBody,
    /// `ed25519(sk, DOMAIN_TX_SIG || borsh(body))`
    pub signature: Signature,
}

/// The part of a transaction its sender signs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct TxBody {
    /// Must equal the chain id of the node.
    pub chain_id: ChainId,
    /// Signer and payer.
    pub sender: Address,
    /// Must equal the nonce of the sender's account.
    pub nonce: Nonce,
    /// Paid to the miner of the including block.
    pub fee: Amount,
    /// What the transaction does.
    #[serde(flatten)]
    pub kind: TxKind,
}

/// The kind-specific fields of a [`TxBody`]. The borsh tag is the variant index.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum TxKind {
    /// Moves `amount` from the sender to `to`.
    Transfer {
        /// Receiver.
        to: Address,
        /// Coins moved, the fee is extra.
        amount: Amount,
    },
    /// Asks the miners to prove `circuit` on the given inputs.
    ProofRequest {
        /// A registered circuit.
        circuit: CircuitId,
        /// The client part of the public inputs.
        public_inputs: Vec<FieldInput>,
        /// Bytes only the prover needs, public on chain (ADR-0011).
        #[serde(with = "serde_base64")]
        witness: Box<[u8]>,
    },
    /// Adds a circuit to the registry. Its txid becomes the circuit id.
    RegisterCircuit {
        /// Proof system the keys belong to.
        system: ProofSystem,
        /// Complexity measure of ADR-0006.
        constraint_count: ConstraintCount,
        /// In the backend's own serialization.
        #[serde(with = "serde_base64")]
        verifying_key: Box<[u8]>,
        /// The circuit in the backend's own serialization.
        #[serde(with = "serde_base64")]
        circuit: Box<[u8]>,
    },
}

impl TxKind {
    /// The lowercase tag of the JSON view.
    pub fn name(&self) -> &'static str {
        match self {
            TxKind::Transfer { .. } => "transfer",
            TxKind::ProofRequest { .. } => "proof_request",
            TxKind::RegisterCircuit { .. } => "register_circuit",
        }
    }
}

/// A proof request after a miner proved it. This is what a block holds.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ProofTx {
    /// Its kind is `ProofRequest`; the request id is its txid.
    pub request: SignedTx,
    /// Usage counter of (`header.miner`, circuit) for this proof.
    pub usage_counter: UsageCounter,
    /// In the backend's own serialization.
    #[serde(with = "serde_base64")]
    pub proof: Box<[u8]>,
}

/// The hashed part of a block: 168 bytes, the same bytes as its borsh encoding, every
/// integer little-endian. A stored block starts with them, so a slice is read in place
/// with [`FromBytes::ref_from_bytes`] or [`FromBytes::ref_from_prefix`], and
/// [`BlockHeader::ref_from_versioned`] dispatches on `version`.
///
/// Layout, byte offset and size of each field:
///
/// | field       | offset | bytes | encoding                    |
/// | ----------- | ------ | ----- | --------------------------- |
/// | `version`   | 0      | 4     | u32 little-endian           |
/// | `chain_id`  | 4      | 4     | u32 little-endian           |
/// | `system_id` | 8      | 8     | u64 little-endian           |
/// | `height`    | 16     | 8     | u64 little-endian           |
/// | `parent`    | 24     | 32    | raw hash bytes              |
/// | `timestamp` | 56     | 8     | u64 little-endian, seconds  |
/// | `miner`     | 64     | 32    | raw Ed25519 public key      |
/// | `tx_root`   | 96     | 32    | raw hash bytes              |
/// | `target`    | 128    | 32    | 256-bit unsigned big-endian |
/// | `nonce`     | 160    | 8     | u64 little-endian           |
///
/// The struct has no padding and no alignment requirement, so any 168 bytes with a
/// known `version` are a header. The block id is [`crate::block_id`] of exactly these
/// bytes. A header has no transaction count: `tx_root` binds the leaf count `n`, as
/// `sha256(0x02 || u32le(n) || merkle_root)`, so an inclusion proof carries `n` and
/// verifies against the header alone.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct BlockHeader {
    /// [`crate::protocol::BLOCK_VERSION`], decides the layout of the rest.
    pub version: U32,
    /// Must equal the chain id of the node, so a header cannot be replayed on another
    /// network.
    pub chain_id: U32,
    /// Proof system of the work in this block, see [`SystemId`]. 0 in v1.
    pub system_id: U64,
    /// Parent height plus one.
    pub height: U64,
    /// Id of the parent block, [`BlockId::ZERO`] in the genesis block.
    pub parent: BlockId,
    /// Unix seconds by the miner's clock.
    pub timestamp: U64,
    /// Receives the block reward and all fees.
    pub miner: Address,
    /// Merkle root over `txs` then `proof_txs`, RFC 6962.
    pub tx_root: Hash32,
    /// The block id, read as a 256-bit big-endian number, must not exceed this.
    pub target: Target,
    /// Varied by the miner, see [`PowNonce`].
    pub nonce: U64,
}

/// Why bytes are not a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HeaderError {
    /// Fewer than the 4 bytes of the version prefix.
    #[error("{found} bytes are too short for a header version")]
    TooShort { found: usize },
    /// No layout is defined for this version.
    #[error("unknown header version {0}")]
    UnknownVersion(u32),
    /// The length differs from the layout of the version.
    #[error("{found} bytes is not the length of the header layout")]
    BadLength { found: usize },
}

impl BlockHeader {
    /// Size of the encoding in bytes.
    pub const SIZE: usize = size_of::<BlockHeader>();

    /// Reads the version prefix first, then the layout it names.
    pub fn ref_from_versioned(bytes: &[u8]) -> Result<&BlockHeader, HeaderError> {
        #[expect(
            clippy::map_err_ignore,
            reason = "the zerocopy error borrows the input, `found` carries its length"
        )]
        let (version, _) = U32::ref_from_prefix(bytes)
            .map_err(|_| HeaderError::TooShort { found: bytes.len() })?;
        match version.get() {
            #[expect(
                clippy::map_err_ignore,
                reason = "the zerocopy error borrows the input, `found` carries its length"
            )]
            BLOCK_VERSION => BlockHeader::ref_from_bytes(bytes)
                .map_err(|_| HeaderError::BadLength { found: bytes.len() }),
            other => Err(HeaderError::UnknownVersion(other)),
        }
    }
}

const _: () = assert!(BlockHeader::SIZE == 168);

impl BorshSerialize for BlockHeader {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(self.as_bytes())
    }
}

impl BorshDeserialize for BlockHeader {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut header = Self::new_zeroed();
        reader.read_exact(header.as_mut_bytes())?;
        Ok(header)
    }
}

/// The JSON view of a [`BlockHeader`] with plain integers.
#[derive(Serialize, Deserialize)]
struct HeaderFields {
    version: u32,
    chain_id: ChainId,
    system_id: SystemId,
    height: Height,
    parent: BlockId,
    timestamp: Timestamp,
    miner: Address,
    tx_root: Hash32,
    target: Target,
    nonce: PowNonce,
}

impl Serialize for BlockHeader {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        HeaderFields {
            version: self.version.get(),
            chain_id: ChainId(self.chain_id.get()),
            system_id: SystemId(self.system_id.get()),
            height: Height(self.height.get()),
            parent: self.parent,
            timestamp: Timestamp(self.timestamp.get()),
            miner: self.miner,
            tx_root: self.tx_root,
            target: self.target,
            nonce: PowNonce(self.nonce.get()),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BlockHeader {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let f = HeaderFields::deserialize(deserializer)?;
        Ok(Self {
            version: U32::new(f.version),
            chain_id: U32::new(f.chain_id.0),
            system_id: U64::new(f.system_id.0),
            height: U64::new(f.height.0),
            parent: f.parent,
            timestamp: U64::new(f.timestamp.0),
            miner: f.miner,
            tx_root: f.tx_root,
            target: f.target,
            nonce: U64::new(f.nonce.0),
        })
    }
}

/// A full block.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Block {
    /// Commits to the rest through `tx_root`.
    pub header: BlockHeader,
    /// `Transfer` and `RegisterCircuit` only.
    pub txs: Vec<SignedTx>,
    /// Proved requests, in eta chaining order.
    pub proof_txs: Vec<ProofTx>,
}

impl Block {
    /// Number of Merkle leaves: `txs` plus `proof_txs`.
    pub fn leaf_count(&self) -> usize {
        self.txs.len().saturating_add(self.proof_txs.len())
    }
}

/// State kept by every full node for one address.
#[derive(
    Debug, Clone, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Account {
    pub balance: Amount,
    /// Nonce the next transaction of this address must carry.
    pub nonce: Nonce,
}

/// Registry entry created when a `RegisterCircuit` transaction is applied.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct CircuitEntry {
    /// Txid of the `RegisterCircuit` transaction.
    pub id: CircuitId,
    /// Proof system the keys belong to.
    pub system: ProofSystem,
    /// Complexity measure of ADR-0006.
    pub constraint_count: ConstraintCount,
    /// Sender of the `RegisterCircuit` transaction.
    pub owner: Address,
    /// Height of the block that applied it.
    pub registered_at: Height,
    /// In the backend's own serialization.
    #[serde(with = "serde_base64")]
    pub verifying_key: Box<[u8]>,
    /// In the backend's own serialization.
    #[serde(with = "serde_base64")]
    pub circuit: Box<[u8]>,
}
