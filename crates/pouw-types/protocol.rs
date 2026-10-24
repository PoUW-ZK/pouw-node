//! Every fixed protocol constant of block.md: the header version, the domain
//! prefixes and the size limits. Changing a value here forks the chain, so a change
//! goes through a pull request to block.md first.
//!
//! Values that a chain chooses (subsidy, block time, fee coefficients) are in its chain
//! spec, [`crate::ConsensusParams`] under [`crate::ChainSpec`].

pub use pouw_crypto::FIELD_INPUT_BYTES;

/// Block header version produced and accepted by this code.
pub const BLOCK_VERSION: u32 = 1;

/// Prefix of the bytes a transaction signature covers.
pub const DOMAIN_TX_SIG: &[u8] = b"pouw-zk/tx-sig/v1";
/// Prefix of the bytes a block id covers, followed by the 168 header bytes.
pub const DOMAIN_HEADER: &[u8] = b"pouw-zk/header/v1";
/// First byte hashed for a Merkle leaf (RFC 6962).
pub const DOMAIN_LEAF: u8 = 0x00;
/// First byte hashed for an inner Merkle node (RFC 6962).
pub const DOMAIN_NODE: u8 = 0x01;
/// First byte hashed for the bound root: `tx_root = sha256(0x02 || u32le(n) || merkle_root)`.
pub const DOMAIN_COUNT: u8 = 0x02;
/// Prefix of every integrity parameter hash.
pub const DOMAIN_ETA: &[u8] = b"pouw-zk/eta/v1";
/// Prefix of every mask hash.
pub const DOMAIN_MASK: &[u8] = b"pouw-zk/mask/v1";
/// Prefix of the leaf hash of a genesis allocation, see [`crate::ChainSpec`].
pub const DOMAIN_GENESIS_ALLOC: &[u8] = b"pouw-zk/genesis-alloc/v1";

/// Field elements in the `public_inputs` of one proof request.
pub const MAX_PUBLIC_INPUTS: usize = 64;
/// Bytes of `witness` in one proof request.
pub const MAX_WITNESS_BYTES: usize = 1 << 20;
/// Bytes of `proof` in one proof tx.
pub const MAX_PROOF_BYTES: usize = 4096;
/// Bytes of `verifying_key` and `circuit` together in one `RegisterCircuit`. Below
/// [`MAX_BLOCK_BYTES`], so every valid registration fits in a block.
pub const MAX_CIRCUIT_BYTES: usize = 4 << 20;
/// Borsh size of a whole `Block`.
pub const MAX_BLOCK_BYTES: usize = 8 << 20;
/// Entries of `proof_txs` in one block: one proof per block, so a block costs one
/// proof verification.
pub const MAX_PROOFS_PER_BLOCK: usize = 1;
/// Entries of `txs` plus `proof_txs` in one block.
pub const MAX_TXS_PER_BLOCK: usize = 1024;
