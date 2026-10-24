//! The tables of the store and the byte layout of their keys and values. The tables are
//! the ABI of the store: any engine that holds them with these keys and values is a
//! backend, and the memory backend (`store/mem.rs`) holds exactly these.
//!
//! | table         | key                          | value                                   |
//! | ------------- | ---------------------------- | --------------------------------------- |
//! | `meta`        | name: `schema_version`, `genesis`, `tip` | [`Meta`] field                |
//! | `headers`     | [`BlockId`], 32 bytes        | the 168 byte `BlockHeader`, zerocopy        |
//! | `block_index` | [`BlockId`], 32 bytes        | the 41 byte [`IndexEntry`], zerocopy    |
//! | `bodies`      | [`BlockId`], 32 bytes        | the received block bytes, borsh         |
//! | `canonical`   | height, u64 big-endian, 8 bytes | [`BlockId`], 32 bytes                |
//! | `undo`        | [`BlockId`], 32 bytes        | `StateDiff` of the block, borsh         |
//! | `tx_index`    | `TxId`, 32 bytes             | the 36 byte [`TxEntry`], zerocopy       |
//! | state         | as `StateView` keys          | accounts, circuits, usage counters      |
//!
//! Keys of the block tables are block ids, which are proof-of-work checked, so a peer
//! cannot choose them freely. The `canonical` key is big-endian so that a range scan
//! visits heights in order.
//!
//! # Who writes what
//!
//! Only the free functions of `store.rs` write, each in one atomic step:
//!
//! - `put_header` writes `headers` and `block_index`;
//! - `put_body` writes `bodies` and sets [`Status::BODY_STORED`];
//! - `mark_work_valid` and `mark_failed` set their status bit;
//! - `connect_block` writes the state tables, `undo`, `tx_index`, `canonical`,
//!   `meta.tip` (and `meta.genesis` for height 0) and sets [`Status::CONNECTED`];
//! - `disconnect_tip` reverses what `connect_block` wrote for the tip block.
//!
//! # Invariants
//!
//! A backend and every writer keep them, and the tests in `store/tests.rs` check them:
//!
//! 1. A `block_index` entry exists for every `headers` row and the reverse.
//! 2. The parent of every header other than a genesis header is indexed, and
//!    `height = parent height + 1`, `work = parent work + block_work(target)`.
//! 3. A `bodies` row exists exactly when [`Status::BODY_STORED`] is set, and its first
//!    168 bytes equal the `headers` row of the same id.
//! 4. `canonical` holds every height from 0 to the tip height, with no gap and nothing
//!    above, and a block is in it exactly when [`Status::CONNECTED`] is set.
//! 5. `canonical[h]` is the parent of `canonical[h + 1]`, and `meta.tip` is the last one.
//! 6. `undo` has a row for every connected block except genesis, and `tx_index` has a
//!    row for every transaction of every connected block and nothing else.
//! 7. A block with [`Status::FAILED`] is never connected, and a header whose parent has
//!    [`Status::FAILED`] gets it too.

use pouw_types::{BlockId, CumWork, Height, U32, U64, U256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The layout version of every table above. A store written with another version is
/// refused when it is opened. Raise it with any change of a key or value layout.
pub const SCHEMA_VERSION: u32 = 1;

/// The `meta` table: three rows, each present once it has a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    /// Row `schema_version`, a u32 little-endian. Written when the store is created.
    pub schema_version: u32,
    /// Row `genesis`, 32 bytes. The id of the block at height 0, written when it is
    /// connected, and never changed after.
    pub genesis: Option<BlockId>,
    /// Row `tip`, 32 bytes. The id of the last canonical block, so the tip height and
    /// work are its `block_index` entry. Absent before genesis is connected.
    pub tip: Option<BlockId>,
}

impl Default for Meta {
    fn default() -> Self {
        Meta {
            schema_version: SCHEMA_VERSION,
            genesis: None,
            tip: None,
        }
    }
}

/// What the node knows about a block, one bit each. A bit is set and never cleared,
/// except [`Status::CONNECTED`], which follows the canonical chain.
///
/// The bits the block path sets, in order: [`Status::HEADER_VALID`] when the header is
/// indexed, [`Status::BODY_STORED`] when the body is stored, [`Status::WORK_VALID`] when
/// the work of the block is verified, [`Status::CONNECTED`] when it is on the canonical
/// chain.
///
/// # Failed blocks
///
/// [`Status::FAILED`] marks a block that broke a rule after its header was accepted
/// (Bitcoin `BLOCK_FAILED_VALID`), and a header whose parent is failed carries it from
/// the start (Bitcoin `BLOCK_FAILED_CHILD`), so the descendants of a failed block are
/// failed. `connect_block` refuses a failed block. A descendant stored before its
/// ancestor failed keeps its status here: `chain::find_branch` meets the failed
/// ancestor on its walk, fork choice skips that branch, and the descendants on it are
/// marked failed then.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(transparent)]
pub struct Status(pub u8);

impl Status {
    /// No bit set.
    pub const NONE: Status = Status(0);
    /// The header is indexed and its parent is known.
    pub const HEADER_VALID: Status = Status(1);
    /// The body is in `bodies`.
    pub const BODY_STORED: Status = Status(1 << 1);
    /// The work of the block (its proof of work, in v2 the re-derivation) is verified.
    pub const WORK_VALID: Status = Status(1 << 2);
    /// The block is on the canonical chain.
    pub const CONNECTED: Status = Status(1 << 3);
    /// The block, or an ancestor of it, is invalid.
    pub const FAILED: Status = Status(1 << 4);

    /// Whether every bit of `flag` is set.
    pub const fn contains(self, flag: Status) -> bool {
        self.0 & flag.0 == flag.0
    }

    /// `self` with the bits of `flag` set.
    #[must_use]
    pub const fn with(self, flag: Status) -> Status {
        Status(self.0 | flag.0)
    }

    /// `self` with the bits of `flag` cleared.
    #[must_use]
    pub const fn without(self, flag: Status) -> Status {
        Status(self.0 & !flag.0)
    }
}

/// A row of `block_index`: 41 bytes, no padding.
///
/// | field      | offset | bytes | encoding                      |
/// | ---------- | ------ | ----- | ----------------------------- |
/// | `height`   | 0      | 8     | u64 little-endian             |
/// | `cum_work` | 8      | 32    | 256-bit unsigned big-endian   |
/// | `status`   | 40     | 1     | [`Status`] bits               |
///
/// `cum_work` is the sum of `block_work(target)` of every block from genesis to this
/// block, the number fork choice compares, computed once when the header is stored.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct IndexEntry {
    /// Height of the block, equal to `header.height`.
    pub height: U64,
    /// Big-endian bytes of the cumulative work, see [`IndexEntry::work`].
    pub cum_work: [u8; 32],
    /// What is known of the block.
    pub status: Status,
}

const _: () = assert!(size_of::<IndexEntry>() == 41);

impl IndexEntry {
    /// An entry of `height` with `work` and `status`.
    pub fn new(height: Height, work: CumWork, status: Status) -> IndexEntry {
        IndexEntry {
            height: U64::new(height.0),
            cum_work: work.0.to_be_bytes(),
            status,
        }
    }

    /// The cumulative work as a number.
    pub fn work(&self) -> CumWork {
        CumWork(U256::from_be_bytes(self.cum_work))
    }

    /// The height as a number.
    pub fn height(&self) -> Height {
        Height(self.height.get())
    }
}

/// A row of `tx_index`: 36 bytes, no padding.
///
/// | field   | offset | bytes | encoding          |
/// | ------- | ------ | ----- | ----------------- |
/// | `block` | 0      | 32    | raw block id      |
/// | `index` | 32     | 4     | u32 little-endian |
///
/// `index` is the leaf index of the transaction in the Merkle tree of the block, which
/// is its position in `txs` then `proof_txs` (a proof request is indexed by the leaf of
/// its proof tx). The height of the including block is that block's `block_index`
/// entry.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct TxEntry {
    /// The canonical block that includes the transaction.
    pub block: BlockId,
    /// Leaf index in the Merkle tree of that block.
    pub index: U32,
}

const _: () = assert!(size_of::<TxEntry>() == 36);
