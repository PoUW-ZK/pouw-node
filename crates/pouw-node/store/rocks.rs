//! The `RocksDB` backend of [`super::Store`], built with the `rocksdb` feature. It has
//! no implementation yet: [`open`] always fails, so no [`Db`] value exists and every
//! other function is unreachable.
//!
//! pouw-node#69: replace `Db` with the database handle and implement every function
//! here as `store/mem.rs` does, one column family per table of [`super::schema`], with
//! keys and values in the byte layout given there. `connect` and `disconnect` each write
//! one `WriteBatch`. The contract tests of `store/tests.rs` pass on this backend too.

use std::path::Path;

use pouw_consensus::{ChainTip, StateDiff, StateError};
use pouw_crypto::Address;
use pouw_types::{
    Account, BlockHeader, BlockId, CircuitEntry, CircuitId, Height, TxId, UsageCounter,
};

use super::{
    StoreError, TxLocation,
    schema::{IndexEntry, TxEntry},
};

#[derive(Debug)]
pub enum Db {}

pub fn open(path: &Path) -> Result<Db, StoreError> {
    Err(StoreError::NotImplemented {
        backend: "RocksDB",
        path: path.to_owned(),
    })
}

pub fn schema_version(view: &Db) -> Result<u32, StoreError> {
    match *view {}
}

pub fn index(view: &Db, _id: &BlockId) -> Result<Option<IndexEntry>, StoreError> {
    match *view {}
}

pub fn tip(view: &Db) -> Result<Option<ChainTip>, StoreError> {
    match *view {}
}

pub fn parent_of_tip(view: &Db) -> Result<Option<ChainTip>, StoreError> {
    match *view {}
}

pub fn header<'v>(view: &'v Db, _id: &BlockId) -> Result<Option<&'v BlockHeader>, StoreError> {
    match *view {}
}

pub fn stored_block<'v>(view: &'v Db, _id: &BlockId) -> Result<Option<&'v [u8]>, StoreError> {
    match *view {}
}

pub fn canonical_id(view: &Db, _height: Height) -> Result<Option<BlockId>, StoreError> {
    match *view {}
}

pub fn tx_location(view: &Db, _id: &TxId) -> Result<Option<TxLocation>, StoreError> {
    match *view {}
}

pub fn account(view: &Db, _address: &Address) -> Result<Option<Account>, StateError> {
    match *view {}
}

pub fn circuit<'v>(view: &'v Db, _id: &CircuitId) -> Result<Option<&'v CircuitEntry>, StateError> {
    match *view {}
}

pub fn usage_counter(
    view: &Db,
    _miner: &Address,
    _circuit: &CircuitId,
) -> Result<Option<UsageCounter>, StateError> {
    match *view {}
}

pub fn insert_header(
    rocks: &mut Db,
    _id: BlockId,
    _header: BlockHeader,
    _entry: IndexEntry,
) -> Result<(), StoreError> {
    match *rocks {}
}

pub fn insert_body(
    rocks: &mut Db,
    _id: BlockId,
    _bytes: &[u8],
    _entry: IndexEntry,
) -> Result<(), StoreError> {
    match *rocks {}
}

pub fn set_index(rocks: &mut Db, _id: BlockId, _entry: IndexEntry) -> Result<(), StoreError> {
    match *rocks {}
}

pub fn connect(
    rocks: &mut Db,
    _new_tip: &ChainTip,
    _entry: IndexEntry,
    _locations: Vec<(TxId, TxEntry)>,
    _diff: &StateDiff,
) -> Result<(), StoreError> {
    match *rocks {}
}

pub fn disconnect(
    rocks: &mut Db,
    _tip: &BlockId,
    _entry: IndexEntry,
    _parent: &BlockId,
    _txids: &[TxId],
) -> Result<(), StoreError> {
    match *rocks {}
}
