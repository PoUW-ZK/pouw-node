//! The calls of the REST API into the node loop. Each request carries a oneshot
//! sender for its answer; the loop answers it with the read functions of this module.
//!
//! Requests reach the loop through the api channel (capacity
//! [`API_CAPACITY`](crate::node::API_CAPACITY)), which the API and metrics threads feed
//! with [`submit`]. The loop reads it last, after control, work, the tick and p2p. A full
//! channel is [`Refused::Busy`], which the HTTP server answers with
//! `pouw_api::error::ErrorClass::Busy` (503, code `busy`) without waiting.

use std::net::SocketAddr;

use pouw_api::{
    event::EventsPage,
    view::{AccountView, HeaderView, MempoolView},
};
use pouw_consensus::{ChainTip, InvalidTx, StateView};
use pouw_crypto::Address;
use pouw_types::{BlockId, TxId};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::{
    chain::TxOutcome,
    events::{self, CursorExpired, EventLog},
    node::ComponentFault,
    precheck::CheckedTx,
    store::{self, Store, StoreError, TxLocation},
};

/// An answer of the store: `None` for something it does not hold.
pub type Answer<T> = oneshot::Sender<Result<Option<T>, StoreError>>;

#[derive(Debug)]
pub enum ApiRequest {
    /// The canonical tip.
    Tip { reply: Answer<ChainTip> },
    /// A stored header.
    Header {
        id: BlockId,
        reply: Answer<HeaderView>,
    },
    /// A stored block.
    Block { id: BlockId, reply: Answer<Vec<u8>> },
    /// An account at the tip.
    Account {
        address: Address,
        reply: Answer<AccountView>,
    },
    /// A transaction for the mempool and the network, with the verdict of
    /// `precheck::check_tx`. The API thread runs the precheck with a `Scratch` of its own
    /// before it sends the request, so the loop verifies no signature.
    SubmitTx {
        checked: Box<Result<CheckedTx, InvalidTx>>,
        reply: oneshot::Sender<TxOutcome>,
    },
    /// Where the canonical chain holds a transaction.
    TxLocation { id: TxId, reply: Answer<TxLocation> },
    /// A page of the event log.
    Events {
        after: u64,
        limit: u32,
        reply: oneshot::Sender<Result<EventsPage, CursorExpired>>,
    },
    /// The mempool summary.
    Mempool { reply: oneshot::Sender<MempoolView> },
    /// The text of `/metrics`.
    Metrics { reply: oneshot::Sender<String> },
}

/// Why a request did not reach the node loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Refused {
    /// The api channel is full. The caller answers 503 at once.
    #[error("the node is busy")]
    Busy,
    /// The loop dropped its receiver, which means the node is shutting down.
    #[error("the node loop is gone")]
    NodeGone,
}

/// Queues `request` for the loop without waiting. On `Err` the request, and the oneshot
/// sender in it, is dropped.
pub fn submit(api: &mpsc::Sender<ApiRequest>, request: ApiRequest) -> Result<(), Refused> {
    match api.try_send(request) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => Err(Refused::Busy),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(Refused::NodeGone),
    }
}

/// The API server thread: turns HTTP calls on `addr` into [`ApiRequest`]s sent with
/// [`submit`]. A submitted transaction is decoded and run through
/// `precheck::check_tx` here, with a `pouw_consensus::Scratch` the thread keeps, and
/// goes out as [`ApiRequest::SubmitTx`] with that verdict, valid or not, so the loop
/// records a rejection. The axum server is pouw-node#59; until it exists the thread
/// ends at once.
///
/// Routes are the constants of [`pouw_api::path`]: `TXS`, `TX`, `TX_INCLUSION_PROOF`, `HEAD`,
/// `BLOCKS`, `BLOCK`, `BLOCK_HEADER`, `HEADERS`, `CIRCUITS`, `CIRCUIT`, `ACCOUNT`,
/// `MEMPOOL`, `EVENTS`, `NODE`, `HEALTH` and `METRICS`. Bodies are `pouw_api::view`,
/// errors `pouw_api::error::ErrorBody` with the status of its `ErrorClass`, and a full
/// node queue answers 503 through [`submit`].
pub fn serve(addr: SocketAddr, _api: &mpsc::Sender<ApiRequest>) -> Result<(), ComponentFault> {
    warn!(%addr, "pouw-node#59: no REST API server, the address is not served");
    Ok(())
}

pub fn tip(store: &Store) -> Result<Option<ChainTip>, StoreError> {
    store::tip(&store::read(store)?)
}

pub fn header(store: &Store, id: &BlockId) -> Result<Option<HeaderView>, StoreError> {
    let reader = store::read(store)?;
    Ok(store::header(&reader, id)?.map(HeaderView::from))
}

/// The borsh bytes of the block as received and stored.
pub fn block(store: &Store, id: &BlockId) -> Result<Option<Vec<u8>>, StoreError> {
    let reader = store::read(store)?;
    Ok(store::block(&reader, id)?.map(|stored| stored.bytes.to_vec()))
}

pub fn account(store: &Store, address: &Address) -> Result<Option<AccountView>, StoreError> {
    let reader = store::read(store)?;
    let account = reader.account(address)?;
    Ok(account.map(|account| AccountView::new(*address, &account)))
}

pub fn tx_location(store: &Store, id: &TxId) -> Result<Option<TxLocation>, StoreError> {
    store::tx_location(&store::read(store)?, id)
}

pub fn events(log: &EventLog, after: u64, limit: u32) -> Result<EventsPage, CursorExpired> {
    let page = events::page(log, after, limit)?;
    Ok(EventsPage {
        events: page.events.into_iter().cloned().collect(),
        next: page.next,
    })
}
