//! The wire protocol between two nodes: protocol ids, the `Status` handshake and the
//! sync requests and answers. Every message is Borsh except the block announcement,
//! whose payload is the 168 raw bytes of a header.
//!
//! Protocol ids are `/pouw/<network>/<name>/<version>`, built only by [`protocol_id`]:
//!
//! ```text
//!  /pouw/<network>/status/1           Status, sent by both sides once per connection
//!  /pouw/<network>/block-announce/1   gossip: tag byte 0, then the 168 header bytes
//!  /pouw/<network>/coin-txs/1         gossip: tag byte 1, then a Borsh SignedTx
//!  /pouw/<network>/proof-requests/1   gossip: tag byte 1, then a Borsh SignedTx
//!  /pouw/<network>/sync/1             request-response: SyncRequest, SyncResponse
//! ```
//!
//! Every limit on the size of a message is a constant of [`limits`](super::limits) or
//! derived from one here, and each decoder checks its limit before it parses.

use borsh::{BorshDeserialize, BorshSerialize};
use pouw_types::{BlockHeader, BlockId, ChainId, CumWork, Height, NetworkName, U256};
use thiserror::Error;

use super::limits::{MAX_AGENT_BYTES, MAX_BLOCKS_PER_REQUEST, MAX_LOCATOR_IDS};

/// The version of every protocol of this module, the last segment of a protocol id and
/// the `protocol_version` of [`Status`]. A change to any message layout raises it.
pub const PROTOCOL_VERSION: u32 = 1;

/// Name of the status protocol.
pub const STATUS: &str = "status";
/// Name of the block announcement topic.
pub const BLOCK_ANNOUNCE: &str = "block-announce";
/// Name of the topic of `Transfer` and `RegisterCircuit` transactions.
pub const COIN_TXS: &str = "coin-txs";
/// Name of the topic of proof requests.
pub const PROOF_REQUESTS: &str = "proof-requests";
/// Name of the request-response protocol.
pub const SYNC: &str = "sync";

/// The id of the protocol `name` on `network`: `/pouw/<network>/<name>/<version>` with
/// the [`PROTOCOL_VERSION`]. Two networks never share a protocol id, so a peer of
/// another network fails the protocol negotiation of the transport before any message.
pub fn protocol_id(network: &NetworkName, name: &str) -> String {
    format!("/pouw/{network}/{name}/{PROTOCOL_VERSION}")
}

/// Flags of the services a node offers, in the [`Status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct Services(pub u64);

impl Services {
    /// Serves every block body since genesis.
    pub const ARCHIVE: Services = Services(1);
    /// Serves only the bodies of recent blocks.
    pub const PRUNED: Services = Services(2);

    /// Whether every flag of `other` is set. Unknown flags are kept and ignored.
    pub const fn contains(self, other: Services) -> bool {
        self.0 & other.0 == other.0
    }
}

/// What a node tells a peer about itself on connect, as the first message of each side.
///
/// Byte layout, Borsh: `protocol_version` u32 LE, `chain_id` u32 LE, `genesis` 32 bytes,
/// `tip` 32 bytes, `height` u64 LE, `cumulative_work` 32 bytes big-endian, `services`
/// u64 LE, `agent` a u32 LE length and that many UTF-8 bytes. The size is
/// at most [`MAX_STATUS_BYTES`] (188), and the agent is at most [`MAX_AGENT_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// [`PROTOCOL_VERSION`] of the sender.
    pub protocol_version: u32,
    pub chain_id: ChainId,
    /// Id of the genesis block, which fixes the chain.
    pub genesis: BlockId,
    /// Id of the best tip of the sender.
    pub tip: BlockId,
    pub height: Height,
    /// Cumulative work of that tip, what the peer compares with its own to decide whether
    /// a sync is worth it.
    pub cumulative_work: CumWork,
    pub services: Services,
    /// Free text naming the software, for logs. Not trusted for anything.
    pub agent: String,
}

/// Borsh bytes of the longest [`Status`].
pub const MAX_STATUS_BYTES: usize = 4 + 4 + 32 + 32 + 8 + 32 + 8 + 4 + MAX_AGENT_BYTES;

/// A [`Status`] as it is encoded: `CumWork` has no Borsh form, so the work is its 32
/// big-endian bytes.
#[derive(BorshSerialize, BorshDeserialize)]
struct StatusWire {
    protocol_version: u32,
    chain_id: ChainId,
    genesis: BlockId,
    tip: BlockId,
    height: Height,
    cumulative_work: [u8; 32],
    services: Services,
    agent: String,
}

/// Why a peer is disconnected right after its [`Status`], or by order of the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DisconnectReason {
    #[error("the peer speaks another protocol version")]
    ProtocolVersion,
    #[error("the peer is on another chain id")]
    ChainId,
    #[error("the peer has another genesis block")]
    Genesis,
    #[error("the peer is banned")]
    Banned,
}

impl Status {
    /// Whether a peer that sent `self` may stay connected to a node with the status
    /// `ours`: the protocol version, the chain id and the genesis id must be equal,
    /// checked in that order. Tip, height, work and services never disconnect. A
    /// mismatch is not misbehaviour: the peer is on another network, so it gets a
    /// [`Command::Disconnect`](super::Command::Disconnect) and no penalty.
    pub fn compatible(&self, ours: &Status) -> Result<(), DisconnectReason> {
        if self.protocol_version != ours.protocol_version {
            return Err(DisconnectReason::ProtocolVersion);
        }
        if self.chain_id != ours.chain_id {
            return Err(DisconnectReason::ChainId);
        }
        if self.genesis != ours.genesis {
            return Err(DisconnectReason::Genesis);
        }
        Ok(())
    }
}

/// Why received bytes are not a valid message of this protocol.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("{found} bytes, the limit is {limit}")]
    Oversized { found: usize, limit: usize },
    /// The bytes are not the canonical encoding: too short, too long or not valid text.
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("{found} entries, the limit is {limit}")]
    TooMany { found: usize, limit: usize },
}

/// The wire bytes of `status`. The agent must be at most [`MAX_AGENT_BYTES`], which
/// [`decode_status`] enforces on the receiving side.
pub fn encode_status(status: &Status) -> Result<Vec<u8>, borsh::io::Error> {
    borsh::to_vec(&StatusWire {
        protocol_version: status.protocol_version,
        chain_id: status.chain_id,
        genesis: status.genesis,
        tip: status.tip,
        height: status.height,
        cumulative_work: status.cumulative_work.0.to_be_bytes(),
        services: status.services,
        agent: status.agent.clone(),
    })
}

/// Decodes a [`Status`]. The size is checked first. Trailing bytes, an agent over
/// [`MAX_AGENT_BYTES`] and invalid UTF-8 are errors. Unknown service bits are kept.
pub fn decode_status(bytes: &[u8]) -> Result<Status, ProtocolError> {
    if bytes.len() > MAX_STATUS_BYTES {
        return Err(ProtocolError::Oversized {
            found: bytes.len(),
            limit: MAX_STATUS_BYTES,
        });
    }
    let wire: StatusWire =
        borsh::from_slice(bytes).map_err(|error| ProtocolError::Malformed(error.to_string()))?;
    if wire.agent.len() > MAX_AGENT_BYTES {
        return Err(ProtocolError::Oversized {
            found: wire.agent.len(),
            limit: MAX_AGENT_BYTES,
        });
    }
    Ok(Status {
        protocol_version: wire.protocol_version,
        chain_id: wire.chain_id,
        genesis: wire.genesis,
        tip: wire.tip,
        height: wire.height,
        cumulative_work: CumWork(U256::from_be_bytes(wire.cumulative_work)),
        services: wire.services,
        agent: wire.agent,
    })
}

/// Asks for the headers that follow the best match of a locator.
///
/// Byte layout, Borsh: `locator` a u32 LE count and that many 32-byte ids, `stop` a
/// tag byte 0 (none) or 1 followed by a 32-byte id.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GetHeaders {
    /// Block ids of the sender's chain, newest first, at most [`MAX_LOCATOR_IDS`], built
    /// by `sync::locator`.
    pub locator: Vec<BlockId>,
    /// The last header to send, when the sender wants fewer than
    /// [`MAX_HEADERS_PER_RESPONSE`](super::limits::MAX_HEADERS_PER_RESPONSE).
    pub stop: Option<BlockId>,
}

/// Asks for whole blocks by id.
///
/// Byte layout, Borsh: `ids` a u32 LE count and that many 32-byte ids.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GetBlocks {
    /// At most [`MAX_BLOCKS_PER_REQUEST`] ids.
    pub ids: Vec<BlockId>,
}

/// A request to one peer, on the `sync` protocol. The Borsh form is a tag byte, 0 for
/// `GetHeaders` and 1 for `GetBlocks`, then the message.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SyncRequest {
    /// Boxed so that a queued request is a few words.
    GetHeaders(Box<GetHeaders>),
    GetBlocks(GetBlocks),
}

/// Borsh bytes of the longest [`SyncRequest`]: a `GetHeaders` with a full locator and a
/// stop id.
pub const MAX_SYNC_REQUEST_BYTES: usize = 1 + 4 + MAX_LOCATOR_IDS * 32 + 1 + 32;

/// Decodes a [`SyncRequest`]. The size is checked first, then the counts of ids.
pub fn decode_request(bytes: &[u8]) -> Result<SyncRequest, ProtocolError> {
    if bytes.len() > MAX_SYNC_REQUEST_BYTES {
        return Err(ProtocolError::Oversized {
            found: bytes.len(),
            limit: MAX_SYNC_REQUEST_BYTES,
        });
    }
    let request: SyncRequest =
        borsh::from_slice(bytes).map_err(|error| ProtocolError::Malformed(error.to_string()))?;
    let (found, limit) = match &request {
        SyncRequest::GetHeaders(get) => (get.locator.len(), MAX_LOCATOR_IDS),
        SyncRequest::GetBlocks(get) => (get.ids.len(), MAX_BLOCKS_PER_REQUEST),
    };
    if found > limit {
        return Err(ProtocolError::TooMany { found, limit });
    }
    Ok(request)
}

/// The answer to a [`SyncRequest`]. The Borsh form is a tag byte, 0 for `Headers` and 1
/// for `Blocks`, then a u32 LE count and the items.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SyncResponse {
    /// Answer to `GetHeaders`: at most [`MAX_HEADERS_PER_RESPONSE`](super::limits::MAX_HEADERS_PER_RESPONSE) headers, ascending
    /// by height, each 168 bytes.
    Headers(Vec<BlockHeader>),
    /// Answer to `GetBlocks`: the Borsh bytes of each block as stored, at most
    /// [`MAX_BLOCKS_PER_REQUEST`], in the order of the request.
    Blocks(Vec<Vec<u8>>),
}

/// Borsh bytes of the longest [`SyncResponse`]: sixteen blocks of the size limit.
pub const MAX_RESPONSE_BYTES: usize =
    1 + 4 + MAX_BLOCKS_PER_REQUEST * (4 + pouw_types::protocol::MAX_BLOCK_BYTES);

/// Decodes a [`SyncResponse`]. The size is checked first, the counts are checked by
/// `precheck::check_response`.
pub fn decode_response(bytes: &[u8]) -> Result<SyncResponse, ProtocolError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProtocolError::Oversized {
            found: bytes.len(),
            limit: MAX_RESPONSE_BYTES,
        });
    }
    borsh::from_slice(bytes).map_err(|error| ProtocolError::Malformed(error.to_string()))
}

#[cfg(test)]
mod tests;
