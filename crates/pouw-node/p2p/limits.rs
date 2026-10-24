//! Every number that bounds the peer-to-peer layer, in one place: queue sizes, message
//! caps, peer counts, discovery sizes and the misbehaviour model. A change to a message
//! cap changes what a peer may send and is a protocol change, see `protocol.rs`.

use std::time::Duration;

use pouw_crypto::FIELD_INPUT_BYTES;
use pouw_types::protocol::{MAX_PUBLIC_INPUTS, MAX_WITNESS_BYTES};

use crate::mempool::MAX_RELAY_CIRCUIT_BYTES;

/// Raw messages wait between the swarm and the transport thread. Each is at most one
/// block (`MAX_BLOCK_BYTES`, 8 MiB), so 16 of them bound the queue at 128 MiB.
pub const WIRE_CAPACITY: usize = 16;

/// Most ids in the locator of a `GetHeaders`. A locator of a chain below 2^54 blocks
/// is shorter, see `sync::locator`.
pub const MAX_LOCATOR_IDS: usize = 64;

/// Most headers one `GetHeaders` is answered with, as in Bitcoin.
pub const MAX_HEADERS_PER_RESPONSE: usize = 2000;

/// Most ids in one `GetBlocks`, so one answer holds at most 16 blocks: 128 MiB.
pub const MAX_BLOCKS_PER_REQUEST: usize = 16;

/// Bytes on top of the variable-size fields of one gossiped transaction: the
/// transaction header, length prefixes and the enum tags.
pub const GOSSIP_FRAMING_BYTES: usize = 1024;

/// Most bytes of one gossiped `Transfer` or `RegisterCircuit` message, the relay cap of
/// the `coin-txs` topic: the circuit cap of the mempool plus the framing.
pub const MAX_COIN_TX_RELAY_BYTES: usize = MAX_RELAY_CIRCUIT_BYTES + GOSSIP_FRAMING_BYTES;

/// Most bytes of one gossiped proof request, the relay cap of the `proof-requests`
/// topic.
pub const MAX_PROOF_REQUEST_RELAY_BYTES: usize =
    MAX_WITNESS_BYTES + MAX_PUBLIC_INPUTS * FIELD_INPUT_BYTES + GOSSIP_FRAMING_BYTES;

/// Most bytes of a [`PeerId`](crate::p2p::PeerId): the longest libp2p peer id, a
/// multihash with a one-byte code, a one-byte length and a digest of up to 64 bytes.
pub const MAX_PEER_ID_BYTES: usize = 66;

/// Most bytes of the agent string of a `Status`.
pub const MAX_AGENT_BYTES: usize = 64;

/// Outbound connections a node keeps: the peers it chose to dial. Bitcoin keeps 8
/// full-relay outbound connections.
pub const DEFAULT_MAX_OUTBOUND: u32 = 8;

/// Inbound connections a node accepts. Beyond it the swarm refuses new connections.
pub const DEFAULT_MAX_INBOUND: u32 = 32;

/// The gossipsub mesh degree `D`: the peers each topic keeps full messages flowing to.
pub const GOSSIPSUB_MESH_D: u32 = 6;

/// Entries of one Kademlia k-bucket. A routing table of 256 buckets of 20 holds at most
/// 5120 addresses, so no node holds every address of the network. Bitcoin's address
/// manager is bounded too, at 1024 buckets of 64 new and 256 of 64 tried.
pub const KADEMLIA_BUCKET_SIZE: usize = 20;

/// The sizes of the connection and discovery layer, from the node configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLimits {
    pub max_outbound: u32,
    pub max_inbound: u32,
    /// Gossipsub mesh degree, [`GOSSIPSUB_MESH_D`].
    pub mesh_d: u32,
    /// Entries of one Kademlia k-bucket, [`KADEMLIA_BUCKET_SIZE`].
    pub kademlia_bucket_size: usize,
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            max_outbound: DEFAULT_MAX_OUTBOUND,
            max_inbound: DEFAULT_MAX_INBOUND,
            mesh_d: GOSSIPSUB_MESH_D,
            kademlia_bucket_size: KADEMLIA_BUCKET_SIZE,
        }
    }
}

/// Points taken off the score of a peer that sent bytes that do not decode.
pub const PENALTY_MALFORMED: i64 = 50;
/// Points taken off for a block that breaks a rule. One such block bans the peer.
pub const PENALTY_INVALID_BLOCK: i64 = 100;
/// Points taken off for a transaction that breaks a rule.
pub const PENALTY_INVALID_TX: i64 = 20;
/// Points taken off for a request that was not answered in time.
pub const PENALTY_UNRESPONSIVE: i64 = 10;

/// A score at or below this bans the peer. Scores start at 0 and only go down.
pub const BAN_SCORE: i64 = -100;

/// How long a banned peer stays refused, as in Bitcoin: 24 hours.
pub const BAN_DURATION: Duration = Duration::from_hours(24);
