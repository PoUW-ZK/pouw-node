//! Endpoint paths of node-api.md, with `{name}` path parameters as axum writes them.

/// `POST` a transaction.
pub const TXS: &str = "/v1/txs";
/// `GET` one transaction.
pub const TX: &str = "/v1/txs/{txid}";
/// `GET` the inclusion proof of one transaction.
pub const TX_INCLUSION_PROOF: &str = "/v1/txs/{txid}/inclusion-proof";
/// `GET` the header of the tip.
pub const HEAD: &str = "/v1/blocks/head";
/// `GET` blocks in a height range.
pub const BLOCKS: &str = "/v1/blocks";
/// `GET` one block by height or `blk:` id.
pub const BLOCK: &str = "/v1/blocks/{height_or_id}";
/// `GET` one header by height or `blk:` id.
pub const BLOCK_HEADER: &str = "/v1/blocks/{height_or_id}/header";
/// `GET` headers in a height range.
pub const HEADERS: &str = "/v1/headers";
/// `GET` the circuit registry.
pub const CIRCUITS: &str = "/v1/circuits";
/// `GET` one registry entry.
pub const CIRCUIT: &str = "/v1/circuits/{circuit_id}";
/// `GET` one account.
pub const ACCOUNT: &str = "/v1/accounts/{addr}";
/// `GET` the mempool summary.
pub const MEMPOOL: &str = "/v1/mempool";
/// `GET` events, long-poll.
pub const EVENTS: &str = "/v1/events";
/// `GET` node information.
pub const NODE: &str = "/v1/node";
/// `GET` liveness, served on the API port.
pub const HEALTH: &str = "/health";
/// `GET` Prometheus text, served on the metrics port.
pub const METRICS: &str = "/metrics";
