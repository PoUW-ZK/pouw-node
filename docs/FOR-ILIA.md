# Map for building the node

This page is for @IliaPoliak. It says where each stage of the node lives, which
stubs remain and in what order to take them. The contracts in [pouw-docs] win over
this page and over the code. The details of each stub are the doc comment on its
function, not this page.

## Pipeline

A block from a peer or from the miner goes through the same stages.

| stage | file and function |
| --- | --- |
| decode | `crates/pouw-node/p2p.rs` `Gossip::decode`, `store::decode` for stored bytes |
| precheck: sizes, `tx_root`, signatures, work claim | `crates/pouw-node/precheck.rs` `check_block`, `check_announce`, `check_tx` |
| verify-work: the proof of work verdict | `crates/pouw-node/miner.rs` `verify_work`, run by the work worker |
| header rules against the parent | `crates/pouw-consensus/validation.rs` `check_header`, through `chain::receive_header` |
| store header and body | `crates/pouw-node/store.rs` `put_header`, `put_body` |
| fork choice | `crates/pouw-consensus/fork_choice.rs` `better`, in `chain::receive_block` |
| state transition | `crates/pouw-consensus/transition.rs` `apply_block` (stub), called by `chain::connect_stored` |
| connect and reorg | `crates/pouw-node/store.rs` `connect_block`, `chain::reorg` |

The node loop is `crates/pouw-node/node.rs`. It owns `NodeState` and is the only
writer of the store, the mempool and the event log.

## Stubs

| issue | file:fn | what |
| --- | --- | --- |
| [pouw-node#77] | `crates/pouw-consensus/transition.rs:apply_block` | state transition of a block: nonces, balances, registry, usage counters, reward |
| [pouw-node#69] | `crates/pouw-node/store/rocks.rs:open` | RocksDB backend of `Store` |
| [pouw-node#59] | `crates/pouw-node/api.rs:serve` | REST API over `pouw_api::path` |
| [pouw-node#63] | `crates/pouw-node/metrics.rs:serve` | `/metrics` endpoint |
| [pouw-node#85] | `crates/pouw-node/p2p.rs:start_swarm` | libp2p swarm behind the transport channels |
| [pouw-node#90] | `crates/pouw-node/node.rs:on_headers` | headers-first initial block download |
| [pouw-node#93] | `crates/pouw-provers/groth16.rs:Groth16` | Groth16 setup, prove, verify, complexity |

`start_swarm` and `on_headers` are `todo!`. The others log a warning or return
`NotImplemented`.

## Order

1. #77, because every block leaves the state unchanged until it exists.
2. #69, against the contract tests in `store/tests.rs`.
3. #59, which needs #77 for answers over real state, and #63, which needs nothing else.
4. #85, then #90, which needs the swarm to have peers and #77 to connect their blocks.
5. #93 can go at any time, it touches only `pouw-provers` and `POUW_PROVER`.

## Running the checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
cargo deny check bans licenses sources
```

`cargo deny` needs a version that reads CVSS 4.0 advisories (0.20 works). The light
client check is in the README.

E2e tests go in `e2e/test_*.py` files, run by `pouw-deploy` as described in
`e2e/README.md`. Unit and component tests sit next to the code in `tests.rs` files.

## Where each ABI is defined

| ABI | definition | contract |
| --- | --- | --- |
| block header, ids, hashes | `crates/pouw-types/types.rs` `BlockHeader`, `crates/pouw-types/hash.rs` `block_id` | `contracts/block.md` |
| protocol constants | `crates/pouw-types/protocol.rs` | `contracts/block.md` |
| P2P messages and topics | `crates/pouw-node/p2p/protocol.rs`, limits in `crates/pouw-node/p2p/limits.rs` | `contracts/p2p.md` |
| REST views, errors, paths | `crates/pouw-api/` | `contracts/node-api.md`, `node-api.yaml` |
| events | `crates/pouw-api/event.rs` | `contracts/node-events.md` |
| stored layout | `crates/pouw-node/store/schema.rs` | none, internal |
| chain spec | `crates/pouw-types/chainspec.rs`, `chainspec/devnet.json` | `docs/CHAINSPEC.md` |

[pouw-docs]: https://github.com/PoUW-ZK/pouw-docs/tree/main/contracts
[pouw-node#59]: https://github.com/PoUW-ZK/pouw-node/issues/59
[pouw-node#63]: https://github.com/PoUW-ZK/pouw-node/issues/63
[pouw-node#69]: https://github.com/PoUW-ZK/pouw-node/issues/69
[pouw-node#77]: https://github.com/PoUW-ZK/pouw-node/issues/77
[pouw-node#85]: https://github.com/PoUW-ZK/pouw-node/issues/85
[pouw-node#90]: https://github.com/PoUW-ZK/pouw-node/issues/90
[pouw-node#93]: https://github.com/PoUW-ZK/pouw-node/issues/93
