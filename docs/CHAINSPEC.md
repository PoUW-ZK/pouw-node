# Chain spec

A chain is fixed by one JSON file. The node reads the file named by `POUW_CHAIN_SPEC`,
or the builtin devnet spec `chainspec/devnet.json` when the variable is unset. The Rust
types are the file format: `pouw_types::ChainSpec` and the structs under it, with
`deny_unknown_fields`. They live in `pouw-types` (`crates/pouw-types/chainspec.rs`), the
crate the light client already depends on, so the light client reads the same file
without the node, prover or consensus crates.

## Fields

| field | meaning |
| --- | --- |
| `network` | name for protocol ids `/pouw/<network>/...`, 1 to 32 of `a-z0-9-`, no `-` at the ends |
| `params.chain_id` | signed into every transaction, carried by every header |
| `params.initial_subsidy` | coins per block before the first halving, smallest unit |
| `params.halving_interval` | blocks between halvings |
| `params.target_block_secs` | block time the target rule aims at, above zero |
| `params.half_life_secs` | schedule lag that moves the target by a factor of two, above zero |
| `params.initial_target` | target of block 1, nonzero and at most `pow_limit` |
| `params.pow_limit` | easiest target any block may carry |
| `params.max_future_secs` | how far a header timestamp may run ahead of the verifier's clock |
| `params.fee_per_public_input` | fee coefficient per public input element |
| `params.fee_per_witness_kib` | fee coefficient per started KiB of witness |
| `genesis.timestamp` | Unix seconds of the genesis header, the anchor of the target schedule |
| `genesis.miner` | `miner` field of the genesis header, `addr:<64 hex>` |
| `genesis.target` | `target` field of the genesis header, 64 hex digits |
| `genesis.nonce` | `nonce` field of the genesis header |
| `allocations` | list of `{address, amount}`, unique addresses, amounts above zero, sum below 2^64 |
| `min_chain_work` | 64 hex digits, floor of cumulative work for initial block download (pouw-node#90) |
| `assume_valid` | optional `blk:<64 hex>`, ancestors of this block skip only the verify-work stage and the Groth16 payload verify in initial block download (pouw-node#90). Header, target, timestamp and linking rules still run |
| `expected_genesis_id` | `blk:<64 hex>`, the id the genesis block must have |

The block size caps are fixed protocol constants in `pouw_types::protocol`, not fields.
`min_chain_work` and `assume_valid` are parsed and kept in `NodeState`. Nothing reads
them before pouw-node#90.

## Genesis block

`pouw_types::genesis_block` builds it: `version` 1, `system_id` 0, `height` 0, zero
`parent`, `chain_id` from `params`, the other header fields from `genesis`. The
`tx_root` is `sha256(0x02 || u32le(n) || merkle_root)` with `n` the number of allocations
and `merkle_root` the Merkle root over one leaf per allocation in listed order, with leaf
`sha256("pouw-zk/genesis-alloc/v1" || address || amount as u64 little-endian)`. The body
is empty. The root commits the initial balances to the genesis id, so two nodes with the
same id have the same state. The node refuses to start with exit code 2 when the computed
id differs from `expected_genesis_id`. The proof of work of genesis is not checked.

A store started on one spec is refused (exit 1) under a spec with another genesis id.

## Printing the genesis id

```
cargo run -p pouw-cli -- genesis-id chainspec/devnet.json
```

prints the computed id without comparing it to the file. A new spec starts with any
`expected_genesis_id`, takes the printed value, and puts it in the file. The CLI fits
because it is offline, already depends on `pouw-types`, and runs the same code as the
node.

## Devnet values

All values of `chainspec/devnet.json` are devnet values. They make a laptop CPU find a
block in about `target_block_secs` with one core.

Hash rate: `sha256` over the 185 bytes of a block id preimage (17 bytes of domain plus
168 bytes of header), release build, `sha2` 0.10.9, one core of an i7-1260P with SHA
extensions, 20 million hashes with a varying nonce. Three runs gave 6736626, 6940783 and
6870280 hashes per second, about 6.9 million.

Derivation: one block in 10 seconds needs about 6.9e7 attempts. A target `t` takes
`2^256 / (t + 1)` attempts. `initial_target = 2^230 - 1` means 2^26 = 67108864 attempts,
which is 9.7 seconds at 6.9 million hashes per second. Hex form: `0000003f` then `ff`
bytes. `genesis.target` is the same value. A CPU without SHA extensions is 3 to 4 times
slower and the target rule adapts within a few half-lives.

`pow_limit` is `00ff...ff`, about 256 attempts, so slow machines and tests can ease down
far.

| value | derivation |
| --- | --- |
| `target_block_secs` 10 | devnet choice |
| `half_life_secs` 2880 | 288 blocks of the block time, the block count of the two-day half-life that Bitcoin Cash ASERT uses at 600 s blocks |
| `max_future_secs` 120 | Bitcoin's 7200 s is 12 blocks, 12 blocks of 10 s |
| `initial_subsidy` 83333333 | Bitcoin's 50 coins per 600 s scaled to 10 s, 1 coin is 10^8 units |
| `halving_interval` 12600000 | Bitcoin's 210000 blocks times 60, about 4 years of 10 s blocks |
| `fee_per_public_input`, `fee_per_witness_kib` 1 | placeholder coefficients |
| `genesis.timestamp` 1792790429 | 2026-10-23, creation time of the spec |

The target rule schedules block 1 from `genesis.timestamp`. A chain started long after
that time begins with a burst of easy blocks until the schedule lag is used up, so a
spec for a new network takes a recent timestamp and a fresh `expected_genesis_id` from
`genesis-id`.

The only allocation goes to the address of the public test seed `0101...01` of
`block.md` of [pouw-docs], 10^14 units.

[pouw-docs]: https://github.com/PoUW-ZK/pouw-docs/tree/main/contracts
