# Contributing

## Code rules

- rustfmt with the default configuration.
- clippy clean: `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
  The lints are set once in `[workspace.lints]` of `Cargo.toml`; every crate opts in
  with `[lints] workspace = true`. Silence a lint only on the item, with
  `#[expect(lint, reason = "...")]`.
- `#![forbid(unsafe_code)]` in every crate.
- Docs state a rule, an invariant, a unit, an encoding, an error condition or a link to a
  contract. A doc that only repeats the name or the signature is left out.
- Errors are enums derived with `thiserror`. An error that the rules produce (an
  invalid block or transaction) is a different type from a fault of the node (disk,
  prover, network), so a peer is never blamed for a local fault.
- Every id and quantity is a newtype from `pouw-types`, every byte blob a `Box<[u8]>`.
- Protocol data is encoded and hashed only through `pouw-types`. All protocol constants
  are in `pouw_types::protocol`; values that a chain chooses are in its chain spec,
  `pouw_types::ChainSpec` (see `docs/CHAINSPEC.md`).
- Arithmetic on balances, nonces and counters is checked (`checked_add`,
  `checked_next`). `clippy::arithmetic_side_effects` is denied in the
  workspace and enforces it.
- Fixed-size wire and stored structs are read in place with the `zerocopy` crate
  (`FromBytes`, `IntoBytes`, `KnownLayout`, `Immutable`, with little-endian integer types
  such as `zerocopy::little_endian::U64`), not decoded into owned values. `borsh` is for
  variable-size types, and a fixed-size type keeps its borsh derive only where a
  variable-size type contains it. The bytes of both paths are identical, a test pins it.
- Hot paths do not allocate: return borrows where the caller only reads, hash into a
  writer instead of collecting bytes, and reuse buffers across a loop.
- Only the prover crates know a proof system.
- The dependency rules of [README.md](README.md) hold.
- ASCII only in source and documentation.
- Comments only where the code cannot say it. Prefer names and types that explain themselves.
- Dependencies are declared once in `[workspace.dependencies]` and must pass `cargo deny`.

## Local hooks

Install [pre-commit](https://pre-commit.com) with `pipx install pre-commit` (or the
distro package), then run `pre-commit install` once in the clone. Every commit then runs
file hygiene checks, gitleaks, `cargo fmt --all --check`, `cargo check` and clippy over
the workspace. `pre-commit run --all-files` runs them on demand.

## Tests

- Every rule has a test that breaks it and expects its error variant.
- Formats are pinned by the test vectors of `block.md` in `pouw-types` and by property
  tests of the borsh and JSON round trips. A change that alters a pinned value is a
  change of the contract.
- API types are tested against the JSON examples of `node-api.md`.

## Pull requests

- Every pull request is reviewed by the owner of each crate it touches (see the table in
  [README.md](README.md)).
- Commit subjects follow conventional commits, for example `feat(types): add block header`,
  `fix(crypto): reject small-order keys`, `docs: describe the dependency rule`.
- CI (`ci-ok`) must be green: format, clippy, tests, docs, cargo-deny and the light-client check.
- Commit `Cargo.lock`.
