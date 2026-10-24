//! Groth16 over BN254 behind the `groth16` feature, pouw-node#93. The methods of
//! [`Groth16`] return `NotImplemented` until the backend exists.
//!
//! To build:
//! - `ark-groth16`, `ark-bn254`, `ark-serialize`, `ark-relations`, `ark-ff` as optional
//!   dependencies of this crate, enabled by the feature, and a Circom loader if the
//!   circuits are Circom. `cargo deny check` must pass: GPL is refused.
//! - `setup` runs the per-circuit setup and serializes both keys compressed.
//!   `complexity` is the R1CS constraint count. `prove` and `verify` take
//!   `statement.public_inputs()`.
//! - A `FieldInput` is a 248-bit little-endian integer, so `Fr::from_le_bytes_mod_order`
//!   maps it without reduction.
//! - Decode failures are `MalformedKey` and `MalformedProof`, a wrong input count is
//!   `InputCount`, an unsatisfied witness is `Unsatisfied`.
//!
//! Test: a tiny circuit proves and verifies, a changed public input, eta or mask fails,
//! truncated key and proof bytes give `Malformed*`, and a proof is at most
//! `MAX_PROOF_BYTES`.

use pouw_types::ProofSystem;

use crate::{CircuitKeys, Complexity, ProverError, Result, Statement};

/// Groth16 over BN254, per-circuit setup.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Groth16;

impl Groth16 {
    /// Tag of the circuits this backend proves.
    pub const SYSTEM: ProofSystem = ProofSystem::Groth16;

    pub fn setup(&self, _circuit: &[u8]) -> Result<CircuitKeys> {
        Err(not_implemented())
    }

    pub fn complexity(&self, _circuit: &[u8]) -> Result<Complexity> {
        Err(not_implemented())
    }

    pub fn prove(
        &self,
        _proving_key: &[u8],
        _statement: &Statement<'_>,
        _witness: &[u8],
    ) -> Result<Box<[u8]>> {
        Err(not_implemented())
    }

    pub fn verify(
        &self,
        _verifying_key: &[u8],
        _statement: &Statement<'_>,
        _proof: &[u8],
    ) -> Result<bool> {
        Err(not_implemented())
    }
}

fn not_implemented() -> ProverError {
    ProverError::NotImplemented { backend: "Groth16" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prover_identifies_as_groth16() {
        assert_eq!(crate::Prover::from(Groth16).id(), ProofSystem::Groth16);
    }
}
