//! Boundary between the node and a proving backend. A backend works over opaque byte
//! keys and [`FieldInput`] public inputs and never sees a block, a hash rule or the
//! chain state. [`Prover`] dispatches to the backend and [`MockProver`] is the one the
//! node uses until a real one is wired in. The Groth16 backend is behind the `groth16`
//! cargo feature.
//!
//! Everything that depends on a particular proof system stays behind [`Prover`].

#![forbid(unsafe_code)]

#[cfg(feature = "groth16")]
mod groth16;
mod mock;

#[cfg(feature = "groth16")]
pub use groth16::Groth16;
pub use mock::MockProver;
pub use pouw_crypto::FieldInput;
pub use pouw_types::ProofSystem;

use pouw_crypto::{Hash32, hash_to_field};
use thiserror::Error;

/// Why a backend could not set up, prove or verify.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProverError {
    /// The circuit bytes are not a circuit of the backend; the text is the backend's
    /// diagnostic.
    #[error("malformed circuit: {0}")]
    MalformedCircuit(String),
    /// The key bytes are not a key of the backend; the text is the backend's
    /// diagnostic.
    #[error("malformed key: {0}")]
    MalformedKey(String),
    /// The proof bytes are not a proof of the backend; the text is the backend's
    /// diagnostic.
    #[error("malformed proof: {0}")]
    MalformedProof(String),
    /// The witness does not satisfy the circuit, so no proof exists; the text is the
    /// backend's diagnostic.
    #[error("unsatisfied witness: {0}")]
    Unsatisfied(String),
    /// The circuit is longer than any size the complexity can count.
    #[error("the circuit length does not fit the complexity: {0}")]
    CircuitTooLong(#[from] std::num::TryFromIntError),
    /// The backend exists as a name only.
    #[error("the {backend} backend is not implemented")]
    NotImplemented {
        /// The backend asked.
        backend: &'static str,
    },
    /// The circuit expects a different number of public inputs.
    #[error("the circuit takes {expected} public inputs, {found} were given")]
    InputCount {
        /// Inputs the circuit takes.
        expected: usize,
        /// Inputs given.
        found: usize,
    },
    /// A fault of the backend itself, not of the inputs; the text is the backend's
    /// diagnostic.
    #[error("backend failure: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, ProverError>;

/// Cost of proving a circuit, readable before proving (ADR-0006). The unit is fixed
/// per backend: R1CS constraints for Groth16.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Complexity(pub u64);

/// Keys produced by [`Prover::setup`], in the backend's own serialization.
/// `verifying_key` is what a `RegisterCircuit` transaction carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitKeys {
    /// Held by provers only.
    pub proving_key: Box<[u8]>,
    /// Published in the circuit registry.
    pub verifying_key: Box<[u8]>,
}

/// What a proof is about: the binding of the proof to its block (eta and mask) and
/// the client's public inputs. How the binding enters the proof is decided only by
/// [`Statement::public_inputs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statement<'a> {
    /// `hash_to_field(eta_i)`.
    pub eta: FieldInput,
    /// `hash_to_field(mask)`.
    pub mask: FieldInput,
    /// `public_inputs` of the proof request.
    pub client_inputs: &'a [FieldInput],
}

impl<'a> Statement<'a> {
    /// Builds the statement from the eta and mask hashes of block.md.
    pub fn new(eta: &Hash32, mask: &Hash32, client_inputs: &'a [FieldInput]) -> Self {
        Self {
            eta: hash_to_field(eta),
            mask: hash_to_field(mask),
            client_inputs,
        }
    }

    /// The public inputs of the circuit, `[eta, mask, client inputs...]` (block.md).
    pub fn public_inputs(&self) -> Vec<FieldInput> {
        [self.eta, self.mask]
            .into_iter()
            .chain(self.client_inputs.iter().copied())
            .collect()
    }
}

/// One proving backend. One chain runs one variant. Calls may take seconds: async
/// callers run them on a blocking thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prover {
    Mock(MockProver),
    #[cfg(feature = "groth16")]
    Groth16(Groth16),
}

impl Prover {
    /// The proof system tag that registered circuits of this backend carry.
    pub fn id(&self) -> ProofSystem {
        match self {
            Self::Mock(prover) => prover.id(),
            #[cfg(feature = "groth16")]
            Self::Groth16(_) => Groth16::SYSTEM,
        }
    }

    /// Derives the keys of `circuit`. For a per-circuit setup this is the ceremony,
    /// for a universal setup it is the key derivation from the common parameters.
    pub fn setup(&self, circuit: &[u8]) -> Result<CircuitKeys> {
        match self {
            Self::Mock(prover) => prover.setup(circuit),
            #[cfg(feature = "groth16")]
            Self::Groth16(prover) => prover.setup(circuit),
        }
    }

    /// The complexity measure of `circuit`, without proving it.
    pub fn complexity(&self, circuit: &[u8]) -> Result<Complexity> {
        match self {
            Self::Mock(prover) => prover.complexity(circuit),
            #[cfg(feature = "groth16")]
            Self::Groth16(prover) => prover.complexity(circuit),
        }
    }

    pub fn prove(
        &self,
        proving_key: &[u8],
        statement: &Statement<'_>,
        witness: &[u8],
    ) -> Result<Box<[u8]>> {
        match self {
            Self::Mock(prover) => prover.prove(proving_key, statement, witness),
            #[cfg(feature = "groth16")]
            Self::Groth16(prover) => prover.prove(proving_key, statement, witness),
        }
    }

    /// `Ok(false)` is a well-formed proof that does not verify. `Err` with a
    /// `Malformed*` variant is a proof or key that does not decode; both make a
    /// block invalid. [`ProverError::Backend`] is a fault of this node.
    pub fn verify(
        &self,
        verifying_key: &[u8],
        statement: &Statement<'_>,
        proof: &[u8],
    ) -> Result<bool> {
        match self {
            Self::Mock(prover) => prover.verify(verifying_key, statement, proof),
            #[cfg(feature = "groth16")]
            Self::Groth16(prover) => prover.verify(verifying_key, statement, proof),
        }
    }
}

impl From<MockProver> for Prover {
    fn from(prover: MockProver) -> Self {
        Self::Mock(prover)
    }
}

#[cfg(feature = "groth16")]
impl From<Groth16> for Prover {
    fn from(prover: Groth16) -> Self {
        Self::Groth16(prover)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eta_and_mask_come_first() {
        let client = [FieldInput([7; 31])];
        let eta = Hash32([1; 32]);
        let mask = Hash32([2; 32]);
        let inputs = Statement::new(&eta, &mask, &client).public_inputs();
        assert_eq!(
            inputs,
            [
                hash_to_field(&eta),
                hash_to_field(&mask),
                FieldInput([7; 31])
            ]
        );
    }

    #[test]
    fn the_enum_dispatches_to_its_variant() {
        let prover = Prover::from(MockProver::default());
        let keys = prover.setup(b"circuit").unwrap();
        let statement = Statement::new(&Hash32([1; 32]), &Hash32([2; 32]), &[]);
        let proof = prover.prove(&keys.proving_key, &statement, b"").unwrap();
        assert!(
            prover
                .verify(&keys.verifying_key, &statement, &proof)
                .unwrap()
        );
        assert_eq!(prover.id(), ProofSystem::Groth16);
    }
}
