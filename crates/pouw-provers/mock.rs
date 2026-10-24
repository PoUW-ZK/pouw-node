use std::{thread, time::Duration};

use pouw_crypto::{Hash32, sha256};
use pouw_types::ProofSystem;

use crate::{CircuitKeys, Complexity, ProverError, Result, Statement};

const DOMAIN_MOCK_PROOF: &[u8] = b"pouw-zk/mock-proof/v1";

/// A backend without cryptography, for running consensus before a real prover exists.
///
/// Both keys are `sha256(circuit)`. A proof is `sha256(domain || key || public
/// inputs)`, so it verifies exactly for the statement and circuit it was made for and
/// a tampered input fails. The witness is ignored and every witness is accepted.
/// [`MockProver::prove`] sleeps for the configured delay to stand in for proving time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockProver {
    system: ProofSystem,
    delay: Duration,
}

impl MockProver {
    /// A mock that registers circuits as `system` and takes `delay` per proof.
    pub fn new(system: ProofSystem, delay: Duration) -> Self {
        Self { system, delay }
    }

    pub fn delay(&self) -> Duration {
        self.delay
    }

    pub fn id(&self) -> ProofSystem {
        self.system
    }

    pub fn setup(&self, circuit: &[u8]) -> Result<CircuitKeys> {
        let key: Box<[u8]> = Box::from(sha256(&[circuit]).0);
        Ok(CircuitKeys {
            proving_key: key.clone(),
            verifying_key: key,
        })
    }

    pub fn complexity(&self, circuit: &[u8]) -> Result<Complexity> {
        Ok(Complexity(u64::try_from(circuit.len())?))
    }

    pub fn prove(
        &self,
        proving_key: &[u8],
        statement: &Statement<'_>,
        _witness: &[u8],
    ) -> Result<Box<[u8]>> {
        if !self.delay.is_zero() {
            thread::sleep(self.delay);
        }
        Ok(Box::from(Self::proof_for(proving_key, statement).0))
    }

    pub fn verify(
        &self,
        verifying_key: &[u8],
        statement: &Statement<'_>,
        proof: &[u8],
    ) -> Result<bool> {
        if proof.len() != 32 {
            return Err(ProverError::MalformedProof(format!(
                "a mock proof has 32 bytes, found {}",
                proof.len()
            )));
        }
        Ok(Self::proof_for(verifying_key, statement).0 == proof)
    }

    fn proof_for(key: &[u8], statement: &Statement<'_>) -> Hash32 {
        let inputs = statement.public_inputs();
        let mut parts: Vec<&[u8]> = vec![DOMAIN_MOCK_PROOF, key];
        parts.extend(inputs.iter().map(|input| input.0.as_slice()));
        sha256(&parts)
    }
}

impl Default for MockProver {
    /// Groth16 with no delay.
    fn default() -> Self {
        Self::new(ProofSystem::Groth16, Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use pouw_crypto::FieldInput;

    use super::*;

    fn statement(inputs: &[FieldInput]) -> Statement<'_> {
        Statement::new(&Hash32([1; 32]), &Hash32([2; 32]), inputs)
    }

    #[test]
    fn a_proof_verifies_for_its_statement_only() {
        let prover = MockProver::default();
        let keys = prover.setup(b"circuit").unwrap();
        let inputs = [FieldInput([3; 31])];
        let proof = prover
            .prove(&keys.proving_key, &statement(&inputs), b"")
            .unwrap();
        assert!(
            prover
                .verify(&keys.verifying_key, &statement(&inputs), &proof)
                .unwrap()
        );

        let other = [FieldInput([4; 31])];
        assert!(
            !prover
                .verify(&keys.verifying_key, &statement(&other), &proof)
                .unwrap()
        );
        let other_keys = prover.setup(b"other circuit").unwrap();
        assert!(
            !prover
                .verify(&other_keys.verifying_key, &statement(&inputs), &proof)
                .unwrap()
        );
    }

    #[test]
    fn a_short_proof_is_malformed() {
        let prover = MockProver::default();
        assert!(matches!(
            prover.verify(b"key", &statement(&[]), &[0; 31]),
            Err(ProverError::MalformedProof(_))
        ));
    }

    #[test]
    fn proving_takes_the_configured_delay() {
        let prover = MockProver::new(ProofSystem::Marlin, Duration::from_millis(20));
        assert_eq!(prover.id(), ProofSystem::Marlin);
        let start = Instant::now();
        prover.prove(b"key", &statement(&[]), b"").unwrap();
        assert!(start.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn complexity_is_the_circuit_size() {
        assert_eq!(
            MockProver::default().complexity(&[0; 10]).unwrap(),
            Complexity(10)
        );
    }
}
