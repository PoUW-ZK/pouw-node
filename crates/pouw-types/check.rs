use pouw_crypto::{CryptoError, verify};
use thiserror::Error;

use crate::{
    ProofTx, SignedTx, TxKind,
    protocol::{MAX_CIRCUIT_BYTES, MAX_PROOF_BYTES, MAX_PUBLIC_INPUTS, MAX_WITNESS_BYTES},
    signing_bytes_into,
};

/// Why one transaction fails the checks that need no chain state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TxError {
    /// The signature does not verify against `body.sender`.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A field is over its limit in block.md.
    #[error("{what} has {found} items or bytes, the limit is {limit}")]
    OverLimit {
        what: &'static str,
        found: usize,
        limit: usize,
    },
    /// The request of a proof tx is not a proof request.
    #[error("the request of a proof tx must have kind proof_request")]
    NotAProofRequest,
}

fn check_len(what: &'static str, found: usize, limit: usize) -> Result<(), TxError> {
    if found > limit {
        return Err(TxError::OverLimit { what, found, limit });
    }
    Ok(())
}

/// Checks the size limits of the body and the signature of `body.sender`.
pub fn verify_tx(tx: &SignedTx) -> Result<(), TxError> {
    verify_tx_with(tx, &mut Vec::new())
}

/// [`verify_tx`] encoding the signed bytes in `buf`, which a loop reuses.
pub fn verify_tx_with(tx: &SignedTx, buf: &mut Vec<u8>) -> Result<(), TxError> {
    match &tx.body.kind {
        TxKind::Transfer { .. } => {}
        TxKind::ProofRequest {
            public_inputs,
            witness,
            ..
        } => {
            check_len("public_inputs", public_inputs.len(), MAX_PUBLIC_INPUTS)?;
            check_len("witness", witness.len(), MAX_WITNESS_BYTES)?;
        }
        TxKind::RegisterCircuit {
            verifying_key,
            circuit,
            ..
        } => {
            let total = verifying_key.len().saturating_add(circuit.len());
            check_len("verifying_key and circuit", total, MAX_CIRCUIT_BYTES)?;
        }
    }
    signing_bytes_into(&tx.body, buf);
    verify(&tx.body.sender, buf, &tx.signature)?;
    Ok(())
}

/// Checks the proof size limit and that the embedded request is a signed `ProofRequest`.
pub fn verify_proof_tx(proof_tx: &ProofTx) -> Result<(), TxError> {
    verify_proof_tx_with(proof_tx, &mut Vec::new())
}

/// [`verify_proof_tx`] encoding the signed bytes in `buf`, which a loop reuses.
pub fn verify_proof_tx_with(proof_tx: &ProofTx, buf: &mut Vec<u8>) -> Result<(), TxError> {
    if !matches!(proof_tx.request.body.kind, TxKind::ProofRequest { .. }) {
        return Err(TxError::NotAProofRequest);
    }
    check_len("proof", proof_tx.proof.len(), MAX_PROOF_BYTES)?;
    verify_tx_with(&proof_tx.request, buf)
}
