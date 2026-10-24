//! Light client: key handling and construction of signed transactions.
//! It depends only on `pouw-types` and `pouw-crypto`, so it builds without the node
//! or any prover. Inclusion proofs are checked with `pouw_types::verify_inclusion`.

#![forbid(unsafe_code)]

use pouw_crypto::{Address, FieldInput, SigningKey};
use pouw_types::{
    Amount, ChainId, CircuitId, ConstraintCount, Nonce, ProofSystem, SignedTx, TxBody, TxKind,
    sign_body,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WalletError {
    /// The next nonce does not exist: signing would reuse or wrap a nonce.
    #[error("the nonce counter of the wallet is exhausted")]
    NonceExhausted,
}

/// A signing key with the nonce of the next transaction it sends.
#[derive(Debug)]
pub struct Wallet {
    key: SigningKey,
    chain_id: ChainId,
    next_nonce: Nonce,
}

impl Wallet {
    /// A wallet that signs for `chain_id`, starting at `next_nonce`.
    pub fn new(key: SigningKey, chain_id: ChainId, next_nonce: Nonce) -> Self {
        Self {
            key,
            chain_id,
            next_nonce,
        }
    }

    /// A wallet with a fresh random key and nonce 0.
    pub fn generate(chain_id: ChainId) -> Self {
        Self::new(SigningKey::generate(), chain_id, Nonce(0))
    }

    pub fn address(&self) -> Address {
        self.key.address()
    }

    pub fn next_nonce(&self) -> Nonce {
        self.next_nonce
    }

    /// Signs a `Transfer` and advances the nonce.
    pub fn transfer(
        &mut self,
        to: Address,
        amount: Amount,
        fee: Amount,
    ) -> Result<SignedTx, WalletError> {
        self.sign(fee, TxKind::Transfer { to, amount })
    }

    /// Signs a `ProofRequest` and advances the nonce.
    pub fn proof_request(
        &mut self,
        circuit: CircuitId,
        public_inputs: Vec<FieldInput>,
        witness: Box<[u8]>,
        fee: Amount,
    ) -> Result<SignedTx, WalletError> {
        self.sign(
            fee,
            TxKind::ProofRequest {
                circuit,
                public_inputs,
                witness,
            },
        )
    }

    /// Signs a `RegisterCircuit` and advances the nonce.
    pub fn register_circuit(
        &mut self,
        system: ProofSystem,
        constraint_count: ConstraintCount,
        verifying_key: Box<[u8]>,
        circuit: Box<[u8]>,
        fee: Amount,
    ) -> Result<SignedTx, WalletError> {
        self.sign(
            fee,
            TxKind::RegisterCircuit {
                system,
                constraint_count,
                verifying_key,
                circuit,
            },
        )
    }

    fn sign(&mut self, fee: Amount, kind: TxKind) -> Result<SignedTx, WalletError> {
        let following = self
            .next_nonce
            .checked_next()
            .ok_or(WalletError::NonceExhausted)?;
        let body = TxBody {
            chain_id: self.chain_id,
            sender: self.address(),
            nonce: self.next_nonce,
            fee,
            kind,
        };
        self.next_nonce = following;
        Ok(sign_body(&body, &self.key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pouw_crypto::Hash32;
    use pouw_types::{TxId, verify_tx};

    fn wallet() -> Wallet {
        Wallet::new(SigningKey::from_seed([3; 32]), ChainId(1), Nonce(5))
    }

    #[test]
    fn transfer_verifies_and_advances_nonce() {
        let mut w = wallet();
        let tx = w.transfer(Address([2; 32]), Amount(50), Amount(1)).unwrap();
        assert_eq!(verify_tx(&tx), Ok(()));
        assert_eq!(tx.body.nonce, Nonce(5));
        assert_eq!(tx.body.sender, w.address());
        assert_eq!(w.next_nonce(), Nonce(6));
    }

    #[test]
    fn proof_request_verifies() {
        let mut w = wallet();
        let circuit = CircuitId(TxId(Hash32([1; 32])));
        let tx = w
            .proof_request(
                circuit,
                vec![FieldInput([1; 31])],
                Box::from([1, 2]),
                Amount(3),
            )
            .unwrap();
        assert_eq!(verify_tx(&tx), Ok(()));
        assert!(matches!(tx.body.kind, TxKind::ProofRequest { .. }));
    }

    #[test]
    fn register_circuit_verifies() {
        let mut w = wallet();
        let tx = w
            .register_circuit(
                ProofSystem::Marlin,
                ConstraintCount(10),
                Box::from([1]),
                Box::from([2]),
                Amount(3),
            )
            .unwrap();
        assert_eq!(verify_tx(&tx), Ok(()));
        assert!(matches!(tx.body.kind, TxKind::RegisterCircuit { .. }));
    }

    #[test]
    fn nonces_increase_per_transaction() {
        let mut w = wallet();
        let a = w.transfer(Address([2; 32]), Amount(1), Amount(1)).unwrap();
        let b = w.transfer(Address([2; 32]), Amount(1), Amount(1)).unwrap();
        assert_eq!((a.body.nonce, b.body.nonce), (Nonce(5), Nonce(6)));
    }

    #[test]
    fn the_last_nonce_is_never_signed() {
        let to = Address([2; 32]);
        let mut w = Wallet::new(
            SigningKey::from_seed([3; 32]),
            ChainId(1),
            Nonce(u64::MAX - 1),
        );
        let last = w.transfer(to, Amount(1), Amount(1)).unwrap();
        assert_eq!(last.body.nonce, Nonce(u64::MAX - 1));
        assert_eq!(w.next_nonce(), Nonce(u64::MAX));
        assert_eq!(
            w.transfer(to, Amount(1), Amount(1)),
            Err(WalletError::NonceExhausted)
        );
        assert_eq!(w.next_nonce(), Nonce(u64::MAX));
    }
}
