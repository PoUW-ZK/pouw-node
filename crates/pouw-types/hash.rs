use borsh::BorshSerialize;
use pouw_crypto::{Address, Hash32, Sha256Writer, SigningKey, sha256};
use zerocopy::IntoBytes;

use crate::{
    Block, BlockHeader, BlockId, CircuitId, ProofHash, ProofTx, SignedTx, TxBody, TxId,
    UsageCounter,
    merkle::{bound_root, leaf_count_u32, root_in_place},
    protocol::{DOMAIN_ETA, DOMAIN_HEADER, DOMAIN_MASK, DOMAIN_TX_SIG},
};

fn borsh_sha256<T: BorshSerialize>(value: &T) -> Hash32 {
    let mut writer = Sha256Writer::default();
    borsh::to_writer(&mut writer, value).expect("a hasher accepts every write");
    writer.finish()
}

/// `DOMAIN_TX_SIG || borsh(body)`, the bytes a transaction signature covers.
pub fn signing_bytes(body: &TxBody) -> Vec<u8> {
    let mut bytes = Vec::new();
    signing_bytes_into(body, &mut bytes);
    bytes
}

/// [`signing_bytes`] written to `buf` after clearing it, so a loop reuses one buffer.
///
/// # Panics
///
/// Never in practice: writing into a `Vec` does not fail.
pub fn signing_bytes_into(body: &TxBody, buf: &mut Vec<u8>) {
    buf.clear();
    buf.extend_from_slice(DOMAIN_TX_SIG);
    borsh::to_writer(&mut *buf, body).expect("borsh serialization into a Vec cannot fail");
}

/// Signs `body` with `key`. The caller sets `body.sender` to `key.address()`.
pub fn sign_body(body: &TxBody, key: &SigningKey) -> SignedTx {
    SignedTx {
        body: body.clone(),
        signature: key.sign(&signing_bytes(body)),
    }
}

/// `sha256(borsh(SignedTx))`
pub fn txid(tx: &SignedTx) -> TxId {
    TxId(borsh_sha256(tx))
}

/// `sha256(DOMAIN_HEADER || header bytes)`. This is the only function that produces a
/// [`BlockId`]. In header v1 the id is the proof-of-work hash that must not exceed
/// `header.target`.
///
/// Seam for the research: a later header version may define the id differently, for
/// example as the ticket of a proof. Only this body changes, the callers keep passing
/// headers.
pub fn block_id(header: &BlockHeader) -> BlockId {
    BlockId(sha256(&[DOMAIN_HEADER, header.as_bytes()]))
}

/// `sha256(borsh(ProofTx))`, the Merkle leaf id of a proof tx.
pub fn proof_tx_hash(proof_tx: &ProofTx) -> ProofHash {
    ProofHash(borsh_sha256(proof_tx))
}

/// Number of bytes of the borsh encoding of `value`, computed without encoding it.
///
/// # Panics
///
/// When a vector of `value` has more than `u32::MAX` items.
pub fn encoded_len<T: BorshSerialize>(value: &T) -> usize {
    borsh::object_length(value).expect("borsh length of a value under the limits")
}

impl Block {
    /// The Merkle leaf ids in block order: txids of `txs`, then proof tx hashes.
    pub fn leaf_ids(&self) -> Vec<Hash32> {
        self.txs
            .iter()
            .map(|tx| txid(tx).hash())
            .chain(self.proof_txs.iter().map(|p| proof_tx_hash(p).hash()))
            .collect()
    }

    /// The `tx_root` the header must carry: [`bound_root`] of [`Block::leaf_count`] and
    /// the Merkle root over [`Block::leaf_ids`].
    pub fn compute_tx_root(&self) -> Hash32 {
        let merkle_root = root_in_place(&mut self.leaf_ids());
        bound_root(leaf_count_u32(self.leaf_count()), &merkle_root)
    }

    /// The unbound Merkle root over `txs` alone, the input of `eta_0`.
    pub fn compute_txs_root(&self) -> Hash32 {
        root_in_place(&mut self.txs.iter().map(|tx| txid(tx).hash()).collect())
    }

    /// Writes to `out`, after clearing it, the txid of every entry of `txs`, then the
    /// txid of the request of every proof tx: the order of the transaction index.
    pub fn txids_into(&self, out: &mut Vec<TxId>) {
        out.clear();
        out.extend(self.txs.iter().map(txid));
        out.extend(self.proof_txs.iter().map(|p| txid(&p.request)));
    }

    /// [`Block::compute_tx_root`] for the `txids` that [`Block::txids_into`] wrote, so
    /// no transaction is hashed twice. Only the first `txs.len()` of them are leaves.
    /// `leaves` is scratch space and is left holding the last level of the tree.
    pub fn tx_root_from(&self, txids: &[TxId], leaves: &mut Vec<Hash32>) -> Hash32 {
        leaves.clear();
        leaves.extend(txids.iter().take(self.txs.len()).map(TxId::hash));
        leaves.extend(self.proof_txs.iter().map(|p| proof_tx_hash(p).hash()));
        let merkle_root = root_in_place(leaves);
        bound_root(leaf_count_u32(self.leaf_count()), &merkle_root)
    }
}

/// The integrity parameter for each proof tx of a block, in block order.
/// `txs_root` is [`Block::compute_txs_root`].
pub fn eta_chain(parent: &BlockId, txs_root: &Hash32, proofs: &[ProofTx]) -> Vec<Hash32> {
    let mut etas = Vec::with_capacity(proofs.len());
    let mut eta = sha256(&[DOMAIN_ETA, parent.0.as_ref(), txs_root.as_ref()]);
    let mut previous: Option<&ProofTx> = None;
    for proof_tx in proofs {
        if let Some(previous) = previous {
            eta = sha256(&[
                DOMAIN_ETA,
                eta.as_ref(),
                sha256(&[&previous.proof]).as_ref(),
            ]);
        }
        etas.push(eta);
        previous = Some(proof_tx);
    }
    etas
}

/// `sha256(DOMAIN_MASK || miner || circuit_id || usage_counter_le_u64)`
pub fn mask(miner: &Address, circuit: &CircuitId, counter: UsageCounter) -> Hash32 {
    sha256(&[
        DOMAIN_MASK,
        &miner.0,
        circuit.hash().as_ref(),
        &counter.0.to_le_bytes(),
    ])
}
