use pouw_consensus::{ConsensusParams, InvalidBlock, InvalidTx, PowError, Scratch};
use pouw_crypto::{Address, FieldInput, Hash32, SigningKey};
use pouw_types::{
    Amount, Block, BlockHeader, BlockId, ChainId, CircuitId, Nonce, ProofTx, SignedTx, Target,
    TxBody, TxId, TxKind, U32, U64, UsageCounter, block_id, protocol::MAX_BLOCK_BYTES, sign_body,
    txid,
};

use super::{
    CheckedBlock, Fetched, PrecheckError, check_announce, check_announce_bytes, check_block,
    check_response, check_tx,
};
use crate::p2p::{SyncResponse, limits::MAX_BLOCKS_PER_REQUEST};

const CHAIN: ChainId = ChainId(7);

fn easy() -> Target {
    let mut bytes = [0xff; 32];
    bytes[0] = 0x0f;
    Target(bytes)
}

fn params() -> ConsensusParams {
    ConsensusParams {
        chain_id: CHAIN,
        initial_subsidy: Amount(50),
        halving_interval: 100,
        target_block_secs: 10,
        half_life_secs: 100,
        initial_target: easy(),
        pow_limit: easy(),
        max_future_secs: 300,
        fee_per_public_input: Amount(0),
        fee_per_witness_kib: Amount(0),
    }
}

fn signed(nonce: u64, kind: TxKind) -> SignedTx {
    let key = SigningKey::from_seed([1; 32]);
    sign_body(
        &TxBody {
            chain_id: CHAIN,
            sender: key.address(),
            nonce: Nonce(nonce),
            fee: Amount(1),
            kind,
        },
        &key,
    )
}

fn transfer(nonce: u64) -> SignedTx {
    let kind = TxKind::Transfer {
        to: Address([2; 32]),
        amount: Amount(5),
    };
    signed(nonce, kind)
}

fn request(nonce: u64) -> SignedTx {
    let kind = TxKind::ProofRequest {
        circuit: CircuitId(TxId(Hash32([3; 32]))),
        public_inputs: vec![FieldInput([4; 31])],
        witness: Box::from([5]),
    };
    signed(nonce, kind)
}

fn mined(mut block: Block) -> Block {
    while block_id(&block.header).0.0 > block.header.target.0 {
        block.header.nonce = U64::new(block.header.nonce.get().wrapping_add(1));
    }
    block
}

fn unmined(mut block: Block) -> Block {
    while block_id(&block.header).0.0 <= block.header.target.0 {
        block.header.nonce = U64::new(block.header.nonce.get().wrapping_add(1));
    }
    block
}

/// Two txs and one proof tx, a sealed header.
fn valid() -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: U32::new(1),
            chain_id: U32::new(CHAIN.0),
            system_id: U64::new(0),
            height: U64::new(5),
            parent: BlockId::ZERO,
            timestamp: U64::new(100),
            miner: Address([9; 32]),
            tx_root: Hash32::ZERO,
            target: easy(),
            nonce: U64::new(0),
        },
        txs: vec![transfer(0), transfer(1)],
        proof_txs: vec![ProofTx {
            request: request(2),
            usage_counter: UsageCounter(0),
            proof: Box::from([0xaa; 32]),
        }],
    };
    block.header.tx_root = block.compute_tx_root();
    mined(block)
}

fn check(bytes: Vec<u8>) -> Result<CheckedBlock, PrecheckError> {
    check_block(bytes, &params(), &mut Scratch::default())
}

fn encode(block: &Block) -> Vec<u8> {
    borsh::to_vec(block).unwrap()
}

#[test]
fn a_valid_block_keeps_its_bytes_and_lists_each_txid_once() {
    let block = valid();
    let bytes = encode(&block);
    let checked = check(bytes.clone()).unwrap();
    assert_eq!(checked.bytes, bytes);
    assert_eq!(checked.block, block);
    let expected: Vec<TxId> = block
        .txs
        .iter()
        .map(txid)
        .chain(block.proof_txs.iter().map(|p| txid(&p.request)))
        .collect();
    assert_eq!(checked.txids, expected);
    assert_eq!(checked.txids.len(), 3);
}

#[test]
fn trailing_bytes_are_malformed() {
    let mut bytes = encode(&valid());
    bytes.push(0);
    assert!(matches!(check(bytes), Err(PrecheckError::Malformed(_))));
}

#[test]
fn a_truncated_block_is_malformed() {
    let mut bytes = encode(&valid());
    bytes.pop();
    assert!(matches!(check(bytes), Err(PrecheckError::Malformed(_))));
}

#[test]
fn bytes_over_the_block_limit_are_refused_unread() {
    let bytes = vec![0; MAX_BLOCK_BYTES + 1];
    assert_eq!(
        check(bytes),
        Err(PrecheckError::Oversized {
            found: MAX_BLOCK_BYTES + 1,
            limit: MAX_BLOCK_BYTES
        })
    );
}

#[test]
fn a_wrong_tx_root_is_invalid() {
    let mut block = valid();
    block.header.tx_root = Hash32([1; 32]);
    let block = mined(block);
    assert_eq!(
        check(encode(&block)),
        Err(PrecheckError::Block(InvalidBlock::BadTxRoot))
    );
}

#[test]
fn a_bad_signature_is_invalid() {
    let mut block = valid();
    block.txs[1].body.fee = Amount(2);
    block.header.tx_root = block.compute_tx_root();
    let block = mined(block);
    assert!(matches!(
        check(encode(&block)),
        Err(PrecheckError::Block(InvalidBlock::Tx {
            proof: false,
            index: 1,
            source: InvalidTx::BadSignature
        }))
    ));
}

#[test]
fn a_header_over_its_target_is_invalid() {
    let block = unmined(valid());
    assert!(matches!(
        check(encode(&block)),
        Err(PrecheckError::Block(InvalidBlock::Pow(
            PowError::AboveTarget { .. }
        )))
    ));
}

#[test]
fn the_work_claim_is_checked_before_the_body() {
    let mut block = valid();
    block.header.tx_root = Hash32([1; 32]);
    let block = unmined(block);
    assert!(matches!(
        check(encode(&block)),
        Err(PrecheckError::Block(InvalidBlock::Pow(_)))
    ));
}

#[test]
fn a_valid_tx_is_checked_with_its_txid() {
    let tx = transfer(0);
    let checked = check_tx(tx.clone(), CHAIN, &mut Scratch::default()).unwrap();
    assert_eq!(checked.txid, txid(&tx));
    assert_eq!(checked.tx, tx);
}

#[test]
fn a_tx_of_another_chain_or_with_a_bad_signature_is_invalid() {
    let mut scratch = Scratch::default();
    assert!(matches!(
        check_tx(transfer(0), ChainId(8), &mut scratch),
        Err(InvalidTx::BadChainId { .. })
    ));
    let mut tx = transfer(0);
    tx.body.fee = Amount(9);
    assert_eq!(
        check_tx(tx, CHAIN, &mut scratch),
        Err(InvalidTx::BadSignature)
    );
}

#[test]
fn a_blocks_response_is_checked_item_by_item_and_bounded() {
    let mut scratch = Scratch::default();
    let block = valid();
    let ok = SyncResponse::Blocks(vec![encode(&block)]);
    let Ok(Fetched::Blocks(checked)) = check_response(ok, &params(), &mut scratch) else {
        panic!("a valid answer is refused");
    };
    assert_eq!(checked[0].block, block);
    let mut bad = encode(&block);
    bad.push(0);
    let mixed = SyncResponse::Blocks(vec![encode(&block), bad]);
    assert!(matches!(
        check_response(mixed, &params(), &mut scratch),
        Err(PrecheckError::Malformed(_))
    ));
    let many = SyncResponse::Blocks(vec![vec![]; MAX_BLOCKS_PER_REQUEST + 1]);
    assert!(matches!(
        check_response(many, &params(), &mut scratch),
        Err(PrecheckError::Oversized { .. })
    ));
}

#[test]
fn a_headers_response_with_an_unmined_header_is_refused() {
    let mut scratch = Scratch::default();
    let good = valid().header;
    let bad = unmined(valid()).header;
    let ok = SyncResponse::Headers(vec![good]);
    assert!(matches!(
        check_response(ok, &params(), &mut scratch),
        Ok(Fetched::Headers(_))
    ));
    let mixed = SyncResponse::Headers(vec![good, bad]);
    assert!(matches!(
        check_response(mixed, &params(), &mut scratch),
        Err(PrecheckError::Block(InvalidBlock::Pow(_)))
    ));
}

#[test]
fn an_announce_keeps_the_header_and_its_id() {
    let header = valid().header;
    let checked = check_announce(&header, &params()).unwrap();
    assert_eq!(checked.header, header);
    assert_eq!(checked.id, block_id(&header));
    let bytes = zerocopy::IntoBytes::as_bytes(&header);
    assert_eq!(check_announce_bytes(bytes, &params()).unwrap(), checked);
}

#[test]
fn an_announce_of_another_chain_or_over_its_target_is_invalid() {
    let mut other = valid().header;
    other.chain_id = U32::new(CHAIN.0 + 1);
    assert!(matches!(
        check_announce(&other, &params()),
        Err(InvalidBlock::BadChainId { .. })
    ));
    let unmined = unmined(valid()).header;
    assert!(matches!(
        check_announce(&unmined, &params()),
        Err(InvalidBlock::Pow(PowError::AboveTarget { .. }))
    ));
}

#[test]
fn announce_bytes_of_the_wrong_length_are_malformed() {
    let header = valid().header;
    let bytes = zerocopy::IntoBytes::as_bytes(&header);
    for bad in [&bytes[..167], &[bytes, &[0]].concat()[..]] {
        assert!(matches!(
            check_announce_bytes(bad, &params()),
            Err(PrecheckError::Malformed(_))
        ));
    }
}
