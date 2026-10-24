use pouw_crypto::{Address, Hash32};
use pouw_types::{
    Amount, BlockHeader, BlockId, ChainId, ConsensusParams, Target, U32, U64, U256, block_id,
    block_work,
};

use super::{PowError, check, meets, verify};

fn easy() -> Target {
    let mut bytes = [0xff; 32];
    bytes[0] = 0x0f;
    Target(bytes)
}

fn params() -> ConsensusParams {
    ConsensusParams {
        chain_id: ChainId(1),
        initial_subsidy: Amount(0),
        halving_interval: 1,
        target_block_secs: 10,
        half_life_secs: 100,
        initial_target: easy(),
        pow_limit: easy(),
        max_future_secs: 300,
        fee_per_public_input: Amount(0),
        fee_per_witness_kib: Amount(0),
    }
}

fn header(target: Target) -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(1),
        system_id: U64::new(0),
        height: U64::new(1),
        parent: BlockId::ZERO,
        timestamp: U64::new(1),
        miner: Address([0; 32]),
        tx_root: Hash32::ZERO,
        target,
        nonce: U64::new(0),
    }
}

fn nonce_where(header: &BlockHeader, meets: bool) -> BlockHeader {
    let mut header = *header;
    loop {
        let found = block_id(&header).0.0 <= header.target.0;
        if found == meets {
            return header;
        }
        header.nonce = U64::new(header.nonce.get().wrapping_add(1));
    }
}

#[test]
fn a_header_under_its_target_passes_and_reports_the_work() {
    let header = nonce_where(&header(easy()), true);
    assert_eq!(check(&params(), &header), Ok(block_work(&easy())));
}

#[test]
fn a_header_over_its_target_fails() {
    let header = nonce_where(&header(easy()), false);
    assert_eq!(
        check(&params(), &header),
        Err(PowError::AboveTarget {
            id: block_id(&header),
            target: easy()
        })
    );
}

#[test]
fn a_zero_target_fails() {
    assert_eq!(
        check(&params(), &header(Target([0; 32]))),
        Err(PowError::ZeroTarget)
    );
}

#[test]
fn a_target_above_the_limit_fails_even_when_the_id_is_under_it() {
    let mut above = easy();
    above.0[0] = 0x10;
    let header = nonce_where(&header(above), true);
    assert_eq!(
        check(&params(), &header),
        Err(PowError::TargetAboveLimit {
            limit: easy(),
            found: above
        })
    );
}

#[test]
fn an_unknown_header_version_has_no_proof_of_work() {
    let mut header = nonce_where(&header(easy()), true);
    header.version = U32::new(2);
    assert_eq!(
        check(&params(), &header),
        Err(PowError::UnsupportedVersion(2))
    );
}

#[test]
fn the_work_of_a_harder_target_is_larger() {
    let mut hard = easy();
    hard.0[0] = 0x01;
    assert!(block_work(&hard).0 > block_work(&easy()).0);
    assert!(block_work(&hard).0 > U256::ZERO);
}

#[test]
fn an_id_equal_to_the_target_meets_it_and_one_above_does_not() {
    let id = BlockId(Hash32([7; 32]));
    assert!(meets(&id, &Target([7; 32])));
    let mut above = [7; 32];
    above[31] = 6;
    assert!(!meets(&id, &Target(above)));
    let mut below = [7; 32];
    below[0] = 8;
    assert!(meets(&id, &Target(below)));
}

#[test]
fn verifying_a_version_1_block_is_the_header_check() {
    let params = params();
    let body = pouw_types::Block {
        header: nonce_where(&header(easy()), true),
        txs: vec![],
        proof_txs: vec![],
    };
    assert_eq!(
        verify(&params, &body.header, &body),
        check(&params, &body.header)
    );
    let unmined = pouw_types::Block {
        header: nonce_where(&header(easy()), false),
        txs: vec![],
        proof_txs: vec![],
    };
    assert_eq!(
        verify(&params, &unmined.header, &unmined),
        check(&params, &unmined.header)
    );
    assert!(verify(&params, &unmined.header, &unmined).is_err());
}

#[test]
fn verifying_an_unknown_version_has_no_proof_of_work() {
    let mut mined = nonce_where(&header(easy()), true);
    mined.version = U32::new(2);
    let body = pouw_types::Block {
        header: mined,
        txs: vec![],
        proof_txs: vec![],
    };
    assert_eq!(
        verify(&params(), &mined, &body),
        Err(PowError::UnsupportedVersion(2))
    );
}
