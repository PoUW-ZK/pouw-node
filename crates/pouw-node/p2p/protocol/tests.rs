use pouw_crypto::Hash32;
use pouw_types::{BlockId, ChainId, CumWork, Height, NetworkName, U256};

use super::*;

fn id(byte: u8) -> BlockId {
    BlockId(Hash32([byte; 32]))
}

fn status() -> Status {
    Status {
        protocol_version: PROTOCOL_VERSION,
        chain_id: ChainId(7),
        genesis: id(1),
        tip: id(2),
        height: Height(300),
        cumulative_work: CumWork(U256::from(123_456_u64)),
        services: Services::ARCHIVE,
        agent: "pouw-node/test".to_string(),
    }
}

#[test]
fn protocol_ids_carry_network_name_and_version() {
    let network = NetworkName::try_from("devnet".to_string()).unwrap();
    assert_eq!(protocol_id(&network, SYNC), "/pouw/devnet/sync/1");
    assert_eq!(
        protocol_id(&network, BLOCK_ANNOUNCE),
        "/pouw/devnet/block-announce/1"
    );
    let other = NetworkName::try_from("main".to_string()).unwrap();
    assert_ne!(protocol_id(&network, STATUS), protocol_id(&other, STATUS));
}

#[test]
fn status_round_trips_with_the_documented_layout() {
    let bytes = encode_status(&status()).unwrap();
    assert_eq!(bytes.len(), 4 + 4 + 32 + 32 + 8 + 32 + 8 + 4 + 14);
    assert_eq!(bytes[..4], 1_u32.to_le_bytes());
    assert_eq!(bytes[4..8], 7_u32.to_le_bytes());
    assert_eq!(bytes[8..40], [1; 32]);
    assert_eq!(bytes[40..72], [2; 32]);
    assert_eq!(bytes[72..80], 300_u64.to_le_bytes());
    assert_eq!(bytes[109..112], [0x01, 0xe2, 0x40]);
    assert_eq!(decode_status(&bytes).unwrap(), status());
}

#[test]
fn the_longest_status_is_the_size_bound() {
    let mut longest = status();
    longest.agent = "a".repeat(MAX_AGENT_BYTES);
    let bytes = encode_status(&longest).unwrap();
    assert_eq!(bytes.len(), MAX_STATUS_BYTES);
    assert_eq!(decode_status(&bytes).unwrap(), longest);
}

#[test]
fn an_oversized_status_is_refused_by_size() {
    let mut long = status();
    long.agent = "a".repeat(MAX_AGENT_BYTES + 1);
    let bytes = encode_status(&long).unwrap();
    assert!(matches!(
        decode_status(&bytes),
        Err(ProtocolError::Oversized { .. })
    ));
    assert!(matches!(
        decode_status(&[0; MAX_STATUS_BYTES + 1]),
        Err(ProtocolError::Oversized { .. })
    ));
}

#[test]
fn a_malformed_status_is_refused() {
    let bytes = encode_status(&status()).unwrap();
    assert!(matches!(
        decode_status(&bytes[..bytes.len() - 1]),
        Err(ProtocolError::Malformed(_))
    ));
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        decode_status(&trailing),
        Err(ProtocolError::Malformed(_))
    ));
    let mut text = bytes;
    let last = text.len() - 1;
    text[last] = 0xff;
    assert!(matches!(
        decode_status(&text),
        Err(ProtocolError::Malformed(_))
    ));
}

#[test]
fn compatibility_checks_version_then_chain_then_genesis() {
    let ours = status();
    assert_eq!(status().compatible(&ours), Ok(()));
    let mut theirs = status();
    theirs.tip = id(9);
    theirs.height = Height(1);
    theirs.services = Services::default();
    assert_eq!(theirs.compatible(&ours), Ok(()));
    theirs.genesis = id(9);
    assert_eq!(theirs.compatible(&ours), Err(DisconnectReason::Genesis));
    theirs.chain_id = ChainId(8);
    assert_eq!(theirs.compatible(&ours), Err(DisconnectReason::ChainId));
    theirs.protocol_version = 2;
    assert_eq!(
        theirs.compatible(&ours),
        Err(DisconnectReason::ProtocolVersion)
    );
}

#[test]
fn services_keep_unknown_bits() {
    let both = Services(Services::ARCHIVE.0 | Services::PRUNED.0 | 0x100);
    assert!(both.contains(Services::ARCHIVE));
    assert!(both.contains(Services::PRUNED));
    assert!(!Services::ARCHIVE.contains(Services::PRUNED));
}

fn headers_request(count: usize) -> SyncRequest {
    SyncRequest::GetHeaders(Box::new(GetHeaders {
        locator: vec![id(3); count],
        stop: Some(id(4)),
    }))
}

#[test]
fn requests_round_trip_and_the_longest_is_the_size_bound() {
    let full = headers_request(MAX_LOCATOR_IDS);
    let bytes = borsh::to_vec(&full).unwrap();
    assert_eq!(bytes.len(), MAX_SYNC_REQUEST_BYTES);
    assert_eq!(decode_request(&bytes).unwrap(), full);
    let blocks = SyncRequest::GetBlocks(GetBlocks {
        ids: vec![id(5); MAX_BLOCKS_PER_REQUEST],
    });
    let bytes = borsh::to_vec(&blocks).unwrap();
    assert_eq!(decode_request(&bytes).unwrap(), blocks);
}

#[test]
fn requests_over_a_limit_are_refused() {
    let many = borsh::to_vec(&headers_request(MAX_LOCATOR_IDS + 1)).unwrap();
    assert!(matches!(
        decode_request(&many),
        Err(ProtocolError::Oversized { .. } | ProtocolError::TooMany { .. })
    ));
    let no_stop = SyncRequest::GetHeaders(Box::new(GetHeaders {
        locator: vec![id(3); MAX_LOCATOR_IDS + 1],
        stop: None,
    }));
    let bytes = borsh::to_vec(&no_stop).unwrap();
    assert!(matches!(
        decode_request(&bytes),
        Err(ProtocolError::TooMany {
            found: 65,
            limit: 64
        })
    ));
    let blocks = SyncRequest::GetBlocks(GetBlocks {
        ids: vec![id(5); MAX_BLOCKS_PER_REQUEST + 1],
    });
    let bytes = borsh::to_vec(&blocks).unwrap();
    assert!(matches!(
        decode_request(&bytes),
        Err(ProtocolError::TooMany {
            found: 17,
            limit: 16
        })
    ));
    assert!(matches!(
        decode_request(&vec![0; MAX_SYNC_REQUEST_BYTES + 1]),
        Err(ProtocolError::Oversized { .. })
    ));
    assert!(matches!(
        decode_request(&[9]),
        Err(ProtocolError::Malformed(_))
    ));
}

#[test]
fn responses_round_trip_and_oversized_ones_are_refused() {
    let headers = SyncResponse::Headers(vec![zerocopy::FromZeros::new_zeroed(); 3]);
    let bytes = borsh::to_vec(&headers).unwrap();
    assert_eq!(bytes.len(), 1 + 4 + 3 * 168);
    assert_eq!(decode_response(&bytes).unwrap(), headers);
    let blocks = SyncResponse::Blocks(vec![vec![1, 2, 3], vec![4]]);
    let bytes = borsh::to_vec(&blocks).unwrap();
    assert_eq!(decode_response(&bytes).unwrap(), blocks);
    assert!(matches!(
        decode_response(&vec![0; MAX_RESPONSE_BYTES + 1]),
        Err(ProtocolError::Oversized { .. })
    ));
    assert!(matches!(
        decode_response(&[7]),
        Err(ProtocolError::Malformed(_))
    ));
}
