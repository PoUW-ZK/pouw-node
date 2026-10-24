use pouw_crypto::{Address, FieldInput, Hash32, Signature};
use pouw_types::{
    Amount, Block, BlockHeader, BlockId, ChainId, CircuitId, Nonce, ProofSystem, ProofTx, SignedTx,
    Target, TxBody, TxId, TxKind, U32, U64, UsageCounter, block_id, proof_tx_hash, txid,
};
use serde_json::{Value, json};

use crate::{
    error::{ErrorBody, ErrorClass, code},
    event::{BlockAccepted, Event, EventKind, EventTime, EventsPage, NodeId},
    view::{
        AccountView, BlockView, CircuitView, HeaderView, MempoolView, NodeInfo, ProofTxView,
        SignedTxView, TxStatus, TxView,
    },
};

fn round_trip<T>(json: &Value) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let value: T = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(&serde_json::to_value(&value).unwrap(), json);
    value
}

fn request() -> SignedTx {
    SignedTx {
        body: TxBody {
            chain_id: ChainId(1),
            sender: Address([0x11; 32]),
            nonce: Nonce(4),
            fee: Amount(120),
            kind: TxKind::ProofRequest {
                circuit: CircuitId(TxId(Hash32([0x22; 32]))),
                public_inputs: vec![FieldInput([3; 31])],
                witness: Box::from([1, 2, 3]),
            },
        },
        signature: Signature([9; 64]),
    }
}

fn block() -> Block {
    Block {
        header: BlockHeader {
            version: U32::new(1),
            chain_id: U32::new(1),
            system_id: U64::new(0),
            height: U64::new(12),
            parent: BlockId::ZERO,
            timestamp: U64::new(1_793_614_530),
            miner: Address([0x33; 32]),
            tx_root: Hash32([5; 32]),
            target: Target([0x0f; 32]),
            nonce: U64::new(7),
        },
        txs: vec![],
        proof_txs: vec![ProofTx {
            request: request(),
            usage_counter: UsageCounter(7),
            proof: Box::from([0xaa; 8]),
        }],
    }
}

#[test]
fn account_example_of_the_contract() {
    let view: AccountView = round_trip(&json!({
        "address": "addr:8fac0a4f4ac266a66249d7c30853b8aafefa405e9f2603b0f820100f34296e29",
        "balance": 1_000_000,
        "nonce": 4
    }));
    assert_eq!(view.nonce, Nonce(4));
}

#[test]
fn node_info_and_mempool_examples_of_the_contract() {
    round_trip::<NodeInfo>(&json!({ "chain_id": 1, "version": "0.1.0", "height": 12, "peers": 3 }));
    let mempool: MempoolView = round_trip(&json!({
        "tx_count": 2,
        "proof_request_count": 1,
        "txids": [
            "tx:4804e3ae090e3fb82de9a66aca0543c39d1ffff786133871f382ed612053687a",
            "tx:1b68b9df54d0ed19660cbf55e77eb77b9bf2eeec9d7f68ead222fdc22d893181"
        ]
    }));
    assert_eq!(mempool.txids.len(), 2);
}

#[test]
fn circuit_example_of_the_contract_has_no_blobs() {
    let view: CircuitView = round_trip(&json!({
        "id": "circ:710347f25bec15b1dce6bed71a7ab719739f0011cda6830e5eb7d3d01b000590",
        "system": "groth16",
        "constraint_count": 20000,
        "owner": "addr:958f0654a70f1dc0ecc52081aa74391b94a31f27dba7956e6f27148b9f142c92",
        "registered_at": 3
    }));
    assert_eq!(view.verifying_key, None);
    let with_keys = CircuitView {
        verifying_key: Some(Box::from([1, 2, 3])),
        circuit: Some(Box::from([4])),
        ..view
    };
    let value = serde_json::to_value(&with_keys).unwrap();
    assert_eq!(value["verifying_key"], "AQID");
    assert_eq!(
        serde_json::from_value::<CircuitView>(value).unwrap(),
        with_keys
    );
}

#[test]
fn signed_tx_view_adds_the_txid_beside_body_and_signature() {
    let tx = request();
    let value = serde_json::to_value(SignedTxView::from(&tx)).unwrap();
    assert_eq!(value["txid"], txid(&tx).to_string());
    assert_eq!(value["body"]["kind"], "proof_request");
    assert!(value["signature"].is_string());
    assert_eq!(value.as_object().unwrap().len(), 3);
}

#[test]
fn pending_tx_view_has_no_inclusion_fields() {
    let tx = request();
    let view = TxView {
        txid: txid(&tx),
        status: TxStatus::Pending,
        tx: SignedTxView::from(&tx),
        height: None,
        index: None,
        proof: None,
    };
    let value = serde_json::to_value(&view).unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["status", "tx", "txid"]);
    assert_eq!(serde_json::from_value::<TxView>(value).unwrap(), view);
}

#[test]
fn block_view_has_the_fields_of_the_contract() {
    let block = block();
    let proof = ProofTxView::new(
        &block.proof_txs[0],
        FieldInput([1; 31]),
        FieldInput([2; 31]),
        ProofSystem::Groth16,
    );
    let view = BlockView::new(&block, vec![proof]);
    let value = serde_json::to_value(&view).unwrap();
    assert_eq!(value["id"], block_id(&block.header).to_string());
    let entry = &value["proof_txs"][0];
    let mut keys: Vec<&str> = entry
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "eta",
            "mask",
            "proof",
            "proof_hash",
            "proof_system",
            "request",
            "request_txid",
            "usage_counter"
        ]
    );
    assert_eq!(
        entry["proof_hash"],
        proof_tx_hash(&block.proof_txs[0]).to_string()
    );
    assert_eq!(entry["request_txid"], entry["request"]["txid"]);
    let header = serde_json::to_value(HeaderView::from(&block.header)).unwrap();
    assert_eq!(header["id"], value["id"]);
    assert_eq!(serde_json::from_value::<BlockView>(value).unwrap(), view);
}

#[test]
fn event_example_of_the_contract() {
    let page: EventsPage = round_trip(&json!({
        "events": [{
            "seq": 1841,
            "time": "2026-11-02T10:15:30.123Z",
            "node_id": "node-a",
            "kind": "block_accepted",
            "data": {
                "id": "blk:dd532958f6a2a903a20f7f7923be98a644f600624193f181ddfe31cb4f53b8b7",
                "height": 12,
                "miner": "addr:958f0654a70f1dc0ecc52081aa74391b94a31f27dba7956e6f27148b9f142c92",
                "tx_count": 1,
                "proof_count": 1
            }
        }],
        "next": 1841
    }));
    let Event { kind, .. } = &page.events[0];
    assert_eq!(kind.name(), "block_accepted");
    assert!(matches!(
        kind,
        EventKind::BlockAccepted(BlockAccepted { proof_count: 1, .. })
    ));
}

#[test]
fn event_time_has_milliseconds_and_utc() {
    let time = EventTime::from_unix_millis(1_760_882_602_417).unwrap();
    assert_eq!(time.to_string(), "2025-10-19T14:03:22.417Z");
    assert_eq!(time.to_string().parse::<EventTime>().unwrap(), time);
    assert!("2025-10-19T14:03:22Z".parse::<EventTime>().is_err());
}

#[test]
fn node_ids_follow_the_pattern() {
    assert!("node-a".parse::<NodeId>().is_ok());
    assert!("miner_1.local".parse::<NodeId>().is_ok());
    assert!("".parse::<NodeId>().is_err());
    assert!("node a".parse::<NodeId>().is_err());
    assert!("x".repeat(65).parse::<NodeId>().is_err());
}

#[test]
fn error_body_of_an_expired_cursor() {
    let body: ErrorBody = round_trip(&json!({
        "error": {
            "code": "cursor_expired",
            "message": "oldest available seq is 52001",
            "details": { "oldest_seq": 52001 }
        }
    }));
    assert_eq!(body.error.code, code::CURSOR_EXPIRED);
    round_trip::<ErrorBody>(&json!({
        "error": { "code": "bad_nonce", "message": "expected nonce 4, got 3" }
    }));
    assert_eq!(ErrorClass::Rejected.status(), 422);
    assert_eq!(ErrorClass::Busy.status(), 503);
}

#[test]
fn the_client_reports_the_missing_transport() {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    let client = crate::NodeClient::new("http://node-1:8000");
    assert_eq!(client.base_url(), "http://node-1:8000");
    let mut call = pin!(client.health());
    let poll = call.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    assert!(matches!(
        poll,
        Poll::Ready(Err(crate::ClientError::NoTransport))
    ));
}
