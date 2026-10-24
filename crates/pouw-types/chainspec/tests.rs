use serde_json::{Value, json};

use super::*;

const TARGET: &str = "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn alice() -> String {
    format!("addr:{}", "11".repeat(32))
}

fn bob() -> String {
    format!("addr:{}", "22".repeat(32))
}

fn spec_json(expected: &str) -> Value {
    json!({
        "network": "test-net",
        "params": {
            "chain_id": 7,
            "initial_subsidy": 50,
            "halving_interval": 100,
            "target_block_secs": 10,
            "half_life_secs": 100,
            "initial_target": TARGET,
            "pow_limit": TARGET,
            "max_future_secs": 120,
            "fee_per_public_input": 1,
            "fee_per_witness_kib": 1
        },
        "genesis": {
            "timestamp": 1000,
            "miner": alice(),
            "target": TARGET,
            "nonce": 5
        },
        "allocations": [
            { "address": alice(), "amount": 1000 },
            { "address": bob(), "amount": 5 }
        ],
        "min_chain_work": "0".repeat(64),
        "expected_genesis_id": expected
    })
}

fn parse(value: &Value) -> Result<ChainSpec, SpecError> {
    parse_chain_spec(&value.to_string())
}

fn zero_id() -> String {
    format!("blk:{}", "00".repeat(32))
}

fn spec() -> ChainSpec {
    parse(&spec_json(&zero_id())).expect("valid spec")
}

#[test]
fn a_wrong_expected_id_is_refused() {
    let error = check_genesis(&spec()).expect_err("zero is not the genesis id");
    assert!(matches!(error, SpecError::GenesisMismatch { .. }));
}

#[test]
fn the_computed_id_passes_the_check() {
    let mut spec = spec();
    spec.expected_genesis_id = genesis_id(&spec);
    let block = check_genesis(&spec).expect("matches");
    assert_eq!(block_id(&block.header), spec.expected_genesis_id);
    assert_eq!(block.header.height.get(), 0);
    assert_eq!(block.header.parent, BlockId::ZERO);
    assert_eq!(block.header.chain_id.get(), 7);
}

#[test]
fn the_spec_roundtrips_through_json() {
    let spec = spec();
    let text = serde_json::to_string(&spec).expect("serialize");
    assert_eq!(parse_chain_spec(&text).expect("parse"), spec);
}

#[test]
fn allocations_change_the_genesis_id() {
    let base = genesis_id(&spec());
    let mut more = spec();
    more.allocations[1].amount = Amount(6);
    assert_ne!(genesis_id(&more), base);
    let mut reordered = spec();
    reordered.allocations.reverse();
    assert_ne!(genesis_id(&reordered), base);
}

#[test]
fn every_header_field_changes_the_genesis_id() {
    let base = genesis_id(&spec());
    let mut changed = spec();
    changed.genesis.nonce = PowNonce(6);
    assert_ne!(genesis_id(&changed), base);
    let mut changed = spec();
    changed.params.chain_id = ChainId(8);
    assert_ne!(genesis_id(&changed), base);
}

#[test]
fn unknown_fields_are_refused() {
    let mut top = spec_json(&zero_id());
    top["surprise"] = json!(1);
    assert!(matches!(parse(&top), Err(SpecError::Json(_))));
    let mut nested = spec_json(&zero_id());
    nested["params"]["surprise"] = json!(1);
    assert!(matches!(parse(&nested), Err(SpecError::Json(_))));
}

#[test]
fn assume_valid_is_optional_and_parsed() {
    assert_eq!(spec().assume_valid, None);
    let mut with = spec_json(&zero_id());
    with["assume_valid"] = json!(format!("blk:{}", "ab".repeat(32)));
    let parsed = parse(&with).expect("parse");
    assert_eq!(parsed.assume_valid, Some(BlockId(Hash32([0xab; 32]))));
}

#[test]
fn duplicate_and_zero_allocations_are_refused() {
    let mut duplicate = spec_json(&zero_id());
    duplicate["allocations"][1]["address"] = json!(alice());
    assert!(matches!(
        parse(&duplicate),
        Err(SpecError::DuplicateAllocation(_))
    ));
    let mut zero = spec_json(&zero_id());
    zero["allocations"][0]["amount"] = json!(0);
    assert!(matches!(parse(&zero), Err(SpecError::ZeroAllocation(_))));
    let mut overflow = spec_json(&zero_id());
    overflow["allocations"][0]["amount"] = json!(u64::MAX);
    assert!(matches!(parse(&overflow), Err(SpecError::SupplyOverflow)));
}

#[test]
fn bad_params_are_refused() {
    for (field, value) in [
        ("target_block_secs", json!(0)),
        ("half_life_secs", json!(0)),
        ("initial_target", json!("0".repeat(64))),
    ] {
        let mut bad = spec_json(&zero_id());
        bad["params"][field] = value;
        assert!(
            matches!(parse(&bad), Err(SpecError::BadParams(_))),
            "{field}"
        );
    }
    let mut harder_limit = spec_json(&zero_id());
    harder_limit["params"]["pow_limit"] = json!("000f".to_owned() + &"ff".repeat(30));
    assert!(matches!(parse(&harder_limit), Err(SpecError::BadParams(_))));
}

#[test]
fn network_names_are_restricted() {
    for name in ["", "UPPER", "-lead", "trail-", "a/b", &"a".repeat(33)] {
        let mut bad = spec_json(&zero_id());
        bad["network"] = json!(name);
        assert!(parse(&bad).is_err(), "{name:?}");
    }
    assert_eq!(spec().network.as_str(), "test-net");
}

#[test]
fn no_allocations_give_the_empty_block_root() {
    let mut empty = spec();
    empty.allocations.clear();
    assert_eq!(
        genesis_block(&empty).header.tx_root.to_string(),
        "f2b2f05a836b7f4277d8cfd5cf46db32f029b4d30a7c991b2a434614a3066a50"
    );
}
