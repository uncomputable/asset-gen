mod json;

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use elements::secp256k1_zkp;
use elements_miniscript as miniscript;
use miniscript::{bitcoin, elements};

use crate::json::{Flag, Parameters, Serde, TestCase};

const UNSPENDABLE_PUBLIC_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

fn test_case(
    comment: &'static str,
    program_bytes: Vec<u8>,
    commit: simplicity::Cmr,
    success: bool,
) -> TestCase {
    let spend_info = get_spend_info(commit);
    let funding_tx = get_funding_tx(&spend_info);
    let spending_tx = get_spending_tx(&funding_tx, program_bytes, commit, &spend_info);

    TestCase {
        tx: Serde(spending_tx),
        prevouts: funding_tx.output.into_iter().map(Serde).collect(),
        index: 0,
        flags: Flag::all_flags().to_vec(),
        comment: comment.to_string(),
        hash_genesis_block: None,
        success: success.then(Parameters::default),
        failure: (!success).then(Parameters::default),
        is_final: false,
    }
}

fn test_case_bytes(comment: &'static str, program_bytes: Vec<u8>, success: bool) -> TestCase {
    let mut bits = simplicity::BitIter::new(program_bytes.iter().copied());
    let program =
        simplicity::CommitNode::<simplicity::jet::Core>::decode(&mut bits).expect("const");
    let commit = program.cmr();

    test_case(comment, program_bytes, commit, success)
}

fn test_case_string(
    comment: &'static str,
    s: &str,
    witness: &HashMap<Arc<str>, Arc<simplicity::Value>>,
    success: bool,
) -> TestCase {
    let forest =
        simplicity::human_encoding::Forest::<simplicity::jet::Core>::parse(s).expect("parse");
    let program = forest
        .to_witness_node(witness)
        .expect("witness")
        .finalize()
        .expect("finalize");
    let program_bytes = program.encode_to_vec();
    dbg!(&program_bytes);
    test_case(comment, program_bytes, program.cmr(), success)
}

fn get_funding_tx(spend_info: &elements::taproot::TaprootSpendInfo) -> elements::Transaction {
    let coinbase = elements::TxIn::default();
    let output = elements::TxOut {
        asset: elements::confidential::Asset::Null,
        value: elements::confidential::Value::Null,
        nonce: elements::confidential::Nonce::Null,
        script_pubkey: get_script_pubkey(spend_info),
        witness: elements::TxOutWitness::default(),
    };
    elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![coinbase],
        output: vec![output],
    }
}

fn get_spending_tx(
    funding_tx: &elements::Transaction,
    program_bytes: Vec<u8>,
    commit: simplicity::Cmr,
    spend_info: &elements::taproot::TaprootSpendInfo,
) -> elements::Transaction {
    let witness = elements::TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![
            program_bytes,
            to_script(commit).into_bytes(),
            get_control_block(commit, spend_info).serialize(),
        ],
        pegin_witness: vec![],
    };
    let input = elements::TxIn {
        previous_output: to_outpoint(funding_tx),
        is_pegin: false,
        script_sig: elements::Script::new(),
        sequence: elements::Sequence::MAX,
        asset_issuance: elements::AssetIssuance::default(),
        witness,
    };
    let dummy = elements::TxOut::default();
    elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![input],
        output: vec![dummy],
    }
}

fn to_outpoint(prevout: &elements::Transaction) -> elements::OutPoint {
    elements::OutPoint {
        txid: prevout.txid(),
        vout: 0,
    }
}

fn to_script(commit: simplicity::Cmr) -> elements::Script {
    elements::Script::from(commit.as_ref().to_vec())
}

fn unspendable_key() -> bitcoin::key::XOnlyPublicKey {
    bitcoin::key::XOnlyPublicKey::from_slice(&UNSPENDABLE_PUBLIC_KEY).expect("const")
}

fn get_spend_info(commit: simplicity::Cmr) -> elements::taproot::TaprootSpendInfo {
    let script = to_script(commit);
    elements::taproot::TaprootBuilder::new()
        .add_leaf_with_ver(0, script, simplicity::leaf_version())
        .expect("const")
        .finalize(secp256k1_zkp::SECP256K1, unspendable_key())
        .expect("const")
}

fn get_script_pubkey(spend_info: &elements::taproot::TaprootSpendInfo) -> elements::Script {
    let output_key = spend_info.output_key();
    let builder = elements::script::Builder::new();
    builder
        .push_opcode(elements::opcodes::all::OP_PUSHNUM_1)
        .push_slice(&output_key.as_inner().serialize())
        .into_script()
}

fn get_control_block(
    commit: simplicity::Cmr,
    spend_info: &elements::taproot::TaprootSpendInfo,
) -> elements::taproot::ControlBlock {
    let script = to_script(commit);
    let script_ver = (script, simplicity::leaf_version());
    spend_info.control_block(&script_ver).expect("const")
}

fn main() {
    let mut test_cases = Vec::new();
    let empty_witness = HashMap::new();

    /* Unit program with empty witness */
    let s = "main := unit";
    test_cases.push(test_case_string(
        "unit_empty_witness",
        s,
        &empty_witness,
        true,
    ));

    /* The untyped Simplicity term (case (drop iden) iden) ought to cause an occurs check failure. */
    /*let program_bytes = vec![0xc1, 0x07, 0x20, 0x30];
    let commit = simplicity::Cmr::case(
        simplicity::Cmr::drop(simplicity::Cmr::iden()),
        simplicity::Cmr::iden(),
    );
    test_cases.push(test_case("type/occurs_check_failure", program_bytes, commit, false));*/

    /* Unit program with incomplete witness of size 2^31. */
    /*let program_bytes = vec![0x27, 0xe1, 0xe0, 0x00, 0x00, 0x00, 0x00];
    test_cases.push(test_case_bytes(
        "witness/value_out_of_range",
        program_bytes,
        false,
    ));*/

    /* Unit program with incomplete witness of size 2^31-1. */
    /*let program_bytes = vec![0x27, 0xe1, 0xdf, 0xff, 0xff, 0xff, 0xff];
    test_cases.push(test_case_bytes(
        "witness/unexpected_end_of_bitstream",
        program_bytes,
        false,
    ));*/

    /* word("2^23 zero bits") ; unit */
    // FIXME: How to compute CMR without waiting forever?
    /*
    let len = (1 << 20) + 4;
    let mut program_bytes = vec![0u8; len];
    program_bytes[0] = 0xb7;
    program_bytes[1] = 0x08;
    program_bytes[len - 2] = 0x48;
    program_bytes[len - 1] = 0x20;

    test_cases.push(test_case_cmr("witness/memory_exceeds_limit", program_bytes, false));
    */

    /* iden composed with itself 2^23 times. */
    // FIXME: Bytes of program below are different from bytes hardcoded in C repo
    /*let s = "
        id0 := iden
        cp0 := comp id0 id0
        cp1 := comp cp0 cp0
        cp2 := comp cp1 cp1
        cp3 := comp cp2 cp2
        cp4 := comp cp3 cp3
        cp5 := comp cp4 cp4
        cp6 := comp cp5 cp5
        cp7 := comp cp6 cp6
        cp8 := comp cp7 cp7
        cp9 := comp cp8 cp8
        cp10 := comp cp9 cp9
        cp11 := comp cp10 cp10
        cp12 := comp cp11 cp11
        cp13 := comp cp12 cp12
        cp14 := comp cp13 cp13
        cp15 := comp cp14 cp14
        cp16 := comp cp15 cp15
        cp17 := comp cp16 cp16
        cp18 := comp cp17 cp17
        cp19 := comp cp18 cp18
        cp20 := comp cp19 cp19
        cp21 := comp cp20 cp20
        main := comp cp21 cp21
    ";

    let mut program_bytes = vec![0u8; 35];
    program_bytes[0] = 0xe1;
    program_bytes[1] = 0x08;
    program_bytes[33] = 0x40;
    dbg!(&program_bytes);

    test_cases.push(test_case_string("cost/large_program_within_budget", s, &empty_witness, true));*/

    let s = serde_json::to_string(&test_cases).expect("serialize");

    let mut file = File::create("script_assets_test.json").expect("Unable to create file");
    file.write_all(s.as_bytes()).expect("Unable to write data");
}
