mod json;
mod util;

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use elements::hex::ToHex;
use elements_miniscript as miniscript;
use miniscript::elements;

use crate::json::{Flag, Parameters, ScriptError, Serde, TestCase};

fn test_case(
    comment: &'static str,
    program_bytes: Vec<u8>,
    commit: simplicity::Cmr,
    cost: Option<simplicity::Cost>,
    error: Option<ScriptError>,
) -> TestCase {
    let spend_info = util::get_spend_info(commit, simplicity::leaf_version());
    let control_block =
        util::get_control_block(commit, simplicity::leaf_version(), &spend_info).expect("const");

    let funding_tx = get_funding_tx(&spend_info);
    let spending_tx = get_spending_tx(&funding_tx);

    let mut witness =
        util::get_witness_stack(program_bytes, util::to_script(commit), control_block);

    if let Some(cost) = cost {
        if let Some(annex) = cost.get_padding(&witness) {
            dbg!(annex.len());
            witness.push(annex);
        }
    }

    let parameters = Parameters::taproot(witness, error);
    let (success, failure) = match error {
        None => (Some(parameters), None),
        Some(_) => (None, Some(parameters)),
    };

    TestCase {
        tx: Serde(spending_tx),
        prevouts: funding_tx.output.into_iter().map(Serde).collect(),
        index: 0,
        flags: Flag::all_flags().to_vec(),
        comment: comment.to_string(),
        hash_genesis_block: None,
        success,
        failure,
        is_final: false,
    }
}

fn test_case_bytes(
    comment: &'static str,
    program_bytes: Vec<u8>,
    error: Option<ScriptError>,
) -> TestCase {
    let mut bits = simplicity::BitIter::new(program_bytes.iter().copied());
    let program =
        simplicity::CommitNode::<simplicity::jet::Core>::decode(&mut bits).expect("const");
    let commit = program.cmr();

    test_case(comment, program_bytes, commit, None, error)
}

fn test_case_string(
    comment: &'static str,
    s: &str,
    witness: &HashMap<Arc<str>, Arc<simplicity::Value>>,
    error: Option<ScriptError>,
) -> TestCase {
    let forest =
        simplicity::human_encoding::Forest::<simplicity::jet::Core>::parse(s).expect("parse");
    let program = forest
        .to_witness_node(witness)
        .finalize()
        .expect("finalize");
    let program_bytes = program.encode_to_vec();
    dbg!(&program_bytes.to_hex(), program_bytes.len());
    test_case(
        comment,
        program_bytes,
        program.cmr(),
        Some(program.bounds().cost),
        error,
    )
}

fn get_funding_tx(spend_info: &elements::taproot::TaprootSpendInfo) -> elements::Transaction {
    let coinbase = elements::TxIn::default();
    let output = elements::TxOut {
        asset: elements::confidential::Asset::Null,
        value: elements::confidential::Value::Null,
        nonce: elements::confidential::Nonce::Null,
        script_pubkey: util::get_script_pubkey(spend_info),
        // The witness is overwritten by script_tests.cpp based on the success / failure parameters
        witness: elements::TxOutWitness::default(),
    };
    elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![coinbase],
        output: vec![output],
    }
}

fn get_spending_tx(funding_tx: &elements::Transaction) -> elements::Transaction {
    let input = elements::TxIn {
        previous_output: util::to_outpoint(funding_tx),
        is_pegin: false,
        script_sig: elements::Script::new(),
        sequence: elements::Sequence::MAX,
        asset_issuance: elements::AssetIssuance::default(),
        witness: elements::TxInWitness::default(),
    };
    let dummy = elements::TxOut::default();
    elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![input],
        output: vec![dummy],
    }
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
        None,
    ));

    /* The untyped Simplicity term (case (drop iden) iden) ought to cause an occurs check failure. */
    let program_bytes = vec![0xc1, 0x07, 0x20, 0x30];
    let commit = simplicity::Cmr::case(
        simplicity::Cmr::drop(simplicity::Cmr::iden()),
        simplicity::Cmr::iden(),
    );
    test_cases.push(test_case(
        "type/occurs_check_failure",
        program_bytes,
        commit,
        None,
        Some(ScriptError::SimplicityTypeInferenceOccursCheck),
    ));

    /* Unit program with incomplete witness of size 2^31. */
    let program_bytes = vec![0x27, 0xe1, 0xe0, 0x00, 0x00, 0x00, 0x00];
    test_cases.push(test_case_bytes(
        "witness/value_out_of_range",
        program_bytes,
        Some(ScriptError::SimplicityDataOutOfRange),
    ));

    /* Unit program with incomplete witness of size 2^31-1. */
    let program_bytes = vec![0x27, 0xe1, 0xdf, 0xff, 0xff, 0xff, 0xff];
    test_cases.push(test_case_bytes(
        "witness/unexpected_end_of_bitstream",
        program_bytes,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

    /* word("2^23 zero bits") ; unit */
    let len = (1 << 20) + 4;
    let mut program_bytes = vec![0u8; len];
    program_bytes[0] = 0xb7;
    program_bytes[1] = 0x08;
    program_bytes[len - 2] = 0x48;
    program_bytes[len - 1] = 0x20;
    let commit = simplicity::Cmr::from_byte_array([
        0x7f, 0x81, 0xc0, 0x76, 0xf0, 0xdf, 0x95, 0x05, 0xbf, 0xce, 0x61, 0xf0, 0x41, 0x19, 0x7b,
        0xd9, 0x2a, 0xaa, 0xa4, 0xf1, 0x70, 0x15, 0xd1, 0xec, 0xb2, 0x48, 0xdd, 0xff, 0xe9, 0xd9,
        0xda, 0x07,
    ]);

    /*
    use simplicity::jet::Core;
    use simplicity::node::{CoreConstructible};
    use simplicity::{Value, WitnessNode};

    let mut word = Value::u8(0x00);
    for _ in 0..20 {
        word = Value::prod(word.clone(), word.clone());
    }

    // FIXME: Finalizing this program takes a long time
    let program = Arc::<WitnessNode<Core>>::comp(
        &Arc::<WitnessNode<Core>>::const_word(word),
        &Arc::<WitnessNode<Core>>::unit(),
    )
    .expect("const")
    .finalize()
    .expect("const");

    assert_eq!(program_bytes, program.encode_to_vec());
    assert_eq!(commit, program.cmr());
    */

    test_cases.push(test_case(
        "cost/memory_exceeds_limit",
        program_bytes,
        commit,
        None,
        Some(ScriptError::SimplicityExecMemory),
    ));

    /* iden composed with itself 2^23 times. */
    let s = "
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
    test_cases.push(test_case_string(
        "cost/large_program_within_budget",
        s,
        &empty_witness,
        None,
    ));

    let mut program_bytes = vec![0u8; 35];
    program_bytes[0] = 0xe1;
    program_bytes[1] = 0x08;
    program_bytes[33] = 0x40;
    dbg!(&program_bytes.to_hex(), program_bytes.len());

    test_cases.push(test_case_bytes(
        "program/program_includes_unused_bytes",
        program_bytes,
        Some(ScriptError::SimplicityBitstreamUnusedBytes),
    ));

    let s = serde_json::to_string(&test_cases).expect("serialize");

    let mut file = File::create("script_assets_test.json").expect("Unable to create file");
    file.write_all(s.as_bytes()).expect("Unable to write data");
}
