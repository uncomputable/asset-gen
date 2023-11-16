mod bit_encoding;
mod json;
mod test;
mod util;

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use simplicity::jet::Core;
use simplicity::node::CoreConstructible;
use simplicity::{Cmr, WitnessNode};

use crate::json::{ScriptError, TestCase};

fn main() {
    let mut test_cases = Vec::new();
    let empty_witness = HashMap::new();

    /*
     * `unit` is an ANYONECANSPEND
     */
    let s = "main := unit";
    test_cases.push(TestCase::from_string(
        "unit_anyonecanspend",
        s,
        &empty_witness,
        None,
    ));

    /*
     * `iden` is an ANYONECANSPEND
     */
    let s = "main := iden";
    test_cases.push(TestCase::from_string(
        "iden_anyonecanspend",
        s,
        &empty_witness,
        None,
    ));

    /*
     * The taproot witness stack must have exactly 3 elements
     */
    let program = Arc::<WitnessNode<Core>>::unit().finalize().unwrap();
    test_cases.push(TestCase::new(
        "wrong_length/extra_script_input",
        program.encode_to_vec(),
        program.cmr(),
        Some(vec![vec![0x00]]),
        None,
        Some(ScriptError::SimplicityWrongLength),
    ));

    /*
     * The CMR (taproot witness script) must be exactly 32 bytes
     */
    let program = Arc::<WitnessNode<Core>>::unit().finalize().unwrap();
    test_cases.push(TestCase::new(
        "wrong_length/extra_cmr_byte",
        program.encode_to_vec(),
        &[0x00; 33],
        None,
        None,
        Some(ScriptError::SimplicityWrongLength),
    ));

    test_cases.push(TestCase::new(
        "wrong_length/missing_cmr_byte",
        program.encode_to_vec(),
        &[0x00; 31],
        None,
        None,
        Some(ScriptError::SimplicityWrongLength),
    ));

    /*
     * EOF inside program length encoding
     */
    let mut bytes = Vec::new();
    let mut encoder = bit_encoding::Encoder::new(&mut bytes);

    // Final bit missing from program length = 2
    encoder.bits_be(0b1, 1).unwrap();
    // The decoder will stop here
    encoder.finalize().unwrap();

    test_cases.push(TestCase::new(
        "bitstream_eof/program_length_eof",
        bytes,
        Cmr::unit(),
        None,
        None,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

    /*
     * EOF inside combinator encoding
     */
    let mut bytes = Vec::new();
    let mut encoder = bit_encoding::Encoder::new(&mut bytes);

    encoder.program_preamble(1).unwrap();
    // Final bit missing from `unit`
    encoder.bits_be(0b0100, 4).unwrap();
    // The decoder will stop here
    encoder.finalize().unwrap();

    test_cases.push(TestCase::new(
        "bitstream_eof/combinator_eof",
        bytes,
        Cmr::unit(),
        None,
        None,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

    /*
     * EOF inside witness block
     */
    let mut bytes = Vec::new();
    let mut encoder = bit_encoding::Encoder::new(&mut bytes);

    encoder.program_preamble(1).unwrap();
    encoder.unit().unwrap();
    encoder.witness_preamble(Some(1)).unwrap();
    // No bits means we declared too many
    // The decoder will stop here
    encoder.finalize().unwrap();

    test_cases.push(TestCase::new(
        "bitstream_eof/witness_eof",
        bytes,
        Cmr::unit(),
        None,
        None,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

    /*
     * `case (drop iden) iden` fails the occurs check
     */
    let program_bytes = vec![0xc1, 0x07, 0x20, 0x30];
    let commit = simplicity::Cmr::case(
        simplicity::Cmr::drop(simplicity::Cmr::iden()),
        simplicity::Cmr::iden(),
    );

    /*
    use simplicity::jet::Core;
    use simplicity::node::CoreConstructible;
    use simplicity::WitnessNode;

    // FIXME: Infinite loop in program finalization
    // https://github.com/BlockstreamResearch/rust-simplicity/issues/177
    let program = Arc::<WitnessNode<Core>>::case(
        &Arc::<WitnessNode<Core>>::drop_(&Arc::<WitnessNode<Core>>::iden()),
        &Arc::<WitnessNode<Core>>::iden(),
    )
    .expect("const")
    .finalize()
    .expect("const");

    assert_eq!(program_bytes, program.encode_to_vec());
    assert_eq!(commit, program.cmr());
    */

    test_cases.push(TestCase::new(
        "type/occurs_check_failure",
        program_bytes,
        commit,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceOccursCheck),
    ));

    /*
     * Too long witness (witness must be shorter than 2^31 bits)
     */
    let mut bytes = Vec::new();
    let mut encoder = bit_encoding::Encoder::new(&mut bytes);

    encoder.program_preamble(1).unwrap();
    encoder.unit().unwrap();
    encoder.witness_preamble(Some(1 << 31)).unwrap();
    // The decoder will stop here
    encoder.finalize().unwrap();

    test_cases.push(TestCase::from_bytes(
        "witness/bitstring_too_long",
        bytes,
        Some(ScriptError::SimplicityDataOutOfRange),
    ));

    /*
     * Incomplete witness (fewer bits than declared)
     */
    let mut bytes = Vec::new();
    let mut encoder = bit_encoding::Encoder::new(&mut bytes);

    encoder.program_preamble(1).unwrap();
    encoder.unit().unwrap();
    encoder.witness_preamble(Some((1 << 31) - 1)).unwrap();
    // No bits means we declared too many
    encoder.finalize().unwrap();

    test_cases.push(TestCase::from_bytes(
        "witness/bitstring_too_short",
        bytes,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

    /*
     * Program exceeds consensus limit on number of cells (memory use):
     * `word("2^23 zero bits") ; unit`
     */
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

    test_cases.push(TestCase::new(
        "cost/memory_exceeds_limit",
        program_bytes,
        commit,
        None,
        None,
        Some(ScriptError::SimplicityExecMemory),
    ));

    /*
     * Large program requires padding:
     * `iden` composed with itself 2^23 times
     */
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
    test_cases.push(TestCase::from_string(
        "cost/large_program_within_budget",
        s,
        &empty_witness,
        None,
    ));

    /*
     * Trailing bytes after program encoding (malleability)
     */
    let program = Arc::<WitnessNode<Core>>::unit().finalize().unwrap();
    let mut bytes = program.encode_to_vec();
    // Trailing byte
    bytes.push(0x00);

    test_cases.push(TestCase::from_bytes(
        "program/trailing_bytes",
        bytes,
        Some(ScriptError::SimplicityBitstreamUnusedBytes),
    ));

    /*
     * Illegal padding in final program byte (malleability)
     */
    let mut bytes = Vec::new();
    let mut encoder = bit_encoding::Encoder::new(&mut bytes);

    encoder.program_preamble(1).unwrap();
    encoder.unit().unwrap();
    encoder.witness_preamble(None).unwrap();
    // Illegal padding
    encoder.bits_be(u64::MAX, 1).unwrap();
    encoder.finalize().unwrap();

    test_cases.push(TestCase::from_bytes(
        "program/illegal_padding",
        bytes,
        Some(ScriptError::SimplicityBitstreamUnusedBits),
    ));

    /*
     * Export test cases to JSON
     */
    let s = serde_json::to_string(&test_cases).expect("serialize");
    let mut file = File::create("script_assets_test.json").expect("Unable to create file");
    file.write_all(s.as_bytes()).expect("Unable to write data");
}
