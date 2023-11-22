mod bit_encoding;
mod json;
mod test;
mod util;

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use simplicity::dag::NoSharing;
use simplicity::jet::Elements;
use simplicity::node::CoreConstructible;
use simplicity::{BitWriter, Cmr, FailEntropy, Value, WitnessNode};

use crate::bit_encoding::Builder;
use crate::json::ScriptError;
use crate::test::TestBuilder;

type Node = Arc<WitnessNode<Elements>>;

fn main() {
    let mut test_cases = Vec::new();
    let empty_witness = HashMap::new();

    /*
     * `unit` is an ANYONECANSPEND
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("ok/unit")
        .human_encoding(s, &empty_witness)
        .expected_result(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * `iden` is an ANYONECANSPEND
     */
    let s = "main := iden";
    let test_case = TestBuilder::comment("ok/iden")
        .human_encoding(s, &empty_witness)
        .expected_result(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * The taproot witness stack is longer than 3 elements
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("wrong_length/extra_script_input")
        .human_encoding(s, &empty_witness)
        .extra_script_input(vec![0x00])
        .expected_result(ScriptError::SimplicityWrongLength)
        .finished();
    test_cases.push(test_case);

    /*
     * The CMR is shorter than 32 bytes
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("wrong_length/missing_cmr_byte")
        .human_encoding(s, &empty_witness)
        .raw_cmr([0; 31])
        .expected_result(ScriptError::SimplicityWrongLength)
        .finished();
    test_cases.push(test_case);

    /*
     * The CMR is longer than 32 bytes
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("wrong_length/extra_cmr_byte")
        .human_encoding(s, &empty_witness)
        .raw_cmr([0; 33])
        .expected_result(ScriptError::SimplicityWrongLength)
        .finished();
    test_cases.push(test_case);

    /*
     * EOF inside program length encoding
     */
    let bytes = bit_encoding::Program::program_preamble(2)
        .delete_bits(1)
        .parser_stops_here()
        .unwrap_err()
        .expect_padding(6);
    let test_case = TestBuilder::comment("bitstream_eof/program_length_eof")
        .raw_program(bytes)
        .raw_cmr([0; 32])
        .expected_result(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * EOF inside combinator encoding
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .unit()
        .iden()
        .comp(2, 1)
        .delete_bits(2 + 1 + 3) // Delete bits to reach byte boundary
        .parser_stops_here()
        .unwrap();
    let cmr = Cmr::case(Cmr::unit(), Cmr::iden());
    let test_case = TestBuilder::comment("bitstream_eof/combinator_eof")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * EOF inside witness block
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .unit()
        .witness_preamble(Some(1))
        .bits_be(u64::default(), 0) // No bits means we declared too many
        .parser_stops_here()
        .unwrap();
    let cmr = Cmr::unit();
    let test_case = TestBuilder::comment("bitstream_eof/witness_eof")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * EOF inside witness block (C test vector)
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .unit()
        .witness_preamble(Some((1 << 31) - 1))
        .bits_be(u64::default(), 0) // No bits means we declared too many
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::unit();
    let test_case = TestBuilder::comment("bitstream_eof/witness_eof_c_test_vector")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Program declared longer than DAG_LEN_MAX
     */
    let dag_len_max = 8_000_000;
    let bytes = bit_encoding::Program::program_preamble(dag_len_max + 1)
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();
    let test_case = TestBuilder::comment("data_out_of_range/program_length")
        .raw_program(bytes)
        .raw_cmr([0; 32])
        .expected_result(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * Witness block declared longer than 2^31 - 1
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .unit()
        .witness_preamble(Some(1 << 31))
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::unit();
    let test_case = TestBuilder::comment("data_out_of_range/witness_length")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * Index points past beginning of program
     */
    let bytes = bit_encoding::Program::program_preamble(2)
        .unit()
        .comp(2, 1) // Left child does not exist
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::comp(Cmr::unit(), Cmr::unit());
    let test_case = TestBuilder::comment("data_out_of_range/relative_combinator_index")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * Jet is not defined
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .jet(u64::MAX, 64) // It is unlikely that all-ones will become a jet soon
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let test_case = TestBuilder::comment("data_out_of_range/undefined_jet")
        .raw_program(bytes)
        .raw_cmr([0; 32])
        .expected_result(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * Word depth greater than 32 (word longer than 2^31 bits)
     */
    let value = Value::u1(0);
    let bytes = bit_encoding::Program::program_preamble(1)
        .word(33, &value)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::const_word(&value);
    let test_case = TestBuilder::comment("data_out_of_range/word_depth")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * Program is not serialized in canonical order
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .unit()
        .iden()
        .comp(1, 2)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::comp(Cmr::unit(), Cmr::iden());
    let test_case = TestBuilder::comment("data_out_of_order/not_in_canonical_order")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityDataOutOfOrder)
        .finished();
    test_cases.push(test_case);

    /*
     * Program contains a `fail` node
     */
    let entropy = FailEntropy::from_byte_array([0; 64]);
    let bytes = bit_encoding::Program::program_preamble(1)
        .fail(entropy.as_ref())
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::fail(entropy);
    let test_case = TestBuilder::comment("fail_code/fail_node")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityFailCode)
        .finished();
    test_cases.push(test_case);

    /*
     * Program contains the stop code
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .stop()
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();
    let test_case = TestBuilder::comment("stop_code/stop_code")
        .raw_program(bytes)
        .raw_cmr([0; 32])
        .expected_result(ScriptError::SimplicityStopCode)
        .finished();
    test_cases.push(test_case);

    /*
     * Node other than `case` has hidden child
     */
    let hidden_cmr = Cmr::from_byte_array([0; 32]);
    let bytes = bit_encoding::Program::program_preamble(3)
        .hidden(hidden_cmr.as_ref())
        .unit()
        .comp(2, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::comp(hidden_cmr, Cmr::unit());
    let test_case = TestBuilder::comment("hidden/comp_hidden_child")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityHidden)
        .finished();
    test_cases.push(test_case);

    /*
     * `Case` has two hidden children
     */
    let hidden_cmr = Cmr::from_byte_array([0; 32]);
    let bytes = bit_encoding::Program::program_preamble(3)
        .hidden(hidden_cmr.as_ref())
        .hidden(hidden_cmr.as_ref())
        .case(2, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::case(hidden_cmr, hidden_cmr);
    let test_case = TestBuilder::comment("hidden/two_hidden_children")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityHidden)
        .finished();
    test_cases.push(test_case);

    /*
     * Trailing bytes after program encoding (malleability)
     */
    let s = "main := unit";
    let program = util::program_from_string::<Elements>(s, &empty_witness).unwrap();
    let mut bytes = program.encode_to_vec();
    // Trailing byte
    bytes.push(0x00);
    let test_case = TestBuilder::comment("bitstream_trailing_bytes/trailing_bytes")
        .raw_program(bytes)
        .raw_cmr(program.cmr())
        .expected_result(ScriptError::SimplicityBitstreamUnusedBytes)
        .finished();
    test_cases.push(test_case);

    /*
     * Illegal padding in final program byte (malleability)
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .unit()
        .witness_preamble(None)
        .illegal_padding()
        .bits_be(u64::MAX, 1)
        .parser_stops_here()
        .unwrap();
    let cmr = Cmr::unit();
    let test_case = TestBuilder::comment("bitstream_illegal_padding/illegal_padding")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityBitstreamUnusedBits)
        .finished();
    test_cases.push(test_case);

    /*
     * Comp combinator: left target != right source
     *
     * unit:      A     -> 1
     * take unit: 1 × B -> 1
     * comp unit (take unit) fails to unify
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .unit()
        .take(1)
        .comp(2, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap();
    let cmr = Cmr::comp(Cmr::unit(), Cmr::take(Cmr::unit()));
    let test_case =
        TestBuilder::comment("type_inference_unification/comp_unify_left_target_right_source")
            .raw_program(bytes)
            .raw_cmr(cmr)
            .expected_result(ScriptError::SimplicityTypeInferenceUnification)
            .finished();
    test_cases.push(test_case);

    /*
     * Pair combinator: left source != right source
     *
     * word(0):    1     -> 2 = 1 + 1
     * take unit:  A × B -> 1
     * pair word(0) (take unit) fails to unify
     */
    let value = Value::u1(0);
    let bytes = bit_encoding::Program::program_preamble(4)
        .word(1, &value)
        .unit()
        .take(1)
        .pair(3, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::pair(Cmr::const_word(&value), Cmr::take(Cmr::unit()));
    let test_case =
        TestBuilder::comment("type_inference_unification/pair_unify_left_source_right_source")
            .raw_program(bytes)
            .raw_cmr(cmr)
            .expected_result(ScriptError::SimplicityTypeInferenceUnification)
            .finished();
    test_cases.push(test_case);

    /*
     * Case combinator: left target != right target
     *
     * take word(0):  A × 1 -> 2^1
     * take word(00): A × 1 -> 2^2
     * case (take word(0)) (take word(00)) fails to unify
     */
    let small_value = Value::u1(0);
    let large_value = Value::u2(0);
    let bytes = bit_encoding::Program::program_preamble(5)
        .word(1, &small_value)
        .take(1)
        .word(2, &large_value)
        .take(1)
        .case(3, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::case(
        Cmr::take(Cmr::const_word(&small_value)),
        Cmr::take(Cmr::const_word(&large_value)),
    );
    let test_case =
        TestBuilder::comment("type_inference_unification/case_unify_left_target_right_target")
            .raw_program(bytes)
            .raw_cmr(cmr)
            .expected_result(ScriptError::SimplicityTypeInferenceUnification)
            .finished();
    test_cases.push(test_case);

    /*
     * Case combinator: left source != A × C
     *
     * word(0):   1     -> 2
     * take unit: B × C -> 1
     * case word(0) (take unit) fails to unify
     */
    let value = Value::u1(0);
    let bytes = bit_encoding::Program::program_preamble(4)
        .word(1, &value)
        .unit()
        .take(1)
        .case(3, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::case(Cmr::const_word(&value), Cmr::take(Cmr::unit()));
    let test_case = TestBuilder::comment("type_inference_unification/case_bind_left_target")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityTypeInferenceUnification)
        .finished();
    test_cases.push(test_case);

    /*
     * Case combinator: right source != B × C
     *
     * take unit: B × C -> 1
     * word(0):   1     -> 2
     * case (take unit) word(0) fails to unify
     */
    let value = Value::u1(0);
    let bytes = bit_encoding::Program::program_preamble(4)
        .unit()
        .take(1)
        .word(1, &value)
        .case(2, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::case(Cmr::take(Cmr::unit()), Cmr::const_word(&value));
    let test_case = TestBuilder::comment("type_inference_unification/case_bind_right_target")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityTypeInferenceUnification)
        .finished();
    test_cases.push(test_case);

    /*
     * Disconnect combinator: left source != 2^256 × A
     *
     * word(0): 1 -> 2
     * iden   : C -> D
     * disconnect word(0) iden fails to unify
     */
    let value = Value::u1(0);
    let bytes = bit_encoding::Program::program_preamble(3)
        .word(1, &value)
        .iden()
        .disconnect(2, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::disconnect(Cmr::const_word(&value));
    let test_case = TestBuilder::comment("type_inference_unification/disconnect_bind_left_source")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityTypeInferenceUnification)
        .finished();
    test_cases.push(test_case);

    /*
     * Disconnect combinator: left target != B × C
     *
     * unit: A -> 1
     * iden: C -> D
     * disconnect unit iden fails to unify
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .unit()
        .iden()
        .disconnect(2, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::disconnect(Cmr::unit());
    let test_case = TestBuilder::comment("type_inference_unification/disconnect_bind_left_target")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityTypeInferenceUnification)
        .finished();
    test_cases.push(test_case);

    /*
     * Infinite type is inferred
     *
     * drop iden: A × B -> B
     * iden:      C     -> C
     * case (drop iden) iden fails the occurs check
     */
    let bytes = bit_encoding::Program::program_preamble(4)
        .iden()
        .drop(1)
        .iden()
        .case(2, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap();
    let cmr = Cmr::case(Cmr::drop(Cmr::iden()), Cmr::iden());
    let test_case = TestBuilder::comment("type_inference_occurs_check/occurs_check")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityTypeInferenceOccursCheck)
        .finished();
    test_cases.push(test_case);

    /*
     * Source of program root is not unit
     *
     * take unit: A × B -> 1
     */
    let bytes = bit_encoding::Program::program_preamble(2)
        .unit()
        .take(1)
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::take(Cmr::unit());
    let test_case = TestBuilder::comment("type_inference_not_program/root_source_type")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityTypeInferenceNotProgram)
        .finished();
    test_cases.push(test_case);

    /*
     * Target of program root is not unit
     *
     * pair unit unit: A -> 1 × 1
     */
    let bytes = bit_encoding::Program::program_preamble(2)
        .unit()
        .pair(1, 1)
        .witness_preamble(None)
        .program_finished()
        .unwrap();
    let cmr = Cmr::pair(Cmr::unit(), Cmr::unit());
    let test_case = TestBuilder::comment("type_inference_not_program/root_target_type")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityTypeInferenceNotProgram)
        .finished();
    test_cases.push(test_case);

    /*
     * Parse next witness value, but bitstring is EOF
     */
    let bytes = bit_encoding::Program::program_preamble(5)
        .witness() // 1 → (1 + 1) * 1 means bit size = 1
        .unit()
        .take(1)
        .case(1, 1)
        .comp(4, 1)
        .witness_preamble(None) // bitstring: []
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::comp(
        Cmr::witness(),
        Cmr::case(Cmr::take(Cmr::unit()), Cmr::take(Cmr::unit())),
    );
    let test_case = TestBuilder::comment("witness_eof/next_value")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityWitnessEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Parse next bit of witness value, but bitstring is EOF
     */
    let bytes = bit_encoding::Program::program_preamble(6)
        .witness() // 1 → ((1 + 1) + (1 + 1)) × 1 means bit size = 2
        .unit()
        .take(1)
        .case(1, 1)
        .case(1, 1)
        .comp(5, 1)
        .witness_preamble(Some(1)) // bitstring: [1]
        .bits_be(u64::MAX, 1)
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::comp(
        Cmr::witness(),
        Cmr::case(
            Cmr::case(Cmr::take(Cmr::unit()), Cmr::take(Cmr::unit())),
            Cmr::case(Cmr::take(Cmr::unit()), Cmr::take(Cmr::unit())),
        ),
    );
    let test_case = TestBuilder::comment("witness_eof/next_bit")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityWitnessEof)
        .finished();
    test_cases.push(test_case);

    /*
     * FIXME: Unknown jet?
     */
    let s = "
        wit := witness
        main := comp (comp wit jet_is_zero_64) jet_verify
    ";
    let mut witness = HashMap::new();
    witness.insert(Arc::from("wit"), Value::u64(0u64));
    let test_case = TestBuilder::comment("data_out_of_range/fixme")
        .human_encoding(s, &witness)
        .expected_result(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * FIXME: EOF despite large-enough witness
     */
    let s = "
        wit := witness
        main := comp (comp wit jet_add_32) unit
    ";
    let mut witness = HashMap::new();
    witness.insert(Arc::from("wit"), Value::u64(0u64));
    let test_case = TestBuilder::comment("bitstream_eof/fixme")
        .human_encoding(s, &witness)
        .expected_result(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Witness block declared too long
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .unit()
        .witness_preamble(Some(1))
        .bits_be(u64::MAX, 1)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = Cmr::unit();
    let test_case = TestBuilder::comment("witness_trailing_bits/trailing_bits")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityWitnessUnusedBits)
        .finished();
    test_cases.push(test_case);

    /*
     * Two unit nodes have the same IMR
     */
    // Cannot use human encoding because it unifies combinators
    let program = Node::comp(&Node::unit(), &Node::unit()).unwrap();
    let bytes = BitWriter::write_to_vec(|w| program.encode_with_tracker_default::<_, NoSharing>(w));
    let test_case = TestBuilder::comment("unshared_subexpression/duplicate_imr")
        .raw_program(bytes)
        .raw_cmr(program.cmr())
        .expected_result(ScriptError::SimplicityUnsharedSubexpression)
        .finished();
    test_cases.push(test_case);

    /*
     * Two hidden nodes have the same payload
     */
    /// Compute a program that is maximally shared iff cmr1 == cmr2.
    ///
    /// Returns the program encoding and the program CMR.
    fn unshared_subexpression_program(cmr1: Cmr, cmr2: Cmr) -> (Vec<u8>, Cmr) {
        // FIXME: Use rust-simplicity encoder with sharing of hidden nodes disabled, once implemented
        let bytes = bit_encoding::Program::program_preamble(13)
            // scribe ([1], [])
            .unit() // 1 → 1
            .injr(1) // 1 → 1 + 1
            .pair(1, 2) // 1 → (1 + 1) × 1
            // End scribe
            .hidden(cmr1.as_ref())
            .unit() // 1 × 1 → 1
            .case(2, 1) // (1 + 1) × 1 → 1
            .comp(4, 1) // 1 → 1
            .hidden(cmr2.as_ref())
            .iden() // 1 → 1
            .take(1) // 1 × 1 → 1
            // Forall cmr1 cmr2, IMR(assertr cmr1 unit) != IMR(assertr cmr2 (take iden))
            .case(3, 1) // (1 + 1) × 1 → 1
            .comp(9, 1) // 1 → 1
            .comp(6, 1) // 1 → 1
            .witness_preamble(None)
            .program_finished()
            .unwrap_err()
            .unwrap_padding();
        let scribe = Cmr::pair(Cmr::injr(Cmr::unit()), Cmr::unit());
        let cmr = Cmr::comp(
            Cmr::comp(scribe, Cmr::case(cmr1, Cmr::unit())),
            Cmr::comp(scribe, Cmr::case(cmr2, Cmr::take(Cmr::iden()))),
        );

        (bytes, cmr)
    }

    let same_cmr = Cmr::from_byte_array([0; 32]);
    let (bytes, cmr) = unshared_subexpression_program(same_cmr, same_cmr);
    let test_case = TestBuilder::comment("unshared_subexpression/duplicate_hidden")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityUnsharedSubexpression)
        .finished();
    test_cases.push(test_case);

    /*
     * Two hidden nodes have different payload
     *
     * Test if `unshared_subexpression_program(cmr1, cmr2)` is maximally shared for cmr1 != cmr2
     */
    let same_cmr = Cmr::from_byte_array([0; 32]);
    let different_cmr = Cmr::from_byte_array([1; 32]);
    let (bytes, cmr) = unshared_subexpression_program(same_cmr, different_cmr);
    let test_case = TestBuilder::comment("unshared_subexpression/no_duplicate_hidden")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * CMR mismatch inside Taproot witness
     */
    let s = "
        main := unit
    ";
    let wrong_cmr = Cmr::iden();
    let test_case = TestBuilder::comment("cmr/mismatch")
        .human_encoding(s, &empty_witness)
        .raw_cmr(wrong_cmr)
        .expected_result(ScriptError::SimplicityCmr)
        .finished();
    test_cases.push(test_case);

    /*
     * CMR match inside Taproot witness
     */
    let s = "
        main := unit
    ";
    let test_case = TestBuilder::comment("cmr/match")
        .human_encoding(s, &empty_witness)
        .expected_result(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

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
    let cmr = Cmr::from_byte_array([
        0x7f, 0x81, 0xc0, 0x76, 0xf0, 0xdf, 0x95, 0x05, 0xbf, 0xce, 0x61, 0xf0, 0x41, 0x19, 0x7b,
        0xd9, 0x2a, 0xaa, 0xa4, 0xf1, 0x70, 0x15, 0xd1, 0xec, 0xb2, 0x48, 0xdd, 0xff, 0xe9, 0xd9,
        0xda, 0x07,
    ]);

    /*
    let mut word = Value::u8(0x00);
    for _ in 0..20 {
        word = Value::prod(word.clone(), word.clone());
    }

    // FIXME: Finalizing this program takes a long time
    let program = Arc::<WitnessNode<Core>>::comp(
        &Arc::<WitnessNode<Core>>::const_word(word),
        &Arc::<WitnessNode<Core>>::unit(),
    )
    .unwrap()
    .finalize()
    .unwrap();

    assert_eq!(program_bytes, program.encode_to_vec());
    assert_eq!(commit, program.cmr());
    */

    let test_case = TestBuilder::comment("cost/memory_exceeds_limit")
        .raw_program(program_bytes)
        .raw_cmr(cmr)
        .expected_result(ScriptError::SimplicityExecMemory)
        .finished();
    test_cases.push(test_case);

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
    let test_case = TestBuilder::comment("cost/large_program_within_budget")
        .human_encoding(s, &empty_witness)
        .expected_result(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Program root is hidden
     */
    let hidden_cmr = Cmr::from_byte_array([0; 32]);
    let bytes = bit_encoding::Program::program_preamble(1)
        .hidden(hidden_cmr.as_ref())
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();
    let test_case = TestBuilder::comment("hidden_root/hidden_root")
        .raw_program(bytes)
        .raw_cmr(hidden_cmr)
        .expected_result(ScriptError::SimplicityHiddenRoot)
        .finished();
    test_cases.push(test_case);

    /*
     * Export test cases to JSON
     */
    let s = serde_json::to_string_pretty(&test_cases).expect("serialize");
    let mut file = File::create("script_assets_test.json").expect("Unable to create file");
    file.write_all(s.as_bytes()).expect("Unable to write data");
}
