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
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * `iden` is an ANYONECANSPEND
     */
    let s = "main := iden";
    let test_case = TestBuilder::comment("ok/iden")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Taproot witness stack is longer than 3 elements
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("wrong_length/multiple_script_inputs")
        .human_encoding(s, &empty_witness)
        .extra_script_input(vec![0x00])
        .expected_error(ScriptError::SimplicityWrongLength)
        .finished();
    test_cases.push(test_case);

    /*
     * Taproot witness stack is shorter than 3 elements
     *
     * Taproot enforces at least two witness stack elements:
     * witness script + control block
     * This is checked by the taproot test suite
     *
     * We check a witness stack of exactly two elements
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("wrong_length/no_script_inputs")
        .human_encoding(s, &empty_witness)
        .skip_script_inputs()
        .expected_error(ScriptError::SimplicityWrongLength)
        .finished();
    test_cases.push(test_case);

    /*
     * Taproot witness stack is exactly 3 elements
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("wrong_length/one_script_input")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * CMR is shorter than 32 bytes
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("wrong_length/too_short_cmr")
        .human_encoding(s, &empty_witness)
        .raw_cmr([0; 31])
        .expected_error(ScriptError::SimplicityWrongLength)
        .finished();
    test_cases.push(test_case);

    /*
     * CMR is longer than 32 bytes
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("wrong_length/too_long_cmr")
        .human_encoding(s, &empty_witness)
        .raw_cmr([0; 33])
        .expected_error(ScriptError::SimplicityWrongLength)
        .finished();
    test_cases.push(test_case);

    /*
     * CMR is exactly 32 bytes
     */
    let s = "main := unit";
    let test_case = TestBuilder::comment("wrong_length/good_cmr")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Empty program
     */
    let test_case = TestBuilder::comment("bitstream_eof/empty_program")
        .raw_program(vec![])
        .raw_cmr([0; 32])
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Unfinished program length
     */
    let bytes = bit_encoding::Program::program_preamble(16)
        .assert_n_total_written(8 + 3)
        .delete_bits(3)
        .parser_stops_here();
    let test_case = TestBuilder::comment("bitstream_eof/unfinished_program_length")
        .raw_program(bytes)
        .raw_cmr([0; 32])
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Unfinished combinator body
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .unit()
        .iden()
        .comp(2, 1)
        .assert_n_total_written(2 * 8 + 6)
        .delete_bits(6)
        .parser_stops_here();
    let cmr = Cmr::case(Cmr::unit(), Cmr::iden());
    let test_case = TestBuilder::comment("bitstream_eof/unfinished_combinator_body")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Unfinished combinator child index
     */
    let bytes = bit_encoding::Program::program_preamble(4) // Increase len for more bits
        .unit()
        .iden()
        .comp(2, 1)
        .assert_n_total_written(3 * 8 + 1)
        .delete_bits(1)
        .parser_stops_here();
    let cmr = Cmr::comp(Cmr::unit(), Cmr::iden());
    let test_case = TestBuilder::comment("bitstream_eof/unfinished_combinator_child_index")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Finished combinator body + child indices
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .unit()
        .iden()
        .comp(2, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::comp(Cmr::unit(), Cmr::iden());
    let test_case = TestBuilder::comment("bitstream_eof/finished_combinator")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Unfinished witness length
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .unit()
        .witness_preamble(16)
        .assert_n_total_written(2 * 8 + 2)
        .delete_bits(2)
        .parser_stops_here();
    let cmr = Cmr::unit();
    let test_case = TestBuilder::comment("bitstream_eof/unfinished_witness_length")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Unfinished witness block
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .unit()
        .witness_preamble(1)
        .bits_be(u64::default(), 0) // No bits means we declared too many
        .parser_stops_here();
    let cmr = Cmr::unit();
    let test_case = TestBuilder::comment("bitstream_eof/unfinished_witness_block")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Unfinished witness block (C test vector)
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .unit()
        .witness_preamble((1 << 31) - 1)
        .bits_be(u64::default(), 0) // No bits means we declared too many
        .parser_stops_here();
    let cmr = Cmr::unit();
    let test_case = TestBuilder::comment("bitstream_eof/unfinished_witness_block2")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Unfinished jet body
     *
     * XXX: Potentially flaky because jet encodings may change
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .jet(462384, 19)
        .assert_n_total_written(3 * 8)
        .delete_bits(8)
        .parser_stops_here();
    let cmr = Cmr::comp(Cmr::jet(Elements::Version), Cmr::unit());
    let test_case = TestBuilder::comment("bitstream_eof/unfinished_jet_body")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Finished jet body
     *
     * XXX: Potentially flaky because jet encodings may change
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .jet(462384, 19)
        .unit()
        .comp(2, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::comp(Cmr::jet(Elements::Version), Cmr::unit());
    let test_case = TestBuilder::comment("bitstream_eof/finished_jet_body")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Unfinished word
     */
    // Program that causes SIMPLICITY_BITSTREAM_EOF iff a non-64-bit value is passed
    fn unfinished_word_program(value: &Value) -> (Vec<u8>, Cmr) {
        let bytes = bit_encoding::Program::program_preamble(3)
            .word(7, value)
            .unit()
            .comp(2, 1)
            .witness_preamble(0)
            .program_finished();
        let cmr = Cmr::comp(Cmr::const_word(value), Cmr::unit());
        (bytes, cmr)
    }

    let value = Value::u1(0);
    let (bytes, cmr) = unfinished_word_program(&value);
    let test_case = TestBuilder::comment("bitstream_eof/unfinished_word")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Finished word
     */
    let value = Value::u64(u64::MAX);
    let (bytes, cmr) = unfinished_word_program(&value);
    let test_case = TestBuilder::comment("bitstream_eof/finished_word")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * DAG_LEN_MAX < program length
     */
    let dag_len_max = 8_000_000;
    let bytes = bit_encoding::Program::program_preamble(dag_len_max + 1).parser_stops_here();
    let test_case = TestBuilder::comment("data_out_of_range/program_length_exceeds_max")
        .raw_program(bytes)
        .raw_cmr([0; 32])
        .expected_error(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * program length <= DAG_LEN_MAX
     */
    // Too lazy to write a program of DAG_LEN_MAX many nodes
    // Instead, test that parser goes past program length and runs out of bits to read
    let bytes = bit_encoding::Program::program_preamble(dag_len_max)
        .bits_be(u64::MAX, 6)
        .assert_n_total_written(5 * 8)
        .parser_stops_here();
    let test_case = TestBuilder::comment("data_out_of_range/program_length_ok")
        .raw_program(bytes)
        .raw_cmr([0; 32])
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * 2^31 <= witness length
     */
    /// If 2^31 <= bit_len, then program causes SIMPLICITY_DATA_OUT_OF_RANGE
    ///
    /// If bit_len < 2^31, then program causes SIMPLICITY_BITSTREAM_EOF
    // Too lazy to write 2^31 - 1 many bits = 2 GiB!
    // Instead, test that parser goes past witness length and runs out of bits to read
    fn witness_length_program(bit_len: usize) -> (Vec<u8>, Cmr) {
        let bytes = bit_encoding::Program::program_preamble(3)
            .witness()
            .unit()
            .comp(2, 1)
            .witness_preamble(bit_len)
            .parser_stops_here();
        let cmr = Cmr::comp(Cmr::witness(), Cmr::unit());
        (bytes, cmr)
    }

    let (bytes, cmr) = witness_length_program(1 << 31);
    let test_case = TestBuilder::comment("data_out_of_range/witness_length_exceeds_max")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * witness length < 2^31
     */
    let (bytes, cmr) = witness_length_program((1 << 31) - 1);
    let test_case = TestBuilder::comment("data_out_of_range/witness_length_ok")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Relative child index points past beginning of program
     */
    /// Program causes SIMPLICITY_DATA_OUT_OF_RANGE iff 1 < left_offset
    fn combinator_child_index_program(left_offset: usize) -> (Vec<u8>, Cmr) {
        let bytes = bit_encoding::Program::program_preamble(2)
            .unit()
            .comp(left_offset, 1)
            .witness_preamble(0)
            .program_finished();
        let cmr = Cmr::comp(Cmr::unit(), Cmr::unit());
        (bytes, cmr)
    }

    let (bytes, cmr) = combinator_child_index_program(2);
    let test_case = TestBuilder::comment("data_out_of_range/relative_child_index_too_large")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * Relative child index points inside program
     */
    let (bytes, cmr) = combinator_child_index_program(1);
    let test_case = TestBuilder::comment("data_out_of_range/relative_child_index_ok")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Jet is not defined
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .jet(u64::MAX, 64) // It is unlikely that all-ones will become a jet soon
        .witness_preamble(0)
        .program_finished();
    let test_case = TestBuilder::comment("data_out_of_range/undefined_jet")
        .raw_program(bytes)
        .raw_cmr([0; 32])
        .expected_error(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * 32 < word depth (2^31 bits < word length)
     */
    /// If 32 < depth, then program causes SIMPLICITY_DATA_OUT_OF_RANGE
    ///
    /// If depth <= 32, then program causes SIMPLICITY_BITSTREAM_EOF
    // Too lazy to write 2^31 many bits = 2 GiB!
    // Instead, test that parser goes past word depth and runs out of bits to read
    fn word_depth_program(depth: usize) -> (Vec<u8>, Cmr) {
        let value = Value::u1(0);
        let bytes = bit_encoding::Program::program_preamble(1)
            .word(depth, &value)
            .parser_stops_here();
        let cmr = Cmr::from_byte_array([0; 32]);
        (bytes, cmr)
    }

    let (bytes, cmr) = word_depth_program(33);
    let test_case = TestBuilder::comment("data_out_of_range/word_depth_exceeds_max")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityDataOutOfRange)
        .finished();
    test_cases.push(test_case);

    /*
     * word_depth <= 32
     */
    let (bytes, cmr) = word_depth_program(32);
    let test_case = TestBuilder::comment("data_out_of_range/word_depth_ok")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Program is not serialized in canonical order
     */
    /// Program that causes SIMPLICITY_DATA_OUT_OF_ORDER iff canonical is false
    fn canonical_order_program(canonical: bool) -> (Vec<u8>, Cmr) {
        let (left_offset, right_offset) = match canonical {
            false => (1, 2),
            true => (2, 1),
        };
        let bytes = bit_encoding::Program::program_preamble(3)
            .unit()
            .iden()
            .comp(left_offset, right_offset)
            .witness_preamble(0)
            .program_finished();
        let cmr = Cmr::comp(Cmr::unit(), Cmr::iden());
        (bytes, cmr)
    }

    let (bytes, cmr) = canonical_order_program(false);
    let test_case = TestBuilder::comment("data_out_of_order/not_in_canonical_order")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityDataOutOfOrder)
        .finished();
    test_cases.push(test_case);

    /*
     * Program is serialized in canonical order
     */
    let (bytes, cmr) = canonical_order_program(true);
    let test_case = TestBuilder::comment("data_out_of_order/in_canonical_order")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Program contains a `fail` node
     */
    let entropy = FailEntropy::from_byte_array([0; 64]);
    let bytes = bit_encoding::Program::program_preamble(1)
        .fail(entropy)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::fail(entropy);
    let test_case = TestBuilder::comment("fail_code/fail_node")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityFailCode)
        .finished();
    test_cases.push(test_case);

    /*
     * Program contains the stop code
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .stop()
        .parser_stops_here();
    let test_case = TestBuilder::comment("stop_code/stop_code")
        .raw_program(bytes)
        .raw_cmr([0; 32])
        .expected_error(ScriptError::SimplicityStopCode)
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
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::comp(hidden_cmr, Cmr::unit());
    let test_case = TestBuilder::comment("hidden/comp_hidden_child")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityHidden)
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
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::case(hidden_cmr, hidden_cmr);
    let test_case = TestBuilder::comment("hidden/two_hidden_children")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityHidden)
        .finished();
    test_cases.push(test_case);

    /*
     * Trailing bytes after program encoding (malleability)
     */
    /// Program causes SIMPLICITY_BITSTREAM_UNUSED_BYTES iff trailing_byte is true
    fn trailing_bytes_program(trailing_byte: bool) -> (Vec<u8>, Cmr) {
        let s = "main := unit";
        let empty_witness = HashMap::new();
        let program = util::program_from_string::<Elements>(s, &empty_witness).unwrap();
        let mut bytes = program.encode_to_vec();
        if trailing_byte {
            bytes.push(0x00);
        }
        (bytes, program.cmr())
    }

    let (bytes, cmr) = trailing_bytes_program(true);
    let test_case = TestBuilder::comment("bitstream_trailing_bytes/trailing_bytes")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamUnusedBytes)
        .finished();
    test_cases.push(test_case);

    /*
     * No trailing bytes after program encoding
     */
    let (bytes, cmr) = trailing_bytes_program(false);
    let test_case = TestBuilder::comment("bitstream_trailing_bytes/no_trailing_bytes")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Illegal padding in final program byte (malleability)
     */
    /// Program causes SIMPLICITY_BITSTREAM_UNUSED_BITS iff pad_with = true
    fn illegal_padding_program(pad_with: bool) -> (Vec<u8>, Cmr) {
        let bytes = bit_encoding::Program::program_preamble(1)
            .unit()
            .witness_preamble(0)
            .illegal_padding()
            .bits_be(u64::from(pad_with), 1)
            .assert_n_total_written(8)
            .parser_stops_here();
        let cmr = Cmr::unit();
        (bytes, cmr)
    }

    let (bytes, cmr) = illegal_padding_program(true);
    let test_case = TestBuilder::comment("bitstream_illegal_padding/illegal_padding")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityBitstreamUnusedBits)
        .finished();
    test_cases.push(test_case);

    /*
     * Legal padding in final program byte
     */
    let (bytes, cmr) = illegal_padding_program(false);
    let test_case = TestBuilder::comment("bitstream_illegal_padding/legal_padding")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Comp combinator: left target != right source
     *
     * unit:      A     → 1
     * take unit: 1 × B → 1
     * comp unit (take unit) fails to unify
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .unit()
        .take(1)
        .comp(2, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::comp(Cmr::unit(), Cmr::take(Cmr::unit()));
    let test_case =
        TestBuilder::comment("type_inference_unification/comp_unify_left_target_right_source")
            .raw_program(bytes)
            .raw_cmr(cmr)
            .expected_error(ScriptError::SimplicityTypeInferenceUnification)
            .finished();
    test_cases.push(test_case);

    /*
     * Pair combinator: left source != right source
     *
     * word(0):    1     → 2 = 1 + 1
     * take unit:  A × B → 1
     * pair word(0) (take unit) fails to unify
     */
    let value = Value::u1(0);
    let bytes = bit_encoding::Program::program_preamble(4)
        .word(1, &value)
        .unit()
        .take(1)
        .pair(3, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::pair(Cmr::const_word(&value), Cmr::take(Cmr::unit()));
    let test_case =
        TestBuilder::comment("type_inference_unification/pair_unify_left_source_right_source")
            .raw_program(bytes)
            .raw_cmr(cmr)
            .expected_error(ScriptError::SimplicityTypeInferenceUnification)
            .finished();
    test_cases.push(test_case);

    /*
     * Case combinator: left target != right target
     *
     * take word(0):  A × 1 → 2^1
     * take word(00): A × 1 → 2^2
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
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::case(
        Cmr::take(Cmr::const_word(&small_value)),
        Cmr::take(Cmr::const_word(&large_value)),
    );
    let test_case =
        TestBuilder::comment("type_inference_unification/case_unify_left_target_right_target")
            .raw_program(bytes)
            .raw_cmr(cmr)
            .expected_error(ScriptError::SimplicityTypeInferenceUnification)
            .finished();
    test_cases.push(test_case);

    /*
     * Case combinator: left source != A × C
     *
     * word(0):   1     → 2
     * take unit: B × C → 1
     * case word(0) (take unit) fails to unify
     */
    let value = Value::u1(0);
    let bytes = bit_encoding::Program::program_preamble(4)
        .word(1, &value)
        .unit()
        .take(1)
        .case(3, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::case(Cmr::const_word(&value), Cmr::take(Cmr::unit()));
    let test_case = TestBuilder::comment("type_inference_unification/case_bind_left_target")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityTypeInferenceUnification)
        .finished();
    test_cases.push(test_case);

    /*
     * Case combinator: right source != B × C
     *
     * take unit: B × C → 1
     * word(0):   1     → 2
     * case (take unit) word(0) fails to unify
     */
    let value = Value::u1(0);
    let bytes = bit_encoding::Program::program_preamble(4)
        .unit()
        .take(1)
        .word(1, &value)
        .case(2, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::case(Cmr::take(Cmr::unit()), Cmr::const_word(&value));
    let test_case = TestBuilder::comment("type_inference_unification/case_bind_right_target")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityTypeInferenceUnification)
        .finished();
    test_cases.push(test_case);

    /*
     * Disconnect combinator: left source != 2^256 × A
     *
     * word(0): 1 → 2
     * iden   : C → D
     * disconnect word(0) iden fails to unify
     */
    let value = Value::u1(0);
    let bytes = bit_encoding::Program::program_preamble(3)
        .word(1, &value)
        .iden()
        .disconnect(2, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::disconnect(Cmr::const_word(&value));
    let test_case = TestBuilder::comment("type_inference_unification/disconnect_bind_left_source")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityTypeInferenceUnification)
        .finished();
    test_cases.push(test_case);

    /*
     * Disconnect combinator: left target != B × C
     *
     * unit: A → 1
     * iden: C → D
     * disconnect unit iden fails to unify
     */
    let bytes = bit_encoding::Program::program_preamble(3)
        .unit()
        .iden()
        .disconnect(2, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::disconnect(Cmr::unit());
    let test_case = TestBuilder::comment("type_inference_unification/disconnect_bind_left_target")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityTypeInferenceUnification)
        .finished();
    test_cases.push(test_case);

    /*
     * Infinite type is inferred
     *
     * drop iden: A × B → B
     * iden:      C     → C
     * case (drop iden) iden fails the occurs check
     */
    let bytes = bit_encoding::Program::program_preamble(4)
        .iden()
        .drop(1)
        .iden()
        .case(2, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::case(Cmr::drop(Cmr::iden()), Cmr::iden());
    let test_case = TestBuilder::comment("type_inference_occurs_check/occurs_check")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityTypeInferenceOccursCheck)
        .finished();
    test_cases.push(test_case);

    /*
     * Source of program root is not unit
     *
     * take unit: A × B → 1
     */
    let bytes = bit_encoding::Program::program_preamble(2)
        .unit()
        .take(1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::take(Cmr::unit());
    let test_case = TestBuilder::comment("type_inference_not_program/root_source_type")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityTypeInferenceNotProgram)
        .finished();
    test_cases.push(test_case);

    /*
     * Target of program root is not unit
     *
     * pair unit unit: A → 1 × 1
     */
    let bytes = bit_encoding::Program::program_preamble(2)
        .unit()
        .pair(1, 1)
        .witness_preamble(0)
        .program_finished();
    let cmr = Cmr::pair(Cmr::unit(), Cmr::unit());
    let test_case = TestBuilder::comment("type_inference_not_program/root_target_type")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityTypeInferenceNotProgram)
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
        .witness_preamble(0) // bitstring: []
        .parser_stops_here();
    let cmr = Cmr::comp(
        Cmr::witness(),
        Cmr::case(Cmr::take(Cmr::unit()), Cmr::take(Cmr::unit())),
    );
    let test_case = TestBuilder::comment("witness_eof/next_value")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityWitnessEof)
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
        .witness_preamble(1) // bitstring: [1]
        .bits_be(u64::MAX, 1)
        .parser_stops_here();
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
        .expected_error(ScriptError::SimplicityWitnessEof)
        .finished();
    test_cases.push(test_case);

    /*
     * Witness block declared too long
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .unit()
        .witness_preamble(1)
        .bits_be(u64::MAX, 1)
        .program_finished();
    let cmr = Cmr::unit();
    let test_case = TestBuilder::comment("witness_trailing_bits/trailing_bits")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityWitnessUnusedBits)
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
        .expected_error(ScriptError::SimplicityUnsharedSubexpression)
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
            .hidden(cmr1)
            .unit() // 1 × 1 → 1
            .case(2, 1) // (1 + 1) × 1 → 1
            .comp(4, 1) // 1 → 1
            .hidden(cmr2)
            .iden() // 1 → 1
            .take(1) // 1 × 1 → 1
            // Forall cmr1 cmr2, IMR(assertr cmr1 unit) != IMR(assertr cmr2 (take iden))
            .case(3, 1) // (1 + 1) × 1 → 1
            .comp(9, 1) // 1 → 1
            .comp(6, 1) // 1 → 1
            .witness_preamble(0)
            .program_finished();
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
        .expected_error(ScriptError::SimplicityUnsharedSubexpression)
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
        .expected_error(ScriptError::Ok)
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
        .expected_error(ScriptError::SimplicityCmr)
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
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Expensive program has insufficient padding
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
        main := comp cp9 cp9
    ";
    let test_case = TestBuilder::comment("exec_budget/insufficient_padding")
        .human_encoding(s, &empty_witness)
        .reset_cost()
        .expected_error(ScriptError::SimplicityExecBudget)
        .finished();
    test_cases.push(test_case);

    /*
     * Expensive program has sufficient padding, but costs more than MAX_BUDGET
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
        cp22 := comp cp21 cp21
        cp23 := comp cp22 cp22
        main := comp cp23 cp23
    ";
    let test_case = TestBuilder::comment("exec_budget/padding_exceeds_max_budget")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::SimplicityExecBudget)
        .finished();
    test_cases.push(test_case);

    /*
     * Expensive program has sufficient padding (C test vector)
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
    let test_case = TestBuilder::comment("exec_budget/sufficient_padding")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Program uses more memory than static maximum (CELLS_MAX) (C test vector)
     */
    let len = (1 << 20) + 4;
    let mut bytes = vec![0u8; len];
    bytes[0] = 0xb7;
    bytes[1] = 0x08;
    bytes[len - 2] = 0x48;
    bytes[len - 1] = 0x20;
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
    let program = Node::comp(
        &Node::const_word(word),
        &Node::unit(),
    )
    .unwrap();

    // FIXME: Writing to vec takes 20 seconds
    let program_bytes = BitWriter::write_to_vec(|w| program.encode_with_tracker_default::<_, NoSharing>(w));
    assert_eq!(bytes, program_bytes);
    assert_eq!(cmr, program.cmr());
    */

    let test_case = TestBuilder::comment("exec_memory/memory_usage_exceeds_max_cells")
        .raw_program(bytes)
        .raw_cmr(cmr)
        .expected_error(ScriptError::SimplicityExecMemory)
        .finished();
    test_cases.push(test_case);

    /*
     * Jet fails during its execution
     */
    let s = "
        false := const 0b0
        main := comp false jet_verify
    ";
    let test_case = TestBuilder::comment("exec_jet/jet_verify_fails")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::SimplicityExecJet)
        .finished();
    test_cases.push(test_case);

    /*
     * Jet succeeds during its execution
     */
    let s = "
        true := const 0b1
        main := comp true jet_verify
    ";
    let test_case = TestBuilder::comment("exec_jet/jet_verify_succeeds")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Execute right branch of left assertion
     */
    let s = "
        input := pair (const 0b1) unit
        output := assertl (take unit) #{take unit}
        main := comp input output
    ";
    let test_case = TestBuilder::comment("exec_assert/right_branch_assertl")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::SimplicityExecAssert)
        .finished();
    test_cases.push(test_case);

    /*
     * Execute left branch of left assertion
     */
    let s = "
        input := pair (const 0b0) unit
        output := assertl (take unit) #{take unit}
        main := comp input output
    ";
    let test_case = TestBuilder::comment("exec_assert/left_branch_assertl")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Execute left branch of right assertion
     */
    let s = "
        input := pair (const 0b0) unit
        output := assertr #{take unit} (take unit)
        main := comp input output
    ";
    let test_case = TestBuilder::comment("exec_assert/left_branch_assertr")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::SimplicityExecAssert)
        .finished();
    test_cases.push(test_case);

    /*
     * Execute right branch of right assertion
     */
    let s = "
        input := pair (const 0b1) unit
        output := assertr #{take unit} (take unit)
        main := comp input output
    ";
    let test_case = TestBuilder::comment("exec_assert/right_branch_assertr")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::Ok)
        .finished();
    test_cases.push(test_case);

    /*
     * Left branch of case node was not executed
     */
    let s = "
        input := pair (const 0b1) unit
        output := case (take unit) (take unit)
        main := comp input output
    ";
    let test_case = TestBuilder::comment("antidos/check_case_left")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::SimplicityAntidos)
        .finished();
    test_cases.push(test_case);

    /*
     * Right branch of case node was not executed
     */
    let s = "
        input := pair (const 0b0) unit
        output := case (take unit) (take unit)
        main := comp input output
    ";
    let test_case = TestBuilder::comment("antidos/check_case_right")
        .human_encoding(s, &empty_witness)
        .expected_error(ScriptError::SimplicityAntidos)
        .finished();
    test_cases.push(test_case);

    /*
     * Program root is hidden
     */
    let hidden_cmr = Cmr::from_byte_array([0; 32]);
    let bytes = bit_encoding::Program::program_preamble(1)
        .hidden(hidden_cmr)
        .parser_stops_here();
    let test_case = TestBuilder::comment("hidden_root/hidden_root")
        .raw_program(bytes)
        .raw_cmr(hidden_cmr)
        .expected_error(ScriptError::SimplicityHiddenRoot)
        .finished();
    test_cases.push(test_case);

    /*
     * Export test cases to JSON
     */
    println!("Writing {} tests", test_cases.len());
    let s = serde_json::to_string_pretty(&test_cases).expect("Unable to create JSON");
    let mut file = File::create("script_assets_test.json").expect("Unable to create file");
    file.write_all(s.as_bytes()).expect("Unable to write data");
}
