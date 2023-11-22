mod bit_encoding;
mod json;
mod test;
mod util;

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;

use simplicity::dag::NoSharing;
use simplicity::jet::{Core, Elements};
use simplicity::node::CoreConstructible;
use simplicity::{BitWriter, Cmr, FailEntropy, Value, WitnessNode};

use crate::bit_encoding::Builder;
use crate::json::{ScriptError, TestCase};

type Node = Arc<WitnessNode<Elements>>;

fn main() {
    let mut test_cases = Vec::new();
    let empty_witness = HashMap::new();

    /*
     * `unit` is an ANYONECANSPEND
     */
    let s = "main := unit";
    test_cases.push(TestCase::from_string("ok/unit", s, &empty_witness, None));

    /*
     * `iden` is an ANYONECANSPEND
     */
    let s = "main := iden";
    test_cases.push(TestCase::from_string("ok/iden", s, &empty_witness, None));

    /*
     * The taproot witness stack must have exactly 3 elements
     */
    let program = Arc::<WitnessNode<Core>>::unit().finalize().unwrap();
    let extra_script_inputs = vec![vec![0x00]];
    test_cases.push(TestCase::new(
        "wrong_length/extra_script_input",
        program.encode_to_vec(),
        program.cmr(),
        Some(extra_script_inputs),
        None,
        Some(ScriptError::SimplicityWrongLength),
    ));

    /*
     * The CMR (taproot witness script) must be exactly 32 bytes
     */
    let program = Arc::<WitnessNode<Core>>::unit().finalize().unwrap();
    let long_cmr = &[0; 33];
    test_cases.push(TestCase::new(
        "wrong_length/extra_cmr_byte",
        program.encode_to_vec(),
        long_cmr,
        None,
        None,
        Some(ScriptError::SimplicityWrongLength),
    ));

    let short_cmr = &[0; 31];
    test_cases.push(TestCase::new(
        "wrong_length/missing_cmr_byte",
        program.encode_to_vec(),
        short_cmr,
        None,
        None,
        Some(ScriptError::SimplicityWrongLength),
    ));

    /*
     * EOF inside program length encoding
     */
    let bytes = bit_encoding::Program::program_preamble(2)
        .delete_bits(1)
        .parser_stops_here()
        .unwrap_err()
        .expect_padding(6);
    let cmr = &[0; 32];

    test_cases.push(TestCase::new(
        "bitstream_eof/program_length_eof",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

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

    test_cases.push(TestCase::new(
        "bitstream_eof/combinator_eof",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

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

    test_cases.push(TestCase::new(
        "bitstream_eof/witness_eof",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

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

    test_cases.push(TestCase::new(
        "bitstream_eof/witness_eof_c_test_vector",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

    /*
     * Program declared longer than DAG_LEN_MAX
     */
    let dag_len_max = 8_000_000;
    let bytes = bit_encoding::Program::program_preamble(dag_len_max + 1)
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();
    let cmr = &[0; 32];

    test_cases.push(TestCase::new(
        "data_out_of_range/program_length",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityDataOutOfRange),
    ));

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

    test_cases.push(TestCase::new(
        "data_out_of_range/witness_length",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityDataOutOfRange),
    ));

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

    test_cases.push(TestCase::new(
        "data_out_of_range/relative_combinator_index",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityDataOutOfRange),
    ));

    /*
     * Jet is not defined
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .jet(u64::MAX, 64) // It is unlikely that all-ones will become a jet soon
        .witness_preamble(None)
        .program_finished()
        .unwrap_err()
        .unwrap_padding();
    let cmr = &[0; 32];

    test_cases.push(TestCase::new(
        "data_out_of_range/undefined_jet",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityDataOutOfRange),
    ));

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

    test_cases.push(TestCase::new(
        "data_out_of_range/word_depth",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityDataOutOfRange),
    ));

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

    test_cases.push(TestCase::new(
        "data_out_of_order/not_in_canonical_order",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityDataOutOfOrder),
    ));

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

    test_cases.push(TestCase::new(
        "fail_code/fail_node",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityFailCode),
    ));

    /*
     * Program contains the stop code
     */
    let bytes = bit_encoding::Program::program_preamble(1)
        .stop()
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();
    let cmr = &[0; 32];

    test_cases.push(TestCase::new(
        "stop_code/stop_code",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityStopCode),
    ));

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

    test_cases.push(TestCase::new(
        "hidden/comp_hidden_child",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityHidden),
    ));

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

    test_cases.push(TestCase::new(
        "hidden/two_hidden_children",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityHidden),
    ));

    /*
     * Trailing bytes after program encoding (malleability)
     */
    let program = Arc::<WitnessNode<Core>>::unit().finalize().unwrap();
    let mut bytes = program.encode_to_vec();
    // Trailing byte
    bytes.push(0x00);
    let cmr = Cmr::unit();

    test_cases.push(TestCase::new(
        "bitstream_trailing_bytes/trailing_bytes",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityBitstreamUnusedBytes),
    ));

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

    test_cases.push(TestCase::new(
        "bitstream_illegal_padding/illegal_padding",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityBitstreamUnusedBits),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_unification/comp_unify_left_target_right_source",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceUnification),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_unification/pair_unify_left_source_right_source",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceUnification),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_unification/case_unify_left_target_right_target",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceUnification),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_unification/case_bind_left_target",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceUnification),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_unification/case_bind_right_target",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceUnification),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_unification/disconnect_bind_left_source",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceUnification),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_unification/disconnect_bind_left_target",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceUnification),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_occurs_check/occurs_check",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceOccursCheck),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_not_program/root_source_type",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceNotProgram),
    ));

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

    test_cases.push(TestCase::new(
        "type_inference_not_program/root_target_type",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityTypeInferenceNotProgram),
    ));

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

    test_cases.push(TestCase::new(
        "witness_eof/next_value",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityWitnessEof),
    ));

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

    test_cases.push(TestCase::new(
        "witness_eof/next_bit",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityWitnessEof),
    ));

    /*
     * FIXME: Unknown jet?
     */
    let s = "
        wit := witness
        main := comp (comp wit jet_is_zero_64) jet_verify
    ";
    let mut witness = HashMap::new();
    witness.insert(Arc::from("wit"), Value::u64(0u64));
    let program = util::program_from_string::<Core>(s, &witness).unwrap();

    test_cases.push(TestCase::new(
        "data_out_of_range/fixme",
        program.encode_to_vec(),
        program.cmr(),
        None,
        None,
        Some(ScriptError::SimplicityDataOutOfRange),
    ));

    /*
     * FIXME: EOF despite large-enough witness
     */
    let s = "
        wit := witness
        main := comp (comp wit jet_add_32) unit
    ";
    let mut witness = HashMap::new();
    witness.insert(Arc::from("wit"), Value::u64(0u64));
    let program = util::program_from_string::<Core>(s, &witness).unwrap();

    test_cases.push(TestCase::new(
        "bitstream_eof/fixme",
        program.encode_to_vec(),
        program.cmr(),
        None,
        None,
        Some(ScriptError::SimplicityBitstreamEof),
    ));

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

    test_cases.push(TestCase::new(
        "witness_trailing_bits/trailing_bits",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityWitnessUnusedBits),
    ));

    /*
     * Two unit nodes have the same IMR
     */
    // Cannot use human encoding because it unifies combinators
    let program = Node::comp(&Node::unit(), &Node::unit()).unwrap();

    test_cases.push(TestCase::new(
        "unshared_subexpression/duplicate_imr",
        BitWriter::write_to_vec(|w| program.encode_with_tracker_default::<_, NoSharing>(w)),
        program.cmr(),
        None,
        None,
        Some(ScriptError::SimplicityUnsharedSubexpression),
    ));

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

    test_cases.push(TestCase::new(
        "unshared_subexpression/duplicate_hidden",
        bytes,
        cmr,
        None,
        None,
        Some(ScriptError::SimplicityUnsharedSubexpression),
    ));

    /*
     * Two hidden nodes have different payload
     *
     * Test if `unshared_subexpression_program(cmr1, cmr2)` is maximally shared for cmr1 != cmr2
     */
    let same_cmr = Cmr::from_byte_array([0; 32]);
    let different_cmr = Cmr::from_byte_array([1; 32]);
    let (bytes, cmr) = unshared_subexpression_program(same_cmr, different_cmr);

    test_cases.push(TestCase::new(
        "unshared_subexpression/no_duplicate_hidden",
        bytes,
        cmr,
        None,
        None,
        None,
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
     * Program root is hidden
     */
    let hidden_cmr = Cmr::from_byte_array([0; 32]);
    let bytes = bit_encoding::Program::program_preamble(1)
        .hidden(hidden_cmr.as_ref())
        .parser_stops_here()
        .unwrap_err()
        .unwrap_padding();

    test_cases.push(TestCase::new(
        "hidden_root/hidden_root",
        bytes,
        hidden_cmr,
        None,
        None,
        Some(ScriptError::SimplicityHiddenRoot),
    ));

    /*
     * Export test cases to JSON
     */
    let s = serde_json::to_string_pretty(&test_cases).expect("serialize");
    let mut file = File::create("script_assets_test.json").expect("Unable to create file");
    file.write_all(s.as_bytes()).expect("Unable to write data");
}
