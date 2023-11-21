# `SCRIPT_ERR_SIMPLICITY_WRONG_LENGTH = 62`

```c++
static bool VerifyWitnessProgram(const CScriptWitness& witness, int witversion, const std::vector<unsigned char>& program, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror, bool is_p2sh)
...
if (stack.size() != 1 || script_bytes.size() != 32) return set_error(serror, SCRIPT_ERR_SIMPLICITY_WRONG_LENGTH);
```

1. not exactly one script input (encoded Simplicity program + witness data)
2. script is not exactly 32 bytes (CMR)

# `SCRIPT_ERR_SIMPLICITY_BITSTREAM_EOF = 63`

- attempted to read bits from bitstream, but reached the end

1. unfinished combinator
    - error in `readNBits`
2. unfinished jet
    - error in `decodeJet`
3. word declared longer than it actually is
    - error in `readBitstring`
4. positive integer declared longer than it actually is
    - error in `decodeUptoMaxInt`
5. witness block declared longer than it actually is
    - error in `decodeWitnessData`
    - failure to read bitstring from bitstream

# `SCRIPT_ERR_SIMPLICITY_NOT_YET_IMPLEMENTED = 64`

- 2023-11-21: there is no occurrence of the error
- the error cannot be triggered

# `SCRIPT_ERR_SIMPLICITY_DATA_OUT_OF_RANGE = 65`

```c++
#define DAG_LEN_MAX 8000000U
```

1. program is declared length > `DAG_LEN_MAX`
2. witness block is declared length >= 2^31
3. index points past beginning of program
    - relative index ix is greater than current absolute node index
    - relative indices cannot be zero because zero cannot be encoded!
4. jet is not defined
5. word depth > 32 (word longer than 2^31 bits)

# `SCRIPT_ERR_SIMPLICITY_DATA_OUT_OF_ORDER = 66`

1. program nodes not serialized in canonical order

# `SCRIPT_ERR_SIMPLICITY_FAIL_CODE = 67`

1. fail node in program "01010" + entropy

# `SCRIPT_ERR_SIMPLICITY_STOP_CODE = 68`

1. stop sequence in program bits "01011"

# `SCRIPT_ERR_SIMPLICITY_HIDDEN = 69`

1. node other than case has hidden child
    - assert{l,r} are encoded as case
2. case has two hidden children

# `SCRIPT_ERR_SIMPLICITY_BITSTREAM_UNUSED_BYTES = 70`

- will be renamed to `SCRIPT_ERR_SIMPLICITY_BITSTREAM_TRAILING_BYTES`

1. trailing bytes after program encoding (program + witness block)

# `SCRIPT_ERR_SIMPLICITY_BITSTREAM_UNUSED_BITS = 71`

- will be renamed to `SCRIPT_ERR_SIMPLICITY_BITSTREAM_ILLEGAL_PADDING`

1. illegal padding in final byte of encoding
    - padding with bits other than zeroes

# `SCRIPT_ERR_SIMPLICITY_TYPE_INFERENCE_UNIFICATION = 72`

```c
#define UNIFY(a, b) { if (!unify((a), (b), bindings_used)) return SIMPLICITY_ERR_TYPE_INFERENCE_UNIFICATION; }
```

- types `a` and `b` are bound to two structurally different types
  - 1 and X + Y
  - 1 and X × Y
  - Z + Y and U × V
- therefore, `a` and `b` cannot be unified

1. comp combinator: left target = right source
2. pair combinator: left source = right source
3. case combinator: left target = right target

```c
#define APPLY_BINDING(a, b) { if (!applyBinding((a), (b), bindings_used)) return SIMPLICITY_ERR_TYPE_INFERENCE_UNIFICATION; }
```

- type `a` is bound to a type that is structurally different from the binding `b`
- therefore, `a` cannot be bound to `b`

1. case combinator: left source = A × C (also assertl)
2. case combinator: right source = B × C (also assertr)
3. disconnect combinator: left source = 2^256 × A
4. disconnect combinator: left target = B × C

# `SCRIPT_ERR_SIMPLICITY_TYPE_INFERENCE_OCCURS_CHECK = 73`

1. type variable X is bound to a type that contains X

# `SCRIPT_ERR_SIMPLICITY_TYPE_INFERENCE_NOT_PROGRAM = 74`

1. program root doesn't have unit source type
2. program root doesn't have unit target type

# `SCRIPT_ERR_SIMPLICITY_WITNESS_EOF = 75`

- attempted to read bits from bitstring, but reached the end
- error in `fillWitnessData`

1. parse next witness value (bit size > 0), but bitstream is EOF
    - eof at value border
2. parse next bit of witness value, but bitstream if EOF
    - eof inside value

# `SCRIPT_ERR_SIMPLICITY_WITNESS_UNUSED_BITS = 76`

- will be renamed to `SIMPLICITY_ERR_WITNESS_TRAILING_BITS`
- error in `fillWitnessData`

1. trailing bits after final value of witness block
    - witness block declared too long

# `SCRIPT_ERR_SIMPLICITY_UNSHARED_SUBEXPRESSION = 77`

- sharing is not maximal

1. two hidden nodes have the same payload
    - by definition of the IMR, this is a special case of 2.
    - it still makes sense to treat 1. separately
2. two nodes have the same IMR
    - this is the "second-pass" IMR
    - the "first-pass" IMR is updated with the TMR of the source and target type

# `SCRIPT_ERR_SIMPLICITY_CMR = 78`

- CMR mismatch inside taproot witness:
    - `[script_input, script, control_block (, annex)]` in Taproot speak
    - `[program, cmr, control_block (, annex)]` in Simplicity speak

1. CMR of parsed Simplicity program (taproot witness script input) differs from literal CMR (taproot witness script)

- `SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH` fires if CMR in taproot output differs from literal CMR in taproot witness

# `SCRIPT_ERR_SIMPLICITY_AMR = 79`

```c++
extern bool elements_simplicity_execSimplicity( simplicity_err* error, unsigned char* imr
                                              , const transaction* tx, uint_fast32_t ix, const tapEnv* taproot
                                              , const unsigned char* genesisBlockHash
                                              , int64_t budget
                                              , const unsigned char* amr
                                              , const unsigned char* program, size_t program_len)
```

- the error only occurs in `elements_simplicity_execSimplicity` if `amr != NULL`

```c++
if (!elements_simplicity_execSimplicity(&error, 0, txdata->m_simplicity_tx_data, nIn, simplicityTapEnv, txdata->m_hash_genesis_block.data(), budget, 0, witness.data(), witness.size())) {
```

- 2023-11-21: Elements calls `elements_simplicity_execSimplicity` with `amr = NULL`
- the error cannot be triggered

# `SCRIPT_ERR_SIMPLICITY_EXEC_BUDGET = 80`
# `SCRIPT_ERR_SIMPLICITY_EXEC_MEMORY = 81`
# `SCRIPT_ERR_SIMPLICITY_EXEC_JET = 82`
# `SCRIPT_ERR_SIMPLICITY_EXEC_ASSERT = 83`
# `SCRIPT_ERR_SIMPLICITY_ANTIDOS = 84`

# `SCRIPT_ERR_SIMPLICITY_HIDDEN_ROOT = 85`

- program root is hidden node

# Simplicity error codes

```c++
SCRIPT_ERR_SIMPLICITY_WRONG_LENGTH = 62
SCRIPT_ERR_SIMPLICITY_BITSTREAM_EOF = 63
SCRIPT_ERR_SIMPLICITY_NOT_YET_IMPLEMENTED = 64
SCRIPT_ERR_SIMPLICITY_DATA_OUT_OF_RANGE = 65
SCRIPT_ERR_SIMPLICITY_DATA_OUT_OF_ORDER = 66
SCRIPT_ERR_SIMPLICITY_FAIL_CODE = 67
SCRIPT_ERR_SIMPLICITY_STOP_CODE = 68
SCRIPT_ERR_SIMPLICITY_HIDDEN = 69
SCRIPT_ERR_SIMPLICITY_BITSTREAM_UNUSED_BYTES = 70
SCRIPT_ERR_SIMPLICITY_BITSTREAM_UNUSED_BITS = 71
SCRIPT_ERR_SIMPLICITY_TYPE_INFERENCE_UNIFICATION = 72
SCRIPT_ERR_SIMPLICITY_TYPE_INFERENCE_OCCURS_CHECK = 73
SCRIPT_ERR_SIMPLICITY_TYPE_INFERENCE_NOT_PROGRAM = 74
SCRIPT_ERR_SIMPLICITY_WITNESS_EOF = 75
SCRIPT_ERR_SIMPLICITY_WITNESS_UNUSED_BITS = 76
SCRIPT_ERR_SIMPLICITY_UNSHARED_SUBEXPRESSION = 77
SCRIPT_ERR_SIMPLICITY_CMR = 78
SCRIPT_ERR_SIMPLICITY_AMR = 79
SCRIPT_ERR_SIMPLICITY_EXEC_BUDGET = 80
SCRIPT_ERR_SIMPLICITY_EXEC_MEMORY = 81
SCRIPT_ERR_SIMPLICITY_EXEC_JET = 82
SCRIPT_ERR_SIMPLICITY_EXEC_ASSERT = 83
SCRIPT_ERR_SIMPLICITY_ANTIDOS = 84
SCRIPT_ERR_SIMPLICITY_HIDDEN_ROOT = 85
```

# Bitcoin + Elements error codes

```c++
SCRIPT_ERR_OK = 0
SCRIPT_ERR_UNKNOWN_ERROR = 1
SCRIPT_ERR_EVAL_FALSE = 2
SCRIPT_ERR_OP_RETURN = 3
SCRIPT_ERR_SCRIPT_SIZE = 4
SCRIPT_ERR_PUSH_SIZE = 5
SCRIPT_ERR_OP_COUNT = 6
SCRIPT_ERR_STACK_SIZE = 7
SCRIPT_ERR_SIG_COUNT = 8
SCRIPT_ERR_PUBKEY_COUNT = 9
SCRIPT_ERR_VERIFY = 10
SCRIPT_ERR_EQUALVERIFY = 11
SCRIPT_ERR_CHECKMULTISIGVERIFY = 12
SCRIPT_ERR_CHECKSIGVERIFY = 13
SCRIPT_ERR_NUMEQUALVERIFY = 14
SCRIPT_ERR_BAD_OPCODE = 15
SCRIPT_ERR_DISABLED_OPCODE = 16
SCRIPT_ERR_INVALID_STACK_OPERATION = 17
SCRIPT_ERR_INVALID_ALTSTACK_OPERATION = 18
SCRIPT_ERR_UNBALANCED_CONDITIONAL = 19
SCRIPT_ERR_NEGATIVE_LOCKTIME = 20
SCRIPT_ERR_UNSATISFIED_LOCKTIME = 21
SCRIPT_ERR_SIG_HASHTYPE = 22
SCRIPT_ERR_SIG_DER = 23
SCRIPT_ERR_MINIMALDATA = 24
SCRIPT_ERR_SIG_PUSHONLY = 25
SCRIPT_ERR_SIG_HIGH_S = 26
SCRIPT_ERR_SIG_NULLDUMMY = 27
SCRIPT_ERR_PUBKEYTYPE = 28
SCRIPT_ERR_CLEANSTACK = 29
SCRIPT_ERR_MINIMALIF = 30
SCRIPT_ERR_SIG_NULLFAIL = 31
SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS = 32
SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 33
SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 34
SCRIPT_ERR_DISCOURAGE_OP_SUCCESS = 35
SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 36
SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH = 37
SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY = 38
SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH = 39
SCRIPT_ERR_WITNESS_MALLEATED = 40
SCRIPT_ERR_WITNESS_MALLEATED_P2SH = 41
SCRIPT_ERR_WITNESS_UNEXPECTED = 42
SCRIPT_ERR_WITNESS_PUBKEYTYPE = 43
SCRIPT_ERR_SCHNORR_SIG_SIZE = 44
SCRIPT_ERR_SCHNORR_SIG_HASHTYPE = 45
SCRIPT_ERR_SCHNORR_SIG = 46
SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE = 47
SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT = 48
SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG = 49
SCRIPT_ERR_TAPSCRIPT_MINIMALIF = 50
SCRIPT_ERR_OP_CODESEPARATOR = 51
SCRIPT_ERR_SIG_FINDANDDELETE = 52
SCRIPT_ERR_RANGEPROOF = 53
SCRIPT_ERR_PEDERSEN_TALLY = 54
SCRIPT_ERR_SHA2_CONTEXT_LOAD = 55
SCRIPT_ERR_SHA2_CONTEXT_WRITE = 56
SCRIPT_ERR_INTROSPECT_CONTEXT_UNAVAILABLE = 57
SCRIPT_ERR_INTROSPECT_INDEX_OUT_OF_BOUNDS = 58
SCRIPT_ERR_EXPECTED_8BYTES = 59
SCRIPT_ERR_ARITHMETIC64 = 60
SCRIPT_ERR_ECMULTVERIFYFAIL = 61
```

# Error count (meta error)

```c++
SCRIPT_ERR_ERROR_COUNT = 86
```
