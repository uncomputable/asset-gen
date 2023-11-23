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

1. two nodes have the same IMR
    - this is the "second-pass" IMR
    - the "first-pass" IMR is updated with the TMR of the source and target type
2. two hidden nodes have the same payload
    - hidden nodes exist only in the encoding, as storage of CMRs
    - hidden nodes have neither TMR nor IMR
    - maximal sharing means that the same CMR is never stored at two places

# `SCRIPT_ERR_SIMPLICITY_CMR = 78`

- CMR mismatch inside taproot witness:
    - `[script_input, script, control_block (, annex)]` in Taproot speak
    - `[program, cmr, control_block (, annex)]` in Simplicity speak

1. CMR of parsed Simplicity program (taproot witness script input) differs from literal CMR (taproot witness script)

- `SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH` fires if CMR in taproot output differs from literal CMR in taproot witness

# `SCRIPT_ERR_SIMPLICITY_AMR = 79`

```c
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

```c
simplicity_err analyseBounds( ubounded *cellsBound, ubounded *UWORDBound, ubounded *frameBound, ubounded *costBound
                            , ubounded maxCells, ubounded maxCost, const dag_node* dag, const type* type_dag, const size_t len)
```

- failure in `analyseBounds(..., maxCost, ...)`
    - `maxCost < costBound`
    - `costBound <= UBOUNDED_MAX` is computed program CPU cost

```c
simplicity_err result = analyseBounds(&cellsBound, &UWORDBound, &frameBound, &costBound, CELLS_MAX, budget ? *budget*1000 : UBOUNDED_MAX, dag, type_dag, len);
```

- `analyseBounds(..., maxCost, ...)` is called by `evalTCOExpression(..., budget, ...)`
    - if a budget is given, then `maxCost = budget * 1000`
    - otherwise, `maxCost = UBOUNDED_MAX`

```c
*error = evalTCOProgram(dag, type_dag, (size_t)dag_len, &(ubounded){budget <= BUDGET_MAX ? (ubounded)budget : BUDGET_MAX}, &env);
```

- `evalTCOExpression(..., budget, ...)` is called by `evalTCOProgram(..., budget, ...)`
- `evalTCOProgram(..., budget, ...)` is called by `elements_simplicity_execSimplicity(..., budget, ...)`
    - `budget` = min(`budget`, `BUDGET_MAX`)

```c
#define BUDGET_MAX 4000050U
```

- the program cost exceeds the program budget
- the budget is proportional to the size of the taproot witness stack
- budget can be added by padding the annex
- once `BUDGET_MAX` is reached, padding no longer increases the budget

1. expensive program has insufficient padding
2. expensive program has sufficient padding, but its cost exceeds `MAX_BUDGET`

# `SCRIPT_ERR_SIMPLICITY_EXEC_MEMORY = 81`

```c
simplicity_err analyseBounds( ubounded *cellsBound, ubounded *UWORDBound, ubounded *frameBound, ubounded *costBound
                            , ubounded maxCells, ubounded maxCost, const dag_node* dag, const type* type_dag, const size_t len)
```

- failure in `analyseBounds(..., maxCells, ...)`
    - `maxCells < cellsBound`
    - `cellsBound <= UBOUNDED_MAX` is computed program memory usage

```c
simplicity_err result = analyseBounds(&cellsBound, &UWORDBound, &frameBound, &costBound, CELLS_MAX, budget ? *budget*1000 : UBOUNDED_MAX, dag, type_dag, len);
```

- `analyseBounds(..., maxCells, ...)` is called by `evalTCOExpression`
    - `maxCells = CELLS_MAX` (static maximum)

```c
#define CELLS_MAX 0x500000U /* 5120 Kibibits ought to be enough for anyone. */
```

1. the program memory usage exceeds `CELLS_MAX`

# `SCRIPT_ERR_SIMPLICITY_EXEC_JET = 82`

```c
typedef bool (*jet_ptr)(frameItem* dst, frameItem src, const txEnv* env);
```

- jets write to a destination frame and return a success Boolean

```c
if(!dag[pc].jet(state.activeWriteFrame, *state.activeReadFrame, env)) return SIMPLICITY_ERR_EXEC_JET;
```

- failure in `runTCO` (called by `evalTCOExpression`)
    - a called jet returns failure

1. a executed jet fails
    - `*verify` jets

# `SCRIPT_ERR_SIMPLICITY_EXEC_ASSERT = 83`

```c
case HIDDEN: return SIMPLICITY_ERR_EXEC_ASSERT; /* We have failed an 'ASSERTL' or 'ASSERTR' combinator. */
```

- failure in `runTCO` (called by `evalTCOExpression)
    - reached a hidden node
    - `assertl expr cmr = case expr hidden(cmr)`
    - `assertr cmr expr = case hidden(cmr) expr`
- failed assertion

1. reached right branch of left assertion
    - left assertion means only the left branch is ever executed
2. reached left branch of right assertion
    - right assertion means only the left branch is ever executed

# `SCRIPT_ERR_SIMPLICITY_ANTIDOS = 84`

```c
flags_type test_flags = (HIDDEN != dag[i].tag ? CHECK_EXEC : 0)
                      | (CASE == dag[i].tag ? CHECK_CASE : 0);

/* Only enable requested checks */
test_flags &= checks;
if (test_flags != (test_flags & stack[i].flags)) {
  return SIMPLICITY_ERR_ANTIDOS;
}
```

- failure in `antiDos`
    - a node set a flag to false that is currently checked
    - `stack` contains information about each node from the past execution

```c
#define FLAG_TCO        0x01 // Whether TCO is on (1) or off (0).
#define FLAG_LAST_CASE  0x02 // For case combinators, last branch executed was right (1) or left (0).
#define FLAG_EXEC       0x10 // Whether this combinator has ever been executed (1) or not (0).
#define FLAG_CASE_LEFT  0x20 // For case combinators, whether the left branch has ever been executed (1) or not (0).
#define FLAG_CASE_RIGHT 0x40 // For case combinators, whether the right branch has ever been executed (1) or not (0).
```

- there are five flags that can be checked

```c
result = antiDos(anti_dos_checks, stack, dag, len);
```

- `antiDos(anti_dos_checks, ...)` is called by `evalTCOExpression(anti_dos_checks, ...)`

```c
#define CHECK_NONE 0
#define CHECK_EXEC 0x10 // = FLAG_EXEC
#define CHECK_CASE 0x60 // = FLAG_CASE_LEFT | FLAG_CASE_RIGHT
#define CHECK_ALL ((flags_type)(-1))

static inline simplicity_err evalTCOProgram(const dag_node* dag, type* type_dag, size_t len, const ubounded* budget, const txEnv* env) {
  return evalTCOExpression(CHECK_ALL, NULL, NULL, dag, type_dag, len, budget, env);
}
```

- `evalTCOExpression(CHECK_ALL, ...)` is called by `evalTCOProgram`
    - `CHECK_ALL` is an all-ones bitmap
    - all checks are enabled
- `FLAG_TCO` is always true
    - the C code only supports TCO evaluation
    - the flag is set by `runTCO`
- `FLAG_LAST_CASE` is always true
    - the flag is implied by canonical order
    - canonical order is checked before execution

1. a node was not executed
    - except for hidden nodes
2. the left branch of a case node was not executed
    - except for assertions
3. the right branch of a case node was not executed
    - except for assertions

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
