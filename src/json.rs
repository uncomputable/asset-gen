use std::fmt;
use std::str::FromStr;

use elements::hex::{FromHex, ToHex};
use elements_miniscript as miniscript;
use miniscript::elements;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Serde<A>(pub A);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ScriptError {
    Ok,
    UnknownError,
    EvalFalse,
    OpReturn,
    // Max sizes
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    // Failed verify operations
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,
    // Logical/Format/Canonical errors
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    // CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY
    NegativeLocktime,
    UnsatisfiedLocktime,
    // Malleability
    SigHashtype,
    SigDer,
    MinimalData,
    SigPushonly,
    SigHighS,
    SigNulldummy,
    Pubkeytype,
    Cleanstack,
    Minimalif,
    SigNullfail,
    // Softfork safeness
    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    DiscourageUpgradableTaprootVersion,
    DiscourageOpSuccess,
    DiscourageUpgradablePubkeytype,
    // Segregated witness
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    WitnessPubkeytype,
    // Taproot
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckMultisig,
    TapscriptMinimalif,
    // Constant scriptCode
    OpCodeseparator,
    SigFindanddelete,
    // Elements
    Rangeproof,
    PedersenTally,
    // Elements: New tapscript related errors
    Sha2ContextLoad,
    Sha2ContextWrite,
    IntrospectContextUnavailable,
    IntrospectIndexOutOfBounds,
    Expected8bytes,
    Arithmetic64,
    Ecmultverifyfail,
    // Elements: Simplicity related errors
    SimplicityWrongLength,
    SimplicityBitstreamEof,
    SimplicityNotYetImplemented,
    SimplicityDataOutOfRange,
    SimplicityDataOutOfOrder,
    SimplicityFailCode,
    SimplicityStopCode,
    SimplicityHidden,
    SimplicityBitstreamUnusedBytes,
    SimplicityBitstreamUnusedBits,
    SimplicityTypeInferenceUnification,
    SimplicityTypeInferenceOccursCheck,
    SimplicityTypeInferenceNotProgram,
    SimplicityWitnessEof,
    SimplicityWitnessUnusedBits,
    SimplicityUnsharedSubexpression,
    SimplicityCmr,
    SimplicityAmr,
    SimplicityExecBudget,
    SimplicityExecMemory,
    SimplicityExecJet,
    SimplicityExecAssert,
    SimplicityAntidos,
    SimplicityHiddenRoot,
}

#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct Parameters {
    #[serde(rename = "scriptSig")]
    pub script_sig: elements::Script,
    pub witness: Vec<Serde<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ScriptError>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Flag {
    P2SH,
    DerSig,
    NullDummy,
    CheckLockTimeVerify,
    CheckSequenceVerify,
    Witness,
    Taproot,
    Simplicity,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TestCase {
    pub tx: Serde<elements::Transaction>,
    pub prevouts: Vec<Serde<elements::TxOut>>,
    pub index: usize,
    #[serde(serialize_with = "serialize_flags")]
    #[serde(deserialize_with = "deserialize_flags")]
    pub flags: Vec<Flag>,
    pub comment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_genesis_block: Option<elements::BlockHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<Parameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<Parameters>,
    #[serde(rename = "final", skip_serializing_if = "std::ops::Not::not", default)]
    pub is_final: bool,
}

impl fmt::Display for ScriptError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptError::Ok => f.write_str("OK"),
            ScriptError::UnknownError => f.write_str("UNKNOWN_ERROR"),
            ScriptError::EvalFalse => f.write_str("EVAL_FALSE"),
            ScriptError::OpReturn => f.write_str("OP_RETURN"),
            ScriptError::ScriptSize => f.write_str("SCRIPT_SIZE"),
            ScriptError::PushSize => f.write_str("PUSH_SIZE"),
            ScriptError::OpCount => f.write_str("OP_COUNT"),
            ScriptError::StackSize => f.write_str("STACK_SIZE"),
            ScriptError::SigCount => f.write_str("SIG_COUNT"),
            ScriptError::PubkeyCount => f.write_str("PUBKEY_COUNT"),
            ScriptError::Verify => f.write_str("VERIFY"),
            ScriptError::EqualVerify => f.write_str("EQUALVERIFY"),
            ScriptError::CheckMultisigVerify => f.write_str("CHECKMULTISIGVERIFY"),
            ScriptError::CheckSigVerify => f.write_str("CHECKSIGVERIFY"),
            ScriptError::NumEqualVerify => f.write_str("NUMEQUALVERIFY"),
            ScriptError::BadOpcode => f.write_str("BAD_OPCODE"),
            ScriptError::DisabledOpcode => f.write_str("DISABLED_OPCODE"),
            ScriptError::InvalidStackOperation => f.write_str("INVALID_STACK_OPERATION"),
            ScriptError::InvalidAltstackOperation => f.write_str("INVALID_ALTSTACK_OPERATION"),
            ScriptError::UnbalancedConditional => f.write_str("UNBALANCED_CONDITIONAL"),
            ScriptError::NegativeLocktime => f.write_str("NEGATIVE_LOCKTIME"),
            ScriptError::UnsatisfiedLocktime => f.write_str("UNSATISFIED_LOCKTIME"),
            ScriptError::SigHashtype => f.write_str("SIG_HASHTYPE"),
            ScriptError::SigDer => f.write_str("SIG_DER"),
            ScriptError::MinimalData => f.write_str("MINIMAL_DATA"),
            ScriptError::SigPushonly => f.write_str("SIG_PUSHONLY"),
            ScriptError::SigHighS => f.write_str("SIG_HIGH_S"),
            ScriptError::SigNulldummy => f.write_str("SIG_NULLDUMMY"),
            ScriptError::Pubkeytype => f.write_str("PUBKEYTYPE"),
            ScriptError::Cleanstack => f.write_str("CLEANSTACK"),
            ScriptError::Minimalif => f.write_str("MINIMALIF"),
            ScriptError::SigNullfail => f.write_str("SIG_NULLFAIL"),
            ScriptError::DiscourageUpgradableNops => f.write_str("DISCOURAGE_UPGRADABLE_NOPS"),
            ScriptError::DiscourageUpgradableWitnessProgram => f.write_str("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"),
            ScriptError::DiscourageUpgradableTaprootVersion => f.write_str("DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"),
            ScriptError::DiscourageOpSuccess => f.write_str("DISCOURAGE_OP_SUCCESS"),
            ScriptError::DiscourageUpgradablePubkeytype => f.write_str("DISCOURAGE_UPGRADABLE_PUBKEYTYPE"),
            ScriptError::WitnessProgramWrongLength => f.write_str("WITNESS_PROGRAM_WRONG_LENGTH"),
            ScriptError::WitnessProgramWitnessEmpty => f.write_str("WITNESS_PROGRAM_WITNESS_EMPTY"),
            ScriptError::WitnessProgramMismatch => f.write_str("WITNESS_PROGRAM_MISMATCH"),
            ScriptError::WitnessMalleated => f.write_str("WITNESS_MALLEATED"),
            ScriptError::WitnessMalleatedP2sh => f.write_str("WITNESS_MALLEATED_P2SH"),
            ScriptError::WitnessUnexpected => f.write_str("WITNESS_UNEXPECTED"),
            ScriptError::WitnessPubkeytype => f.write_str("WITNESS_PUBKEYTYPE"),
            ScriptError::SchnorrSigSize => f.write_str("SCHNORR_SIG_SIZE"),
            ScriptError::SchnorrSigHashtype => f.write_str("SCHNORR_SIG_HASHTYPE"),
            ScriptError::SchnorrSig => f.write_str("SCHNORR_SIG"),
            ScriptError::TaprootWrongControlSize => f.write_str("TAPROOT_WRONG_CONTROL_SIZE"),
            ScriptError::TapscriptValidationWeight => f.write_str("TAPSCRIPT_VALIDATION_WEIGHT"),
            ScriptError::TapscriptCheckMultisig => f.write_str("TAPSCRIPT_CHECK_MULTISIG"),
            ScriptError::TapscriptMinimalif => f.write_str("TAPSCRIPT_MINIMALIF"),
            ScriptError::OpCodeseparator => f.write_str("OP_CODESEPARATOR"),
            ScriptError::SigFindanddelete => f.write_str("SIG_FINDANDDELETE"),
            ScriptError::Rangeproof => f.write_str("RANGEPROOF"),
            ScriptError::PedersenTally => f.write_str("PEDERSEN_TALLY"),
            ScriptError::Sha2ContextLoad => f.write_str("SHA2_CONTEXT_LOAD"),
            ScriptError::Sha2ContextWrite => f.write_str("SHA2_CONTEXT_WRITE"),
            ScriptError::IntrospectContextUnavailable => f.write_str("INTROSPECT_CONTEXT_UNAVAILABLE"),
            ScriptError::IntrospectIndexOutOfBounds => f.write_str("INTROSPECT_INDEX_OUT_OF_BOUNDS"),
            ScriptError::Expected8bytes => f.write_str("EXPECTED_8BYTES"),
            ScriptError::Arithmetic64 => f.write_str("ARITHMETIC_64"),
            ScriptError::Ecmultverifyfail => f.write_str("ECMULTVERIFYFAIL"),
            ScriptError::SimplicityWrongLength => f.write_str("SIMPLICITY_WRONG_LENGTH"),
            ScriptError::SimplicityBitstreamEof => f.write_str("SIMPLICITY_BITSTREAM_EOF"),
            ScriptError::SimplicityNotYetImplemented => f.write_str("SIMPLICITY_NOT_YET_IMPLEMENTED"),
            ScriptError::SimplicityDataOutOfRange => f.write_str("SIMPLICITY_DATA_OUT_OF_RANGE"),
            ScriptError::SimplicityDataOutOfOrder => f.write_str("SIMPLICITY_DATA_OUT_OF_ORDER"),
            ScriptError::SimplicityFailCode => f.write_str("SIMPLICITY_FAIL_CODE"),
            ScriptError::SimplicityStopCode => f.write_str("SIMPLICITY_STOP_CODE"),
            ScriptError::SimplicityHidden => f.write_str("SIMPLICITY_HIDDEN"),
            ScriptError::SimplicityBitstreamUnusedBytes => f.write_str("SIMPLICITY_BITSTREAM_UNUSED_BYTES"),
            ScriptError::SimplicityBitstreamUnusedBits => f.write_str("SIMPLICITY_BITSTREAM_UNUSED_BITS"),
            ScriptError::SimplicityTypeInferenceUnification => f.write_str("SIMPLICITY_TYPE_INFERENCE_UNIFICATION"),
            ScriptError::SimplicityTypeInferenceOccursCheck => f.write_str("SIMPLICITY_TYPE_INFERENCE_OCCURS_CHECK"),
            ScriptError::SimplicityTypeInferenceNotProgram => f.write_str("SIMPLICITY_TYPE_INFERENCE_NOT_PROGRAM"),
            ScriptError::SimplicityWitnessEof => f.write_str("SIMPLICITY_WITNESS_EOF"),
            ScriptError::SimplicityWitnessUnusedBits => f.write_str("SIMPLICITY_WITNESS_UNUSED_BITS"),
            ScriptError::SimplicityUnsharedSubexpression => f.write_str("SIMPLICITY_UNSHARED_SUBEXPRESSION"),
            ScriptError::SimplicityCmr => f.write_str("SIMPLICITY_CMR"),
            ScriptError::SimplicityAmr => f.write_str("SIMPLICITY_AMR"),
            ScriptError::SimplicityExecBudget => f.write_str("SIMPLICITY_EXEC_BUDGET"),
            ScriptError::SimplicityExecMemory => f.write_str("SIMPLICITY_EXEC_MEMORY"),
            ScriptError::SimplicityExecJet => f.write_str("SIMPLICITY_EXEC_JET"),
            ScriptError::SimplicityExecAssert => f.write_str("SIMPLICITY_EXEC_ASSERT"),
            ScriptError::SimplicityAntidos => f.write_str("SIMPLICITY_ANTIDOS"),
            ScriptError::SimplicityHiddenRoot => f.write_str("SIMPLICITY_HIDDEN_ROOT"),
        }
    }
}

impl FromStr for ScriptError {
    type Err = &'static str;

    #[rustfmt::skip]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OK" => Ok(ScriptError::Ok),
            "UNKNOWN_ERROR" => Ok(ScriptError::UnknownError),
            "EVAL_FALSE" => Ok(ScriptError::EvalFalse),
            "OP_RETURN" => Ok(ScriptError::OpReturn),
            "SCRIPT_SIZE" => Ok(ScriptError::ScriptSize),
            "PUSH_SIZE" => Ok(ScriptError::PushSize),
            "OP_COUNT" => Ok(ScriptError::OpCount),
            "STACK_SIZE" => Ok(ScriptError::StackSize),
            "SIG_COUNT" => Ok(ScriptError::SigCount),
            "PUBKEY_COUNT" => Ok(ScriptError::PubkeyCount),
            "VERIFY" => Ok(ScriptError::Verify),
            "EQUALVERIFY" => Ok(ScriptError::EqualVerify),
            "CHECKMULTISIGVERIFY" => Ok(ScriptError::CheckMultisigVerify),
            "CHECKSIGVERIFY" => Ok(ScriptError::CheckSigVerify),
            "NUMEQUALVERIFY" => Ok(ScriptError::NumEqualVerify),
            "BAD_OPCODE" => Ok(ScriptError::BadOpcode),
            "DISABLED_OPCODE" => Ok(ScriptError::DisabledOpcode),
            "INVALID_STACK_OPERATION" => Ok(ScriptError::InvalidStackOperation),
            "INVALID_ALTSTACK_OPERATION" => Ok(ScriptError::InvalidAltstackOperation),
            "UNBALANCED_CONDITIONAL" => Ok(ScriptError::UnbalancedConditional),
            "NEGATIVE_LOCKTIME" => Ok(ScriptError::NegativeLocktime),
            "UNSATISFIED_LOCKTIME" => Ok(ScriptError::UnsatisfiedLocktime),
            "SIG_HASHTYPE" => Ok(ScriptError::SigHashtype),
            "SIG_DER" => Ok(ScriptError::SigDer),
            "MINIMAL_DATA" => Ok(ScriptError::MinimalData),
            "SIG_PUSHONLY" => Ok(ScriptError::SigPushonly),
            "SIG_HIGH_S" => Ok(ScriptError::SigHighS),
            "SIG_NULLDUMMY" => Ok(ScriptError::SigNulldummy),
            "PUBKEYTYPE" => Ok(ScriptError::Pubkeytype),
            "CLEANSTACK" => Ok(ScriptError::Cleanstack),
            "MINIMALIF" => Ok(ScriptError::Minimalif),
            "SIG_NULLFAIL" => Ok(ScriptError::SigNullfail),
            "DISCOURAGE_UPGRADABLE_NOPS" => Ok(ScriptError::DiscourageUpgradableNops),
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => Ok(ScriptError::DiscourageUpgradableWitnessProgram),
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => Ok(ScriptError::DiscourageUpgradableTaprootVersion),
            "DISCOURAGE_OP_SUCCESS" => Ok(ScriptError::DiscourageOpSuccess),
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => Ok(ScriptError::DiscourageUpgradablePubkeytype),
            "WITNESS_PROGRAM_WRONG_LENGTH" => Ok(ScriptError::WitnessProgramWrongLength),
            "WITNESS_PROGRAM_WITNESS_EMPTY" => Ok(ScriptError::WitnessProgramWitnessEmpty),
            "WITNESS_PROGRAM_MISMATCH" => Ok(ScriptError::WitnessProgramMismatch),
            "WITNESS_MALLEATED" => Ok(ScriptError::WitnessMalleated),
            "WITNESS_MALLEATED_P2SH" => Ok(ScriptError::WitnessMalleatedP2sh),
            "WITNESS_UNEXPECTED" => Ok(ScriptError::WitnessUnexpected),
            "WITNESS_PUBKEYTYPE" => Ok(ScriptError::WitnessPubkeytype),
            "SCHNORR_SIG_SIZE" => Ok(ScriptError::SchnorrSigSize),
            "SCHNORR_SIG_HASHTYPE" => Ok(ScriptError::SchnorrSigHashtype),
            "SCHNORR_SIG" => Ok(ScriptError::SchnorrSig),
            "TAPROOT_WRONG_CONTROL_SIZE" => Ok(ScriptError::TaprootWrongControlSize),
            "TAPSCRIPT_VALIDATION_WEIGHT" => Ok(ScriptError::TapscriptValidationWeight),
            "TAPSCRIPT_CHECK_MULTISIG" => Ok(ScriptError::TapscriptCheckMultisig),
            "TAPSCRIPT_MINIMALIF" => Ok(ScriptError::TapscriptMinimalif),
            "OP_CODESEPARATOR" => Ok(ScriptError::OpCodeseparator),
            "SIG_FINDANDDELETE" => Ok(ScriptError::SigFindanddelete),
            "RANGEPROOF" => Ok(ScriptError::Rangeproof),
            "PEDERSEN_TALLY" => Ok(ScriptError::PedersenTally),
            "SHA2_CONTEXT_LOAD" => Ok(ScriptError::Sha2ContextLoad),
            "SHA2_CONTEXT_WRITE" => Ok(ScriptError::Sha2ContextWrite),
            "INTROSPECT_CONTEXT_UNAVAILABLE" => Ok(ScriptError::IntrospectContextUnavailable),
            "INTROSPECT_INDEX_OUT_OF_BOUNDS" => Ok(ScriptError::IntrospectIndexOutOfBounds),
            "EXPECTED_8BYTES" => Ok(ScriptError::Expected8bytes),
            "ARITHMETIC_64" => Ok(ScriptError::Arithmetic64),
            "ECMULTVERIFYFAIL" => Ok(ScriptError::Ecmultverifyfail),
            "SIMPLICITY_WRONG_LENGTH" => Ok(ScriptError::SimplicityWrongLength),
            "SIMPLICITY_BITSTREAM_EOF" => Ok(ScriptError::SimplicityBitstreamEof),
            "SIMPLICITY_NOT_YET_IMPLEMENTED" => Ok(ScriptError::SimplicityNotYetImplemented),
            "SIMPLICITY_DATA_OUT_OF_RANGE" => Ok(ScriptError::SimplicityDataOutOfRange),
            "SIMPLICITY_DATA_OUT_OF_ORDER" => Ok(ScriptError::SimplicityDataOutOfOrder),
            "SIMPLICITY_FAIL_CODE" => Ok(ScriptError::SimplicityFailCode),
            "SIMPLICITY_STOP_CODE" => Ok(ScriptError::SimplicityStopCode),
            "SIMPLICITY_HIDDEN" => Ok(ScriptError::SimplicityHidden),
            "SIMPLICITY_BITSTREAM_UNUSED_BYTES" => Ok(ScriptError::SimplicityBitstreamUnusedBytes),
            "SIMPLICITY_BITSTREAM_UNUSED_BITS" => Ok(ScriptError::SimplicityBitstreamUnusedBits),
            "SIMPLICITY_TYPE_INFERENCE_UNIFICATION" => Ok(ScriptError::SimplicityTypeInferenceUnification),
            "SIMPLICITY_TYPE_INFERENCE_OCCURS_CHECK" => Ok(ScriptError::SimplicityTypeInferenceOccursCheck),
            "SIMPLICITY_TYPE_INFERENCE_NOT_PROGRAM" => Ok(ScriptError::SimplicityTypeInferenceNotProgram),
            "SIMPLICITY_WITNESS_EOF" => Ok(ScriptError::SimplicityWitnessEof),
            "SIMPLICITY_WITNESS_UNUSED_BITS" => Ok(ScriptError::SimplicityWitnessUnusedBits),
            "SIMPLICITY_UNSHARED_SUBEXPRESSION" => Ok(ScriptError::SimplicityUnsharedSubexpression),
            "SIMPLICITY_CMR" => Ok(ScriptError::SimplicityCmr),
            "SIMPLICITY_AMR" => Ok(ScriptError::SimplicityAmr),
            "SIMPLICITY_EXEC_BUDGET" => Ok(ScriptError::SimplicityExecBudget),
            "SIMPLICITY_EXEC_MEMORY" => Ok(ScriptError::SimplicityExecMemory),
            "SIMPLICITY_EXEC_JET" => Ok(ScriptError::SimplicityExecJet),
            "SIMPLICITY_EXEC_ASSERT" => Ok(ScriptError::SimplicityExecAssert),
            "SIMPLICITY_ANTIDOS" => Ok(ScriptError::SimplicityAntidos),
            "SIMPLICITY_HIDDEN_ROOT" => Ok(ScriptError::SimplicityHiddenRoot),
            _ => Err("unknown error"),
        }
    }
}

impl Parameters {
    pub fn taproot(witness: Vec<Vec<u8>>, error: Option<ScriptError>) -> Self {
        Self {
            script_sig: elements::Script::new(),
            witness: witness.into_iter().map(Serde).collect(),
            error,
        }
    }
}

impl Flag {
    pub const fn all_flags() -> [Self; 8] {
        [
            Flag::P2SH,
            Flag::DerSig,
            Flag::NullDummy,
            Flag::CheckLockTimeVerify,
            Flag::CheckSequenceVerify,
            Flag::Witness,
            Flag::Taproot,
            Flag::Simplicity,
        ]
    }
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Flag::P2SH => f.write_str("P2SH"),
            Flag::DerSig => f.write_str("DERSIG"),
            Flag::NullDummy => f.write_str("NULLDUMMY"),
            Flag::CheckLockTimeVerify => f.write_str("CHECKLOCKTIMEVERIFY"),
            Flag::CheckSequenceVerify => f.write_str("CHECKSEQUENCEVERIFY"),
            Flag::Witness => f.write_str("WITNESS"),
            Flag::Taproot => f.write_str("TAPROOT"),
            Flag::Simplicity => f.write_str("SIMPLICITY"),
        }
    }
}

impl FromStr for Flag {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "P2SH" => Ok(Flag::P2SH),
            "DERSIG" => Ok(Flag::DerSig),
            "NULLDUMMY" => Ok(Flag::NullDummy),
            "CHECKLOCKTIMEVERIFY" => Ok(Flag::CheckLockTimeVerify),
            "CHECKSEQUENCEVERIFY" => Ok(Flag::CheckSequenceVerify),
            "WITNESS" => Ok(Flag::Witness),
            "TAPROOT" => Ok(Flag::Taproot),
            "SIMPLICITY" => Ok(Flag::Simplicity),
            _ => Err("unknown flag"),
        }
    }
}

impl<A: elements::pset::serialize::Serialize> Serialize for Serde<A> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.serialize();
        serializer.serialize_str(&bytes.to_hex())
    }
}

impl<'de, A: elements::pset::serialize::Deserialize> Deserialize<'de> for Serde<A> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex: String = Deserialize::deserialize(deserializer)?;
        let bytes = Vec::<u8>::from_hex(&hex).map_err(D::Error::custom)?;
        let inner = A::deserialize(&bytes).map_err(D::Error::custom)?;
        Ok(Serde(inner))
    }
}

// https://github.com/serde-rs/serde/issues/1316
impl Serialize for ScriptError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ScriptError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

fn serialize_flags<S>(flags: &[Flag], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s = flags
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<String>>()
        .join(",");
    serializer.serialize_str(&s)
}

fn deserialize_flags<'de, D>(deserializer: D) -> Result<Vec<Flag>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.split(',')
        .map(Flag::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn serialize_roundtrip() {
        let txout = elements::TxOut::default();
        let tx = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![txout.clone(), txout],
        };
        let parameters = Parameters {
            script_sig: elements::Script::from(vec![0xca, 0xfe, 0xba, 0xbe]),
            witness: vec![Serde(vec![0xde, 0xad, 0xbe, 0xef])],
            error: None,
        };
        let mut test_case = TestCase {
            tx: Serde(tx.clone()),
            prevouts: vec![Serde(tx.output[0].clone()), Serde(tx.output[1].clone())],
            index: 0,
            flags: Flag::all_flags().to_vec(),
            comment: "my awesome comment".to_string(),
            hash_genesis_block: None,
            success: None,
            failure: Some(parameters.clone()),
            is_final: true,
        };

        let s = serde_json::to_string(&test_case).expect("serialize");
        let original: TestCase = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(test_case, original);

        test_case.is_final = false;
        let s = serde_json::to_string(&test_case).expect("serialize");
        let original: TestCase = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(test_case, original);
    }

    #[test]
    fn deserialize_single() {
        let s = r#"{
        "tx": "0100000000017411650fe7800c4b1c695776d7fb70e075e6f2bc235bbdd40aa800f62eced1cab700000000a0179c490101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000004a936f000064000000",
        "prevouts": ["01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000004a936f00225d20a9d25cf32bfcac56e2caef97256424dd77dd23f732614d52219bad14d86974af"],
        "index": 0,
        "flags": "P2SH,DERSIG,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,NULLDUMMY,TAPROOT",
        "comment": "applic/keypath",
        "hash_genesis_block": "cd179c84c35f51825f20a3b91a18d45f0c53b5ceb744a5b6ef8f0babe809396f",
        "success": {
            "scriptSig": "",
            "witness": [
                "4facb94910cb2ec9572d39f764aaed25ec596fd49bd688bb4833a48e51c4488903ef6053513b75f03b395f2127d4976471851afaddaf9bf55e820208b1ee9861"
            ]
        }}"#;
        let _: TestCase = serde_json::from_str(s).expect("deserialize");
    }

    #[test]
    fn deserialize_file() {
        let mut file = File::open("data/script_assets_test.json").expect("Unable to open file");

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Unable to read file");

        let data: Vec<TestCase> = serde_json::from_str(&contents).expect("Unable to parse JSON");
        assert_eq!(250, data.len());
    }
}
