use std::collections::HashMap;
use std::sync::Arc;

use elements_miniscript as miniscript;
use miniscript::elements;
use simplicity::jet::Elements;
use simplicity::RedeemNode;

use crate::json::{Flag, Parameters, ScriptError, Serde, TestCase};
use crate::util;

pub trait MaybeBytes {}
pub struct NoBytes;
pub struct Bytes(Vec<u8>);
impl MaybeBytes for NoBytes {}
impl MaybeBytes for Bytes {}

pub trait MaybeCmr {}
pub struct NoCmr;
pub struct Cmr(Vec<u8>);
impl MaybeCmr for NoCmr {}
impl MaybeCmr for Cmr {}

pub trait MaybeError {}
pub struct NoError;
pub struct Error(ScriptError);
impl MaybeError for NoError {}
impl MaybeError for Error {}

#[derive(Debug)]
pub struct TestBuilder<B: MaybeBytes, C: MaybeCmr, E: MaybeError>(
    Result<BuilderInner<B, C, E>, String>,
);

impl TestBuilder<NoBytes, NoCmr, NoError> {
    pub fn comment(comment: &'static str) -> Self {
        Self(Ok(BuilderInner::comment(comment)))
    }
}

impl<B: MaybeBytes, C: MaybeCmr, E: MaybeError> TestBuilder<B, C, E> {
    pub fn raw_program(self, bytes: Vec<u8>) -> TestBuilder<Bytes, C, E> {
        TestBuilder(self.0.map(|inner| inner.raw_program(bytes)))
    }

    pub fn raw_cmr<A: AsRef<[u8]>>(self, cmr: A) -> TestBuilder<B, Cmr, E> {
        TestBuilder(self.0.map(|inner| inner.raw_cmr(cmr)))
    }

    pub fn program(self, program: &RedeemNode<Elements>) -> TestBuilder<Bytes, Cmr, E> {
        TestBuilder(self.0.map(|inner| inner.program(program)))
    }

    pub fn human_encoding(
        self,
        s: &str,
        witness: &HashMap<Arc<str>, Arc<simplicity::Value>>,
    ) -> TestBuilder<Bytes, Cmr, E> {
        TestBuilder(self.0.and_then(|inner| inner.human_encoding(s, witness)))
    }

    pub fn extra_script_input(self, script_input: Vec<u8>) -> Self {
        Self(self.0.map(|inner| inner.extra_script_input(script_input)))
    }

    pub fn expected_error(self, error: ScriptError) -> TestBuilder<B, C, Error> {
        TestBuilder(self.0.map(|inner| inner.expected_error(error)))
    }
}

impl TestBuilder<Bytes, Cmr, Error> {
    pub fn finished(self) -> Result<TestCase, String> {
        self.0.map(|inner| inner.finished())
    }
}

#[derive(Debug)]
struct BuilderInner<B: MaybeBytes, C: MaybeCmr, E: MaybeError> {
    comment: &'static str,
    program_bytes: B,
    cmr: C,
    extra_script_inputs: Vec<Vec<u8>>,
    cost: Option<simplicity::Cost>,
    error: E,
}

impl BuilderInner<NoBytes, NoCmr, NoError> {
    pub fn comment(comment: &'static str) -> Self {
        Self {
            comment,
            program_bytes: NoBytes,
            cmr: NoCmr,
            extra_script_inputs: vec![],
            cost: None,
            error: NoError,
        }
    }
}

impl<B: MaybeBytes, C: MaybeCmr, E: MaybeError> BuilderInner<B, C, E> {
    pub fn raw_program(self, bytes: Vec<u8>) -> BuilderInner<Bytes, C, E> {
        BuilderInner {
            comment: self.comment,
            program_bytes: Bytes(bytes),
            cmr: self.cmr,
            extra_script_inputs: self.extra_script_inputs,
            cost: self.cost,
            error: self.error,
        }
    }

    pub fn raw_cmr<A: AsRef<[u8]>>(self, cmr: A) -> BuilderInner<B, Cmr, E> {
        BuilderInner {
            comment: self.comment,
            program_bytes: self.program_bytes,
            cmr: Cmr(cmr.as_ref().to_vec()),
            extra_script_inputs: self.extra_script_inputs,
            cost: self.cost,
            error: self.error,
        }
    }

    pub fn program(self, program: &RedeemNode<Elements>) -> BuilderInner<Bytes, Cmr, E> {
        BuilderInner {
            comment: self.comment,
            program_bytes: Bytes(program.encode_to_vec()),
            cmr: Cmr(program.cmr().to_byte_array().to_vec()),
            extra_script_inputs: self.extra_script_inputs,
            cost: Some(program.bounds().cost),
            error: self.error,
        }
    }

    pub fn human_encoding(
        self,
        s: &str,
        witness: &HashMap<Arc<str>, Arc<simplicity::Value>>,
    ) -> Result<BuilderInner<Bytes, Cmr, E>, String> {
        let program = util::program_from_string::<Elements>(s, witness)?;
        Ok(self.program(&program))
    }

    pub fn extra_script_input(mut self, script_input: Vec<u8>) -> Self {
        self.extra_script_inputs.push(script_input);
        self
    }

    pub fn expected_error(self, error: ScriptError) -> BuilderInner<B, C, Error> {
        BuilderInner {
            comment: self.comment,
            program_bytes: self.program_bytes,
            cmr: self.cmr,
            extra_script_inputs: self.extra_script_inputs,
            cost: self.cost,
            error: Error(error),
        }
    }
}

impl BuilderInner<Bytes, Cmr, Error> {
    pub fn finished(self) -> TestCase {
        let program_bytes = self.program_bytes.0;
        let cmr = self.cmr.0;
        let error = match self.error.0 {
            ScriptError::Ok => None,
            error => Some(error),
        };

        let spend_info = util::get_spend_info(cmr.clone(), simplicity::leaf_version());
        let control_block =
            util::get_control_block(cmr.clone(), simplicity::leaf_version(), &spend_info).unwrap();

        let funding_tx = get_funding_tx(&spend_info);
        let spending_tx = get_spending_tx(&funding_tx);

        let mut script_inputs = vec![program_bytes];
        script_inputs.extend(self.extra_script_inputs);
        let script = util::to_script(cmr);
        let mut witness = util::get_witness_stack(script_inputs, script, control_block);

        if let Some(cost) = self.cost {
            if let Some(annex) = cost.get_padding(&witness) {
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
            comment: self.comment.to_string(),
            hash_genesis_block: None,
            success,
            failure,
            is_final: false,
        }
    }
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
