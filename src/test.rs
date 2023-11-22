use std::collections::HashMap;
use std::sync::Arc;

use elements_miniscript as miniscript;
use miniscript::elements;
use simplicity::jet::Elements;
use simplicity::RedeemNode;

use crate::json::{Flag, Parameters, ScriptError, Serde, TestCase};
use crate::util;

#[derive(Debug)]
pub struct TestBuilder {
    comment: &'static str,
    program_bytes: Option<Vec<u8>>,
    cmr: Option<Vec<u8>>,
    extra_script_inputs: Vec<Vec<u8>>,
    cost: Option<simplicity::Cost>,
    error: Option<ScriptError>,
}

impl TestBuilder {
    pub fn comment(comment: &'static str) -> Self {
        Self {
            comment,
            program_bytes: None,
            cmr: None,
            extra_script_inputs: vec![],
            cost: None,
            error: None,
        }
    }

    pub fn raw_program(mut self, bytes: Vec<u8>) -> Self {
        self.program_bytes = Some(bytes);
        self
    }

    pub fn raw_cmr<A: AsRef<[u8]>>(mut self, cmr: A) -> Self {
        self.cmr = Some(cmr.as_ref().to_vec());
        self
    }

    pub fn program(mut self, program: &RedeemNode<Elements>) -> Self {
        self.program_bytes = Some(program.encode_to_vec());
        self.cmr = Some(program.cmr().to_byte_array().to_vec());
        self.cost = Some(program.bounds().cost);
        self
    }

    pub fn human_encoding(
        self,
        s: &str,
        witness: &HashMap<Arc<str>, Arc<simplicity::Value>>,
    ) -> Self {
        // TODO: Return first error that occurred upon finished()
        // Semantics like Option::map
        let program = util::program_from_string::<Elements>(s, witness).unwrap();
        self.program(&program)
    }

    pub fn extra_script_input(mut self, extra_script_input: Vec<u8>) -> Self {
        self.extra_script_inputs.push(extra_script_input);
        self
    }

    pub fn expected_result(mut self, error: ScriptError) -> Self {
        self.error = Some(error);
        self
    }

    pub fn finished(self) -> TestCase {
        let program_bytes = self.program_bytes.expect("required");
        let commit = self.cmr.expect("required");
        let error = match self.error.expect("required") {
            ScriptError::Ok => None,
            error => Some(error),
        };

        let spend_info = util::get_spend_info(commit.clone(), simplicity::leaf_version());
        let control_block =
            util::get_control_block(commit.clone(), simplicity::leaf_version(), &spend_info)
                .unwrap();

        let funding_tx = get_funding_tx(&spend_info);
        let spending_tx = get_spending_tx(&funding_tx);

        let mut script_inputs = vec![program_bytes];
        script_inputs.extend(self.extra_script_inputs);
        let script = util::to_script(commit);
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
