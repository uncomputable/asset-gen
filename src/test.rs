use std::collections::HashMap;
use std::sync::Arc;

use elements_miniscript as miniscript;
use miniscript::elements;

use crate::json::{Flag, Parameters, ScriptError, Serde, TestCase};
use crate::util;

impl TestCase {
    pub fn new<A: AsRef<[u8]> + Clone>(
        comment: &'static str,
        program_bytes: Vec<u8>,
        commit: A,
        cost: Option<simplicity::Cost>,
        error: Option<ScriptError>,
    ) -> Self {
        let spend_info = util::get_spend_info(commit.clone(), simplicity::leaf_version());
        let control_block =
            util::get_control_block(commit.clone(), simplicity::leaf_version(), &spend_info)
                .unwrap();

        let funding_tx = get_funding_tx(&spend_info);
        let spending_tx = get_spending_tx(&funding_tx);

        let mut witness =
            util::get_witness_stack(program_bytes, util::to_script(commit), control_block);

        if let Some(cost) = cost {
            if let Some(annex) = cost.get_padding(&witness) {
                witness.push(annex);
            }
        }

        let parameters = Parameters::taproot(witness, error);
        let (success, failure) = match error {
            None => (Some(parameters), None),
            Some(_) => (None, Some(parameters)),
        };

        Self {
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

    pub fn from_bytes(
        comment: &'static str,
        program_bytes: Vec<u8>,
        error: Option<ScriptError>,
    ) -> Self {
        let mut bits = simplicity::BitIter::new(program_bytes.iter().copied());
        let program = simplicity::CommitNode::<simplicity::jet::Core>::decode(&mut bits).unwrap();
        let commit = program.cmr();

        Self::new(comment, program_bytes, commit, None, error)
    }

    pub fn from_string(
        comment: &'static str,
        s: &str,
        witness: &HashMap<Arc<str>, Arc<simplicity::Value>>,
        error: Option<ScriptError>,
    ) -> Self {
        let forest =
            simplicity::human_encoding::Forest::<simplicity::jet::Core>::parse(s).expect("parse");
        let program = forest
            .to_witness_node(witness)
            .finalize()
            .expect("finalize");
        let program_bytes = program.encode_to_vec();

        Self::new(
            comment,
            program_bytes,
            program.cmr(),
            Some(program.bounds().cost),
            error,
        )
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
