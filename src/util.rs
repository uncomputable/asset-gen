//! # Utility functions
//!
//! Reimplementation of low-level descriptor features.
//!
//! This lets us manipulate the spending process more freely and it lets us provoke errors.

use elements::secp256k1_zkp;
use elements_miniscript as miniscript;
use miniscript::{bitcoin, elements};

/// Nothing-up-my-sleeve point.
///
/// https://github.com/BlockstreamResearch/secp256k1-zkp/blob/11af7015de624b010424273be3d91f117f172c82/src/modules/rangeproof/main_impl.h#L16
const UNSPENDABLE_PUBLIC_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Convert the given transaction into an outpoint that points to the 0-th output.
pub fn to_outpoint(prevout: &elements::Transaction) -> elements::OutPoint {
    elements::OutPoint {
        txid: prevout.txid(),
        vout: 0,
    }
}

/// Convert the given byte structure into Elements Script.
pub fn to_script<A: AsRef<[u8]>>(bytes: A) -> elements::Script {
    elements::Script::from(bytes.as_ref().to_vec())
}

/// Return a constant x-only public key with unknown discrete logarithm.
///
/// The key is therefore unspendable.
pub fn unspendable_key() -> bitcoin::key::XOnlyPublicKey {
    bitcoin::key::XOnlyPublicKey::from_slice(&UNSPENDABLE_PUBLIC_KEY).expect("const")
}

/// Compute Taproot spending information about an output with
///
/// 1. An unspendable internal key (see [`unspendable_key()`])
/// 2. A tap tree with a single leaf of the given `version` that contains `commit`.
pub fn get_spend_info<A: AsRef<[u8]>>(
    commit: A,
    version: elements::taproot::LeafVersion,
) -> elements::taproot::TaprootSpendInfo {
    let script = to_script(commit);
    elements::taproot::TaprootBuilder::new()
        .add_leaf_with_ver(0, script, version)
        .expect("const")
        .finalize(secp256k1_zkp::SECP256K1, unspendable_key())
        .expect("const")
}

/// Compute the `script_pubkey` of the Taproot output with the given spending information.
pub fn get_script_pubkey(spend_info: &elements::taproot::TaprootSpendInfo) -> elements::Script {
    let output_key = spend_info.output_key();
    let builder = elements::script::Builder::new();
    builder
        .push_opcode(elements::opcodes::all::OP_PUSHNUM_1)
        .push_slice(&output_key.as_inner().serialize())
        .into_script()
}

/// Compute a control block of the Taproot output with the given spending information.
///
/// The control block selects the leaf of the given `version` that contains `commit`, if it exists.
pub fn get_control_block<A: AsRef<[u8]>>(
    commit: A,
    version: elements::taproot::LeafVersion,
    spend_info: &elements::taproot::TaprootSpendInfo,
) -> Option<elements::taproot::ControlBlock> {
    let script = to_script(commit);
    let script_ver = (script, version);
    spend_info.control_block(&script_ver)
}
