use bitcoin::{
    key::Secp256k1, opcodes, script::Instruction, Address, BlockHash, Network, PublicKey,
    ScriptBuf, TapNodeHash, Transaction, Txid, XOnlyPublicKey,
};
use bitcoincore_rpc::RpcApi;
use frost_secp256k1_tr::VerifyingKey;

use crate::app::config;

pub fn get_group_address(verify_key: &VerifyingKey, network: Network) -> Address {
    // let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verify_key.serialize()[..]).unwrap();
    let internal_key = XOnlyPublicKey::from(pubk.inner);
    let secp = Secp256k1::new();
    Address::p2tr(&secp, internal_key, None, network)
}

pub fn get_group_address_by_tweak(
    verify_key: &VerifyingKey,
    tweak: Vec<u8>,
    network: Network,
) -> Address {
    // let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verify_key.serialize()[..]).unwrap();
    let internal_key = XOnlyPublicKey::from(pubk.inner);
    let secp = Secp256k1::new();

    let mut hash: [u8; 32] = [0; 32];
    hash[0..tweak.len()].copy_from_slice(tweak.as_slice());
    let merkle_root = TapNodeHash::assume_hidden(hash);

    Address::p2tr(&secp, internal_key, Some(merkle_root), network)
}

pub fn get_address_from_pk_script(pk_script: ScriptBuf, network: Network) -> String {
    match Address::from_script(&pk_script, network) {
        Ok(address) => address.to_string(),
        _ => String::new(),
    }
}

// TODO: calculate proof from local
pub fn get_tx_proof(
    client: &bitcoincore_rpc::Client,
    txid: Txid,
    block_hash: &BlockHash,
) -> Option<Vec<String>> {
    match client.get_tx_out_proof(&[txid], Some(&block_hash)) {
        Ok(proof_bytes) => {
            let mut proof = Vec::new();
            proof_bytes
                .chunks_exact(32)
                .for_each(|chunk| proof.push(hex::encode(chunk)));

            Some(proof)
        }
        _ => None,
    }
}

pub fn is_deposit_tx(tx: &Transaction, network: Network) -> bool {
    tx.output.iter().any(|out| {
        config::address_exists(
            get_address_from_pk_script(out.clone().script_pubkey, network).as_str(),
        )
    })
}

pub fn may_be_withdraw_tx(tx: &Transaction) -> bool {
    let script = &tx.output[0].script_pubkey;
    let instructions = script.instruction_indices();

    for inst in instructions {
        match inst {
            Ok((0, Instruction::Op(opcodes::all::OP_RETURN))) => {}
            Ok((1, Instruction::PushBytes(bytes))) => {
                if bytes.as_bytes().ne("side".as_bytes()) {
                    return false;
                }
            }
            Ok((2, Instruction::PushBytes(bytes))) => {
                if bytes.len() > 8 {
                    return false;
                }
            }
            _ => {
                return false;
            }
        }
    }

    return true;
}
