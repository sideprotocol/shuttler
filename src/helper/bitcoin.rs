use bitcoin::{
    key::Secp256k1, opcodes, Address, Network, PublicKey, ScriptBuf,
    TapNodeHash, Transaction, Txid, XOnlyPublicKey,
};
use frost_secp256k1_tr::VerifyingKey;
use ordinals::SpacedRune;

use super::merkle_proof;

// Magic txin sequence for withdrawal txs
const MAGIC_SEQUENCE: u32 = (1 << 31) + 0xde;

pub fn get_group_address(verify_key: &VerifyingKey, network: Network) -> Address {
    // let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verify_key.serialize()[..]).unwrap();
    let internal_key = XOnlyPublicKey::from(pubk.inner);
    let secp = Secp256k1::new();
    Address::p2tr(&secp, internal_key, None, network)
}

pub fn get_group_address_by_tweak(
    verify_key: &VerifyingKey,
    tweak: Option<TapNodeHash>,
    network: Network,
) -> Address {
    // let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verify_key.serialize()[..]).unwrap();
    let internal_key = XOnlyPublicKey::from(pubk.inner);
    let secp = Secp256k1::new();

    Address::p2tr(&secp, internal_key, tweak, network)
}

pub fn get_address_from_pk_script(pk_script: ScriptBuf, network: Network) -> String {
    match Address::from_script(&pk_script, network) {
        Ok(address) => address.to_string(),
        _ => String::new(),
    }
}

pub fn compute_tx_proof(txids: Vec<Txid>, index: usize) -> Vec<String> {
    merkle_proof::compute_tx_proof(txids, index)
}

/// Check if the transaction is a deposit transaction
/// A deposit transaction is a transaction that has a vault address as one of its output
/// the vault address should be fetched from side chain. so none signer can also run a relayer
pub fn is_deposit_tx(tx: &Transaction, network: Network, vaults: &Vec<String>) -> bool {
    tx.output.iter().any(|out| {
        vaults.contains(&get_address_from_pk_script(
            out.clone().script_pubkey,
            network,
        ))
    })
}

// Check if the given tx may be a withdrawal tx by sequence
pub fn may_be_withdraw_tx(tx: &Transaction) -> bool {
    if tx.input.len() < 1 {
        return false;
    }

    tx.input[0].sequence.0 == MAGIC_SEQUENCE
}

// Check if the given deposit tx is for runes
pub fn is_runes_deposit(tx: &Transaction) -> bool {
    let runes_identifier = vec![
        opcodes::all::OP_RETURN.to_u8(),
        opcodes::all::OP_PUSHNUM_13.to_u8(),
    ];

    tx.output
        .iter()
        .any(|out| out.script_pubkey.as_bytes().starts_with(&runes_identifier))
}

// Parse runes from the given tx
// Only an edict operation is allowed
pub fn parse_runes(tx: &Transaction) -> Option<ordinals::Edict> {
    match ordinals::Runestone::decipher(tx) {
        Some(artifact) => match artifact {
            ordinals::Artifact::Runestone(runestone) => {
                if runestone.etching.is_some()
                    || runestone.mint.is_some()
                    || runestone.edicts.len() != 1
                    || runestone.edicts[0].output >= tx.output.len() as u32
                {
                    return None;
                }

                return Some(runestone.edicts[0]);
            }
            _ => None,
        },
        None => None,
    }
}

// Validate runes against the output of the ord indexer
pub fn validate_runes(
    edict: &ordinals::Edict,
    rune: &SpacedRune,
    runes_output: &ord::api::Output,
) -> bool {
    if let Some(runes) = &runes_output.runes {
        match runes.get(rune) {
            Some(rune) => rune.amount >= edict.amount,
            None => false,
        }
    } else {
        return false;
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{opcodes, transaction::Version, Amount, OutPoint, Sequence, TxIn, TxOut};
    use bitcoin_hashes::Hash;

    use crate::helper::encoding::from_base64;

    use super::*;

    #[test]
    fn test_withdraw_tx_check() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: [TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                sequence: Sequence(MAGIC_SEQUENCE),
                ..Default::default()
            }]
            .to_vec(),
            output: [TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::builder()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
            }]
            .to_vec(),
        };

        assert!(may_be_withdraw_tx(&tx), "may be a withdrawal tx")
    }

    #[test]
    fn test_tx_proof() {
        // mainnet block: 80000
        let mut txid1 =
            hex::decode("c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25")
                .unwrap();
        let mut txid2 =
            hex::decode("5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2")
                .unwrap();

        txid1.reverse();
        txid2.reverse();

        let txids = vec![
            Txid::from_slice(txid1.as_slice()).unwrap(),
            Txid::from_slice(txid2.as_slice()).unwrap(),
        ];

        let proof = compute_tx_proof(txids, 1);
        assert_eq!(proof.len(), 1);

        let mut branch = from_base64(&proof[0]).unwrap();
        branch[1..].reverse();
        assert_eq!(
            hex::encode(branch),
            "01c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25"
        );
    }
}
