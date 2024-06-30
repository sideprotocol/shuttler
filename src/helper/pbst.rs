use bitcoin::{key::Secp256k1, sighash::SighashCache, Address, EcdsaSighashType, Network, Psbt, PublicKey, XOnlyPublicKey};
use frost_secp256k1_tr::VerifyingKey;

use super::encoding::from_base64;
use tracing::{debug, error, info};

pub  fn get_group_address(verify_key: &VerifyingKey, network: Network) -> Address {
    // let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verify_key.serialize()[..]).unwrap();
    let internal_key = XOnlyPublicKey::from(pubk.inner);
    let secp = Secp256k1::new();
    Address::p2tr(&secp, internal_key, None, network)
    //     let xpubk_hex = hex::encode(&xpubk.serialize());
    //     let s = format!("tr({})", xpubk_hex);
    //     let d = Descriptor::<DefiniteDescriptorKey>::from_str(&s).unwrap();
    //     d.address(network).unwrap()
}

// pub fn pbst_signing_requests(pbst_str: &str, network: Network) -> Vec<String> {
//     let psbt_bytes = from_base64(pbst_str).unwrap();
//     let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
//         Ok(psbt) => psbt,
//         Err(e) => {
//             error!("Failed to deserialize PSBT: {}", e);
//             return Vec::new();
//         }
//     };

//     let len = psbt.inputs.len();
//     debug!("(signing round 0) prepare for signing: {:?} tasks", len);
//     for i in 0..len {

//         let input = &psbt.inputs[i];
//         if input.witness_utxo.is_none() {
//             continue;
//         }


//         let mut sighash_cache = SighashCache::new(psbt.unsigned_tx.clone());

//         let msg = psbt.sighash_ecdsa(i, &mut sighash_cache).unwrap();

//         let script = input.witness_utxo.clone().unwrap().script_pubkey;
//         let address = Address::from_script(&script, network).unwrap();
//     }
//     requests
// }