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
}

