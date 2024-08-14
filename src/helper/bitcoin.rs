use bitcoin::{key::Secp256k1, Address, Network, PublicKey, TapNodeHash, XOnlyPublicKey};
use frost_secp256k1_tr::VerifyingKey;

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
