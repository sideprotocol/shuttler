use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use frost_secp256k1_tr::Identifier;

pub fn to_base64(input: &[u8]) -> String {
    // base64::encode(data)
    STANDARD.encode(input)
}

pub fn from_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // base64::decode(data)
    STANDARD.decode(input)
}

pub fn hash(bytes: &[u8]) -> String {
    let x = sha256::Hash::hash(bytes);
    x.to_string()
}
