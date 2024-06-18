use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Network, Script, Transaction, TxIn, TxOut, address::AddressType,
    key::PublicKey,
};
use bitcoin::amount::Amount;
use bitcoin::blockdata::opcodes::all::OP_CHECKSIG;
use bitcoin::blockdata::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use std::str::FromStr;

#[test]
fn test_taproot() {
    // let secp = Secp256k1::new();

    // // Define input transaction details
    // let input_tx_hex = "INPUT_TX_HEX";
    // let input_index = 0; // Index of the output you want to spend
    // let input_tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(input_tx_hex).unwrap()).unwrap();

    // let secret_key = SecretKey::new(&mut rand::thread_rng());
    // println!("{:?}", secret_key);

    // let kp = bitcoin::key::Keypair::from_secret_key(&secp, &secret_key);
    
    // let public_key = kp.public_key();
    // let output_address = Address::p2pkh(&public_key, Network::Bitcoin);

    // // Define the amount to send
    // let amount = Amount::from_btc(0.1).unwrap();

    // // Create a transaction input spending the specified output
    // let txin = TxIn {
    //     previous_output: input_tx.txid(),
    //     script_sig: Script::default(),
    //     sequence: 0xffffffff,
    //     witness: vec![],
    // };
    // let txout = TxOut {
    //     value: amount,
    //     script_pubkey: output_address.script_pubkey(),
    // };

    // // Create a taproot output script
    // let taproot_script = Builder::new()
    //     .push_int(2) // Required threshold for spending
    //     .push_key(&public_key.key)
    //     .push_opcode(OP_CHECKSIG)
    //     .into_script();

    // // Create a transaction with the taproot output script
    // let mut tx = Transaction {
    //     version: Version::TWO,
    //     lock_time: LockTime::ZERO,
    //     input: vec![txin],
    //     output: vec![txout],
    // };
    // tx.output[0].script_pubkey = taproot_script;

    // // Sign the transaction input
    // let secp = Secp256k1::new();
    // let msg = Message::from_slice(&txwtxid(&tx).as_bytes()).unwrap();
    // let sig = secp.sign(&msg, &private_key.key);
    // let witness = vec![
    //     sig.serialize_der().to_vec(),
    //     public_key.to_bytes().to_vec(),
    //     taproot_script.to_bytes(),
    // ];
    // tx.input[0].witness = witness;

    // // Print the signed transaction hex
    // println!("Signed Transaction Hex: {}", hex::encode(tx.consensus_encode().unwrap()));
}

// fn txwtxid(tx: &Transaction) -> String {
//     let mut clone_tx = tx.clone();
//     clone_tx.input.iter_mut().for_each(|i| i.witness = vec![]);
//     clone_tx.txid().to_string()
// }
