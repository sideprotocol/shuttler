
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::key::{Keypair, TapTweak, TweakedKeypair};
use bitcoin::locktime::absolute;
use bitcoin::psbt::Input;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{ecdsa, schnorr, PublicKey};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey, rand};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::sign_message::MessageSignature;
use bitcoin::{
 transaction, Address, Amount, CompressedPublicKey, Network, OutPoint, Psbt, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash, Witness, XOnlyPublicKey
};
use clap::Id;
use frost_core::{Ciphersuite, Field};
use frost_secp256k1::Identifier;
use serde::Deserialize;

// #[test]
// fn test_taproot_update() {
//     let secp = Secp256k1::new();
//     // let root_key = ExtendedPrivateKey::new_master(Network::Bitcoin, &[]).unwrap();
//     let initial_unlock_script = Script::from_bytes(b"Initial Taproot unlock script");
//     let taproot_address = Address::from_script(
//         &Script::new_taproot(&[initial_unlock_script.clone()]),
//         Network::Bitcoin,
//     )
//     .unwrap();

//     println!("Initial Taproot address: {}", taproot_address);

//     // Update the unlock script of the Taproot address
//     let new_unlock_script = Script::from_bytes(b"Updated Taproot unlock script");
//     let updated_taproot_key = Script::new_taproot(&[new_unlock_script.clone()]);

//     // The Taproot address remains the same, even with the updated unlock script
//     println!("Updated Taproot address: {}", taproot_address);
// }

#[test]
fn test_psbt() {

    let pubkey = CompressedPublicKey::from_str("0299e126bfd58a7dad478ad21cf7467d2927362ea8fd4a58dc7ac8f5fdfb218fab").expect("parse pubkey");
    let address = Address::p2wpkh(&pubkey, bitcoin::network::Network::Bitcoin);

    // Create a new transaction
    let mut unsigned_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Add an input (previously funded UTXO)
    let prev_txid = bitcoin::Txid::from_str("4d3b1e3caa0f3c4bbd3d8b51b52d2f5b6769d14d9a72db9d9f5b2b3a4d2e8c1b").unwrap();
    let prev_vout = 0;
    let prev_outpoint = OutPoint {
        txid: prev_txid,
        vout: prev_vout,
    };
    let prev_txout = TxOut {
        value: Amount::from_sat(50000), // Value in satoshis
        script_pubkey: address.script_pubkey(),
    };
    let script_sig = ScriptBuf::default();
    unsigned_tx.input.push(TxIn {
        previous_output: prev_outpoint,
        script_sig ,
        sequence: Sequence::ZERO,
        witness: Witness::default(),
    });

    // Add an output
    let recipient_txout = TxOut {
        value: Amount::from_sat(40000), // Value in satoshis
        script_pubkey: address.script_pubkey(),
    };
    unsigned_tx.output.push(recipient_txout);

    // Add a change output
    let change_txout = TxOut {
        value: Amount::from_sat(9000), // Value in satoshis (assuming 1000 satoshis fee)
        script_pubkey: address.script_pubkey(),
    };
    unsigned_tx.output.push(change_txout);

    // Create the PSBT
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("failed to create PSBT");

    // Add the previous transaction output to the PSBT input
    psbt.inputs[0] = Input {
        witness_utxo: Some(prev_txout),
        sighash_type: Some(bitcoin::psbt::PsbtSighashType::from_str("SIGHASH_ALL").unwrap()),
        ..Default::default()
    };

   // Serialize the PSBT to a base64 string
    let psbt_bytes = psbt.serialize();
    let psbt_base64 = base64::encode(&psbt_bytes); 

    // Print the PSBT
    println!("PSBT (base64): {}", psbt_base64);

}

#[test]
fn test_key_generation() {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut rand::thread_rng());
    
    println!("priv: {:?}", keypair.secret_bytes().as_hex());
    println!("pub: {:?}", keypair.public_key().serialize().as_hex());
}

#[test]
fn test_key_bitcoin() {

    const DUMMY_UTXO_AMOUNT: Amount = Amount::from_sat(20_000_000);
    const SPEND_AMOUNT: Amount = Amount::from_sat(5_000_000);
    const CHANGE_AMOUNT: Amount = Amount::from_sat(14_999_000); // 1000 sat fee.

    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    println!("{:?}", secret_key);

    let kp = Keypair::from_secret_key(&secp, &secret_key);
    
    let (internal_key, _) = kp.x_only_public_key();

    let script_pubkey = ScriptBuf::new_p2tr(&secp, internal_key, None);

    let out_point = OutPoint {
        txid: Txid::all_zeros(), // Obviously invalid.
        vout: 0,
    };

    let utxo = TxOut { value: DUMMY_UTXO_AMOUNT, script_pubkey };
    let witness =  Witness::default();

    // The input for the transaction we are constructing.
    let input = TxIn {
        previous_output: out_point, // The dummy output we are spending.
        script_sig: ScriptBuf::default(), // For a p2tr script_sig is empty.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness, // Filled in after signing.
    };

    // Get an address to send to.
    let address = receivers_address();

    // The spend output is locked to a key controlled by the receiver.
    let spend = TxOut { value: SPEND_AMOUNT, script_pubkey: address.script_pubkey() };

    // The change output is locked to a key controlled by us.
    let change = TxOut {
        value: CHANGE_AMOUNT,
        script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None), // Change comes back to us.
    };

    // The transaction we want to sign and broadcast.
    let mut unsigned_tx = Transaction {
        version: transaction::Version::TWO,  // Post BIP-68.
        lock_time: absolute::LockTime::ZERO, // Ignore the locktime.
        input: vec![input],                  // Input goes into index 0.
        output: vec![spend, change],         // Outputs, order does not matter.
    };

    let input_index = 0;

    // Get the sighash to sign.

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![utxo];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash using the secp256k1 library (exported by rust-bitcoin).
    let tweaked: TweakedKeypair = kp.tap_tweak(&secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    println!("{:?}", msg);
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack.
    // let signature = bitcoin::taproot::Signature { sig: signature, hash_ty: sighash_type };
    // println!("{:?}", signature);

   // Verifies the signature.
    // let pubkey = kp.x_only_public_key().0;
    // pubkey.verify(&secp, &msg, &signature.sig).expect("signature is invalid");

    // sighasher.witness_mut(input_index).unwrap().push(signature);

    // // Get the signed transaction.
    // let tx = sighasher.into_transaction();

    // // BOOM! Transaction signed and ready to broadcast.
    // println!("{:#?}", tx);

}

/// A dummy address for the receiver.
///
/// We lock the spend output to the key associated with this address.
///
/// (FWIW this is an arbitrary mainnet address from block 805222.)
pub fn receivers_address() -> Address {
    Address::from_str("bc1p0dq0tzg2r780hldthn5mrznmpxsxc0jux5f20fwj0z3wqxxk6fpqm7q0va")
        .expect("a valid address")
        .require_network(Network::Bitcoin)
        .expect("valid address for mainnet")
}

#[test]
fn test_indentifier() {

    let zero = frost_secp256k1::Secp256K1ScalarField::serialize(&frost_secp256k1::Secp256K1ScalarField::one());
    println!("zero: {:?}", zero);

    let zero1 = frost_secp256k1::Secp256K1ScalarField::deserialize(&zero).unwrap();
    println!("zero1: {:?}", zero1);

    let privkey = x25519_dalek::StaticSecret::from(zero);
    println!("privkey: {:?}", hex::encode(privkey.as_bytes()));
    
    let pubkey = x25519_dalek::PublicKey::from(&privkey);

    println!("pubkey: {:?}", hex::encode(pubkey.to_bytes()));
    println!("bytes: {:?}", pubkey.as_bytes());

    // let ident = Identifier::new(frost_secp256k1::Secp256K1ScalarField::deserialize(&pubkey.as_bytes()).unwrap()).unwrap();
    // println!("{:?}", ident);

    // let byt = frost_secp256k1::Secp256K1ScalarField::serialize(&ident.to_scalar());
    // println!("{:?}", byt);

    
}
#[test]
fn test_verification() {
    let msg = "bc877d681dff63a2195b9179f39f05ac1fb0fc709389c9e79804ceb952cdb95d";
    println!("msg: {:?}", msg);
    // let raw = hex::decode(msg).unwrap();
    let raw = [62, 162, 82, 27, 173, 124, 142, 221, 180, 230, 209, 237, 25, 178, 167, 37, 94, 168, 190, 180, 72, 239, 214, 130, 163, 127, 91, 247, 66, 58, 106, 188];
    // let raw = msg.as_bytes();
    let key_raw = [2, 153, 225, 38, 191, 213, 138, 125, 173, 71, 138, 210, 28, 247, 70, 125, 41, 39, 54, 46, 168, 253, 74, 88, 220, 122, 200, 245, 253, 251, 33, 143, 171];
    let signature_raw: [u8; 65] = [3, 41, 127, 214, 45, 77, 55, 14, 100, 209, 74, 255, 112, 240, 103, 107, 87, 62, 170, 202, 120, 138, 102, 19, 245, 66, 227, 2, 93, 228, 17, 154, 197, 65, 127, 196, 205, 207, 167, 203, 233, 102, 195, 1, 102, 90, 209, 87, 195, 75, 133, 225, 53, 73, 3, 168, 245, 179, 42, 252, 186, 49, 29, 11, 108];
    

    println!("raw: {:?}", hex::encode(raw));
    println!("key: {:?}", hex::encode(key_raw));
    println!("sig: {:?}", hex::encode(signature_raw));

    let msgb = Message::from_digest_slice(&raw).expect("Invalid message");
    println!("msgb: {:?}", msgb.as_ref());
    
    // let sig_ecdsa = ecdsa::Signature::from_str(&hex::encode(&signature_raw[..64])).unwrap();
    // let pk = PublicKey::from_slice(&key_raw).unwrap();
    // println!("pk: {:?}", pk.serialize());
    let scep = Secp256k1::new();
    // match scep.verify_ecdsa(&msgb, &sig_ecdsa, &pk) {
    //     Ok(_) => println!("Signature is valid"),
    //     Err(e) => println!("Signature is invalid: {:?}", e),
    // };

    let sig = schnorr::Signature::from_slice(&signature_raw[..]).unwrap();
    let pubkey = XOnlyPublicKey::from_slice(&key_raw[1..]).unwrap();

    assert_eq!(scep.verify_schnorr(&sig, &msgb, &pubkey), Ok(()));

    
}

// We can use the following code to generate a transaction and sign it using the secp256k1 library.
// The transaction can be broadcasted using the `bitcoin` library.
// the address is a taproot address.
#[test]
fn test_transaction() {
    // Create a new secp256k1 context.
    let secp = Secp256k1::new();

    // Generate a new key pair.
    let keypair = Keypair::new(&secp, &mut rand::thread_rng() );
    
    let (xonlykey, _) = keypair.x_only_public_key();
    println!("xonly pubkey:{:?}", xonlykey.serialize());
    // Generate a new taproot address.
    let address = Address::p2tr(&secp, xonlykey, None, Network::Bitcoin);
    // Create a new transaction.
    let mut transaction = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    // Create a new input.
    let input = TxIn {
        previous_output: OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        },
        script_sig: ScriptBuf::default(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };
    // Create a new output.
    let output = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: address.script_pubkey(),
    };
    // Add the input and output to the transaction.
    transaction.input.push(input);
    transaction.output.push(output.clone());

    // We use schnorr signature.
    let sighash_type: TapSighashType = TapSighashType::Default;
    let tx_outs: Vec<TxOut> = vec![output];
    let prevouts = Prevouts::All(&tx_outs);
    let mut sighasher = SighashCache::new(&mut transaction);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .expect("failed to construct sighash");
    println!("sigHash: {:?}", sighash.as_byte_array());
    let signature = secp.sign_schnorr(&Message::from_digest(sighash.to_byte_array()), &keypair);
    println!("signature: {:?}", signature.serialize());

    // let sig = bitcoin::taproot::Signature { sig: signature, hash_ty: sighash_type };

    match &xonlykey.verify(&secp, &Message::from_digest(sighash.to_byte_array()), &signature) {
        Ok(_) => println!("Signature is valid"),
        Err(e) => println!("Signature is invalid: {:?}", e),
    };

}

#[test]
fn test_keys() {
    // XOnlyPublicKey::from_slice(data)
    
    // Create a new secp256k1 context.
    let secp = Secp256k1::new();

    let key_raw = [ 2, 199, 157, 245, 180, 116, 236, 171, 125, 55, 141, 30, 2, 193, 188, 55, 55, 49, 129, 24, 121, 106, 222, 12, 165, 158, 157, 232, 184, 176, 91, 179, 237];
    let pk = PublicKey::from_slice(&key_raw).unwrap();

    println!("pk: {:?}", pk);

    let sig = [3, 91, 97, 68, 143, 100, 135, 36, 254, 83, 83, 52, 175, 9, 197, 73, 201, 237, 40, 169, 180, 171, 143, 214, 142, 38, 98, 170, 111, 140, 116, 117, 121, 112, 149, 24, 70, 172, 154, 220, 94, 116, 62, 67, 216, 6, 214, 168, 180, 47, 183, 15, 88, 20, 146, 204, 214, 168, 60, 103, 180, 17, 114, 181, 130];
   
    let signature = ecdsa::Signature::from_compact(&sig).expect("Invalid Signatures");
    // keypair.public_key().verify(&secp, msg, sig)
    let text = [181, 121, 244, 3, 218, 122, 170, 51, 38, 102, 122, 153, 179, 167, 118, 242, 174, 45, 157, 135, 155, 177, 158, 39, 134, 66, 84, 1, 56, 169, 227, 164];
    
    // let xonlykey = XOnlyPublicKey::from_slice(&key).expect("invalid xonly key");
    // println!("xonly pubkey:{:?}", xonlykey);
    let message = Message::from_digest(text);

    assert!( pk.verify(&secp, &message, &signature).expect("Invalid") == (), "invalid" )
       

}

#[test]
// verify the Xonly signature
fn verify_xonly_signatures() {
    let secp = Secp256k1::new();
    // key and signature from single signer
    // let key = [184, 142, 17, 226, 51, 110, 107, 130, 215, 208, 131, 211, 253, 110, 220, 43, 1, 18, 132, 200, 182, 148, 164, 252, 183, 241, 163, 181, 174, 37, 138, 181];
    // let sig = [162, 64, 13, 160, 112, 37, 113, 205, 110, 252, 79, 132, 29, 75, 34, 170, 3, 147, 187, 133, 177, 254, 129, 126, 40, 56, 31, 165, 248, 28, 242, 49, 87, 122, 202, 201, 237, 28, 27, 223, 170, 14, 129, 154, 98, 249, 107, 134, 250, 112, 166, 193, 201, 143, 42, 40, 54, 252, 77, 82, 149, 75, 195, 150];

    // key and signature from tss singer
    let key = [ 2, 199, 157, 245, 180, 116, 236, 171, 125, 55, 141, 30, 2, 193, 188, 55, 55, 49, 129, 24, 121, 106, 222, 12, 165, 158, 157, 232, 184, 176, 91, 179, 237];
    let sig = [ 3, 91, 97, 68, 143, 100, 135, 36, 254, 83, 83, 52, 175, 9, 197, 73, 201, 237, 40, 169, 180, 171, 143, 214, 142, 38, 98, 170, 111, 140, 116, 117, 121, 112, 149, 24, 70, 172, 154, 220, 94, 116, 62, 67, 216, 6, 214, 168, 180, 47, 183, 15, 88, 20, 146, 204, 214, 168, 60, 103, 180, 17, 114, 181, 130];
    
    let text = [181, 121, 244, 3, 218, 122, 170, 51, 38, 102, 122, 153, 179, 167, 118, 242, 174, 45, 157, 135, 155, 177, 158, 39, 134, 66, 84, 1, 56, 169, 227, 164];
    
    // let xonlykey = XOnlyPublicKey::from_slice(&key).expect("invalid xonly key");
    // println!("xonly pubkey:{:?}", xonlykey);
    let message = Message::from_digest(text);
    let pk = PublicKey::from_slice(&key).expect("invalid key slice");

    // let message = Message::from_hashed_data::<bitcoin::hashes::sha256::Hash>(&text);

    // let signature = Signature::
    // from_slice(&[216, 29, 74, 80, 227, 190, 83, 201, 130, 52, 160, 119, 89, 68, 35, 145, 156, 10, 44, 99, 62, 41, 247, 92, 154, 230, 222, 126, 194, 96, 20, 104, 236, 135, 44, 51, 125, 105, 69, 47, 57, 25, 21, 202, 54, 55, 116, 13, 54, 78, 221, 151, 175, 55, 22, 67, 132, 9, 124, 86, 217, 72, 249, 207]).expect("invalid signature");
    let signature = MessageSignature::from_slice(&sig).expect("invalid signature");
    // let signature = ecdsa::Signature::from_compact(&sig).unwrap();
    // let signature = ecdsa::Signature::from_compact(&sig[1..]).expect("invalid signature slice");
    println!("signature: {:?}", signature);

    // let verified = pk.verify(&secp, &message, &signature).is_ok();
    // assert!(verified, "verify failed");

    // assert!( &xonlykey.verify(&secp, &message, &signature).is_ok(), "verify failed"); 
}

#[test]
fn test_rpc() {
    use bitcoincore_rpc::{Auth, Client, RpcApi};

    let rpc = Client::new("149.28.156.79:18332",
                          Auth::UserPass("side".to_string(), "12345678".to_string())).unwrap();
    let best_block_hash = rpc.get_block_count().unwrap();
    println!("best block hash: {}", best_block_hash);
}