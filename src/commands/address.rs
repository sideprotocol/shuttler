use ed25519_compact::SecretKey;

use crate::{apps::signer::Signer, config::Config, helper::encoding::{identifier_to_peer_id, pubkey_to_identifier}};

use super::Cli;

pub fn execute(cli: &Cli) {
    let conf = Config::from_file(&cli.home).unwrap();
    let signer = Signer::new(conf.clone(), false);

    let priv_validator_key = conf.load_validator_key();

    let mut b = priv_validator_key
        .priv_key
        .ed25519_signing_key()
        .unwrap()
        .as_bytes()
        .to_vec();
    b.extend(priv_validator_key.pub_key.to_bytes());
    let node_key = SecretKey::new(b.as_slice().try_into().unwrap());
    let identifier = pubkey_to_identifier(node_key.public_key().as_slice());
    let peer_id = identifier_to_peer_id(&identifier);

    println!("\n{:?}", identifier );
    println!("{:?}\n", peer_id );

    println!("Relayer address");
    println!("-------------------------------------------------------------");
    println!(" {}", conf.relayer_bitcoin_address());
    println!("\n NOTE: Please fund relayer address on sidechain before using it.");
    println!("-------------------------------------------------------------");

    println!("\nVault Address:");
    // signer.list_keypairs().iter().enumerate().for_each(| (i, (addr, kp))| {
    //     println!("{i}. {addr} ({}-of-{})", kp.priv_key.min_signers(), kp.pub_key.verifying_shares().len());
    // });
}