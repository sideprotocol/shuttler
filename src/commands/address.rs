use crate::{config::Config,apps::signer::Signer};

use super::Cli;

pub fn execute(cli: &Cli) {
    let conf = Config::from_file(&cli.home).unwrap();
    let signer = Signer::new(conf.clone());

    println!("\n{:?}", signer.identifier());
    println!("{:?}\n", signer.peer_id());

    println!("Relayer address");
    println!("-------------------------------------------------------------");
    println!(" {}", conf.relayer_bitcoin_address());
    println!("\n NOTE: Please fund relayer address on sidechain before using it.");
    println!("-------------------------------------------------------------");

    println!("\nVault Address:");
    signer.list_keypairs().iter().enumerate().for_each(| (i, (addr, kp))| {
        println!("{i}. {addr} ({}-of-{})", kp.priv_key.min_signers(), kp.pub_key.verifying_shares().len());
    });
}