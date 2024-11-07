use crate::app::config::Config;

use super::Cli;

pub fn execute(cli: &Cli) {
    let conf = Config::from_file(&cli.home).unwrap();
    println!("Relayer address");
    println!("-------------------------------------------------------------");
    println!(" {}", conf.relayer_bitcoin_address());
    println!("\n NOTE: Please fund relayer address on sidechain before using it.");
    println!("-------------------------------------------------------------");

    // println!("\nVault addresses: ({})", keypairs.len());
    // println!("-------------------------------------------------------------");
    // let keypairs = config::list_keypairs();
    // for (index, k) in keypairs.iter().enumerate() {
    //     println!("{}: {}", index, k);
    // }
    // println!("\n");
}