use crate::app::config::Config;

use super::Cli;

pub fn execute(cli: &Cli) {
    let conf = Config::from_file(&cli.home).unwrap();

    println!("=============================================================");
    println!("Signer address: {}", conf.signer_address());
    println!("Please fund signer address before using it.");
    println!("=============================================================");

    println!("\nVault addresses: ({})", conf.keypairs.len());
    println!("-------------------------------------------------------------");
    let mut index = 1;
    for (k, _v) in conf.keypairs.iter() {
        println!("{}: {}", index, k);
        index += 1;
    }
    println!("\n");
}