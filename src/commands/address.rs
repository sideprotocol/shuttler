use tracing::info;

use crate::app::config::Config;

use super::Cli;

pub fn execute(cli: &Cli) {
    let conf = Config::from_file(&cli.home).unwrap();

    info!("Signer address: {}", conf.signer_address());
    info!("Please fund signer address before using it.");

    info!("Vault addresses: ({})", conf.keys.len());
    let mut index = 1;
    for (k, _v) in conf.keys.iter() {
        info!("{}: {}", index, k);
        index += 1;
    }
    
}