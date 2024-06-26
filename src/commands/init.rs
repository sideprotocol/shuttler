use crate::config;

use super::Cli;
use bitcoin::Network;
use log::info;

pub fn execute(cli: &Cli, port : u16, network: Network) {
    info!("init config to: {}", &cli.home);
    config::update_app_home(&cli.home);
    config::Config::default(port, network).save().unwrap();
}