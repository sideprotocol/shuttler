use crate::app::config;

use super::Cli;
use bitcoin::Network;
use tracing::info;

pub fn execute(cli: &Cli, port : u32, network: Network) {
    info!("init config to: {}", &cli.home);
    config::update_app_home(&cli.home);
    config::Config::default(port, network).save().unwrap();
}