use crate::app::config;

use super::Cli;
use bitcoin::Network;

pub fn execute(cli: &Cli, port : u32, network: Network) {
    println!("Initialize Shuttler Home: {}", &cli.home);
    // config::update_app_home(&cli.home);
    config::Config::default(&cli.home, port, network).save().unwrap();
}