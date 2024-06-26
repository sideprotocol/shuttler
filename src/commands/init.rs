use crate::config;

use super::Cli;
use log::info;

pub fn execute(cli: &Cli, port : u16) {
    info!("init config to: {}", &cli.home);
    config::update_app_home(&cli.home);
    config::Config::default(port).save().unwrap();
}