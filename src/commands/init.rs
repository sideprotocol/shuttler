use crate::config;

use super::Cli;

pub fn execute(cli: &Cli) {
    println!("init config to: {}", &cli.home);
    config::Config::default().save(&cli.home).unwrap();
}