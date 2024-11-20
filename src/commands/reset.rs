use crate::app::{config::Config, signer::Signer};

use super::Cli;

pub fn execute(cli: &Cli) {

    let conf = Config::from_file(&cli.home).unwrap();
    let signer = Signer::new(conf);
    signer.reset_db();
    println!("Reset all tasks");
}