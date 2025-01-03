use crate::{config::Config, apps::signer::Signer};

use super::Cli;

pub fn execute(cli: &Cli) {

    // let conf = Config::from_file(&cli.home).unwrap();
    // let signer = Signer::new(conf, false);
    // signer.reset_db();
    println!("Reset all tasks");
}