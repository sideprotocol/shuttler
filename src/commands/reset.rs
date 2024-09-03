use crate::{app::config, protocols::{dkg, sign}};

use super::Cli;

pub fn execute(cli: &Cli) {
    config::update_app_home(&cli.home);
    dkg::delete_tasks();
    sign::delete_tasks();
    println!("Reset all tasks");
}