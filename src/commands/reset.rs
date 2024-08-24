use tracing::info;

use crate::{app::config, protocols::dkg};

use super::Cli;

pub fn execute(cli: &Cli) {
    config::update_app_home(&cli.home);
    dkg::delete_tasks();
    info!("Reset all tasks");
}