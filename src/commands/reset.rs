use tracing::info;

use crate::{app::config, helper::store};

use super::Cli;

pub fn execute(cli: &Cli) {
    config::update_app_home(&cli.home);
    store::delete_tasks();
    info!("Reset all tasks");
}