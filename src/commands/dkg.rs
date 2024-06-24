
use crate::messages::Task;

use super::{publish, Cli};

pub async fn execute(cli: &Cli) {
    // Add your logic here
    let conf = crate::config::Config::from_file(&cli.home).unwrap();
    let task = Task::new(crate::messages::SigningSteps::DkgInit, "".to_string());
    publish(&conf, task).await;
}