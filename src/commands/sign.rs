use crate::messages::Task;

use super::{publish, Cli};


pub async fn execute(cli : &Cli, pbst : String) {
    let conf = crate::config::Config::from_file(&cli.home).unwrap();
    let task = Task::new(crate::messages::SigningSteps::SignInit, pbst);
    publish(&conf, task).await;
}