use crate::helper::messages::{Task, SigningSteps};

use super::{publish, Cli};


pub async fn execute(cli : &Cli, pbst : String) {
    let conf = crate::app::config::Config::from_file(&cli.home).unwrap();
    let task = Task::new(SigningSteps::SignInit, pbst);
    publish(&conf, task).await;
}