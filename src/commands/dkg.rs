
use crate::{app::config::Config, helper::messages::{Task, SigningSteps} };

use super::{publish, Cli};

pub async fn execute(cli: &Cli) {
    // Add your logic here
    let conf = Config::from_file(&cli.home).unwrap();
    let task = Task::new(SigningSteps::DkgInit, "".to_string());
    publish(&conf, task).await;
    
}