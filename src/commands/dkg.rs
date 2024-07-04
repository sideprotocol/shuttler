
use crate::{app::config::Config, helper::messages::{Task, SigningSteps} };

use super::{publish, Cli};

pub async fn execute(cli: &Cli, min_signers: u16, max_signers: u16) {
    // Add your logic here
    let conf = Config::from_file(&cli.home).unwrap();
    let task = Task::new_with_signers(SigningSteps::DkgInit, "".to_string(), min_signers, max_signers);
    publish(&conf, task).await;
    
}