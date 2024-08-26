use futures::join;

use crate::app::{config::Config, relayer, signer};
use super::Cli;

pub async fn execute(cli: &Cli) {
    
    let conf = Config::from_file(&cli.home).unwrap();
    let conf_2 = conf.clone();
    // let s = thread::spawn(move || {
    //     signer::run_signer_daemon(conf);
    // });
    // let r = thread::spawn(move || {
    //     relayer::run_relayer_daemon(conf_2);
    // });
    
    join!(signer::run_signer_daemon(conf), relayer::run_relayer_daemon(conf_2) );
}