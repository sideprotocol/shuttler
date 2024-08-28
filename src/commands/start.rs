use futures::join;

use crate::app::{config::Config, relayer, signer};

pub async fn execute(home: &str, relayer: bool, signer: bool) {
    
    let conf = Config::from_file(home).unwrap();
    let conf_2 = conf.clone();
    // let s = thread::spawn(move || {
    //     signer::run_signer_daemon(conf);
    // });
    // let r = thread::spawn(move || {
    //     relayer::run_relayer_daemon(conf_2);
    // });

    if relayer && signer {
        join!(signer::run_signer_daemon(conf), relayer::run_relayer_daemon(conf_2));
    } else if relayer {
        relayer::run_relayer_daemon(conf_2).await;
    } else if signer {
        signer::run_signer_daemon(conf).await;
    }
}