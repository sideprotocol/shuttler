use futures::join;

use crate::app::{config::Config, relayer, signer};

pub async fn execute(home: &str, relayer: bool, signer: bool) {
    
    let conf = Config::from_file(home).unwrap();

    if relayer && !signer {
        relayer::run_relayer_daemon(conf).await;
    } else if signer && !relayer {
        signer::run_signer_daemon(conf).await;
    } else {
        // Start both signer and relayer as default
        join!(signer::run_signer_daemon(conf.clone()), relayer::run_relayer_daemon(conf));
    }
}