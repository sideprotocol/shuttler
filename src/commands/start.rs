use futures::join;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use crate::app::{config::Config, relayer, signer};

pub async fn execute(home: &str, relayer: bool, signer: bool) {
    
    let conf = Config::from_file(home).unwrap();

    let filter = EnvFilter::new("info").add_directive(format!("shuttler={}", conf.log_level).parse().unwrap());
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter) // Enable log filtering through environment variable
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    if relayer && !signer {
        relayer::run_relayer_daemon(conf).await;
    } else if signer && !relayer {
        signer::run_signer_daemon(conf).await;
    } else {
        // Start both signer and relayer as default
        join!(signer::run_signer_daemon(conf.clone()), relayer::run_relayer_daemon(conf));
    }
}