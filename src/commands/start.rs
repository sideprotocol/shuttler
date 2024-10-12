
use tokio::join;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use crate::app::{config::Config, relayer, signer};

pub async fn execute(home: &str, relayer: bool, signer: bool) {
    
    let conf = Config::from_file(home).unwrap();

    let filter = EnvFilter::new("info").add_directive(format!("shuttler={}", conf.log_level).parse().unwrap());
    let subscriber = FmtSubscriber::builder()
        .with_line_number(true)
        .with_env_filter(filter) // Enable log filtering through environment variable
        .finish();
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        println!("Unable to set global log config!");
    }
        

    if relayer && !signer {
        relayer::run_relayer_daemon(conf).await;
    } else if signer && !relayer {
        signer::run_signer_daemon(conf).await;
    } else {
        let conf2 = conf.clone();
        let sign_handler = tokio::spawn(async move { signer::run_signer_daemon(conf).await });
        let relay_handler = tokio::spawn(async move { relayer::run_relayer_daemon(conf2).await });
        // Start both signer and relayer as default
        match join!(sign_handler, relay_handler) {
            (Ok(_), Ok(_)) => {
                println!("Signer and Relayer started successfully");
            }
            (Err(e), _) => {
                println!("Error starting signer: {:?}", e);
            }
            (_, Err(e)) => {
                println!("Error starting relayer: {:?}", e);
            }
        }
    }
}