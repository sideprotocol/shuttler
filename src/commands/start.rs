
use tokio::spawn;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use crate::{apps::{agency::Agency, bridge::BridgeSigner, oracle::Oracle, relayer::Relayer, App, Shuttler }, config::Config};

pub async fn execute(home: &str, relayer: bool, bridge: bool, oracle: bool, agency: bool, seed: bool) {
    
    let conf = Config::from_file(home).unwrap();

    let filter = EnvFilter::new("info").add_directive(format!("shuttler={}", conf.log_level).parse().unwrap());
    let subscriber = FmtSubscriber::builder()
        .with_line_number(true)
        .with_env_filter(filter) // Enable log filtering through environment variable
        .finish();
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        println!("Unable to set global log config!");
    }

    let mut shuttler = Shuttler::new(home, seed);

    // let r = Relayer::new(conf.clone());
    // if relayer { shuttler.registry( &r); }
    let b = BridgeSigner::new(conf.clone());
    if bridge { shuttler.registry( &b); }
    let o = Oracle::new(conf.clone());
    if oracle { shuttler.registry(&o); }
    let a = Agency::new();
    if agency { shuttler.registry(&a);}

    // start relayer if enabled
    if relayer {
        let r = Relayer::new(conf.clone());
        spawn(async move { r.start().await });
    }

    shuttler.start(&conf).await;
}