
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use crate::{apps::{bridge::BridgeApp, lending::LendingApp, relayer::{tick::start_relayer_tasks, Relayer}, Shuttler }, config::Config};

pub async fn execute(home: &str, relayer: bool, bridge: bool, lending: bool, seed: bool) {

    
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

    
    if relayer { 
        let r = Relayer::new(conf.clone());
        tokio::spawn(start_relayer_tasks(r));
    }
    let b = BridgeApp::new(conf.clone());
    if bridge { shuttler.registry( &b); }
    let o = LendingApp::new();
    if lending { shuttler.registry(&o); }

    shuttler.start(&conf).await;

}