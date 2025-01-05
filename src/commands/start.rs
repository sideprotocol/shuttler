
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use crate::{apps::{bridge::BridgeSigner, relayer::Relayer, Shuttler, Task}, config::Config};

pub async fn execute(home: &str, relayer: bool, signer: bool, seed: bool) {
    
    let conf = Config::from_file(home).unwrap();

    let filter = EnvFilter::new("info").add_directive(format!("shuttler={}", conf.log_level).parse().unwrap());
    let subscriber = FmtSubscriber::builder()
        .with_line_number(true)
        .with_env_filter(filter) // Enable log filtering through environment variable
        .finish();
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        println!("Unable to set global log config!");
    }

    let mut app = Shuttler::new(home, seed);

    let r = Relayer::new(conf.clone());
    if relayer {
        app.registry( &r);
    }
    let b = BridgeSigner::new(conf.clone());
    if signer {
        app.registry( &b);
    }

    app.start(&conf).await;
}