

use chrono::{Timelike, Utc};
use bitcoincore_rpc::{Auth, Client};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tokio::{select, time::Instant};
use crate::{app::config::Config, helper::{client_ordinals::OrdinalsClient, now}, tickers::relayer};

use std::time::Duration;
use tracing::info;

#[derive(Debug)]
pub struct Relayer {
    config: Config,
    pub bitcoin_client: Client,
    pub ordinals_client: OrdinalsClient,
}

impl Relayer {
    pub fn new(conf: Config) -> Self {

        let bitcoin_client = Client::new(
            &conf.bitcoin.rpc, 
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone()))
            .expect("Could not initial bitcoin RPC client");

        let ordinals_client = OrdinalsClient::new(&conf.ordinals.endpoint);

        Self {
            // priv_validator_key: validator_key,
            bitcoin_client,
            ordinals_client,
            config: conf,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

}

pub async fn run_relayer_daemon(conf: Config) {
    
    info!("Starting relayer daemon");

    let relayer = Relayer::new(conf);

    // this is to ensure that each node fetches tasks at the same time    
    let d = 6 as u64;
    let start = Instant::now() + (Duration::from_secs(d) - Duration::from_secs(now() % d));
    let mut interval_relayer = tokio::time::interval_at(start, Duration::from_secs(d));

    let seed = Utc::now().minute() as u64;
    let mut rng = ChaCha8Rng::seed_from_u64(seed );

    loop {
        select! {
            _ = interval_relayer.tick() => {
                relayer::start_relayer_tasks(&relayer, &mut rng).await;
            }
        }
    }
}
