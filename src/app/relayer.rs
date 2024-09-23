

use bitcoincore_rpc::{Auth, Client};
use crate::{app::config::Config, helper::client_ordinals::OrdinalsClient, tickers::relayer};

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
    relayer::start_relayer_tasks(&relayer).await;

}
