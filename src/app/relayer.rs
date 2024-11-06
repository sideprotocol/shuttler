

use bitcoincore_rpc::{Auth, Client};
use crate::{app::config::Config, helper::{client_oracle::OracleClient, client_ordinals::OrdinalsClient}, tickers::relayer};

use tracing::info;

#[derive(Debug)]
pub struct Relayer {
    config: Config,
    pub bitcoin_client: Client,
    pub ordinals_client: OrdinalsClient,
    pub oracle_client: OracleClient,
    pub db_relayer: sled::Db,
}

impl Relayer {
    pub fn new(conf: Config) -> Self {

        let auth = if !conf.bitcoin.user.is_empty() {
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone())
        } else {
            Auth::None
        };

        let bitcoin_client = Client::new(
            &conf.bitcoin.rpc, 
            auth,
        )
            .expect("Could not initial bitcoin RPC client");

        let ordinals_client = OrdinalsClient::new(&conf.ordinals.endpoint);
        let oracle_client = OracleClient::new(&conf.oracle);


        let db_relayer = sled::open(conf.get_database_with_name("relayer")).expect("Counld not create database!");

        Self {
            // priv_validator_key: validator_key,
            bitcoin_client,
            ordinals_client,
            oracle_client,
            config: conf,
            db_relayer,
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
