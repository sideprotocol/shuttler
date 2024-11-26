

use std::time::Duration;

use bitcoincore_rpc::{Auth, Client};
use tick::{scan_vault_txs_loop, submit_fee_rate_loop, sync_btc_blocks_loop};
use tokio::join;
use crate::{config::Config, helper::{client_oracle::OracleClient, client_ordinals::OrdinalsClient}};

use super::{App, Context, SubscribeMessage};

pub mod tick;

#[derive(Debug)]
pub struct Relayer {
    config: Config,
    pub bitcoin_client: Client,
    pub ordinals_client: OrdinalsClient,
    pub oracle_client: OracleClient,
    pub db_relayer: sled::Db,
}

impl App for Relayer {
    fn on_message(&self, _ctx: &mut Context, _message: &SubscribeMessage) {
        todo!()
    }

    async fn ticker(&self) -> tokio::time::Interval {
        tokio::time::interval(Duration::from_secs(self.config.loop_interval))
    }

    async fn on_tick(&self, _ctx: &mut Context) {
        join!(
            sync_btc_blocks_loop(self),
            scan_vault_txs_loop(self),
            submit_fee_rate_loop(self),
        );
    }
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
        ).expect("Could not initial bitcoin RPC client");

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

