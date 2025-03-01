

use std::time::Duration;

use bitcoincore_rpc::{Auth, Client};
use libp2p::gossipsub::IdentTopic;
use crate::{config::Config, helper::{client_fee_provider::FeeProviderClient, client_ordinals::OrdinalsClient}};

use super::{App, Context, SideEvent, SubscribeMessage};

pub mod bridge;
pub mod lending;

#[derive(Debug)]
pub struct Relayer {
    // deprecated
    config: Config,
    pub bitcoin_client: Client,
    pub ordinals_client: OrdinalsClient,
    pub fee_provider_client: FeeProviderClient,
    pub db_relayer: sled::Db,
    pub ticker: tokio::time::Interval,
}

impl App for Relayer {
    fn on_message(&self, _ctx: &mut Context, _message: &SubscribeMessage) -> anyhow::Result<()> {
        Ok(())
    }
    
    fn subscribe_topics(&self) -> Vec<IdentTopic> {
        vec![]
    }
    fn on_event(&self, _ctx: &mut Context, _event: &SideEvent) {
        
    }
    fn on_start(&self, ctx: &mut Context) {
        bridge::start_relayer_tasks(self);
        lending::start_relayer_tasks(self);
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
        let fee_provider_client = FeeProviderClient::new(&conf.fee_provider);

        let db_relayer = sled::open(conf.get_database_with_name("relayer")).expect("Counld not create database!");
        let ticker = tokio::time::interval(Duration::from_secs(conf.loop_interval as u64));

        Self {
            // priv_validator_key: validator_key,
            bitcoin_client,
            ordinals_client,
            fee_provider_client,
            config: conf,
            db_relayer,
            ticker,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

}

