use core::{NonceGenerator, NonceHandler, OracleKeyShareGenerator, OracleKeyShareHandler};
use std::time::Duration;
use side_proto::side::dlc::query_client::QueryClient as DLCQueryClient;
use nonce::NonceGeneration;
use tokio::time::{Instant, Interval};
use tonic::transport::Channel;

use crate::{config::{Config, VaultKeypair}, helper::store::DefaultStore};

use super::{App, Context, SubscribeMessage};
pub mod core;
pub mod nonce;

pub struct Oracle {    
    enable: bool,
    config: Config,
    ticker: Interval,
    db_nonce: NonceStore,
    db_keyshare: KeyStore,
    nonce_generator: NonceGenerator,
    keyshare_generator: OracleKeyShareGenerator,
    dlc_client: DLCQueryClient<Channel>,
}

type NonceStore = DefaultStore<String, NonceGeneration>;
type KeyStore = DefaultStore<String, VaultKeypair>;

impl Oracle {
    pub async fn new(conf: Config, enable: bool) -> Self {
        let ticker = tokio::time::interval(Duration::from_secs(10));

        let db_nonce = NonceStore::new(conf.get_database_with_name("oracle-nonces"));
        let db_keyshare = KeyStore::new(conf.get_database_with_name("oracle-keypair"));
        let nonce_generator = NonceGenerator::new(NonceHandler{});
        let keyshare_generator = OracleKeyShareGenerator::new(OracleKeyShareHandler{});
        let dlc_client = match DLCQueryClient::connect(conf.side_chain.grpc.clone()).await {
            Ok(c) => c,
            Err(e) => panic!("{}", e),
        };

        Self {
            config: conf,
            ticker,
            enable,
            db_nonce,
            db_keyshare,
            nonce_generator,
            keyshare_generator,
            dlc_client,
        }
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl App for Oracle {
    async fn on_tick(&self, _ctx: &mut Context) {
        // todo!()
    }

    fn on_message(&self, _ctx: &mut Context, _message: &SubscribeMessage) {
        // todo!()
    }

    fn enabled(&self) -> bool {
        self.enable
    }

    async fn tick(&mut self) -> Instant {
        self.ticker.tick().await
    }
}

