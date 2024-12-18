use handler::{NonceGenerator, OracleKeyShareGenerator};
use std::time::Duration;
use side_proto::side::dlc::query_client::QueryClient as DLCQueryClient;
use tokio::time::{Instant, Interval};
use tonic::transport::Channel;

use crate::config::Config;

use super::{App, Context, SubscribeMessage};
mod handler;
mod nonce;

pub struct Oracle {    
    enable: bool,
    config: Config,
    ticker: Interval,
    nonce_generator: NonceGenerator,
    keyshare_generator: OracleKeyShareGenerator,
    dlc_client: DLCQueryClient<Channel>,
}

impl Oracle {
    pub async fn new(conf: Config, enable: bool) -> Self {
        let ticker = tokio::time::interval(Duration::from_secs(10));

        let nonce_generator = NonceGenerator::new();
        let keyshare_generator = OracleKeyShareGenerator::new();
        let dlc_client = match DLCQueryClient::connect(conf.side_chain.grpc.clone()).await {
            Ok(c) => c,
            Err(e) => panic!("{}", e),
        };

        Self {
            config: conf,
            ticker,
            enable,
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
    async fn on_tick(&mut self, ctx: &mut Context) {
        // todo!()
        self.fetch_new_key_generation(ctx).await;
        self.fetch_new_nonce_generation(ctx).await;
    }

    fn on_message(&mut self, _ctx: &mut Context, _message: &SubscribeMessage) {
        // todo!()
    }

    fn enabled(&mut self) -> bool {
        self.enable
    }

    async fn tick(&mut self) -> Instant {
        self.ticker.tick().await
    }
}

