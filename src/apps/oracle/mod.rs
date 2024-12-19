use handler::{NonceGenerator, NonceHandler, NonceSigner, OracleKeyShareGenerator, OracleKeyShareHandler};
use std::time::Duration;
use side_proto::side::dlc::query_client::QueryClient as DLCQueryClient;
use tokio::time::{Instant, Interval};
use tonic::transport::Channel;

use crate::config::Config;

use super::{App, Context, SubscribeMessage, TopicAppHandle};
mod handler;
mod nonce;

pub struct Oracle {    
    enable: bool,
    config: Config,
    ticker: Interval,
    nonce_generator: NonceGenerator,
    nonce_signer: NonceSigner,
    keyshare_generator: OracleKeyShareGenerator,
    dlc_client: DLCQueryClient<Channel>,
}

impl Oracle {
    pub async fn new(conf: Config, enable: bool) -> Self {
        let ticker = tokio::time::interval(Duration::from_secs(10));

        let nonce_generator = NonceGenerator::new();
        let nonce_signer = NonceSigner::new();
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
            nonce_signer,
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
        self.fetch_new_key_generation(ctx).await;
        self.fetch_new_nonce_generation(ctx).await;
    }

    fn on_message(&mut self, ctx: &mut Context, message: &SubscribeMessage) {
        self.nonce_generator.on_message(ctx, message);
        self.keyshare_generator.on_message(ctx, message);
    }

    fn enabled(&mut self) -> bool {
        self.enable
    }

    async fn tick(&mut self) -> Instant {
        self.ticker.tick().await
    }
    
    fn subscribe(&self, ctx: &mut Context) {
        let _ = ctx.swarm.behaviour_mut().gossip.subscribe(&NonceHandler::topic());
        let _ = ctx.swarm.behaviour_mut().gossip.subscribe(&OracleKeyShareHandler::topic());
    }
}

