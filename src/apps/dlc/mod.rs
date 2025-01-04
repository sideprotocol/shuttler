use std::time::Duration;
use side_proto::side::dlc::query_client::QueryClient as DLCQueryClient;
use tokio::time::{Instant, Interval};
use tonic::transport::Channel;

use crate::config::Config;

use super::{App, Context, SubscribeMessage};
mod tick;
mod nonce;
mod oracle;
mod agency;
mod attestation;

pub struct DLC {    
    enable: bool,
    config: Config,
    ticker: Interval,
    // nonce_generator: NonceGenerator,
    // keyshare_generator: OracleGenerator,
    // agency_generator: AgencyGenerator,
    dlc_client: DLCQueryClient<Channel>,
}

impl DLC {
    pub async fn new(conf: Config, enable: bool) -> Self {
        let ticker = tokio::time::interval(Duration::from_secs(10));

        let dlc_client = match DLCQueryClient::connect(conf.side_chain.grpc.clone()).await {
            Ok(c) => c,
            Err(e) => panic!("{}", e),
        };

        Self {
            config: conf,
            ticker,
            enable,
            // nonce_generator: NonceGenerator::new(),
            // keyshare_generator: OracleGenerator::new(),
            // agency_generator: AgencyGenerator::new(),
            dlc_client,
        }
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl App for DLC {
    async fn on_tick(&mut self, ctx: &mut Context) {
        // self.fetch_new_key_generation(ctx).await;
        // self.fetch_new_nonce_generation(ctx).await;
        // self.fetch_new_agency(ctx).await;
    }

    fn on_message(&mut self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()>{
        // self.nonce_generator.on_message(ctx, message);
        // self.keyshare_generator.on_message(ctx, message);
        Ok(())
    }

    fn enabled(&mut self) -> bool {
        self.enable
    }

    async fn tick(&mut self) -> Instant {
        self.ticker.tick().await
    }
    
    fn subscribe_topics(&self) -> Vec<libp2p::gossipsub::IdentTopic> {
        vec![]
    }
    
}

