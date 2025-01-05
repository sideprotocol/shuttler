use std::{future::Future, pin::Pin, time::Duration};
use side_proto::side::dlc::query_client::QueryClient as DLCQueryClient;
use tonic::transport::Channel;

use crate::config::Config;

use super::{App, Context, SubscribeMessage};
mod tick;
mod nonce;
mod oracle;
mod agency;
mod attestation;

pub struct DLC {
    // nonce_generator: NonceGenerator,
    // keyshare_generator: OracleGenerator,
    // agency_generator: AgencyGenerator,
    dlc_client: DLCQueryClient<Channel>,
}

impl DLC {
    pub async fn new(conf: &Config) -> Self {

        let dlc_client = match DLCQueryClient::connect(conf.side_chain.grpc.clone()).await {
            Ok(c) => c,
            Err(e) => panic!("{}", e),
        };

        Self {
            // nonce_generator: NonceGenerator::new(),
            // keyshare_generator: OracleGenerator::new(),
            // agency_generator: AgencyGenerator::new(),
            dlc_client,
        }
    }
}

impl App for DLC {

    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()>{
        // self.nonce_generator.on_message(ctx, message);
        // self.keyshare_generator.on_message(ctx, message);
        Ok(())
    }

    fn subscribe_topics(&self) -> Vec<libp2p::gossipsub::IdentTopic> {
        vec![]
    }
    fn tick(&self) -> Duration {
        Duration::from_secs(30)
    }
    fn on_tick(&self, _ctxx: &mut Context) {

    }
}


