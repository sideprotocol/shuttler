

use frost_adaptor_signature::Identifier;
use libp2p::{gossipsub::IdentTopic, Swarm};
use serde::{Deserialize, Serialize};
use side_proto::cosmos::base::tendermint::v1beta1::{service_client::ServiceClient as BlockService, GetLatestBlockRequest};

use crate::apps::{Context, Shuttler, ShuttlerBehaviour};

use super::{mem_store, now};
pub const HEART_BEAT_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SubscribeTopic {
    HEARTBEAT,
}

impl SubscribeTopic {
    pub fn topic(&self) -> IdentTopic {
        IdentTopic::new(format!("{:?}", self))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeartBeatMessage {
    pub payload: HeartBeatPayload,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HeartBeatPayload {
    pub identifier: Identifier,
    pub last_seen: u64,
    pub block_height: u64,
}

pub fn subscribe_gossip_topics(swarm: &mut Swarm<ShuttlerBehaviour>, app: &Shuttler) {
    let mut topics = vec![
        SubscribeTopic::HEARTBEAT.topic(),
    ];
    app.apps.iter().for_each(|a| topics.extend(a.subscribe_topics()));

    for topic in topics {
        swarm.behaviour_mut().gossip.subscribe(&topic).expect("Failed to subscribe TSS events");
    }
}

pub fn sending_heart_beat(ctx: &mut Context, block_height: u64) {

        // let mut client = match BlockService::connect(ctx.conf.side_chain.grpc.clone()).await {
        //     Ok(c) => c,
        //     Err(e) => {
        //         tracing::error!("{}", e);
        //         return;
        //     },
        // };
        // let block = match client.get_latest_block(GetLatestBlockRequest{}).await {
        //     Ok(res) => res.into_inner().block,
        //     Err(e) => {
        //         tracing::error!("{}", e);
        //         return;
        //     },
        // };

        // tracing::debug!("block: {:?}", block);

        // let block_height = match block {
        //     Some(b) => match b.header {
        //         Some(h) => h.height,
        //         None => return,
        //     }
        //     None => return,
        // };

        let last_seen = now() + mem_store::HEART_BEAT_WINDOW;
        let payload = HeartBeatPayload {
            identifier: ctx.identifier.clone(),
            last_seen,
            block_height,
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let signature = ctx.node_key.sign(bytes, None).to_vec();
        let alive = HeartBeatMessage { payload, signature };
        let message = serde_json::to_vec(&alive).unwrap();
        publish_message(ctx, SubscribeTopic::HEARTBEAT, message);
        
        mem_store::update_alive_table(&ctx.identifier, alive);
}

pub fn publish_message(ctx: &mut Context, topic: SubscribeTopic, message: Vec<u8>) {
    match ctx.swarm.behaviour_mut().gossip.publish(topic.topic(), message) {
        Ok(_) => { },
        Err(e) => {
            tracing::error!("Failed to publish message to topic {:?}: {:?}", topic, e);
        }
    }
}

pub fn publish_topic_message(ctx: &mut Context, topic: IdentTopic, message: Vec<u8>) {
    match ctx.swarm.behaviour_mut().gossip.publish(topic.clone(), message) {
        Ok(_) => { },
        Err(e) => {
            tracing::error!("Failed to publish message to topic {:?}: {:?}", topic, e);
        }
    }
}





