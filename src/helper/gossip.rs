
use frost_core::Identifier;
use frost_secp256k1_tr::Secp256K1Sha256;
use libp2p::{gossipsub::IdentTopic, Swarm};
use serde::{Deserialize, Serialize};

use crate::{apps::{signer::Signer, Context}, shuttler::ShuttlerBehaviour};

use super::{mem_store, now};
pub const HEART_BEAT_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SubscribeTopic {
    DKG,
    SIGNING,
    ALIVE,
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
    pub identifier: Identifier<Secp256K1Sha256>,
    pub last_seen: u64,
    pub task_ids: Vec<String>,
}

pub fn subscribe_gossip_topics(swarm: &mut Swarm<ShuttlerBehaviour>) {
    let topics = vec![
        SubscribeTopic::DKG,
        SubscribeTopic::SIGNING,
        SubscribeTopic::ALIVE,
    ];
    for topic in topics {
        swarm.behaviour_mut().gossip.subscribe(&topic.topic()).expect("Failed to subscribe TSS events");
    }
}

pub async fn sending_heart_beat(ctx: &mut Context, signer: &Signer) {

        let last_seen = now() + mem_store::ALIVE_WINDOW;
        let task_ids = signer.list_signing_tasks().iter().map(|a| a.id.clone()).collect::<Vec<_>>();
        let payload = HeartBeatPayload {
            identifier: signer.identifier().clone(),
            last_seen,
            task_ids,
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let signature = signer.identity_key.sign(bytes, None).to_vec();
        let alive = HeartBeatMessage { payload, signature };
        let message = serde_json::to_vec(&alive).unwrap();
        publish_message(ctx, SubscribeTopic::ALIVE, message);
        
        mem_store::update_alive_table(alive);
}

pub fn publish_message(ctx: &mut Context, topic: SubscribeTopic, message: Vec<u8>) {
    match ctx.swarm.behaviour_mut().gossip.publish(topic.topic(), message) {
        Ok(_) => { },
        Err(e) => {
            tracing::error!("Failed to publish message to topic {:?}: {:?}", topic, e);
        }
    }
}





