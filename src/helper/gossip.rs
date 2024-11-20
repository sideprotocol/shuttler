
use frost_core::{serde::{Deserialize, Serialize}, Identifier};
use frost_secp256k1_tr::Secp256K1Sha256;
use libp2p::{gossipsub::IdentTopic, Swarm};

use crate::{app::signer::Signer, protocols::{dkg::{self, prepare_response_for_task}, sign::SignMesage, TSSBehaviour}};

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

pub fn subscribe_gossip_topics(swarm: &mut Swarm<TSSBehaviour>) {
    let topics = vec![
        SubscribeTopic::DKG,
        SubscribeTopic::SIGNING,
        SubscribeTopic::ALIVE,
    ];
    for topic in topics {
        swarm.behaviour_mut().gossip.subscribe(&topic.topic()).expect("Failed to subscribe TSS events");
    }
}

pub fn publish_dkg_packages(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer, task: &dkg::DKGTask) {
    let response = prepare_response_for_task(signer, task.id.clone());
    // debug!("Broadcasting: {:?}", response.);
    let message = serde_json::to_vec(&response).expect("Failed to serialize DKG package");
    publish_message(swarm, SubscribeTopic::DKG, message);
}

pub fn publish_signing_package(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer, message: &mut SignMesage) {
    let raw = serde_json::to_vec(&message.package).unwrap();
    let signaure = signer.identity_key.sign(raw, None).to_vec();
    message.signature = signaure;

    // tracing::debug!("Broadcasting: {:?}", message);
    let message = serde_json::to_vec(&message).expect("Failed to serialize Sign package");
    publish_message(swarm, SubscribeTopic::SIGNING, message);
}

pub async fn sending_heart_beat(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer) {

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
        publish_message(swarm, SubscribeTopic::ALIVE, message);
        
        mem_store::update_alive_table(alive);
}

fn publish_message(swarm: &mut Swarm<TSSBehaviour>, topic: SubscribeTopic, message: Vec<u8>) {
    match swarm.behaviour_mut().gossip.publish(topic.topic(), message) {
        Ok(_) => { },
        Err(e) => {
            tracing::error!("Failed to publish message to topic {:?}: {:?}", topic, e);
        }
    }
}





