
use frost_core::serde::{Serialize, Deserialize};
use libp2p::{gossipsub::IdentTopic, Swarm};

use crate::{app::signer::Signer, protocols::{dkg::{self, prepare_response_for_task}, sign::SignMesage, TSSBehaviour}};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SubscribeTopic {
    DKG,
    SIGNING,
}

impl SubscribeTopic {
    pub fn topic(&self) -> IdentTopic {
        IdentTopic::new(format!("{:?}", self))
    }
}

pub fn subscribe_gossip_topics(swarm: &mut Swarm<TSSBehaviour>) {
    let topics = vec![
        SubscribeTopic::DKG,
        SubscribeTopic::SIGNING,
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

    // debug!("Broadcasting: {:?}", package);
    let message = serde_json::to_vec(&message).expect("Failed to serialize Sign package");
    publish_message(swarm, SubscribeTopic::SIGNING, message);
}

fn publish_message(swarm: &mut Swarm<TSSBehaviour>, topic: SubscribeTopic, message: Vec<u8>) {
    match swarm.behaviour_mut().gossip.publish(topic.topic(), message) {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("Failed to publish message to topic {:?}: {:?}", topic, e);
        }
    }
}





