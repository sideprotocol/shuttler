
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::{service_client::ServiceClient as TendermintServiceClient, GetLatestBlockRequest};
use frost_core::{serde::{Deserialize, Serialize}, Identifier};
use frost_secp256k1_tr::Secp256K1Sha256;
use libp2p::{gossipsub::IdentTopic, Swarm};

use crate::{app::signer::Signer, protocols::{dkg::{self, prepare_response_for_task}, sign::SignMesage, TSSBehaviour}};

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
    pub identifier: Identifier<Secp256K1Sha256>,
    pub last_seen: u64,
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

    tracing::debug!("Broadcasting: {:?}", message);
    let message = serde_json::to_vec(&message).expect("Failed to serialize Sign package");
    publish_message(swarm, SubscribeTopic::SIGNING, message);
}

pub async fn sending_heart_beat(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer) {
    let host = signer.config().side_chain.grpc.clone();
    let mut base_client = match TendermintServiceClient::connect(host).await {
        Ok(c) => c,
        Err(_) => return,
    };
    if let Ok(res) = base_client.get_latest_block(GetLatestBlockRequest{}).await {
        let response = res.get_ref();
        let blocktime = response
                .block.as_ref().unwrap()
                .header.as_ref().unwrap()
                .time.as_ref().unwrap();
        
        // let mut last = mem_store::LastSendingTime.lock().unwrap();
        // sending alive message 
        let alive = HeartBeatMessage {
            identifier: signer.identifier().clone(),
            last_seen: blocktime.seconds as u64
        };
        let message = serde_json::to_vec(&alive).unwrap();
        publish_message(swarm, SubscribeTopic::ALIVE, message);
    };
}

fn publish_message(swarm: &mut Swarm<TSSBehaviour>, topic: SubscribeTopic, message: Vec<u8>) {
    match swarm.behaviour_mut().gossip.publish(topic.topic(), message) {
        Ok(_) => { },
        Err(e) => {
            tracing::error!("Failed to publish message to topic {:?}: {:?}", topic, e);
        }
    }
}





