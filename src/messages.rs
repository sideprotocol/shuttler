use std::time;
use std::time::SystemTime;

use frost_core::serde::{Serialize, Deserialize};
use libp2p::{gossipsub::IdentTopic, swarm::NetworkBehaviour};
use libp2p::{gossipsub, mdns};


use frost_secp256k1 as frost;

#[derive(NetworkBehaviour)]
pub struct SigningBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningSteps {
    DkgInit,
    DkgRound1,
    DkgRound2,
    SignInit,
    SignRound1,
    SignRound2,
}

impl SigningSteps {
    pub fn topic(&self) -> IdentTopic {
        IdentTopic::new(format!("{:?}", self))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub step: SigningSteps,
    pub pubkey: String,
    pub message: String,
}

impl Task {
    pub fn new(step: SigningSteps, message: String) -> Self {
        Self::new_with_pubkey(step, "".to_string(), message)
    }
    pub fn new_with_pubkey(step: SigningSteps, pubkey: String, message: String) -> Self {
        Self {
            id: new_task_id(),
            step,
            pubkey,
            message,
        }
    }    
}

pub fn new_task_id() -> String {
    SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGRoundMessage<T> {
    pub task_id: String,
    pub from_party_id: frost::Identifier,
    pub to_party_id: Option<frost::Identifier>,
    pub packet: T,
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct DKGRound2Message {
//     pub task_id: String,
//     pub sender_party_id: frost::Identifier,
//     pub receiver_party_id: frost::Identifier,
//     pub packet: frost::keys::dkg::round2::Package,
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessage<T> {
    pub task_id: String,
    pub party_id: frost::Identifier,
    pub address: String,
    pub message: String,
    pub packet: T,
}

#[test]
fn test_steps() {
    let steps = vec![
        SigningSteps::DkgInit,
        SigningSteps::DkgRound1,
        SigningSteps::DkgRound2,
        SigningSteps::SignInit,
        SigningSteps::SignRound1,
        SigningSteps::SignRound2,
    ];
    for i in steps {
        let topic = format!("sign_round {:?}", i);
        println!("{}", topic);
    }
}
