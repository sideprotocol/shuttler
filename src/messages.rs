use bitcoin::{ Address, PublicKey, secp256k1::{Message, Secp256k1}};

use frost_core::serde::{Serialize, Deserialize};
use futures::StreamExt;
use libp2p::{gossipsub::IdentTopic, swarm::{NetworkBehaviour, SwarmEvent}};
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
        IdentTopic::new(format!("sign_round {:?}", self))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub step: SigningSteps,
    pub message: String,
}

impl Task {
    pub fn new(step: SigningSteps, message: String) -> Self {
        Self {
            step,
            message,
        }
    }
    
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGRoundMessage<T> {
    pub party_id: frost::Identifier,
    pub packet: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DKGRound2Message {
    pub sender_party_id: frost::Identifier,
    pub receiver_party_id: frost::Identifier,
    pub packet: frost::keys::dkg::round2::Package,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMessage<T> {
    pub party_id: frost::Identifier,
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
