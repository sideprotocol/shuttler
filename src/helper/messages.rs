use std::time;
use std::time::SystemTime;

use frost_core::serde::{Serialize, Deserialize};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{ mdns, request_response};


use frost_secp256k1_tr as frost;


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGRequest {
    task_id: String,
    step: SigningSteps,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DKGResponse {
    
}

#[derive(NetworkBehaviour)]
pub struct SigningBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub dkg: request_response::cbor::Behaviour<DKGRequest, DKGResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SigningSteps {
    DkgInit,
    DkgRound1,
    DkgRound2,
    SignInit,
    SignRound1,
    SignRound2,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub step: SigningSteps,
    pub message: String,
    pub min_signers: u16,
    pub max_signers: u16,
}

impl Task {
    pub fn new(step: SigningSteps, message: String) -> Self {
    //     Self::new_with_pubkey(step, "".to_string(), message)
    // }
    // pub fn new_with_pubkey(step: SigningSteps, message: String) -> Self {
        Self {
            id: new_task_id(),
            step,
            message,
            min_signers: 0,
            max_signers: 0,
        }
    }    

    pub fn new_with_signers(step: SigningSteps, message: String, min_signers: u16, max_signers: u16) -> Self {
        Self {
            id: new_task_id(),
            step,
            message,
            min_signers,
            max_signers,
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
    // pub min_signers: u16,
    // pub max_signers: u16,
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
    // pub message: String,
    pub packet: T,
    pub timestamp: u64,
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
