
use libp2p::{gossipsub, kad::store::MemoryStore, mdns, swarm::NetworkBehaviour};
use serde::{Deserialize, Serialize};

pub mod dkg;
pub mod sign;

#[derive(NetworkBehaviour)]
pub struct TSSBehaviour {
    pub kad: libp2p::kad::Behaviour<MemoryStore>,
    pub identify: libp2p::identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub gossip: gossipsub::Behaviour,
    // pub dkg: request_response::cbor::Behaviour<dkg::DKGRequest, dkg::DKGResponse>,
    // pub signer: request_response::cbor::Behaviour<sign::SignRequest, sign::SignResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Round {
    Initial,
    Round1,
    Round2,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignTaskStatus {
    Initial,
    Pending,
    Completed,
    Failure,
}

