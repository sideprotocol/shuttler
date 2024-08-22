
use base64::engine::general_purpose;
use libp2p::{mdns, request_response, gossipsub, swarm::NetworkBehaviour};
use serde::{Deserialize, Serialize};

pub mod dkg;
pub mod sign;

#[derive(NetworkBehaviour)]
pub struct TSSBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub gossip: gossipsub::Behaviour,
    pub dkg: request_response::cbor::Behaviour<dkg::DKGRequest, dkg::DKGResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Round {
    Round1,
    Round2,
    Closed,
}

