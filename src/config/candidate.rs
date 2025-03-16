use std::str::FromStr;

use frost_adaptor_signature::Identifier;
use libp2p::PeerId;
use tracing::{debug, warn};

use crate::helper::{client_side, encoding::{identifier_to_peer_id, pubkey_to_identifier}, now};

#[derive(Debug)]
pub struct Candidate {
    last_sync_time: u64,
    host: String,
    identifiers: Vec<Identifier>,
    peers: Vec<PeerId>,
    bootstraps: Vec<String>,
}

impl Candidate {
    pub fn new(host: String, bootstraps: &Vec<String>) -> Self {
        let mut peers = vec![];
        bootstraps.iter().for_each(|p| 
            if let Some(pid_str) = p.split("/").last() {
                if let Ok(pid) = PeerId::from_str(pid_str) {
                    peers.push(pid);
                }
            }
        );
        Self {
            last_sync_time: 0,
            host,
            identifiers: vec![],
            peers,
            bootstraps: bootstraps.clone(),
        }
    }

    pub fn has_bootstrap_nodes(&self) -> bool {
        self.bootstraps.len() > 0
    }

    pub async fn sync_from_validators(&mut self, ) {
        // hourly update
        if self.last_sync_time + 3600 > now() { 
            return 
        }
        
        let validators: Vec<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::Validator> = match client_side::get_latest_validators(&self.host).await {
            Ok(r) => r.into_inner().validators,
            Err(e) => {
                warn!("failed to sync valdiators: {:?}", e);
                return
            },
        };

        self.last_sync_time = now();

        self.peers.clear();
        self.identifiers.clear();

        validators.iter().for_each(|v| {
            if let Some(k) = &v.pub_key {
                if let Ok(pk ) = k.to_msg::<cosmos_sdk_proto::cosmos::crypto::ed25519::PubKey>() {
                    let id = pubkey_to_identifier(&pk.key);
                    debug!("added {:?} in white list", id);
                    self.peers.push(identifier_to_peer_id(&id ));
                    self.identifiers.push( id );
                }
            }
        });
    }

    pub fn identifiers(&self) -> &Vec<Identifier> {
        &self.identifiers
    }

    pub fn peers(&self) -> &Vec<PeerId> {
        &self.peers
    }
}
