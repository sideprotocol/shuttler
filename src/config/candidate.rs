use std::{cmp::Ordering, str::FromStr};

use frost_secp256k1_tr::Identifier;
use libp2p::PeerId;
use tracing::warn;

use cosmrs::crypto::PublicKey;

use crate::helper::{client_side, encoding::{identifier_to_peer_id, pubkey_to_identifier}, now};

#[derive(Debug)]
pub struct Candidate {
    last_sync_time: u64,
    host: String,
    identifiers: Vec<Identifier>,
    peers: Vec<PeerId>,
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
        }
    }

    pub async fn sync_from_validators(&mut self, ) {
        // hourly update
        if self.last_sync_time + 3600 > now() { 
            return 
        }
        
        let mut validators: Vec<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::Validator> = match client_side::get_latest_validators(&self.host).await {
            Ok(r) => r.into_inner().validators,
            Err(e) => {
                warn!("failed to sync valdiators: {:?}", e);
                return
            },
        };

        self.last_sync_time = now();

        // self.peers.clear();
        self.identifiers.clear();

        validators.sort_by(|a, b| {
            if b.voting_power - a.voting_power >= 0 {
                return Ordering::Greater;
            } else {
                return Ordering::Less;
            }
        });
        // println!("Top50: {:?}", validators);

        let candidate_num = std::cmp::min(validators.len(), 50);

        validators[0..candidate_num].iter().for_each(|v| {
            if let Some(k) = &v.pub_key {
                let pub_key = PublicKey::try_from(k).unwrap();
                let id = pubkey_to_identifier(&pub_key.to_bytes());
                let peer_id = identifier_to_peer_id(&id );
                if !self.peers.contains(&peer_id) {
                    self.peers.push(peer_id);
                }
                self.identifiers.push( id );
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