
use core::task;
use std::collections::BTreeMap;
use cosmos_sdk_proto::side::btcbridge::{DkgRequest, DkgRequestStatus};
use ed25519_compact::{x25519, SecretKey};
use rand::thread_rng;
use tracing::{debug, error, info};
use libp2p::{request_response::{self, Message}, PeerId};
use serde::{de::value, Deserialize, Serialize};


use frost_secp256k1_tr::{self as frost, keys::dkg::{round1, round2}};
use frost::keys::dkg::round1::SecretPackage;
use frost::{keys, Identifier, Secp256K1Sha256};
use tracing_subscriber::fmt::format;

use frost_core::{keys::{PublicKeyPackage, KeyPackage}, Field};
use super::{Round, TSSBehaviour};
use crate::{app::{config::get_database_path, signer::Shuttler}, helper::{cipher::encrypt, store::{self, list_tasks}}};

use lazy_static::lazy_static;

lazy_static! {
    static ref DB: sled::Db = {
        let path = get_database_path();
        sled::open(path).unwrap()
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGTask {
    pub id: String,
    pub participants: Vec<String>,
    pub threshold: u16,
    pub round: Round,
    pub timestamp: i64,
}

impl DKGTask {
    pub fn from_request(request: &DkgRequest) -> Self {
        Self {
            id: format!("dkg-{}", request.id),
            participants: request.participants.iter().map(|p| {
                // let buf = hex::decode(p.consensus_address.clone()).expect("Invalid concensus address");
                // let id = frost_secp256k1_tr::Secp256K1ScalarField::deserialize(&buf[0..20].try_into().unwrap()).unwrap();
                // frost_core::Identifier::new(id).unwrap()
                p.consensus_address.clone()
            }).collect(), 
            threshold: request.threshold as u16,
            round: Round::Round1,
            timestamp: match request.expiration {
                Some(expiration) => expiration.seconds,
                None => 0,
            },
        }
    }
    
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGRequest {
    pub task_id: String,
    pub round: Round,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DKGResponse {
    Round1 {
        task_id: String,
        packets: BTreeMap<Identifier, keys::dkg::round1::Package>,
    },
    Round2 {
        task_id: String,
        // <sender, <receiver, package>>
        packets: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>,
    },
}

pub fn generate_round1_package(identifier: Identifier, task: &DKGTask) {

    // if !task.participants.contains(&identifier) {
    //     debug!("I am not a participant in DKG: {}", task.id);
    //     return;
    // }

    if store::has_dkg_preceeded(task.id.to_string().as_str()) {
        debug!("DKG has already preceeded: {}", task.id);
        return;
    };

    let mut rng = thread_rng();
    if let Ok((secret_packet, round1_package)) = frost::keys::dkg::part1(
        identifier,
        task.participants.len() as u16,
        task.threshold as u16,
        &mut rng,
    ) {
        debug!(
            "round1_secret_package: {:?}, {:?}",
            task.id, &round1_package
        );
        store::set_dkg_round1_secret_packet(task.id.to_string().as_str(), secret_packet);

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(identifier, round1_package);

        let value = serde_json::to_vec(&round1_packages).unwrap();
        match DB.insert(format!("dkg-{}-round1", task.id), value) {
            Ok(_) => {
                info!("DKG round 1 completed: {}", task.id);
            }
            Err(e) => {
                error!("error in DKG round 1: {:?}", e);
            }
        }
     } else {
        error!("error in DKG round 1: {:?}", task.id);
     }
}

pub fn generate_round2_packages(enc_key: &SecretKey, task: &DKGTask) {

    let task_id = task.id.clone();

    let secret_package = match store::get_dkg_round1_secret_packet(&task_id) {
        Some(secret_packet) => secret_packet,
        None => {
            error!("No secret packet found for DKG: {task_id}");
            return;
        }
    };

    let round1_packages = match store::get_dkg_round1_packets(&task_id) {
        Some(round1_packages) => round1_packages,
        None => {
            error!("No round1 packages found for DKG: {task_id}");
            return;
        }
    };

    if task.participants.len() as u16 != round1_packages.len() as u16 {
        debug!("Not all participants have submitted their round1 packages: {task_id}");
        return;
    }

    match frost::keys::dkg::part2(secret_package, &round1_packages) {
        Ok((round2_secret_package, round2_packages)) => {
            store::set_dkg_round2_secret_packet(&task_id, round2_secret_package);

            let mut output_packages = BTreeMap::new();
            for (receiver_identifier, round2_package) in round2_packages {
                let bz = receiver_identifier.serialize();
                let target = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
    
                let share_key = target.dh(&x25519::SecretKey::from_ed25519(enc_key).unwrap()).unwrap();
    
                let byte = round2_package.serialize().unwrap();
                let packet = encrypt(byte.as_slice(), share_key.as_slice().try_into().unwrap());
    
                output_packages.insert(receiver_identifier, packet);
            };

            let value = serde_json::to_vec(&output_packages).unwrap();

            match DB.insert(format!("dkg-{}-round2", &task_id), value) {
                Ok(_) => {
                    info!("DKG round 2 completed: {task_id}");
                }
                Err(e) => {
                    error!("error in DKG round 2: {:?}", e);
                }
            };
        }
        Err(e) => {
            error!("error in DKG round 2: {:?}", e);
        }
    };

}

pub fn collect_dkg_packages(peers: &Vec<PeerId>, behave: &mut TSSBehaviour) {
    let tasks = list_tasks();
    for t in tasks.iter() {

        debug!("Collecting dkg packages for DKG: {}, {:?}", t.id, peers);
        peers.iter().for_each(|p| {
            let request = DKGRequest {
                task_id: t.id.clone(),
                round: t.round.clone(),
            };
            let r =  behave.dkg.send_request(p, request); 
            debug!("Sent DKG Round 1 Request to {p}: {r}");
        })
    }
}

pub fn dkg_event_handler(behave: &mut TSSBehaviour, peer: &PeerId, enc_key: &SecretKey, message: Message<DKGRequest, DKGResponse>) {
    // handle dkg events
    debug!("Received DKG response from {peer}: {:?}", &message);
    match message {
        request_response::Message::Request { request_id, request, channel } => {
            debug!("Received DKG Request from {peer}: {request_id}");
            let response = match request { DKGRequest { task_id, round } => {
                    match round {
                        Round::Round1 => {
                            // send round 1 packets to requester
                            debug!("Received DKG Round 1 Request from {peer}: {request_id}");
                            // behave.dkg.send_response(channel, DKGResponse::Round1 { task_id, packets: BTreeMap::new() });
                            let packets = match DB.get(format!("dkg-{}-round1", task_id)) {
                                Ok(Some(packets)) => {
                                    match serde_json::from_slice(&packets) {
                                        Ok(packets) => packets,
                                        Err(e) => {
                                            error!("Failed to deserialize DKG Round 1 packets: {:?}", e);
                                            BTreeMap::new()
                                        }
                                    }
                                },
                                _ => {
                                    debug!("No DKG Round 1 packets found: {task_id}");
                                    BTreeMap::new()
                                },
                            };
                            DKGResponse::Round1 { task_id, packets }
                        }
                        Round::Round2 => {
                            // send round 2 packets to requester
                            debug!("Received DKG Round 2 Request from {peer}: {request_id}");
                            // behave.dkg.send_response(channel, DKGResponse::Round2 { task_id, packets: BTreeMap::new() });
                            let packets = match DB.get(format!("dkg-{}-round2", task_id)) {
                                Ok(Some(packets)) => {
                                    match serde_json::from_slice(&packets) {
                                        Ok(packets) => packets,
                                        Err(e) => {
                                            error!("Failed to deserialize DKG Round 2 packets: {:?}", e);
                                            BTreeMap::new()
                                        }
                                    }
                                },
                                _ => {
                                    debug!("No DKG Round 2 packets found: {task_id}");
                                    BTreeMap::new()
                                },
                            };
                            DKGResponse::Round2 { task_id, packets }
                        }
                    }
                }
            };
            match behave.dkg.send_response(channel, response) {
                Ok(_) => {
                    info!("Sent DKG Response to {peer}: {request_id}");
                }
                Err(e) => {
                    info!("Failed to send DKG Response to {peer}: {request_id} - {:?}", e);
                }
            };
        }

        request_response::Message::Response { request_id, response } => {
            info!("Received DKG Response from {peer}: {request_id}");
            match response {
                // collect round 1 packets
                DKGResponse::Round1 { task_id, packets } => {
                    let mut task = match store::get_task(&task_id) {
                        Some(task) => task,
                        None => {
                            error!("No task found for DKG: {}", task_id);
                            return;
                        }
                    };
                    // store round 1 packets
                    let mut local = match DB.get(format!("dkg-{}-round1", task_id)) {
                        Ok(Some(local)) => {
                            match serde_json::from_slice(&local) {
                                Ok(local) => local,
                                Err(e) => {
                                    error!("Failed to deserialize local DKG Round 1 packets: {:?}", e);
                                    BTreeMap::new()
                                }
                            }
                        },
                        _ => {
                            debug!("No local DKG Round 1 packets found: {task_id}");
                            BTreeMap::new()
                        },
                    };

                    // merge packets with local
                    local.extend(packets);

                    match DB.insert(format!("dkg-{}-round1", task_id), serde_json::to_vec(&local).unwrap()) {
                        Ok(_) => {
                            debug!("Stored DKG Round 1 packets: {task_id}");
                        }
                        Err(e) => {
                            error!("Failed to store DKG Round 1 packets: {task_id} - {:?}", e);
                        }
                    }

                    if task.participants.len() as u16 == local.len() as u16 {
                        info!("Received round1 packets from all participants: {task_id}");
                        task.round = Round::Round2;
                        store::save_task(&task);
                        generate_round2_packages(enc_key, &task);
                        return;
                    }
                }
                // collect round 2 packets
                DKGResponse::Round2 { task_id, packets } => {
                    // store round 2 packets
                    match DB.insert(format!("dkg-{}-round2", task_id), serde_json::to_vec(&packets).unwrap()) {
                        Ok(_) => {
                            debug!("Stored DKG Round 2 packets: {task_id}");
                        }
                        Err(e) => {
                            error!("Failed to store DKG Round 2 packets: {task_id} - {:?}", e);
                        }
                    }
                }
            }

        }
    }
}
