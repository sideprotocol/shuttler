

use core::fmt;
use std::{collections::BTreeMap, fmt::Debug};
use cosmos_sdk_proto::side::btcbridge::DkgRequest;
use ed25519_compact::x25519;
use rand::thread_rng;
use tracing::{debug, error, info};
use serde::{Deserialize, Serialize};

use frost_adaptor_signature as frost;
use frost::{keys, Identifier, keys::dkg::round1::Package};

use super::{broadcast_dkg_packages, Round};
use crate::apps::Context;
use crate::helper::{mem_store, now};
use crate::apps::signer::Signer;
use crate::helper::cipher::{decrypt, encrypt};


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DKGType {
    GroupKey,
    Nonce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGTask {
    pub id: String,
    pub use_case: DKGType,
    pub participants: Vec<String>,
    pub threshold: u16,
    pub round: Round,
    pub timestamp: i64,
    pub address_num: u16,
    pub dkg_vaults: Vec<String>,
    pub submitted: bool,
}

impl DKGTask {
    pub fn from_request(request: &DkgRequest) -> Self {
        Self {
            use_case: DKGType::GroupKey,
            id: format!("dkg-{}", request.id),
            participants: request.participants.iter().map(|p| {
                p.consensus_address.clone()
            }).collect(), 
            threshold: request.threshold as u16,
            round: Round::Round1,
            timestamp: match request.expiration {
                Some(expiration) => expiration.seconds,
                None => 0,
            },
            address_num: request.vault_types.len() as u16,
            dkg_vaults: vec![],
            submitted: false,
        }
    }
    
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGRequest {
    pub task_id: String,
    pub round: Round,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct  DKGResponse {
    pub payload: DKGPayload,
    pub nonce: u64,
    pub sender: Identifier,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGPayload {
    pub task_id: String,
    pub round1_packages: BTreeMap<Identifier, keys::dkg::round1::Package>,
    pub round2_packages: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>,
}

pub fn generate_round1_package(ctx: &mut Context, signer: &Signer, task: &mut DKGTask) {

    if signer.has_task_preceeded(&task.id) {
        debug!("DKG has already preceeded: {}", task.id);
        return;
    };

    let mut rng = thread_rng();
    if let Ok((secret_packet, round1_package)) = frost::keys::dkg::part1(
        ctx.identifier.clone(),
        task.participants.len() as u16,
        task.threshold as u16,
        &mut rng,
    ) {
        debug!("round1_secret_package: {:?}", task.id );
        mem_store::set_dkg_round1_secret_packet(task.id.to_string().as_str(), secret_packet);

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(ctx.identifier.clone(), round1_package);

        signer.save_dkg_round1_package(&task.id, &round1_packages);

        received_round1_packages(ctx, task, round1_packages, signer);

        broadcast_dkg_packages(ctx, signer, &task.id);
     } else {
        error!("error in DKG round 1: {:?}", task.id);
     }
}

pub fn generate_round2_packages(ctx: &mut Context, signer: &Signer, task: &mut DKGTask, round1_packages: BTreeMap<Identifier, Package>) -> Result<(), DKGError> {

    let task_id = task.id.clone();

    let secret_package = match mem_store::get_dkg_round1_secret_packet(&task_id) {
        Some(secret_packet) => secret_packet,
        None => {
            return Err(DKGError(format!("No secret packet found for DKG: {}", task_id)));
        }
    };

    if task.participants.len() as u16 != round1_packages.len() as u16 {
        return Err(DKGError(format!("Have not received enough packages: {}", task_id)));
    }

    let mut cloned = round1_packages.clone();
    cloned.remove(&ctx.identifier);

    match frost::keys::dkg::part2(secret_package, &cloned) {
        Ok((round2_secret_package, round2_packages)) => {
            mem_store::set_dkg_round2_secret_packet(&task_id, round2_secret_package);

            // convert it to <receiver, Vec<u8>>, then only the receiver can decrypt it.
            let mut output_packages = BTreeMap::new();
            for (receiver_identifier, round2_package) in round2_packages {
                let bz = receiver_identifier.serialize();
                let target = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
    
                let share_key = target.dh(&x25519::SecretKey::from_ed25519(&ctx.node_key).unwrap()).unwrap();
    
                let byte = round2_package.serialize().unwrap();
                let packet = encrypt(byte.as_slice(), share_key.as_slice().try_into().unwrap());
    
                output_packages.insert(receiver_identifier, packet);
            };

            // convert it to <sender, <receiver, Vec<u8>>
            let mut merged = BTreeMap::new();
            merged.insert(ctx.identifier.clone(), output_packages);

            signer.save_dkg_round2_package(&task.id, &merged);

            received_round2_packages(ctx, task, merged, &signer);

            broadcast_dkg_packages(ctx, signer, &task.id);
        }
        Err(e) => {
            return Err(DKGError(e.to_string()));
        }
    };
    Ok(())
}

pub fn sync_dkg_task_packages(ctx: &mut Context, signer: &Signer) {
    let tasks = signer.list_dkg_tasks();
    for t in tasks.iter() {
        if t.timestamp as u64 >= now() {
            // publish its packages to other peers
            // broadcast_dkg_packages(ctx, signer, &t.id);
        } else {
            // remove the task
            signer.remove_dkg_task(&t.id);
        }
    }
}

pub fn prepare_response_for_task(ctx: &Context, signer: &Signer, task_id: &str) -> DKGResponse {
    let round1_packages = match signer.get_dkg_round1_package(&task_id) {
        Some(packets) => packets,
        _ => {
            debug!("No DKG Round 1 packets found: {task_id}");
            BTreeMap::new()
        },
    };
    let round2_packages = match signer.get_dkg_round2_package(&task_id) {
        Some(packets) => packets,
        _ => {
            debug!("No DKG Round 2 packets found: {task_id}");
            BTreeMap::new()
        },
    };

    
    let payload = DKGPayload {
        task_id: task_id.to_string(),
        round1_packages,
        round2_packages,
    };
    
    let raw = serde_json::to_vec(&payload).unwrap();
    let signature = ctx.node_key.sign(raw, None).to_vec();
    
    DKGResponse{ payload, nonce: now(), sender: ctx.identifier.clone(), signature }
}

pub fn received_dkg_response(ctx: &mut Context, response: DKGResponse, signer: &Signer) {
    let task_id = response.payload.task_id.clone();
    let mut task = match signer.get_dkg_task(&task_id) {
        Some(task) => task,
        None => {
            return;
        }
    };

    let addr = sha256::digest(&response.sender.serialize())[0..40].to_uppercase();
    if !task.participants.contains(&addr) {
        debug!("Invalid DKG participant {:?}, {:?}", response.sender, addr);
        return;
    }

    if task.round == Round::Round1 {
        received_round1_packages(ctx, &mut task, response.payload.round1_packages, signer)
    } else if task.round == Round::Round2 {
        received_round2_packages(ctx, &mut task, response.payload.round2_packages, signer)
    }
}

pub fn received_round1_packages(ctx: &mut Context, task: &mut DKGTask, packets: BTreeMap<Identifier, keys::dkg::round1::Package>, signer: &Signer) {

    // store round 1 packets
    let mut local = signer.get_dkg_round1_package(&task.id).map_or(BTreeMap::new(), |v|v);
    
    // merge packets with local
    local.extend(packets);
    signer.save_dkg_round1_package(&task.id, &local);

    // let k = local.keys().map(|k| to_base64(&k.serialize()[..])).collect::<Vec<_>>();
    debug!("Received round1 packets: {} {:?}", task.id, local.keys());

    // if DB.insert(format!("dkg-{}-round1", task.id), serde_json::to_vec(&local).unwrap()).is_err() {
    //     error!("Failed to store DKG Round 1 packets: {} ", task.id);
    // }

    if task.participants.len() == local.len() {
        
        info!("Received round1 packets from all participants: {}", task.id);
        match generate_round2_packages(ctx, &signer, task, local) {
            Ok(_) => {
                task.round = Round::Round2;
                signer.save_dkg_task(&task);
            }
            Err(e) => {
                task.round = Round::Closed;
                signer.save_dkg_task(&task);
                error!("Failed to generate round2 packages: {} - {:?}", task.id, e);
            }
        }
        return;
    }
}

pub fn received_round2_packages(ctx: &mut Context, task: &mut DKGTask, packets: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>, signer: &Signer) {

    if task.round == Round::Closed {
        debug!("DKG is already closed: {}", task.id);
        return;
    }

    // store round 1 packets
    let mut local = signer.get_dkg_round2_package(&task.id).map_or(BTreeMap::new(), |v| v); 
    local.extend(packets);
    signer.save_dkg_round2_package(&task.id, &local);

     debug!("Received round2 packets: {} {:?}", task.id, local.keys());

    if task.participants.len() == local.len() {
        // info!("Received round2 packets from all participants: {}", task.id);

        let mut round2_packages = BTreeMap::new();
        local.iter().for_each(|(sender, packages)| {
            packages.iter().for_each(|(receiver, packet)| {
                if receiver == &ctx.identifier {
                    let packet = packet.clone();
                    
                    let bz = sender.serialize();
                    let source = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
                    let share_key = source.dh(&x25519::SecretKey::from_ed25519(&ctx.node_key).unwrap()).unwrap();

                    let packet = decrypt(packet.as_slice(), share_key.as_slice().try_into().unwrap());
                    let received_round2_package = frost::keys::dkg::round2::Package::deserialize(&packet).unwrap();
                    // debug!("Received {} round2 package from: {:?}", task.id, sender.clone());
                    round2_packages.insert(sender.clone(), received_round2_package);
                }
            })
        });

        info!("Received round2 packages from all participants: {}", task.id);

        // compute the threshold key
        let round2_secret_package = match mem_store::get_dkg_round2_secret_packet(&task.id) {
            Some(secret_package) => secret_package,
            None => {
                error!("No secret packet found for DKG: {}", task.id);
                return;
            }
        };

        let mut round1_packages = signer.get_dkg_round1_package(&task.id).map_or(BTreeMap::new(), |v| v);
        // let mut round1_packages_cloned = round1_packages.clone();
        // remove self
        // frost does not need its own package to compute the threshold key
        round1_packages.remove(&ctx.identifier); 

        match frost::keys::dkg::part3(
            &round2_secret_package,
            &round1_packages,
            &round2_packages,
        ) {
            Ok((key, pubkey)) => { 
                // generate vault addresses and save its key share
                let address_with_tweak = signer.generate_vault_addresses(pubkey, key, task.address_num);
                task.round = Round::Closed;
                task.dkg_vaults = address_with_tweak;
                signer.save_dkg_task(&task);
            },
            Err(e) => {
                error!("Failed to compute threshold key: {} {:?}", &task.id, e);
                signer.remove_dkg_task(&task.id);
            }
        };        
    }
}

#[derive(Debug, Clone)]
pub struct DKGError(String);

impl fmt::Display for DKGError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Use `self.number` to refer to each positional data point.
        write!(f, "dkg error: {}", self.0 )
    }
}
