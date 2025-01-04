

use core::fmt;
use std::{collections::BTreeMap, fmt::Debug};
use ed25519_compact::x25519;
use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};
use libp2p::gossipsub::IdentTopic;
use rand::thread_rng;
use serde::de::DeserializeOwned;
use tracing::{debug, error, info};
use serde::{Deserialize, Serialize};

use frost_adaptor_signature as frost;
use frost::{Identifier, keys::dkg::round1};

use crate::apps::{Context, Status, SubscribeMessage, Task};
use crate::helper::gossip::publish_topic_message;
use crate::helper::store::{MemStore, Store};
use crate::helper::mem_store;
use crate::helper::cipher::{decrypt, encrypt};

pub type Round1Store = MemStore<String, BTreeMap<Identifier, round1::Package>>;
pub type Round2Store = MemStore<String, BTreeMap<Identifier, Vec<u8>>>;
pub type DKGHandleFn = dyn Fn(&mut Context, &mut Task, &KeyPackage, &PublicKeyPackage);

pub struct DKG {
    name: String,
    db_round1: Round1Store,
    db_round2: Round2Store,
    on_complete: Box<DKGHandleFn>,
}

impl DKG {
    pub fn new(name: impl Into<String>, on_complete: Box<DKGHandleFn>) -> Self {
        Self {
            name: name.into(),
            db_round1: MemStore::new(),
            db_round2: MemStore::new(),
            on_complete,
        }
    }

    pub fn topic(&self) -> IdentTopic {
        IdentTopic::new(&self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGInput {
    pub id: String,
    pub participants: Vec<String>,
    pub threshold: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGMessage {
    pub sender: Identifier,
    pub payload: DKGPayload,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DKGPayload {
    Round1(Data<round1::Package>),
    Round2(Data<BTreeMap<Identifier, Vec<u8>>>)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
pub struct Data<T> where T: Serialize + DeserializeOwned{
    pub task_id: String,
    pub sender: Identifier,
    pub data: T,
}

impl DKG {

    fn broadcast_dkg_packages(&self, ctx: &mut Context, payload: DKGPayload) {

        let raw = serde_json::to_vec(&payload).unwrap();
        let signature = ctx.node_key.sign(raw, None).to_vec();
        
        let msg = DKGMessage{ sender: ctx.identifier, payload, signature };
        debug!("Broadcasting: {:?}", msg);
        let bytes = serde_json::to_vec(&msg).expect("Failed to serialize DKG package");
        publish_topic_message(ctx, IdentTopic::new(&self.name), bytes);
    }

    pub fn generate(&mut self, ctx: &mut Context, task: &Task) {

        let mut rng = thread_rng();
        if let Ok((secret_packet, round1_package)) = frost::keys::dkg::part1(
            ctx.identifier.clone(),
            task.dkg_input.participants.len() as u16,
            task.dkg_input.threshold,
            &mut rng,
        ) {
            debug!("round1_secret_package: {:?}", task.id );
            mem_store::set_dkg_round1_secret_packet(task.id.to_string().as_str(), secret_packet);

            let mut round1_packages = BTreeMap::new();
            round1_packages.insert(ctx.identifier.clone(), round1_package.clone());

            self.db_round1.save(&task.id, &round1_packages);

            let data = Data{task_id: task.id.clone(), sender: ctx.identifier.clone(), data: round1_package};
            self.received_round1_packages(ctx, data.clone());

            self.broadcast_dkg_packages(ctx, DKGPayload::Round1(data));
        } else {
            error!("error in DKG round 1: {:?}", task.id);
        }
    }

    fn generate_round2_packages(&mut self, ctx: &mut Context, task: &Task, round1_packages: BTreeMap<Identifier, round1::Package>) -> Result<(), DKGError> {

        let task_id = task.id.clone();

        let secret_package = match mem_store::get_dkg_round1_secret_packet(&task_id) {
            Some(secret_packet) => secret_packet,
            None => {
                return Err(DKGError(format!("No secret packet found for DKG: {}", task_id)));
            }
        };

        if task.dkg_input.participants.len() as u16 != round1_packages.len() as u16 {
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
                // let mut merged = BTreeMap::new();
                // merged.insert(ctx.identifier.clone(), output_packages.clone());

                // self.db_round2.save(&task.id, &merged);

                let data  = Data{task_id, sender: ctx.identifier.clone(), data: output_packages};
                self.received_round2_packages(ctx, data.clone());

                self.broadcast_dkg_packages(ctx, DKGPayload::Round2(data));
            }
            Err(e) => {
                return Err(DKGError(e.to_string()));
            }
        };
        Ok(())
    }

    pub fn on_message(&mut self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()> {
        if message.topic.to_string() == self.name {
            let m = serde_json::from_slice(&message.data)?;
            self.received_dkg_message(ctx, m);
        }
        // if let Ok(m) =  H::message(message) {
        //     self.received_dkg_message(ctx, m);
        // }
        return Ok(())
    }

    fn received_dkg_message(&mut self, ctx: &mut Context, message: DKGMessage) {

        // Ensure the message is not forged.
        match ed25519_compact::PublicKey::from_slice(&message.sender.serialize()) {
            Ok(public_key) => {
                let raw = serde_json::to_vec(&message.payload).unwrap();
                let sig = ed25519_compact::Signature::from_slice(&message.signature).unwrap();
                if public_key.verify(&raw, &sig).is_err() {
                    debug!("Reject, untrusted package from {:?}", message.sender);
                    return;
                }
            }
            Err(_) => return
        }

        match message.payload {
            DKGPayload::Round1(data) => self.received_round1_packages(ctx, data),
            DKGPayload::Round2(data) => self.received_round2_packages(ctx, data),
        }

    }

    fn received_round1_packages(&mut self, ctx: &mut Context, packets: Data<round1::Package>) {

        let task_id = &packets.task_id;
        // store round 1 packets
        let mut local = self.db_round1.get(task_id).map_or(BTreeMap::new(), |v|v);
        
        // merge packets with local
        local.insert(packets.sender, packets.data);
        self.db_round1.save(&task_id, &local);

        // let k = local.keys().map(|k| to_base64(&k.serialize()[..])).collect::<Vec<_>>();
        debug!("Received round1 packets: {} {:?}", &task_id, local.keys());

        let mut task = match ctx.task_store.get(&task_id) {
            Some(t) => t,
            None => return,
        };

        local.retain(|id, _| task.dkg_input.participants.contains(id));

        if task.dkg_input.participants.len() == local.len() {
            
            info!("Received round1 packets from all participants: {}", task_id);
            match self.generate_round2_packages(ctx,  &task, local) {
                Ok(_) => {
                    task.status = Status::DkgRound2;
                    ctx.task_store.save(&task.id, &task);
                }
                Err(e) => {
                    task.status = Status::DkgComplete;
                    ctx.task_store.save(&task.id, &task);
                    error!("Failed to generate round2 packages: {} - {:?}", task.id, e);
                }
            }
            return;
        }
    }

    fn received_round2_packages(&mut self, ctx: &mut Context, packets: Data<BTreeMap<Identifier, Vec<u8>>>) {

        let task_id = &packets.task_id;
        // store round 1 packets

        let data = match packets.data.get(&ctx.identifier) {
            Some(t) => t.clone(),
            None => return,
        };
        let mut local = self.db_round2.get(task_id).unwrap_or(BTreeMap::new()); 
        local.insert(packets.sender, data);
        self.db_round2.save(&task_id, &local);

        debug!("Received round2 packets: {} {:?}", task_id, local.keys());

        let mut task = match ctx.task_store.get(&task_id) {
            Some(t) => t,
            None => return,
        };

        local.retain(|id, _| task.dkg_input.participants.contains(id));

        if task.dkg_input.participants.len() - 1 == local.len() {
            // info!("Received round2 packets from all participants: {}", task.id);

            let mut round2_packages = BTreeMap::new();
            local.iter().for_each(|(sender, packet)| {
                
                let bz = sender.serialize();
                let source = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
                let share_key = source.dh(&x25519::SecretKey::from_ed25519(&ctx.node_key).unwrap()).unwrap();

                let packet = decrypt(packet.as_slice(), share_key.as_slice().try_into().unwrap());
                let received_round2_package = frost::keys::dkg::round2::Package::deserialize(&packet).unwrap();
                // debug!("Received {} round2 package from: {:?}", task.id, sender.clone());
                round2_packages.insert(sender.clone(), received_round2_package);

            });

            info!("Received round2 packages from all participants: {}", task_id);

            // compute the threshold key
            let round2_secret_package = match mem_store::get_dkg_round2_secret_packet(task_id) {
                Some(secret_package) => secret_package,
                None => {
                    error!("No secret packet found for DKG: {}", task_id);
                    return;
                }
            };

            let mut round1_packages = self.db_round1.get(task_id).unwrap_or(BTreeMap::new());
            // let mut round1_packages_cloned = round1_packages.clone();
            // remove self
            // frost does not need its own package to compute the threshold key
            round1_packages.remove(&ctx.identifier); 

            match frost::keys::dkg::part3(&round2_secret_package, &round1_packages, &round2_packages ) {
                Ok((priv_key, pub_key)) => { 
                    (self.on_complete)(ctx, &mut task, &priv_key, &pub_key);
                    // self.on_com(ctx, &mut task, priv_key, pub_key);
                },
                Err(e) => {
                    error!("Failed to compute threshold key: {} {:?}", task_id, e);
                }
            };        
        }
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

// impl DKGMessage {
//     pub fn sender(&self) -> String {
//         hex::encode(&self.sender.serialize())
//     }
// }
