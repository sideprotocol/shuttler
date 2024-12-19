

use core::fmt;
use std::marker::PhantomData;
use std::{collections::BTreeMap, fmt::Debug};
use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};
use ed25519_compact::x25519;
use rand::thread_rng;
use tracing::{debug, error, info};
use serde::{Deserialize, Serialize};

use frost_adaptor_signature as frost;
use frost::{keys, Identifier, keys::dkg::round1};

use crate::apps::{Context, SubscribeMessage, TopicAppHandle};
use crate::helper::gossip::{publish_message, publish_topic_message, SubscribeTopic};
use crate::helper::store::{MemStore, Store};
use crate::helper::{mem_store, now};
use crate::helper::cipher::{decrypt, encrypt};

pub type Round1Store = MemStore<String, BTreeMap<Identifier, round1::Package>>;
pub type Round2Store = MemStore<String, BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Round {
    Round1,
    Round2,
    Closed,
}

pub trait KeyHander {
    fn on_completed(ctx: &mut Context, priv_key: KeyPackage, pubkey: PublicKeyPackage);
}

pub struct DKG<H: KeyHander> {
    db_task: MemStore<String, DKGTask>,
    db_round1: Round1Store,
    db_round2: Round2Store,
    _p: PhantomData<H>,
}

impl<H> DKG<H> where H: KeyHander{
    pub fn new() -> Self {
        Self {
            db_task: MemStore::new(),
            db_round1: MemStore::new(),
            db_round2: MemStore::new(),
            _p: PhantomData::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGTask {
    pub id: String,
    pub participants: Vec<String>,
    pub threshold: u16,
    pub round: Round,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGMessage {
    pub payload: DKGPayload,
    pub nonce: u64,
    pub sender: Identifier,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGPayload {
    pub task_id: String,
    pub round1_packages: BTreeMap<Identifier, round1::Package>,
    pub round2_packages: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>,
}

impl<H> DKG<H> where H: KeyHander + TopicAppHandle {

    fn broadcast_dkg_packages(&self, ctx: &mut Context, task_id: &str, round1_packages: BTreeMap<Identifier, round1::Package>, round2_packages: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>) {
        let response = self.prepare_response_for_task(ctx, task_id, round1_packages, round2_packages );
        // debug!("Broadcasting: {:?}", response.);
        let message = serde_json::to_vec(&response).expect("Failed to serialize DKG package");
        publish_topic_message(ctx, H::topic(), message);
    }

    pub fn generate(&mut self, ctx: &mut Context, task: &mut DKGTask) {

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

            self.db_round1.save(&task.id, &round1_packages);

            self.received_round1_packages(ctx, task, round1_packages.clone());

            self.broadcast_dkg_packages(ctx, &task.id, round1_packages, BTreeMap::new());
        } else {
            error!("error in DKG round 1: {:?}", task.id);
        }
    }

    fn generate_round2_packages(&mut self, ctx: &mut Context, task: &mut DKGTask, round1_packages: BTreeMap<Identifier, round1::Package>) -> Result<(), DKGError> {

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

                self.db_round2.save(&task.id, &merged);

                self.received_round2_packages(ctx, task, merged.clone());

                self.broadcast_dkg_packages(ctx, &task.id, BTreeMap::new(), merged);
            }
            Err(e) => {
                return Err(DKGError(e.to_string()));
            }
        };
        Ok(())
    }

    fn prepare_response_for_task(&self, ctx: &Context, task_id: &str, round1_packages: BTreeMap<Identifier, round1::Package>, round2_packages: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>) -> DKGMessage {
        
        let payload = DKGPayload {
            task_id: task_id.to_string(),
            round1_packages,
            round2_packages,
        };
        
        let raw = serde_json::to_vec(&payload).unwrap();
        let signature = ctx.node_key.sign(raw, None).to_vec();
        
        DKGMessage{ payload, nonce: now(), sender: ctx.identifier.clone(), signature }
    }

    pub fn on_message(&mut self, ctx: &mut Context, message: &SubscribeMessage) {
        if let Ok(m) =  H::message(message) {
            self.received_dkg_message(ctx, m);
        }
    }

    fn received_dkg_message(&mut self, ctx: &mut Context, message: DKGMessage) {
        let task_id = message.payload.task_id.clone();
        let mut task = match self.db_task.get(&task_id) {
            Some(task) => task,
            None => {
                return;
            }
        };

        let addr = sha256::digest(&message.sender.serialize())[0..40].to_uppercase();
        if !task.participants.contains(&addr) {
            debug!("Invalid DKG participant {:?}, {:?}", message.sender, addr);
            return;
        }

        if task.round == Round::Round1 {
            self.received_round1_packages(ctx, &mut task, message.payload.round1_packages)
        } else if task.round == Round::Round2 {
            self.received_round2_packages(ctx, &mut task, message.payload.round2_packages)
        }
    }

    fn received_round1_packages(&mut self, ctx: &mut Context, task: &mut DKGTask, packets: BTreeMap<Identifier, keys::dkg::round1::Package>) {

        // store round 1 packets
        let mut local = self.db_round1.get(&task.id).map_or(BTreeMap::new(), |v|v);
        
        // merge packets with local
        local.extend(packets);
        self.db_round1.save(&task.id, &local);

        // let k = local.keys().map(|k| to_base64(&k.serialize()[..])).collect::<Vec<_>>();
        debug!("Received round1 packets: {} {:?}", task.id, local.keys());

        // if DB.insert(format!("dkg-{}-round1", task.id), serde_json::to_vec(&local).unwrap()).is_err() {
        //     error!("Failed to store DKG Round 1 packets: {} ", task.id);
        // }

        if task.participants.len() == local.len() {
            
            info!("Received round1 packets from all participants: {}", task.id);
            match self.generate_round2_packages(ctx, task, local) {
                Ok(_) => {
                    task.round = Round::Round2;
                    self.db_task.save(&task.id, &task);
                }
                Err(e) => {
                    task.round = Round::Closed;
                    self.db_task.save(&task.id, &task);
                    error!("Failed to generate round2 packages: {} - {:?}", task.id, e);
                }
            }
            return;
        }
    }

    fn received_round2_packages(&mut self, ctx: &mut Context, task: &mut DKGTask, packets: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>) {

        if task.round == Round::Closed {
            debug!("DKG is already closed: {}", task.id);
            return;
        }

        // store round 1 packets
        let mut local = self.db_round2.get(&task.id).unwrap_or(BTreeMap::new()); 
        packets.iter().for_each(|(k, v)| {
            match local.get_mut(k) {
                Some(lv) => lv.extend(v.clone()),
                None => {
                    local.insert(k.clone(), v.clone());
                },
            }
        });

        self.db_round2.save(&task.id, &local);

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

            let mut round1_packages = self.db_round1.get(&task.id).unwrap_or(BTreeMap::new());
            // let mut round1_packages_cloned = round1_packages.clone();
            // remove self
            // frost does not need its own package to compute the threshold key
            round1_packages.remove(&ctx.identifier); 

            match frost::keys::dkg::part3(&round2_secret_package, &round1_packages, &round2_packages ) {
                Ok((key, pubkey)) => { 
                    // generate vault addresses and save its key share
                    H::on_completed(ctx, key, pubkey);
                },
                Err(e) => {
                    error!("Failed to compute threshold key: {} {:?}", &task.id, e);
                    self.db_task.remove(&task.id);
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
