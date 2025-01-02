

use core::fmt;
use std::marker::PhantomData;
use std::{collections::BTreeMap, fmt::Debug};
use ed25519_compact::x25519;
use rand::thread_rng;
use tracing::{debug, error, info};
use serde::{Deserialize, Serialize};

use frost_adaptor_signature as frost;
use frost::{keys, Identifier, keys::dkg::round1};

use crate::apps::{DKGHander, Context, Status, SubscribeMessage, Task, TopicAppHandle};
use crate::helper::gossip::publish_topic_message;
use crate::helper::store::{MemStore, Store};
use crate::helper::{mem_store, now};
use crate::helper::cipher::{decrypt, encrypt};

pub type Round1Store = MemStore<String, BTreeMap<Identifier, round1::Package>>;
pub type Round2Store = MemStore<String, BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>>;

pub struct DKG<H: DKGHander> {
    db_round1: Round1Store,
    db_round2: Round2Store,
    _p: PhantomData<H>,
}

impl<H> DKG<H> where H: DKGHander{
    pub fn new() -> Self {
        Self {
            db_round1: MemStore::new(),
            db_round2: MemStore::new(),
            _p: PhantomData::default(),
        }
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
    pub payload: DKGPayload,
    pub nonce: u64,
    pub sender: Identifier,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DKGPayload {
    Round1((String, BTreeMap<Identifier, round1::Package>)),
    Round2((String, BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>))
}

impl<H> DKG<H> where H: DKGHander + TopicAppHandle {

    fn broadcast_dkg_packages(&self, ctx: &mut Context, payload: DKGPayload) {

        let raw = serde_json::to_vec(&payload).unwrap();
        let signature = ctx.node_key.sign(raw, None).to_vec();
        
        let msg = DKGMessage{ payload, nonce: now(), sender: ctx.identifier.clone(), signature };
        // debug!("Broadcasting: {:?}", response.);
        let bytes = serde_json::to_vec(&msg).expect("Failed to serialize DKG package");
        publish_topic_message(ctx, H::topic(), bytes);
    }

    pub fn generate(&mut self, ctx: &mut Context, input: &Task) {

        let mut rng = thread_rng();
        if let Ok((secret_packet, round1_package)) = frost::keys::dkg::part1(
            ctx.identifier.clone(),
            input.participants.len() as u16,
            input.threshold,
            &mut rng,
        ) {
            debug!("round1_secret_package: {:?}", input.id );
            mem_store::set_dkg_round1_secret_packet(input.id.to_string().as_str(), secret_packet);

            let mut round1_packages = BTreeMap::new();
            round1_packages.insert(ctx.identifier.clone(), round1_package);

            self.db_round1.save(&input.id, &round1_packages);

            self.received_round1_packages(ctx, &input.id, round1_packages.clone());

            self.broadcast_dkg_packages(ctx, DKGPayload::Round1((input.id.clone(), round1_packages)));
        } else {
            error!("error in DKG round 1: {:?}", input.id);
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

                self.received_round2_packages(ctx, &task_id, merged.clone());

                self.broadcast_dkg_packages(ctx, DKGPayload::Round2((task_id, merged)));
            }
            Err(e) => {
                return Err(DKGError(e.to_string()));
            }
        };
        Ok(())
    }

    pub fn on_message(&mut self, ctx: &mut Context, message: &SubscribeMessage) {
        if let Ok(m) =  H::message(message) {
            self.received_dkg_message(ctx, m);
        }
    }

    fn received_dkg_message(&mut self, ctx: &mut Context, message: DKGMessage) {

        match message.payload {
            DKGPayload::Round1((task_id,package)) => self.received_round1_packages(ctx, &task_id, package),
            DKGPayload::Round2((task_id,package)) => self.received_round2_packages(ctx, &task_id, package),
        }

    }

    fn received_round1_packages(&mut self, ctx: &mut Context, task_id: &String , packets: BTreeMap<Identifier, keys::dkg::round1::Package>) {

        // store round 1 packets
        let mut local = self.db_round1.get(task_id).map_or(BTreeMap::new(), |v|v);
        
        // merge packets with local
        local.extend(packets);
        self.db_round1.save(&task_id, &local);

        // let k = local.keys().map(|k| to_base64(&k.serialize()[..])).collect::<Vec<_>>();
        debug!("Received round1 packets: {} {:?}", &task_id, local.keys());

        let mut task = match ctx.task_store.get(&task_id) {
            Some(t) => t,
            None => return,
        };

        if task.participants.len() == local.len() {
            
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

    fn received_round2_packages(&mut self, ctx: &mut Context, task_id: &String, packets: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>) {

        // store round 1 packets
        let mut local = self.db_round2.get(task_id).unwrap_or(BTreeMap::new()); 
        packets.iter().for_each(|(k, v)| {
            match local.get_mut(k) {
                Some(lv) => lv.extend(v.clone()),
                None => {
                    local.insert(k.clone(), v.clone());
                },
            }
        });

        self.db_round2.save(&task_id, &local);

        debug!("Received round2 packets: {} {:?}", task_id, local.keys());

        let mut task = match ctx.task_store.get(&task_id) {
            Some(t) => t,
            None => return,
        };

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
                    H::on_completed(ctx, &mut task, priv_key, pub_key);
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

impl DKGMessage {
    pub fn sender(&self) -> String {
        hex::encode(&self.sender.serialize())
    }
}
