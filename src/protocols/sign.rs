use std::{collections::BTreeMap, marker::PhantomData};

use chrono::serde::ts_nanoseconds::deserialize;
use frost_adaptor_signature::{keys::Tweak, round1, round2, Group, Identifier, Secp256K1Group, SigningPackage};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
pub use tracing::error;
use usize as Index;
use crate::{apps::Context, helper::{bitcoin::convert_tweak, encoding, gossip::{publish_message, SubscribeTopic}, mem_store, store::{MemStore, Store}}};

use ed25519_compact::{PublicKey, Signature};
pub type Round1Store = MemStore<String, BTreeMap<Index,BTreeMap<Identifier,round1::SigningCommitments>>>;
pub type Round2Store = MemStore<String, BTreeMap<Index,BTreeMap<Identifier,round2::SignatureShare>>>;
pub type NonceStore = MemStore<String, BTreeMap<Index, round1::SigningNonces>>;

pub struct StandardSigner<H>{
    db_task: MemStore<String, SignTask>,
    db_round1: Round1Store,
    db_round2: Round2Store,
    db_nonce: NonceStore,
    _p: PhantomData<H>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignMesage {
    pub task_id: String,
    pub package: SignPackage,
    pub sender: Identifier,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignPackage {
    Round1(BTreeMap<Index,BTreeMap<Identifier,round1::SigningCommitments>>),
    Round2(BTreeMap<Index,BTreeMap<Identifier,round2::SignatureShare>>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    WIP,
    RESET,
    CLOSE,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    key: String, 
    message: Vec<u8>,
    signature: Option<frost_adaptor_signature::Signature>,
    adaptor_signature: Option<frost_adaptor_signature::AdaptorSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignTask {
    id: String,
    adaptor_point: String,
    status: Status,
    inputs: Vec<Input>,
    participants: Vec<Identifier>,
}

impl<H> StandardSigner<H> {
    pub fn clean_stores(&mut self, task_id: &String) {
        self.db_nonce.remove(task_id);
        self.db_round1.remove(task_id);
        self.db_round2.remove(task_id);
    }
    
    pub fn generate_commitments(&mut self, ctx: &mut Context, task: &SignTask) {

        if task.status == Status::CLOSE {
            return
        }

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        //let mut commitments = signer.get_signing_commitments(&task.id);

        task.inputs.iter().enumerate().for_each(|(index, input)| {
            let mut rng = thread_rng();
            let key = match ctx.keystore.get(&input.key) {
                Some(k) => k,
                None => return,
            };
            let (nonce, commitment) = round1::commit(key.priv_key.signing_share(), &mut rng);
            nonces.insert(index, nonce);
            let mut input_commit = BTreeMap::new();
            input_commit.insert(ctx.identifier.clone(), commitment);
            commitments.insert(index, input_commit.clone());
        });

        // Save nonces to local storage.
        self.db_nonce.save(&task.id, &nonces);

        // Publish commitments to other pariticipants
        let mut msg =  SignMesage {
            task_id: task.id.clone(),
            package: SignPackage::Round1(commitments),
            sender: ctx.identifier.clone(),
            signature: vec![], 
        };
        broadcast_signing_packages(ctx, &mut msg);

        self.received_sign_message(ctx, msg);
    }

    pub fn received_sign_message(&mut self, ctx: &mut Context, msg: SignMesage) {

        // Ensure the message is not forged.
        match PublicKey::from_slice(&msg.sender.serialize()) {
            Ok(public_key) => {
                let raw = serde_json::to_vec(&msg.package).unwrap();
                let sig = Signature::from_slice(&msg.signature).unwrap();
                if public_key.verify(&raw, &sig).is_err() {
                    debug!("Reject, untrusted package from {:?}", msg.sender);
                    return;
                }
            }
            Err(_) => return
        }

        // Ensure the message is from the participants
        // if !mem_store::is_peer_trusted_peer(ctx, &msg.sender) {
        //     return
        // }

        let task_id = msg.task_id.clone();
        let first = 0;

        match msg.package {
            SignPackage::Round1(commitments) => {

                let mut remote_commitments = self.db_round1.get(&task_id).unwrap_or(BTreeMap::new());
                // return if msg has received.
                if let Some(exists) = remote_commitments.get(&first) {
                    if exists.contains_key(&msg.sender) {
                        return
                    }
                }

                // merge received package
                commitments.iter().for_each(|(index, incoming)| {
                    match remote_commitments.get_mut(index) {
                        Some(existing) => {
                            existing.extend(incoming);
                        },
                        None => {
                            remote_commitments.insert(*index, incoming.clone());
                        },
                    }
                });

                self.db_round1.save(&task_id, &remote_commitments);

                self.try_generate_signature_shares(ctx, &task_id);

            },
            SignPackage::Round2(sig_shares) => {

                let mut remote_sig_shares = self.db_round2.get(&task_id).unwrap_or(BTreeMap::new());
                // return if msg has received.
                if let Some(exists) = remote_sig_shares.get(&first) {
                    if exists.contains_key(&msg.sender) {
                        return
                    }
                }

                // Merge all signature shares
                sig_shares.iter().for_each(|(index, incoming)| {
                    match remote_sig_shares.get_mut(index) {
                        Some(existing) => {
                            existing.extend(incoming);
                        },
                        None => {
                            remote_sig_shares.insert(*index, incoming.clone());
                        }
                    }
                });

                self.db_round2.save(&task_id, &remote_sig_shares);

                self.try_aggregate_signature_shares(ctx, &task_id);
                
            }
        }
    }

    pub fn try_generate_signature_shares(&mut self, ctx: &mut Context, task_id: &String) {

        // Ensure the task exists locally to prevent forged signature tasks. 
        let mut task = match self.db_task.get(task_id) {
            Some(t) => t,
            None => return,
        };

        let stored_nonces = self.db_nonce.get(&task.id).unwrap_or_default();
        if stored_nonces.len() == 0 {
            return;
        }
        let stored_remote_commitments = self.db_round1.get(&task.id).unwrap_or_default();

        let mut broadcast_packages = BTreeMap::new();
        for (index, input) in task.inputs.iter().enumerate() {
            
            // filter packets from unknown parties
            if let Some(keypair) = ctx.keystore.get(&input.key) {

                let mut signing_commitments = match stored_remote_commitments.get(&index) {
                    Some(e) => e.clone(),
                    None => return
                };

                sanitize( &mut signing_commitments, &keypair.pub_key.verifying_shares().keys().map(|k| k).collect::<Vec<_>>());

                let received = signing_commitments.len();
                if received < keypair.priv_key.min_signers().clone() as usize {
                    return
                }
    
                // Only check the first one, because all inputs are in the same package
                if index == 0 {
                    let participants = keypair.pub_key.verifying_shares().keys().collect::<Vec<_>>();
                    let alive = mem_store::count_task_participants(&task_id);
                
                    debug!("Commitments {} {}/[{},{}]", &task.id[..6], received, alive.len(), participants.len());

                    if !(received == participants.len() || received == alive.len()) {
                        return
                    }
                    task.participants = alive;
                    self.db_task.save(&task.id, &task);
                }
                
                let signing_package = SigningPackage::new(
                    signing_commitments, 
                    &input.message,
                    );

                let signer_nonces = match stored_nonces.get(&index) {
                    Some(d) => d,
                    None => {
                        debug!("not found local nonce for input {index}");
                        return
                    },
                };

                let signature_shares = if &task.adaptor_point.len() > &0usize {
                    // adatpor signature
                    let b = hex::decode(&task.adaptor_point).unwrap();
                    let adaptor_point = match <Secp256K1Group as Group>::deserialize(&b[..].try_into().unwrap()) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("adaptor point is invalid: {}", e);
                            return;
                        },
                    };
                    match round2::sign_with_adaptor_point(
                        &signing_package, signer_nonces, &keypair.priv_key, &adaptor_point,
                    ) {
                        Ok(shares) => shares,
                        Err(e) => {
                            error!("Error: {:?}", e);
                            return;
                        }
                    }
                } else {
                    // regular signature
                    let tweek  = convert_tweak(&keypair.tweak);
                    match round2::sign_with_tweak(
                        &signing_package, signer_nonces, &keypair.priv_key, tweek
                    ) {
                        Ok(shares) => shares,
                        Err(e) => {
                            error!("Error: {:?}", e);
                            return;
                        }
                    }
                };
                
                let mut my_share = BTreeMap::new();
                my_share.insert(ctx.identifier.clone(), signature_shares);
                
                // broadcast my share
                broadcast_packages.insert(index.clone(), my_share.clone());
            
            };
        };

        if broadcast_packages.len() == 0 {
            return;
        }

        let mut msg = SignMesage {
            task_id: task.id.clone(),
            package: SignPackage::Round2(broadcast_packages),
            sender: ctx.identifier.clone(),
            signature: vec![],
        };

        broadcast_signing_packages(ctx, &mut msg);

        self.received_sign_message(ctx, msg);

    }

    pub fn try_aggregate_signature_shares(&mut self, ctx: &mut Context, task_id: &String) {

        // Ensure the task exists locally to prevent forged signature tasks. 
        let mut task = match self.db_task.get(task_id) {
            Some(t) => t,
            None => return,
        };

        let stored_remote_commitments = self.db_round1.get(&task.id).unwrap_or_default();
        let stored_remote_signature_shares = self.db_round2.get(&task.id).unwrap_or_default();
        
        let mut verifies = vec![];
        for (index, input) in task.inputs.iter_mut().enumerate() {

            let keypair = match ctx.keystore.get(&input.key) {
                Some(keypair) => keypair,
                None => {
                    error!("Failed to get keypair for address: {}", input.key);
                    return;
                }
            };

            let mut signature_shares = match stored_remote_signature_shares.get(&index) {
                Some(e) => e.clone(),
                None => return
            };

            let mut signing_commitments = match stored_remote_commitments.get(&index) {
                Some(e) => e.clone(),
                None => return
            };
            let threshold = keypair.priv_key.min_signers().clone() as usize;

            if task.participants.len() >= threshold {
                signing_commitments.retain(|k, _| {task.participants.contains(k)});
            }

            if signature_shares.len() < threshold || signature_shares.len() < signing_commitments.len() {
                return
            }

            if index == 0 {
                debug!("Signature share {} {}/{}", &task_id[..6], signature_shares.len(), signing_commitments.len() )
            }

            signature_shares.retain(|k, _| {signing_commitments.contains_key(k)});
            
            let signing_package = SigningPackage::new(
                signing_commitments,
                &input.message
            );

            if task.adaptor_point.len() > 0 {

                let adaptor_point = match encoding::hex_to_adaptor_point(&task.adaptor_point) {
                    Ok(p) => p,
                    Err(_e) => return,
                };

                match frost_adaptor_signature::aggregate_with_adaptor_point(&signing_package, &signature_shares, &keypair.pub_key, &adaptor_point) {
                    Ok(frost_signature) => {
                        match frost_signature.verify_signature(signing_package.message(), &keypair.pub_key.verifying_key(), &adaptor_point) {
                            Ok(_) => {
                                verifies.push(true);
                                input.adaptor_signature = Some(frost_signature);
                            },
                            Err(e) => {
                                error!( "{}:{} is invalid: {e}", &task.id[..6], index );
                                return
                            }
                        }
                    },
                    Err(e) => {
                        error!("Signature aggregation error: {:?} {:?}", &task.id[..6], e);
                        return
                    }
                }

            } else {

                let tweek  = convert_tweak(&keypair.tweak);

                match frost_adaptor_signature::aggregate_with_tweak(&signing_package, &signature_shares, &keypair.pub_key, tweek) { 
                    Ok(frost_signature) => {
                        match keypair.pub_key.tweak(tweek).verifying_key().verify(signing_package.message(), &frost_signature) {
                            Ok(_) => {
                                verifies.push(true);
                                input.signature = Some(frost_signature);
                            },
                            Err(e) => {
                                error!( "{}:{} is invalid: {e}", &task.id[..6], index );
                                return
                            }
                        }
                    }
                    Err(e) => {
                        error!("Signature aggregation error: {:?} {:?}", &task.id[..6], e);
                        return
                    }
                };
            }
        };

        if verifies.len() ==0 {
            return
        }

        let output  = verifies.iter().enumerate()
                            .map(|(i, v)| format!("{i}:{}", if *v {"✔"} else {"✘"}))
                            .collect::<Vec<_>>().join(" ");
        info!("Verify {}: {}", &task.id[..6], output );

        // let psbt_bytes = psbt.serialize();
        // let psbt_base64 = to_base64(&psbt_bytes);
        // task.psbt = psbt_base64;
        task.status = Status::CLOSE;
        self.db_task.save(&task.id, &task);

    }


}

pub fn broadcast_signing_packages(ctx: &mut Context, message: &mut SignMesage) {
    let raw = serde_json::to_vec(&message.package).unwrap();
    let signaure = ctx.node_key.sign(raw, None).to_vec();
    message.signature = signaure;

    // tracing::debug!("Broadcasting: {:?}", message);
    let message = serde_json::to_vec(&message).expect("Failed to serialize Sign package");
    publish_message(ctx, SubscribeTopic::SIGNING, message);
}

pub fn sanitize<T>(storages: &mut BTreeMap<Identifier, T>, keys: &Vec<&Identifier>) {
    if keys.len() > 0 {
        storages.retain(|k, _| { keys.contains(&k)});
    }
}