use std::collections::BTreeMap;

use frost_adaptor_signature::{keys::Tweak, round1::{self, Nonce, SigningNonces}, round2::{self, SignatureShare}, Field, Identifier, Secp256K1ScalarField, SigningPackage};
use libp2p::gossipsub::IdentTopic;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tendermint::abci::Event;
use tracing::{debug, info};
pub use tracing::error;
use usize as Index;
use crate::{apps::{Context, FrostSignature, SignMode, Status, SubscribeMessage, Task}, config::VaultKeypair, 
    helper::{
        bitcoin::convert_tweak, encoding::{self, hex_to_projective_point}, 
        gossip::publish_topic_message, 
        store::Store
}};

use ed25519_compact::{PublicKey, Signature};

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

pub trait SignAdaptor {
    fn new_task(&self, events: &Vec<Event>) -> Option<Task>;
    fn on_complete(&self, ctx: &mut Context, task: &mut Task) -> anyhow::Result<()>;
}

#[derive(Clone)]
pub struct StandardSigner<H: SignAdaptor> {
    name: String,
    handler: H,
}

impl<H> StandardSigner<H> where H: SignAdaptor{

    pub fn new(name: impl Into<String>, handler: H) -> Self {
        Self {name: name.into(), handler}
    }

    pub fn topic(&self) -> IdentTopic {
        IdentTopic::new(&self.name)
    }

    // pub fn hander(&self) -> &H {
    //     &self.handler
    // }

    pub fn execute(&self, ctx: &mut Context, events: &Vec<Event>) {
        if let Some(task) = self.handler.new_task(events) {
            if ctx.task_store.exists(&task.id) { return }
            ctx.task_store.save(&task.id, &task);
            self.generate_commitments(ctx, &task);
        }
    }
    
    pub fn generate_commitments(&self, ctx: &mut Context, task: &Task) {

        if task.status == Status::SignComplete {
            return
        }

        debug!("Start a new signing task: {}", task.id);

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        //let mut commitments = signer.get_signing_commitments(&task.id);

        task.sign_inputs.iter().for_each(|(index, input)| {
            let mut rng = thread_rng();
            let key = match ctx.keystore.get(&input.key) {
                Some(k) => k,
                None => return,
            };

            let (nonce, commitment) = round1::commit(key.priv_key.signing_share(), &mut rng);
            nonces.insert(*index, nonce);
            let mut input_commit = BTreeMap::new();
            input_commit.insert(ctx.identifier.clone(), commitment);
            commitments.insert(*index, input_commit.clone());
        });

        println!("nonnce {:?}", nonces);
        // Save nonces to local storage.
        ctx.nonce_store.save(&task.id, &nonces);

        // Publish commitments to other pariticipants
        let mut msg =  SignMesage {
            task_id: task.id.clone(),
            package: SignPackage::Round1(commitments),
            sender: ctx.identifier.clone(),
            signature: vec![], 
        };

        self.broadcast_signing_packages(ctx, &mut msg);

        self.received_sign_message(ctx, msg);
    }


    pub fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()> {
        if message.topic.to_string() == self.name {
            let m = serde_json::from_slice(&message.data)?;
            self.received_sign_message(ctx, m);
        }
        // if let Ok(m) =  H::message(message) {
        //     self.received_dkg_message(ctx, m);
        // }
        return Ok(())
    }

    fn received_sign_message(&self, ctx: &mut Context, msg: SignMesage) {

        tracing:: debug!("Received: {:?}", msg);
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

                let mut remote_commitments = ctx.commitment_store.get(&task_id).unwrap_or(BTreeMap::new());
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

                ctx.commitment_store.save(&task_id, &remote_commitments);

                self.try_generate_signature_shares(ctx, &task_id);

            },
            SignPackage::Round2(sig_shares) => {

                let mut remote_sig_shares = ctx.signature_store.get(&task_id).unwrap_or(BTreeMap::new());
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

                ctx.signature_store.save(&task_id, &remote_sig_shares);

                self.try_aggregate_signature_shares(ctx, &task_id);
                
            }
        }
    }

    fn try_generate_signature_shares(&self, ctx: &mut Context, task_id: &String) {

        // Ensure the task exists locally to prevent forged signature tasks. 
        let task = match ctx.task_store.get(task_id) {
            Some(t) => t,
            None => return,
        };

        let stored_nonces = ctx.nonce_store.get(&task.id).unwrap_or_default();
        if stored_nonces.len() == 0 {
            return;
        }
        let stored_remote_commitments = ctx.commitment_store.get(&task.id).unwrap_or_default();

        let mut broadcast_packages = BTreeMap::new();
        for (index, input) in task.sign_inputs.iter() {
            
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
                if *index == 0 {
                    let participants = &input.participants;
                
                    debug!("Commitments {} {}/{}", &task.id[..6], received, participants.len());

                    if received != participants.len() {
                        return
                    }
                }
                
                let signing_package = SigningPackage::new(
                    signing_commitments, 
                    &input.message,
                    );

                let signer_nonces = match &input.mode {
                    SignMode::SignWithGroupcommitment(g) => { 
                        let nonce = match ctx.keystore.get(g) {
                            Some(t) => t,
                            None => return,
                        };
                
                        let hiding = Nonce::from_scalar(nonce.priv_key.signing_share().to_scalar());
                        let binding = Nonce::from_scalar(Secp256K1ScalarField::zero());
                
                        &SigningNonces::from_nonces(hiding, binding)
                    }, 
                    _ => {
                        match stored_nonces.get(&index) {
                            Some(d) => d,
                            None => {
                                debug!("not found local nonce for input {index}");
                                return;
                            },
                        }
                    }};

                let signature_shares = match sign(&input.mode, &keypair, &signing_package, signer_nonces, ) {
                    Ok(s) => s,
                    Err(_e) => return,
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

        self.broadcast_signing_packages(ctx, &mut msg);

        self.received_sign_message(ctx, msg);

    }

    fn try_aggregate_signature_shares(&self, ctx: &mut Context, task_id: &String) {

        // Ensure the task exists locally to prevent forged signature tasks. 
        let mut task = match ctx.task_store.get(task_id) {
            Some(t) => t,
            None => return,
        };

        let stored_remote_commitments = ctx.commitment_store.get(&task.id).unwrap_or_default();
        let stored_remote_signature_shares = ctx.signature_store.get(&task.id).unwrap_or_default();
        
        let mut verifies = vec![];
        for (index, input) in task.sign_inputs.iter_mut() {

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

            if input.participants.len() >= threshold {
                signing_commitments.retain(|k, _| {input.participants.contains(k)});
            }

            if signature_shares.len() < threshold || signature_shares.len() < signing_commitments.len() {
                return
            }

            if *index == 0 {
                debug!("Signature share {} {}/{}", &task_id[..6], signature_shares.len(), signing_commitments.len() )
            }

            signature_shares.retain(|k, _| {signing_commitments.contains_key(k)});
            
            let signing_package = SigningPackage::new(
                signing_commitments,
                &input.message
            );

            match aggregate(&signing_package, &signature_shares, &keypair, &input.mode) {
                Ok(s) => {
                    verifies.push(true);
                    input.signature = Some(s);
                },
                Err(e) => {
                    error!("aggregate error: {}", e);
                    return
                }
            };
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
        task.status = Status::SignComplete;
        ctx.task_store.save(&task.id, &task);
        
        if let Err(e) = self.handler.on_complete(ctx, &mut task) {
            error!("signing error: {:?}", e);
        }

    }

    fn broadcast_signing_packages(&self, ctx: &mut Context, message: &mut SignMesage) {
        let raw = serde_json::to_vec(&message.package).unwrap();
        let signaure = ctx.node_key.sign(raw, None).to_vec();
        message.signature = signaure;
    
        tracing::debug!("Broadcasting: {:?}", message);
        let message = serde_json::to_vec(&message).expect("Failed to serialize Sign package");
        publish_topic_message(ctx, self.topic(), message);
    }

}


fn sign(mode: &SignMode, keypair: &VaultKeypair, signing_package: &SigningPackage, signer_nonces: &SigningNonces) -> anyhow::Result<SignatureShare>  {
    match mode {
        SignMode::Sign => {
            Ok(round2::sign(signing_package, signer_nonces, &keypair.priv_key)?)
        },
        SignMode::SignWithTweak => {
            let tweek  = convert_tweak(&keypair.tweak);
            Ok(round2::sign_with_tweak(
                signing_package, signer_nonces, &keypair.priv_key, tweek
            )?)
        },
        SignMode::SignWithGroupcommitment(group) => {
            let group_commitment = hex_to_projective_point(group)?;
            Ok(round2::sign_with_dkg_nonce(signing_package, signer_nonces, &keypair.priv_key, &group_commitment)?)
        },
        SignMode::SignWithAdaptorPoint(point) => {
            // adatpor signature
            let adaptor_point = hex_to_projective_point(point)?;
            Ok(round2::sign_with_adaptor_point(
                signing_package, signer_nonces, &keypair.priv_key, &adaptor_point,
            )?)
        },
    }
}

fn aggregate(signing_package: &SigningPackage, signature_shares: &BTreeMap<Identifier, SignatureShare>, keypair: &VaultKeypair, mode: &SignMode) -> anyhow::Result<FrostSignature>  {

    match mode {
        SignMode::SignWithTweak => {
            let tweek  = convert_tweak(&keypair.tweak);
            let frost_signature = frost_adaptor_signature::aggregate_with_tweak(&signing_package, signature_shares, &keypair.pub_key, tweek)?;

            Ok(keypair.pub_key.clone().tweak(tweek)
                            .verifying_key()
                            .verify(signing_package.message(), &frost_signature)
                            .map(|_| FrostSignature::Standard(frost_signature))?)
        },
        SignMode::SignWithGroupcommitment(gc) => {

            let group_commitment = hex_to_projective_point(gc)?; 
            let frost_signature = frost_adaptor_signature::aggregate_with_group_commitment(&signing_package, signature_shares, &keypair.pub_key, &group_commitment)?;

            Ok(keypair.pub_key.clone().verifying_key().verify(signing_package.message(), &frost_signature).map(|_| FrostSignature::Standard(frost_signature))?)
        },
        SignMode::SignWithAdaptorPoint(..) => {
            let frost_signature = frost_adaptor_signature::aggregate(&signing_package, signature_shares, &keypair.pub_key)?;
            Ok(keypair.pub_key.clone().verifying_key().verify(signing_package.message(), &frost_signature)
            .map(|_| FrostSignature::Adaptor(frost_adaptor_signature::AdaptorSignature(frost_signature)))?)

        }
        _ => {

            let frost_signature = frost_adaptor_signature::aggregate(&signing_package, signature_shares, &keypair.pub_key)?;
            Ok(keypair.pub_key.clone().verifying_key().verify(signing_package.message(), &frost_signature).map(|_| FrostSignature::Standard(frost_signature))?)

        }
    }

}

fn sanitize<T>(storages: &mut BTreeMap<Identifier, T>, keys: &Vec<&Identifier>) {
    if keys.len() > 0 {
        storages.retain(|k, _| { keys.contains(&k)});
    }
}