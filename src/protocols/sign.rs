use std::{collections::BTreeMap, marker::PhantomData};

use frost_adaptor_signature::{keys::Tweak, round1::{self, SigningNonces}, round2::{self, SignatureShare}, Identifier, SigningPackage};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
pub use tracing::error;
use usize as Index;
use crate::{apps::{Context, DKGHander, SignMode, SigningHandler, Status, Task}, config::VaultKeypair, 
    helper::{
        bitcoin::convert_tweak, encoding::{self, hex_to_projective_point}, 
        gossip::{publish_message, SubscribeTopic}, mem_store, 
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

pub struct StandardSigner<H: SigningHandler>{
    _p: PhantomData<H>,
}

impl<H> StandardSigner<H> where H: SigningHandler {
    
    pub fn generate_commitments(ctx: &mut Context, task: &Task) {

        if task.status == Status::SignComplete {
            return
        }

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        //let mut commitments = signer.get_signing_commitments(&task.id);

        task.sign_inputs.iter().enumerate().for_each(|(index, input)| {
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
        ctx.nonce_store.save(&task.id, &nonces);

        // Publish commitments to other pariticipants
        let mut msg =  SignMesage {
            task_id: task.id.clone(),
            package: SignPackage::Round1(commitments),
            sender: ctx.identifier.clone(),
            signature: vec![], 
        };
        broadcast_signing_packages(ctx, &mut msg);

        Self::received_sign_message(ctx, msg);
    }

    fn received_sign_message(ctx: &mut Context, msg: SignMesage) {

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

                Self::try_generate_signature_shares(ctx, &task_id);

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

                Self::try_aggregate_signature_shares(ctx, &task_id);
                
            }
        }
    }

    fn try_generate_signature_shares(ctx: &mut Context, task_id: &String) {

        // Ensure the task exists locally to prevent forged signature tasks. 
        let mut task = match ctx.task_store.get(task_id) {
            Some(t) => t,
            None => return,
        };

        let stored_nonces = ctx.nonce_store.get(&task.id).unwrap_or_default();
        if stored_nonces.len() == 0 {
            return;
        }
        let stored_remote_commitments = ctx.commitment_store.get(&task.id).unwrap_or_default();

        let mut broadcast_packages = BTreeMap::new();
        for (index, input) in task.sign_inputs.iter().enumerate() {
            
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
                    ctx.task_store.save(&task.id, &task);
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

                let signature_shares = match partial_sign(&task, &keypair, &signing_package, &signer_nonces, ) {
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

        broadcast_signing_packages(ctx, &mut msg);

        Self::received_sign_message(ctx, msg);

    }

    fn try_aggregate_signature_shares(ctx: &mut Context, task_id: &String) {

        // Ensure the task exists locally to prevent forged signature tasks. 
        let mut task = match ctx.task_store.get(task_id) {
            Some(t) => t,
            None => return,
        };

        let stored_remote_commitments = ctx.commitment_store.get(&task.id).unwrap_or_default();
        let stored_remote_signature_shares = ctx.signature_store.get(&task.id).unwrap_or_default();
        
        let mut verifies = vec![];
        for (index, input) in task.sign_inputs.iter_mut().enumerate() {

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

            match aggregate(&signing_package, &signature_shares, &keypair, &task.sign_mode, &task.sign_adaptor_point) {
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
        H::on_completed(ctx, &mut task);

    }

}


fn partial_sign(task: &Task, keypair: &VaultKeypair, signing_package: &SigningPackage, signer_nonces: &SigningNonces) -> Result<SignatureShare, frost_adaptor_signature::Error>  {
    match task.sign_mode {
        SignMode::Sign => {
            round2::sign(signing_package, signer_nonces, &keypair.priv_key)
        },
        SignMode::SignWithTweak => {
            let tweek  = convert_tweak(&keypair.tweak);
            round2::sign_with_tweak(
                signing_package, signer_nonces, &keypair.priv_key, tweek
            )
        },
        SignMode::SignWithGroupcommitment => {
            let group_commitment = hex_to_projective_point(&task.sign_group_commitment).unwrap();
            round2::sign_with_dkg_nonce(signing_package, signer_nonces, &keypair.priv_key, &group_commitment)
        },
        SignMode::SignWithAdaptorPoint => {
            // adatpor signature
            let adaptor_point = match hex_to_projective_point(&task.sign_adaptor_point) {
                Ok(p) => p,
                Err(_) => panic!("Invalid adaptor point"),
            };
            round2::sign_with_adaptor_point(
                signing_package, signer_nonces, &keypair.priv_key, &adaptor_point,
            )
        },
    }
}

fn aggregate(signing_package: &SigningPackage, signature_shares: &BTreeMap<Identifier, SignatureShare>, keypair: &VaultKeypair, mode: &SignMode, adaptor_point: &String) -> Result<frost_adaptor_signature::Signature, frost_adaptor_signature::Error>  {

    match mode {
        SignMode::SignWithTweak => {
            let tweek  = convert_tweak(&keypair.tweak);
            let frost_signature = frost_adaptor_signature::aggregate_with_tweak(&signing_package, signature_shares, &keypair.pub_key, tweek)?;

            keypair.pub_key.clone().tweak(tweek)
                            .verifying_key()
                            .verify(signing_package.message(), &frost_signature)
                            .map(|_| frost_signature)
        },
        SignMode::SignWithGroupcommitment => {

            let group_commitment = encoding::hex_to_projective_point(adaptor_point)?; 
            let frost_signature = frost_adaptor_signature::aggregate_with_group_commitment(&signing_package, signature_shares, &keypair.pub_key, &group_commitment)?;

            keypair.pub_key.clone().verifying_key().verify(signing_package.message(), &frost_signature).map(|_| frost_signature)
        },
        _ => {

            let frost_signature = frost_adaptor_signature::aggregate(&signing_package, signature_shares, &keypair.pub_key)?;
            keypair.pub_key.clone().verifying_key().verify(signing_package.message(), &frost_signature).map(|_| frost_signature)

        }
    }

}

fn broadcast_signing_packages(ctx: &mut Context, message: &mut SignMesage) {
    let raw = serde_json::to_vec(&message.package).unwrap();
    let signaure = ctx.node_key.sign(raw, None).to_vec();
    message.signature = signaure;

    // tracing::debug!("Broadcasting: {:?}", message);
    let message = serde_json::to_vec(&message).expect("Failed to serialize Sign package");
    publish_message(ctx, SubscribeTopic::SIGNING, message);
}

fn sanitize<T>(storages: &mut BTreeMap<Identifier, T>, keys: &Vec<&Identifier>) {
    if keys.len() > 0 {
        storages.retain(|k, _| { keys.contains(&k)});
    }
}