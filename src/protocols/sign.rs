use std::collections::{btree_map::Keys, BTreeMap};

use bitcoin::{sighash::{self, SighashCache}, Address, Psbt, TapSighashType, Witness};
use bitcoin_hashes::Hash;
use bitcoincore_rpc::RpcApi;
use cosmos_sdk_proto::side::btcbridge::{MsgSubmitSignatures, SigningRequest, SigningStatus};
use cosmrs::Any;

use ed25519_compact::{PublicKey, Signature};
use libp2p::Swarm;
use prost_types::Timestamp;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use frost::{Identifier, round1, round2}; 
use frost_secp256k1_tr::{self as frost, round1::{SigningCommitments, SigningNonces}};
use crate::{
    app::{config::TASK_INTERVAL, signer::Signer}, 
    helper::{
        client_side::{get_signing_request_by_txid, send_cosmos_transaction}, encoding::{abbr, from_base64, hash, to_base64}, gossip::publish_signing_package, mem_store, now
    }
};

use super::TSSBehaviour;
use usize as Index;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    pub task_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignResponse {
    task_id: String,
    commitments: BTreeMap<usize, BTreeMap<Identifier, round1::SigningCommitments>>,
    // <sender, <receiver, package>>
    signature_shares: BTreeMap<usize, BTreeMap<Identifier, round2::SignatureShare>>,
    nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignMesage {
    pub task_id: String,
    pub package: SignPackage,
    pub nonce: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTask {
    pub id: String,
    pub psbt: String,
    pub status: Status,
    pub inputs: BTreeMap<Index, TransactionInput>,
    pub is_signature_submitted: bool,
    pub start_time: u64,
    pub retry: u64,
}

impl SignTask {
    pub fn new(id: String, psbt: String, inputs: BTreeMap<Index, TransactionInput>, creation_time: Option<Timestamp>) -> Self {
        let start_time = match creation_time {
            Some(t) =>  t.seconds as u64,
            None => now(),
        };
        Self {
            id,
            psbt,
            status: Status::RESET,
            inputs,
            is_signature_submitted: false,
            start_time,
            retry: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub task_id: String,
    pub index: Index,
    pub sig_hash: Vec<u8>,
    pub address: String,
}

pub fn save_task_into_signing_queue(request: SigningRequest, signer: &Signer) {
    if signer.is_signing_task_exists(&request.txid) {
        return
    }

    let psbt_bytes = from_base64(&request.psbt).unwrap();
    let task_id = request.txid.clone();

    let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return;
        }
    };

    info!("Prepare for signing: {:?} {} inputs ", &request.txid[..6], psbt.inputs.len()  );
    let mut inputs = BTreeMap::new();
    let preouts = psbt.inputs.iter()
        //.filter(|input| input.witness_utxo.is_some())
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect::<Vec<_>>();

    psbt.inputs.iter().enumerate().for_each(|(i, input)| {

        let script = input.witness_utxo.clone().unwrap().script_pubkey;
        let address: Address = Address::from_script(&script, signer.config().bitcoin.network).unwrap();

        // get the message to sign
        let hash_ty = input
            .sighash_type
            .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
            .unwrap_or(bitcoin::TapSighashType::Default);
        let hash = match SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
            i,
            &sighash::Prevouts::All(&preouts),
            hash_ty,
        ) {
            Ok(hash) => hash,
            Err(e) => {
                error!("failed to compute sighash: {}", e);
                return;
            }
        };

        let input = TransactionInput {
            task_id: task_id.clone(),
            index: i,
            sig_hash: hash.to_raw_hash().to_byte_array().to_vec(),
            address: address.to_string(),
        };

        inputs.insert(i, input);
 
    });

    if inputs.len() == 0 {
        return
    }

    let task = SignTask::new(task_id, request.psbt, inputs, request.creation_time);
    signer.save_signing_task(&task);

}

pub async fn dispatch_executions(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer) {

    for mut task in signer.list_signing_tasks() {
        match task.status {
            Status::CLOSE => {
                if task.is_signature_submitted {
                    continue;
                }
                let psbt_bytes = from_base64(&task.psbt).unwrap();
                let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
                    Ok(psbt) => psbt,
                    Err(e) => {
                        error!("Failed to deserialize PSBT: {}", e);
                        continue;
                    }
                };
                if psbt.inputs.iter().all(|input| input.final_script_witness.is_some() ) {
                    submit_signatures(psbt, signer).await;
                    task.is_signature_submitted = true;
                    task.status = Status::CLOSE;
                    signer.save_signing_task(&task);
                }
            },
            Status::RESET => {
                task.status = Status::WIP;
                signer.save_signing_task(&task);
                generate_commitments(swarm, signer, &mut task);
            },
            Status::WIP => {
                let window = TASK_INTERVAL.as_secs() * 20; // n = 20, n should large than 3 
                let retry = (now() - task.start_time) / window;
                
                if task.retry != retry {
                    info!("Timeout, re-sign {retry}, {}", task.id);
                    task.retry = retry;
                    task.status = Status::RESET;
                    signer.save_signing_task(&task);
                    signer.remove_signing_task_variables(&task.id);
                }
            }
        }
    };
}

fn generate_commitments(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer, task: &SignTask) {

    if task.status == Status::CLOSE {
        return
    }

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    task.inputs.iter().for_each(|(index, input)| {
        if let Some((nonce, commitment)) = generate_nonce_and_commitment_by_address(&input.address, signer) {
            nonces.insert(*index, nonce);
            let mut input_commit = BTreeMap::new();
            input_commit.insert(signer.identifier().clone(), commitment);
            commitments.insert(*index, input_commit.clone());
        }
    });

    // Save nonces to local storage.
    signer.save_signing_local_variable(&task.id, &nonces);

    // Publish commitments to other pariticipants
    let mut msg =  SignMesage {
        task_id: task.id.clone(),
        package: SignPackage::Round1(commitments),
        nonce: now(),
        sender: signer.identifier().clone(),
        signature: vec![], 
    };
    publish_signing_package(swarm, signer, &mut msg);

    received_sign_message(swarm, signer, msg);
}

pub fn received_sign_message(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer, msg: SignMesage) {

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

    // Ensure the task exists locally to prevent forged signature tasks. 
    let task_id = msg.task_id.clone();
    let mut task = match signer.get_signing_task(&task_id) {
        Some(t) => t,
        None => {
            debug!("Reject, unknown task: {}", &task_id);
            return;
        }
    };

    // Only check the first input, because all other inputs used the same vault address.
    let first = 0;
    let vault = match task.inputs.get(&first) {
        Some(input) => &input.address,
        None => return
    };
    let vkp = match signer.get_keypair_from_db(vault) {
        Some(kp) => kp,
        None => {
            debug!("Reject, unknown vault address: {task_id} {vault}");
            return;
        }
    };

    // Ensure the message is from the participants.
    let participants = vkp.pub_key.verifying_shares().keys().collect::<Vec<_>>();
    if !participants.contains(&&msg.sender) {
        return
    }
    let threshold = vkp.priv_key.min_signers().clone() as usize;

    match msg.package {
        SignPackage::Round1(commitments) => {

            let mut remote_commitments = signer.get_signing_commitments(&task_id);
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

            signer.save_signing_commitments(&task_id, &remote_commitments);

            // check whether it's ready to generate signature share
            let commitments = match remote_commitments.get_mut(&first) {
                Some(c) => c,
                None => return,
            };

            let alive = mem_store::get_alive_participants(&participants);
            debug!("Commitment: {}:{first} {}/{}({alive}) from {}", 
                &task_id[..6], commitments.len(), participants.len(), abbr(&msg.sender)
            );
            
            if commitments.len() == participants.len() {
                generate_signature_shares(swarm, signer, &task);
            } else if alive >= threshold && commitments.len() == alive {
                generate_signature_shares(swarm, signer, &task);
            }
        },
        SignPackage::Round2(sig_shares) => {

            let mut remote_sig_shares = signer.get_signing_signature_shares(&task_id);
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

            signer.save_signing_signature_shares(&task_id, &remote_sig_shares);

            if let Some(shares) = remote_sig_shares.get(&first) {

                let alive = mem_store::get_alive_participants(&participants);
                debug!("Signature shares: {}:{first} {:?}/{}({alive}) from {}", &task_id[..6], shares.len(), participants.len(), abbr(&msg.sender));
                
                if shares.len() == participants.len() {
                    aggregate_signature_shares(signer, &mut task);
                } else if alive >= threshold && shares.len() == alive {
                    aggregate_signature_shares(signer, &mut task);
                } 
            }
        }
    }
}

pub fn sanitize<T>(storages: &mut BTreeMap<Identifier, T>, keys: &Vec<&Identifier>) {
    if keys.len() > 0 {
        storages.retain(|k, _| { keys.contains(&k)});
    }
}

pub fn generate_signature_shares(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer, task: &SignTask) {

    let stored_nonces = signer.get_signing_local_variable(&task.id);
    if stored_nonces.len() == 0 {
        return;
    }
    let stored_remote_commitments = signer.get_signing_commitments(&task.id);

    let mut broadcast_packages = BTreeMap::new();
    task.inputs.iter().for_each(|(index, input)| {
        // filter packets from unknown parties
        if let Some(keypair) = signer.get_keypair_from_db(&input.address) {

            let mut signing_commitments = match stored_remote_commitments.get(index) {
                Some(e) => e.clone(),
                None => return
            };

            if signing_commitments.len() < keypair.priv_key.min_signers().clone() as usize {
                return
            }

            sanitize( &mut signing_commitments, &keypair.pub_key.verifying_shares().keys().map(|k| k).collect::<Vec<_>>());

            // when number of receved commitments is larger than min_signers
            // the following code will be executed or re-executed
            let signing_package = frost::SigningPackage::new(
                signing_commitments, 
                frost::SigningTarget::new(
                    &input.sig_hash, 
                    frost::SigningParameters{
                        tapscript_merkle_root: match keypair.tweak {
                            Some(tweak) => Some(tweak.to_vec()),
                            None => None,
                        },
                    }
                ));

            let signer_nonces = match stored_nonces.get(index) {
                Some(d) => d,
                None => {
                    debug!("not found local nonce for input {index}");
                    return
                },
            };

            let signature_shares = match frost::round2::sign(
                &signing_package, signer_nonces, &keypair.priv_key
            ) {
                Ok(shares) => shares,
                Err(e) => {
                    error!("Error: {:?}", e);
                    return;
                }
            };
            
            let mut my_share = BTreeMap::new();
            my_share.insert(signer.identifier().clone(), signature_shares);
            
            // broadcast my share
            broadcast_packages.insert(index.clone(), my_share.clone());
        
        };
    });

    if broadcast_packages.len() == 0 {
        return;
    }

    let mut msg = SignMesage {
        task_id: task.id.clone(),
        package: SignPackage::Round2(broadcast_packages),
        nonce: now(),
        sender: signer.identifier().clone(),
        signature: vec![],
    };

    // debug!("Publish signature share: {:?}", msg);

    publish_signing_package(swarm, signer, &mut msg);

    received_sign_message(swarm, signer, msg);

}

pub fn aggregate_signature_shares(signer: &Signer, task: &mut SignTask) -> Option<Psbt> {

    // if task.round == Round::Closed {
    //     return None;
    // }

    let stored_remote_commitments = signer.get_signing_commitments(&task.id);
    let stored_remote_signature_shares = signer.get_signing_signature_shares(&task.id);

    let psbt_bytes = from_base64(&task.psbt).unwrap();
    let mut psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return None;
        }
    };

    let verifies = task.inputs.iter().map(|(index, input)| {

        let keypair = match signer.get_keypair_from_db(&input.address) {
            Some(keypair) => keypair,
            None => {
                error!("Failed to get keypair for address: {}", input.address);
                return false;
            }
        };

        let signing_commitments = match stored_remote_commitments.get(index) {
            Some(e) => e.clone(),
            None => return false
        };

        let signature_shares = match stored_remote_signature_shares.get(index) {
            Some(e) => e.clone(),
            None => return false
        };

        if signing_commitments.len() != signature_shares.len() {
            let s_keys = signature_shares.keys();
            let c_keys = signing_commitments.keys();
            error!("Aggregate error: {} != {} {:?} {:?}", signing_commitments.len(), signature_shares.len(), c_keys, s_keys);
            return false;
        }

        let sig_target = frost::SigningTarget::new(
            &input.sig_hash,
            frost::SigningParameters {
                tapscript_merkle_root:  match keypair.tweak {
                        Some(tweak) => Some(tweak.to_vec()),
                        None => None,
                    },
                }
        );
        
        let signing_package = frost::SigningPackage::new(
            signing_commitments,
            sig_target
        );

        match frost::aggregate(&signing_package, &signature_shares, &keypair.pub_key) {
            Ok(signature) => {
                match keypair.pub_key.verifying_key().verify(signing_package.sig_target().clone(), &signature) {
                    Ok(_) => {
                        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature.serialize()).unwrap();

                        psbt.inputs[*index].tap_key_sig = Option::Some(bitcoin::taproot::Signature {
                            signature: sig,
                            sighash_type: TapSighashType::Default,
                        });
        
                        let witness = Witness::p2tr_key_spend(&psbt.inputs[*index].tap_key_sig.unwrap());
                        psbt.inputs[*index].final_script_witness = Some(witness);
                        psbt.inputs[*index].partial_sigs = BTreeMap::new();
                        psbt.inputs[*index].sighash_type = None;
                        return true;
                    },
                    Err(e) => {
                        error!( "{}:{} is invalid: {e}", &task.id[..6], index );
                    }
                }
            }
            Err(e) => {
                error!("Signature aggregation error: {:?} {:?}", &task.id[..6], e);
            }
        };
        false
    }).collect::<Vec<_>>();

    let result  = verifies.iter().enumerate()
                        .map(|(i, v)| format!("{i}:{}", if *v {"✔"} else {"✘"}))
                        .collect::<Vec<_>>().join(" ");
    info!("Verify {}: {}", &task.id[..6], result );

    if verifies.iter().all(|a| *a) {

        debug!("Completed task {}", &task.id[..6]);

        let psbt_bytes = psbt.serialize();
        let psbt_base64 = to_base64(&psbt_bytes);
        task.psbt = psbt_base64;
        task.status = Status::CLOSE;
        signer.save_signing_task(task);
        signer.remove_signing_task_variables(&task.id);
        Some(psbt.to_owned())
    } else {
        None
    }

}

// need check whether other participants have submitted or not.
pub async fn submit_signatures(psbt: Psbt, signer: &Signer) {

    // broadcast to bitcoin network
    let signed_tx = psbt.clone().extract_tx().expect("failed to extract signed tx");

    let host = signer.config().side_chain.grpc.clone();
    let txid = signed_tx.compute_txid().to_string();
    if let Ok(response) = get_signing_request_by_txid(&host, txid.clone()).await {
        match response.into_inner().request {
            Some(request) => if request.status != SigningStatus::Pending as i32 {
               debug!("Other participant has broadcasted. {txid}",);  
               return;  
            },
            None => return,
        };
    };
    match signer.bitcoin_client.send_raw_transaction(&signed_tx) {
        Ok(txid) => {
            info!("PSBT broadcasted to Bitcoin: {}", txid);
        }
        Err(err) => {
            error! ("Failed to broadcast PSBT: {:?}, err: {:?}", signed_tx.compute_txid(), err);
            // return;
        }
    }

    let psbt_bytes = psbt.serialize();
    let psbt_base64 = to_base64(&psbt_bytes);

    // submit signed psbt to side chain
    let msg = MsgSubmitSignatures {
        sender: signer.config().relayer_bitcoin_address(),
        txid: signed_tx.compute_txid().to_string(),
        psbt: psbt_base64,
    };

    let any = Any::from_msg(&msg).unwrap();
    match send_cosmos_transaction(signer.config(), any).await {
        Ok(resp) => {
            let tx_response = resp.into_inner().tx_response.unwrap();
            if tx_response.code != 0 {
                error!("Failed to submit signatures: {:?}", tx_response);
                return
            }
            info!("Submitted signatures: {:?}", tx_response);
        },
        Err(e) => {
            error!("Failed to submit signatures: {:?}", e);
        },
    };
    // send message to the network
}

fn generate_nonce_and_commitment_by_address(address: &str, signer: &Signer) -> Option<(SigningNonces, SigningCommitments)> {
    if let Some(key) = signer.get_keypair_from_db(address) {
        if key.pub_key.verifying_shares().contains_key(signer.identifier()) {
            let mut rng = thread_rng();
            return Some(frost::round1::commit(key.priv_key.signing_share(), &mut rng));
        }
    };
    None
}

pub fn participants_fingerprint<V>(keys: Keys<'_, Identifier, V>) -> String {
    let x = keys.map(|c| {c.serialize()}).collect::<Vec<_>>();
    hash(x.join(&0).as_slice())[..6].to_string()
}