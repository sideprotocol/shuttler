use std::collections::{btree_map::Keys, BTreeMap};

use bitcoin::{sighash::{self, SighashCache}, Address, Psbt, TapSighashType, Witness};
use bitcoin_hashes::Hash;
use bitcoincore_rpc::RpcApi;
use cosmos_sdk_proto::side::btcbridge::{MsgSubmitSignatures, SigningRequest};
use cosmrs::Any;

use libp2p::Swarm;
use prost_types::Timestamp;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use frost::{Identifier, round1, round2}; 
use frost_secp256k1_tr::{self as frost, round1::{SigningCommitments, SigningNonces}};
use crate::{
    app::{config::{self, get_database_with_name}, signer::Signer}, 
    helper::{
        client_side::{self, send_cosmos_transaction}, 
        encoding::{self, from_base64, hash, to_base64}, 
        gossip::publish_signing_package, now,
    }};

use super::{Round, TSSBehaviour};
use lazy_static::lazy_static;
use usize as Index;

lazy_static! {
    static ref DB_TASK: sled::Db = {
        let path = get_database_with_name("sign-task");
        sled::open(path).unwrap()
    };
    static ref DB_TASK_VARIABLES: sled::Db = {
        let path = get_database_with_name("sign-task-variables");
        sled::open(path).unwrap()
    };
}

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignPackage {
    Round1(BTreeMap<Index,BTreeMap<Identifier,round1::SigningCommitments>>),
    Round2(BTreeMap<Index,BTreeMap<Identifier,round2::SignatureShare>>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTask {
    pub id: String,
    pub psbt: String,
    // pub round: Round,
    pub inputs: BTreeMap<Index, TransactionInput>,
    pub is_signature_submitted: bool,
    pub mismatch_fp: usize,
    pub start_time: u64,
    pub fingerprint: String,
}

impl SignTask {
    pub fn new(id: String, psbt: String, inputs: BTreeMap<Index, TransactionInput>, creation_time: Option<Timestamp>) -> Self {
        let start_time = match creation_time {
            Some(t) => {
                t.seconds as u64
            },
            None => {
                now()
            },
        };
        Self {
            id,
            psbt,
            // round: Round::Round1,
            inputs,
            is_signature_submitted: false,
            mismatch_fp: 0,
            start_time,
            fingerprint: "".to_string(),
        }
    }
    pub fn reset(&mut self) {
        // self.round = Round::Round1;
        self.is_signature_submitted = false;
        self.mismatch_fp = 0;
        self.start_time = now();
        self.fingerprint = "".to_string();
    }

    pub fn round(&self, seconds: u64) -> Round {
        let x = (now() - self.start_time) / seconds;
        let windows = 4u64;
        match x % windows {
            0 => Round::Round1,
            1 => Round::Round2,
            2 => Round::Aggregate,
            3 => Round::Closed,
            _ => Round::Round1,
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
    match DB_TASK.contains_key(request.txid.as_bytes()) {
        Ok(false) => {
            info!("Fetched a new signing task: {:?}", request);
        }
        _ => return
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

        if config::get_keypair_from_db(&address.to_string()).is_none() {
            debug!("Skip, I am not signer of address: {}", address);
            return;
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

    save_sign_task(&task);
}

pub async fn process_tasks(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer) {

    let host = signer.config().side_chain.grpc.as_str();
    let seconds = client_side::get_cached_task_round_window(host).await;

    for item in DB_TASK.iter() {
        let mut task: SignTask = match serde_json::from_slice(&item.unwrap().1) {
            Ok(task) => task,
            _ => continue
        };

        info!("Process: {}, {:?}", &task.id[..6], task.round(seconds));
        match task.round(seconds) {
            Round::Round1 => {
                generate_commitments(swarm, signer, &mut task);
            },
            Round::Round2 => {
                generate_signature_shares(swarm, &mut task, signer.identifier());
            },
            Round::Aggregate => {
                aggregate_signature_shares(&mut task);
            },
            Round::Closed => {
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
                    save_sign_task(&task);
                    // remove_task_variables(&task.id);
                } else {
                    remove_task_variables(&task.id);
                }
            }
        }
    };
}

fn generate_commitments(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer, task: &mut SignTask) {

    let mut nonces = BTreeMap::new();
    let mut stored_commitments = get_sign_remote_commitments(&task.id);
    let mut broadcast_package = BTreeMap::new();

    task.inputs.iter().for_each(|(index, input)| {
        if let Some((nonce, commitment)) = generate_nonce_and_commitment_by_address(&input.address) {
            nonces.insert(*index, nonce);
            let mut my_commits: BTreeMap<frost_core::Identifier<frost_secp256k1_tr::Secp256K1Sha256>, frost_core::round1::SigningCommitments<frost_secp256k1_tr::Secp256K1Sha256>> = BTreeMap::new();
            my_commits.insert(signer.identifier().clone(), commitment);
            broadcast_package.insert(*index, my_commits.clone());
            if let Some(existing) = stored_commitments.get_mut(index) {
                existing.extend(my_commits);
            } else {
                stored_commitments.insert(*index, my_commits);
            };
        }
    });
    // save local variable: nonces
    save_sign_local_variable(&task.id, &nonces);
    save_sign_remote_commitments(&task.id, &stored_commitments);

    // publish remote variable: commitment
    publish_signing_package(swarm, &SignMesage {
        task_id: task.id.clone(),
        package: SignPackage::Round1(broadcast_package),
        nonce: now(),
    });
}

pub fn received_sign_message(msg: SignMesage) {

    let task_id = msg.task_id.clone();
    match msg.package {
        SignPackage::Round1(commitments) => {
            // merge all commitments by input index
            let mut remote_commitments = get_sign_remote_commitments(&task_id);
            // remote_commitments.iter_mut().for_each(|(index, map)| {
            //     if let Some(incoming) = commitments.get(index) {
            //         map.extend(incoming);
            //     }
            // });
            commitments.iter().for_each(|(index, coming)| {
                match remote_commitments.get_mut(index) {
                    Some(existing) => {
                        existing.extend(coming);
                    },
                    None => {
                        remote_commitments.insert(*index, coming.clone());
                    },
                }
            });

            match get_sign_task(&task_id) {
                Some(task) => {
                    let first = 0; 
                    // Move to Round2 if the commitment of all inputs received from the latest retry exceeds the minimum number of signers.
                    // Only check the first input, because all other inputs are in the same package.
                    if let Some(commitments) = remote_commitments.get(&first) {
                        if let Some(input) = task.inputs.get(&first) {
                            if let Some(key) = config::get_keypair_from_db(&input.address) {
                                let threshold = key.priv_key.min_signers().clone() as usize;
                                if commitments.len() >= threshold {
                                    info!("{}:{first} is ready for Round2: {}>={}", &task_id[..6], commitments.len(), threshold);
                                    // task.round = Round::Round2;
                                    // save_sign_task(&task);
                                } else {
                                    debug!("{}:{first} commitment lens: {}/{}", &task_id[..6], commitments.len(), threshold);
                                }
                            }
                        }
                    }

                    // Commitments are accepted only when a fingerprint does not exist. if it does, the task moves to the next round.
                    if task.fingerprint.len() == 0 {
                    }
                },
                None => {
                    debug!("Not found task {} on my sided", &task_id[..6]);
                    // save_sign_remote_commitments(&task_id, &remote_commitments);
                }
            };

            save_sign_remote_commitments(&task_id, &remote_commitments);
            
        },
        SignPackage::Round2(sig_shares) => {

            // Merge all commitments by input index
            let mut remote_sig_shares = get_sign_remote_signature_shares(&task_id);
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

            save_sign_remote_signature_shares(&task_id, &remote_sig_shares);

            let first = 0;
            // Move to Round2 if the commitment of all inputs received from the latest retry exceeds the minimum number of signers.
            // Only check the first input, because all other inputs are in the same package.
            if let Some(shares) = remote_sig_shares.get(&first) {
            
                let task = match get_sign_task(&task_id) {
                    Some(t) => t,
                    None => {
                        debug!("Skip, not found the task {} from local sign queue.", &task_id);
                        return
                    }
                };

                if let Some(input) = task.inputs.get(&first) {
                    if let Some(key) = config::get_keypair_from_db(&input.address) {
                        let threshold = key.priv_key.min_signers().clone() as usize;
                        if shares.len() >= threshold {
                            info!("Ready for aggregration: {}:{first} {:?}>={}", &task_id[..6], shares.len(), threshold);
                        } else {
                            debug!("Received signature shares: {}:{first} {:?}/{}", &task_id[..6], shares.len(), threshold);
                        }
                    }
                }
            }
        }
    }

}

pub fn generate_signature_shares(swarm: &mut Swarm<TSSBehaviour>, task: &mut SignTask, identifier: &Identifier) {

    let stored_nonces = get_sign_local_nonces(&task.id);
    if stored_nonces.len() == 0 {
        return;
    }
    let stored_remote_commitments = get_sign_remote_commitments(&task.id);

    let mut received_sig_shares = get_sign_remote_signature_shares(&task.id);
    // let received_sig_shares.get_mut(&retry);
    let mut broadcast_packages = BTreeMap::new();
    task.inputs.iter_mut().for_each(|(index, input)| {
        // filter packets from unknown parties
        match config::get_keypair_from_db(&input.address) {
            Some(keypair) => {

                let signing_commitments = match stored_remote_commitments.get(index) {
                    Some(e) => e.clone(),
                    None => return
                };

                if signing_commitments.len() < keypair.priv_key.min_signers().clone() as usize {
                    return
                }

                if *index == 0 {
                    let k = signing_commitments.keys().map(|k| to_base64(&k.serialize()[..])).collect::<Vec<_>>();
                    debug!("Commitments: {} {}, {:?}", &task.id[..6], signing_commitments.len(), k);
                }

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
                my_share.insert(identifier.clone(), signature_shares);
                
                // broadcast my share
                broadcast_packages.insert(index.clone(), my_share.clone());
                // save my share to local
                match received_sig_shares.get_mut(index) {
                    Some(existing) => {
                        existing.extend(my_share);
                    },
                    None => {
                        received_sig_shares.insert(index.clone(), my_share);
                    }
                }
            }
            None => {
                error!("skip, I am not the signer of task: {:?}", task.id);
                return;
            }
        };
    });

    if broadcast_packages.len() == 0 {
        return;
    }

    let msg = SignMesage {
        task_id: task.id.clone(),
        package: SignPackage::Round2(broadcast_packages),
        nonce: now(),
    };

    debug!("publish signature share: {:?}", msg);

    publish_signing_package(swarm, &msg);
    save_sign_remote_signature_shares(&task.id, &received_sig_shares);
    // save_sign_task(task)

}

pub fn aggregate_signature_shares(task: &mut SignTask) -> Option<Psbt> {

    // if task.round == Round::Closed {
    //     return None;
    // }

    // let stored_nonces = get_sign_local_nonces(&task.id);
    let stored_remote_commitments = get_sign_remote_commitments(&task.id);
    let stored_remote_signature_shares = get_sign_remote_signature_shares(&task.id);

    let psbt_bytes = from_base64(&task.psbt).unwrap();
    let mut psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return None;
        }
    };

    for (index, input) in task.inputs.iter() {

        let signing_commitments = match stored_remote_commitments.get(index) {
            Some(e) => e.clone(),
            None => return None
        };

        let signature_shares = match stored_remote_signature_shares.get(index) {
            Some(e) => e.clone(),
            None => return None
        };

        if signing_commitments.len() != signature_shares.len() {
            let s_keys = signature_shares.keys();
            let c_keys = signing_commitments.keys();
            error!("Aggregate error: {} != {} {:?} {:?}", signing_commitments.len(), signature_shares.len(), c_keys, s_keys);
            return None;
        }

        let keypair = match config::get_keypair_from_db(&input.address) {
            Some(keypair) => keypair,
            None => {
                error!("Failed to get keypair for address: {}", input.address);
                return None;
            }
        };

        if signature_shares.len() < *keypair.priv_key.min_signers() as usize {
            return None;
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
        
        let mut filtered = BTreeMap::new();
        signature_shares.keys().for_each(|key| {
            if let Some(v) = signing_commitments.get(key) {
                filtered.insert(key.clone(), v.clone());
            }
        });
        let signing_package = frost::SigningPackage::new(
            filtered,
            sig_target
        );

        match frost::aggregate(&signing_package, &signature_shares, &keypair.pub_key) {
            Ok(signature) => {
                // println!("public key: {:?}", pub)
                // let sighash = &hex::decode(sig_shares_message.message).unwrap();
                match keypair.pub_key.verifying_key().verify(signing_package.sig_target().clone(), &signature) {
                    Ok(_) => info!( "{}:{} {:?} is verified", &task.id[..6], index, signature ),
                    Err(e) => {
                        error!("Signature is invalid {}", e);
                        return None;
                    }
                }

                let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature.serialize()).unwrap();

                psbt.inputs[*index].tap_key_sig = Option::Some(bitcoin::taproot::Signature {
                    signature: sig,
                    sighash_type: TapSighashType::Default,
                });

                let witness = Witness::p2tr_key_spend(&psbt.inputs[*index].tap_key_sig.unwrap());
                psbt.inputs[*index].final_script_witness = Some(witness);
                psbt.inputs[*index].partial_sigs = BTreeMap::new();
                psbt.inputs[*index].sighash_type = None;
            }
            Err(e) => {
                error!("Signature aggregation error: {:?} {:?}", task.id, e);
            }
        };
    };

    if psbt.inputs.iter().all(|input| input.final_script_witness.is_some() ) {
        debug!("Signing task {} completed", &task.id[..6]);
        // task.round = Round::Closed;
        let psbt_bytes = psbt.serialize();
        let psbt_base64 = encoding::to_base64(&psbt_bytes);
        task.psbt = psbt_base64;
        save_sign_task(task);
        Some(psbt.to_owned())
    } else {
        None
    }

}

// need check whether other participants have submitted or not.
pub async fn submit_signatures(psbt: Psbt, signer: &Signer) {

    // broadcast to bitcoin network
    let signed_tx = psbt.clone().extract_tx().expect("failed to extract signed tx");
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
    let psbt_base64 = encoding::to_base64(&psbt_bytes);

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

fn generate_nonce_and_commitment_by_address(address: &str) -> Option<(SigningNonces, SigningCommitments)> {
    let sign_key = match config::get_keypair_from_db(address) {
        Some(key) => key.priv_key,
        None => {
            error!("Failed to get signing key for address: {}", address);
            return None;
        }
    };

    let mut rng = thread_rng();
    Some(frost::round1::commit(sign_key.signing_share(), &mut rng))
}

pub fn list_sign_tasks() -> Vec<SignTask> {
    let mut tasks = vec![];
    for task in DB_TASK.iter() {
        let (_, task) = task.unwrap();
        if let Ok(sign_task) = serde_json::from_slice(&task) {
            tasks.push(sign_task);
        }
    }
    tasks
}

pub fn get_sign_task(id: &str) -> Option<SignTask> {
    match DB_TASK.get(id) {
        Ok(Some(task)) => {
            match serde_json::from_slice(&task) {
                Ok(task) => Some(task),
                _ => None
            }
        },
        _ => None,
    }
}

fn get_sign_remote_commitments(id: &str) -> BTreeMap<Index, BTreeMap<Identifier, round1::SigningCommitments>> {
    match DB_TASK_VARIABLES.get(format!("{}-commitments",id).as_bytes()) {
        Ok(Some(value)) => {
            serde_json::from_slice(&value).unwrap()
        },
        _ => BTreeMap::new()
    }
}

fn get_sign_remote_signature_shares(id: &str) -> BTreeMap<Index, BTreeMap<Identifier, round2::SignatureShare>> {
    match DB_TASK_VARIABLES.get(format!("{}-sig-shares",id).as_bytes()) {
        Ok(Some(value)) => {
            serde_json::from_slice(&value).unwrap()
        },
        _ => BTreeMap::new()
    }
}

fn get_sign_local_nonces(id: &str) -> BTreeMap<Index, SigningNonces> {
    match DB_TASK_VARIABLES.get(id.as_bytes()) {
        Ok(Some(value)) => {
            serde_json::from_slice(&value).unwrap()
        },
        _ => BTreeMap::new()
    }
}

fn save_sign_task(task: &SignTask) {
    let value = serde_json::to_vec(&task).unwrap();
    DB_TASK.insert(task.id.as_bytes(), value).unwrap();
}
/// saved local variable of each retry
/// <retry, SignLocalData>
fn save_sign_local_variable(id: &str, data: &BTreeMap<Index, SigningNonces>) {
    let value = serde_json::to_vec(&data).unwrap();
    DB_TASK_VARIABLES.insert(id.as_bytes(), value).unwrap();
}
/// saved remote variable of each retry
/// <retry, SignRemoteData>
fn save_sign_remote_commitments(id: &str, data: &BTreeMap<Index, BTreeMap<Identifier, round1::SigningCommitments>>) {
    let value = serde_json::to_vec(&data).unwrap();
    DB_TASK_VARIABLES.insert(format!("{}-commitments",id).as_bytes(), value).unwrap();
}

/// saved remote variable of each retry
/// <retry, SignRemoteData>
fn save_sign_remote_signature_shares(id: &str, data: &BTreeMap<Index, BTreeMap<Identifier, round2::SignatureShare>>) {
    let value = serde_json::to_vec(&data).unwrap();
    DB_TASK_VARIABLES.insert(format!("{}-sig-shares",id).as_bytes(), value).unwrap();
}

pub fn delete_tasks() {
    DB_TASK.clear().unwrap();
    DB_TASK.flush().unwrap();
}

pub fn remove_task_variables(task_id: &str) {
    let _ = DB_TASK_VARIABLES.remove(task_id.as_bytes());
    let _ = DB_TASK_VARIABLES.remove(format!("{}-commitments", task_id).as_bytes());
    let _ = DB_TASK_VARIABLES.remove(format!("{}-sig-shares", task_id).as_bytes());
}

pub fn remove_task(task_id: &str) {
    let _ = DB_TASK_VARIABLES.remove(task_id.as_bytes());
    let _ = DB_TASK_VARIABLES.remove(format!("{}-commitments", task_id).as_bytes());
    let _ = DB_TASK_VARIABLES.remove(format!("{}-sig-shares", task_id).as_bytes());
    match DB_TASK.remove(task_id) {
        Ok(_) => {
            info!("Removed task from database: {}", task_id);
        },
        _ => {
            error!("Failed to remove task from database: {}", task_id);
        }
    };
}

pub fn participants_fingerprint<V>(keys: Keys<'_, Identifier, V>) -> String {
    let x = keys.map(|c| {c.serialize()}).collect::<Vec<_>>();
    hash(x.join(&0).as_slice())[..6].to_string()
}