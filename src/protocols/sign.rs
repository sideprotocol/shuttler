use std::collections::BTreeMap;

use bitcoin::{sighash::{self, SighashCache}, Address, Psbt, TapSighashType, Witness};
use bitcoin_hashes::Hash;
use bitcoincore_rpc::RpcApi;
use cosmos_sdk_proto::side::btcbridge::{MsgSubmitSignatures, SigningRequest};
use cosmrs::Any;

use libp2p::Swarm;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use frost::{Identifier, round1, round2}; 
use frost_secp256k1_tr::{self as frost, round1::{SigningCommitments, SigningNonces}};
use crate::{
    app::{config::{self, get_database_with_name}, 
    signer::Signer}, 
    helper::{
        client_side::send_cosmos_transaction, 
        encoding::{self, from_base64}, 
        gossip::publish_signing_package,
    }};

use super::{Round, TSSBehaviour};
use lazy_static::lazy_static;
use usize as Retry;
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
    pub retry: Retry,
    pub package: SignPackage,
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
    pub round: Round,
    pub inputs: BTreeMap<Index, TransactionInput>,
    pub is_signature_submitted: bool,
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
        _ => {
            debug!("Task already exists: {:?}", request.txid);
            return;
        }
    }

    let psbt_bytes = from_base64(&request.psbt).unwrap();
    let group_task_id = request.txid.clone();

    let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return;
        }
    };

    debug!("(signing round 0) prepare for signing: {:?} inputs in {:?}", psbt.inputs.len(), request.txid );
    let mut inputs = BTreeMap::new();
    let preouts = psbt.inputs.iter()
        //.filter(|input| input.witness_utxo.is_some())
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect::<Vec<_>>();

    psbt.inputs.iter().enumerate().for_each(|(i, input)| {

        let prev_utxo = match input.witness_utxo.clone() {
            Some(utxo) => utxo,
            None => {
                error!("Failed to get witness_utxo {}-{}", request.txid, i);
                return;
            }
        };

        debug!("prev_tx: {:?}", prev_utxo.script_pubkey);
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
            task_id: group_task_id.clone(),
            index: i,
            sig_hash: hash.to_raw_hash().to_byte_array().to_vec(),
            address: address.to_string(),
        };

        inputs.insert(i, input);
 
    });

    if inputs.len() == 0 {
        return
    }

    let task = SignTask {
        id: group_task_id.clone(),
        psbt: request.psbt.clone(),
        round: Round::Round1,
        inputs,
        is_signature_submitted: false,
    };

    save_sign_task(&task);
}

pub async fn broadcast_tss_packages(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer) {

    for item in DB_TASK.iter() {
        let mut task: SignTask = serde_json::from_slice(&item.unwrap().1).unwrap();

        debug!("process task: {:?}", task);
        match task.round {
            Round::Round1 => {
                generate_commitments(swarm, signer, &mut task);
            },
            Round::Round2 => {
                generate_signature_shares(swarm, &mut task, signer.identifier());
            },
            Round::Aggregate => {
                // let psbt_bytes = from_base64(&task.psbt).unwrap();
                // let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
                //     Ok(psbt) => psbt,
                //     Err(e) => {
                //         error!("Failed to deserialize PSBT: {}", e);
                //         continue;
                //     }
                // };
                // if psbt.inputs.iter().all(|input| input.final_script_witness.is_some() ) {
                //     submit_signatures(psbt, signer).await;
                // } else {
                //     debug!("Re-sign incompleted task: {}.", task.id);
                //     task.round = Round::Round1;
                //     save_sign_task(&task);
                // }  
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
                }
            }
        }
    };
}

fn generate_commitments(swarm: &mut Swarm<TSSBehaviour>, signer: &Signer, task: &mut SignTask) {

    let mut local_nonces = get_sign_local_nonces(&task.id);

    let retry = local_nonces.len() + 1;
    // If it is not completed after 10 retries, the task is considered closed
    if retry >= 10 {
        task.round = Round::Closed;
        save_sign_task(&task);
        return;
    }

    let mut nonces = BTreeMap::new();
    let mut packages = BTreeMap::new();
    task.inputs.iter().for_each(|(index, input)| {
        if let Some((nonce, commitment)) = generate_nonce_and_commitment_by_address(&input.address) {
            nonces.insert(*index, nonce);
            let mut map: BTreeMap<frost_core::Identifier<frost_secp256k1_tr::Secp256K1Sha256>, frost_core::round1::SigningCommitments<frost_secp256k1_tr::Secp256K1Sha256>> = BTreeMap::new();
            map.insert(signer.identifier().clone(), commitment);
            packages.insert(*index, map);
        }
    });
    // save local variable: nonces
    local_nonces.insert(retry, nonces);
    save_sign_local_variable(&task.id, &local_nonces);

    let mut commitments = get_sign_remote_commitments(&task.id);
    commitments.insert(retry, packages.clone());
    save_sign_remote_commitments(&task.id, &commitments);

    // publish remote variable: commitment
    publish_signing_package(swarm, &SignMesage {
        task_id: task.id.clone(),
        retry,
        package: SignPackage::Round1(packages)
    });
}

pub fn received_sign_message(msg: SignMesage) {

    let task_id = msg.task_id.clone();
    match msg.package {
        SignPackage::Round1(commitments) => {
            // merge all commitment by retry, input index
            let mut remote_commitments = get_sign_remote_commitments(&task_id);
            match remote_commitments.get_mut(&msg.retry) {
                Some(srd) => {
                    // srd.extend(commitments);
                    // debug!("srd {:?}", srd);
                    srd.iter_mut().for_each(|(index, map)| {
                        map.extend(commitments.get(index).unwrap());
                        debug!("Received commitments: {}:{index} {:?}",&msg.retry, map.keys());
                    });
                },
                None => {
                    remote_commitments.insert(msg.retry, commitments);
                }
            }
            save_sign_remote_commitments(&task_id, &remote_commitments);

            match get_sign_task(&task_id) {
                Some(mut task) => {
                    // Move to Round2 if the commitment of all inputs received from the latest retry exceeds the minimum number of signers.
                    if remote_commitments.get(&msg.retry).unwrap().iter().all(|(index, commitments)| {
                        match task.inputs.get(index) {
                            Some(input) => {
                                match config::get_keypair_from_db(&input.address) {
                                    Some(key) => {
                                        debug!("{task_id}:{index} commitment lens: {}>={}?", commitments.len(), key.priv_key.min_signers());
                                        commitments.len() as u16 >= key.priv_key.min_signers().clone()
                                    },
                                    None => false
                                }
                            },
                            None => false
                        }
                    }) {
                        info!("Move to round2: {}", task_id);
                        task.round = Round::Round2;
                        save_sign_task(&task);
                    }
                },
                None => {
                    debug!("Not found task {} on my sided", task_id);
                }
            };
            
        },
        SignPackage::Round2(sig_shares) => {
            let mut task = match get_sign_task(&task_id) {
                Some(t) => t,
                None => {
                    debug!("Skip, not found the task {} from local sign queue.", &task_id);
                    return
                }
            };

            // Double check task's round is still in round2
            // The task could be closed in previously aggregation.
            if task.round == Round::Closed {
                return
            }

            // Merge all commitments by retry, input index
            let mut remote_sig_shares = get_sign_remote_signature_shares(&task_id);
            match remote_sig_shares.get_mut(&msg.retry) {
                Some(srd) => {
                    srd.iter_mut().for_each(|(index, map)| {
                        map.extend(sig_shares.get(index).unwrap());
                        debug!("Received signature shares: {}:{index} {:?}",&msg.retry, map.keys());
                    });
                },
                None => {
                    remote_sig_shares.insert(msg.retry, sig_shares);
                }
            }
            
            save_sign_remote_signature_shares(&task_id, &remote_sig_shares);

            // Move to Round2 if the commitment of all inputs received from the latest retry exceeds the minimum number of signers.
            if remote_sig_shares.get(&msg.retry).unwrap().iter().all(|(index, shares)| {
                match task.inputs.get(index) {
                    Some(input) => {
                        match config::get_keypair_from_db(&input.address) {
                            Some(key) => shares.len() as u16 >= key.priv_key.min_signers().clone(),
                            None => false
                        }
                    },
                    None => false
                }
            }) {
                info!("Move to Round::Aggregate: {}", task_id);
                task.round = Round::Aggregate;
                save_sign_task(&task);

                // aggregate signatures if it's possible
                aggregate_signature_shares(&mut task);
            }

        }
    }

}

pub fn generate_signature_shares(swarm: &mut Swarm<TSSBehaviour>, task: &mut SignTask, identifier: &Identifier) {

    let stored_nonces = get_sign_local_nonces(&task.id);
    let retry = stored_nonces.len(); // latest retry
    let latest_nonces = match stored_nonces.get(&retry) {
        Some(t) => t,
        None => return
    };

    let stored_remote_commitments = get_sign_remote_commitments(&task.id);
    let latest_remote_commitments = match stored_remote_commitments.get(&retry) {
        Some(t) => t,
        None => return
    };

    let mut packages = BTreeMap::new();
    task.inputs.iter_mut().for_each(|(index, input)| {
        // filter packets from unknown parties
        match config::get_keypair_from_db(&input.address) {
            Some(keypair) => {

                let signing_commitments = match latest_remote_commitments.get(index) {
                    Some(e) => e.clone(),
                    None => return
                };

                if signing_commitments.len() < keypair.priv_key.min_signers().clone() as usize {
                    return
                }

                debug!("Commitments: {}, {:?}", signing_commitments.len(), signing_commitments);

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

                let signer_nonces = match latest_nonces.get(index) {
                    Some(d) => d,
                    None => {
                        debug!("not found local nonce for input {index}");
                        return
                    },
                };

                let signature_shares =
                    match frost::round2::sign(&signing_package, signer_nonces, &keypair.priv_key) {
                        Ok(shares) => shares,
                        Err(e) => {
                            error!("Error: {:?}", e);
                            return;
                        }
                    };
                
                let mut map = BTreeMap::new();
                map.insert(identifier.clone(), signature_shares);
                packages.insert(index.clone(), map);
            }
            None => {
                error!("skip, I am not the signer of task: {:?}", task.id);
                return;
            }
        };
    });

    if packages.len() < 1 {
        return
    }

    let msg = SignMesage {
        task_id: task.id.clone(),
        retry,
        package: SignPackage::Round2(packages.clone())
    };

    publish_signing_package(swarm, &msg);

    // save local signature share
    let mut remote_sig_shares = get_sign_remote_signature_shares(&task.id);
    match remote_sig_shares.get_mut(&retry) {
        Some(srd) => {
            srd.extend(packages);
        },
        None => {
            remote_sig_shares.insert(retry, packages);
        }
    }
    save_sign_remote_signature_shares(&task.id, &remote_sig_shares);
    // save_sign_task(task)

}

pub fn aggregate_signature_shares(task: &mut SignTask) -> Option<Psbt> {

    if task.round == Round::Closed {
        return None;
    }

    let stored_nonces = get_sign_local_nonces(&task.id);
    let retry = stored_nonces.len(); // latest retry

    let stored_remote_commitments = get_sign_remote_commitments(&task.id);
    let latest_remote_commitments = match stored_remote_commitments.get(&retry) {
        Some(t) => t,
        None => return None
    };

    let stored_remote_signature_shares = get_sign_remote_signature_shares(&task.id);
    let latest_remote_signature_shares = match stored_remote_signature_shares.get(&retry) {
        Some(t) => t,
        None => return None
    };

    let psbt_bytes = from_base64(&task.psbt).unwrap();
    let mut psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return None;
        }
    };

    for (index, input) in task.inputs.iter() {

        let signing_commitments = match latest_remote_commitments.get(index) {
            Some(e) => e.clone(),
            None => return None
        };

        let signature_shares = match latest_remote_signature_shares.get(index) {
            Some(e) => e.clone(),
            None => return None
        };

        if signing_commitments.len() != signature_shares.len() {
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
        let signing_package = frost::SigningPackage::new(
            signing_commitments,
            sig_target
        );

        match frost::aggregate(&signing_package, &signature_shares, &keypair.pub_key) {
            Ok(signature) => {
                // println!("public key: {:?}", pub)
                // let sighash = &hex::decode(sig_shares_message.message).unwrap();
                match keypair.pub_key.verifying_key().verify(signing_package.sig_target().clone(), &signature) {
                    Ok(_) => info!( "{}:{} {:?} is verified",task.id, index, signature ),
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
        debug!("Signing task {} completed", task.id);
        task.round = Round::Closed;
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
            info!("Tx broadcasted: {}", txid);
        }
        Err(err) => {
            error! ("Failed to broadcast tx: {:?}, err: {:?}", signed_tx.compute_txid(), err);
            return;
        }
    }

    let psbt_bytes = psbt.serialize();
    let psbt_base64 = encoding::to_base64(&psbt_bytes);
    info!("Signed PSBT: {:?}", psbt_base64);

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
            return
        },
    };
    // send message to the network
}

fn generate_nonce_and_commitment_by_address(address: &str) -> Option<(SigningNonces, SigningCommitments)> {
    let sign_key = match config::get_keypair_from_db(address) {
        Some(key) => {
            debug!("loaded key for address: {:?}", address);
            key.priv_key
        }
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
    debug!("loading in-process sign tasks from database, total: {:?}", DB_TASK.len());
    for task in DB_TASK.iter() {
        let (_, task) = task.unwrap();
        tasks.push(serde_json::from_slice(&task).unwrap());
    }
    tasks
}

pub fn get_sign_task(id: &str) -> Option<SignTask> {
    match DB_TASK.get(id) {
        Ok(Some(task)) => {
            let task: SignTask = serde_json::from_slice(&task).unwrap();
            Some(task)
        },
        _ => None,
    }
}

fn get_sign_remote_commitments(id: &str) -> BTreeMap<Retry, BTreeMap<Index, BTreeMap<Identifier, round1::SigningCommitments>>> {
    match DB_TASK_VARIABLES.get(format!("{}-commitments",id).as_bytes()) {
        Ok(Some(value)) => {
            serde_json::from_slice(&value).unwrap()
        },
        _ => BTreeMap::new()
    }
}

fn get_sign_remote_signature_shares(id: &str) -> BTreeMap<Retry, BTreeMap<Index, BTreeMap<Identifier, round2::SignatureShare>>> {
    match DB_TASK_VARIABLES.get(format!("{}-sig-shares",id).as_bytes()) {
        Ok(Some(value)) => {
            serde_json::from_slice(&value).unwrap()
        },
        _ => BTreeMap::new()
    }
}

fn get_sign_local_nonces(id: &str) -> BTreeMap<Retry, BTreeMap<Index, SigningNonces>> {
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
fn save_sign_local_variable(id: &str, data: &BTreeMap<Retry, BTreeMap<Index, SigningNonces>>) {
    let value = serde_json::to_vec(&data).unwrap();
    DB_TASK_VARIABLES.insert(id.as_bytes(), value).unwrap();
}
/// saved remote variable of each retry
/// <retry, SignRemoteData>
fn save_sign_remote_commitments(id: &str, data: &BTreeMap<Retry, BTreeMap<Index, BTreeMap<Identifier, round1::SigningCommitments>>>) {
    let value = serde_json::to_vec(&data).unwrap();
    DB_TASK_VARIABLES.insert(format!("{}-commitments",id).as_bytes(), value).unwrap();
}

/// saved remote variable of each retry
/// <retry, SignRemoteData>
fn save_sign_remote_signature_shares(id: &str, data: &BTreeMap<Retry, BTreeMap<Index, BTreeMap<Identifier, round2::SignatureShare>>>) {
    let value = serde_json::to_vec(&data).unwrap();
    DB_TASK_VARIABLES.insert(format!("{}-sig-shares",id).as_bytes(), value).unwrap();
}

pub fn delete_tasks() {
    DB_TASK.clear().unwrap();
    DB_TASK.flush().unwrap();
}

pub fn remove_task(task_id: &str) {
    match DB_TASK.remove(task_id) {
        Ok(_) => {
            info!("Removed task from database: {}", task_id);
        },
        _ => {
            error!("Failed to remove task from database: {}", task_id);
        }
    };
}