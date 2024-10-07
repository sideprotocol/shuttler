use std::collections::BTreeMap;

use bitcoin::{sighash::{self, SighashCache}, Address, Psbt, TapSighashType, Witness};
use bitcoin_hashes::Hash;
use bitcoincore_rpc::RpcApi;
use cosmos_sdk_proto::side::btcbridge::{SigningRequest, MsgSubmitSignatures};
use cosmrs::Any;

use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use frost::{Identifier, round1, round2}; 
use frost_secp256k1_tr::{self as frost, round1::SigningNonces};
use crate::{app::{config::{self, get_database_with_name}, signer::Signer}, helper::{client_side::send_cosmos_transaction, encoding::{self, from_base64}, gossip::publish_sign_package, now}};

use super::{Round, SignTaskStatus, TSSBehaviour};
use lazy_static::lazy_static;

lazy_static! {
    static ref DB_TASK: sled::Db = {
        let path = get_database_with_name("sign-task");
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTask {
    pub id: String,
    pub psbt: String,
    pub batchs: Vec<SignTaskBatch>,
    pub status: SignTaskStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTaskBatch {
    pub round: Round,
    pub sessions: BTreeMap<usize, SignSession>,
}

impl SignTask {
    
    pub fn get_current_batch(&mut self) -> &mut SignTaskBatch {
        self.batchs.last_mut().unwrap()
    }

    pub fn get_current_round(&mut self) -> Round {
        self.get_current_batch().round.clone()
    }

    pub fn get_current_sessions(&mut self) -> &mut BTreeMap<usize, SignSession> {
        &mut self.get_current_batch().sessions
    }
    
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignSession {
    pub task_id: String,
    pub index: usize,
    pub sig_hash: Vec<u8>,
    pub address: String,
    /// NOTE: Should not share this with other parties
    // #[serde(skip_serializing)]
    pub nonces: SigningNonces,
    pub commitments: BTreeMap<Identifier, round1::SigningCommitments>,
    pub signatures: BTreeMap<Identifier, round2::SignatureShare>,
}

pub fn generate_nonce_and_commitments(request: SigningRequest, signer: &Signer) {
    let task_id = request.txid.clone();
    match DB_TASK.contains_key(task_id.as_bytes()) {
        Ok(false) => {
            info!("Fetched a new signing task: {:?}", request);
        }
        _ => {
            debug!("Task already exists: {:?}", task_id);
            return;
        }
    }

    let psbt_bytes = from_base64(&request.psbt).unwrap();
    let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return;
        }
    };

    debug!("(signing round 0) prepare for signing: {:?} sessions of {:?}", psbt.inputs.len(), task_id);
    let mut sessions = BTreeMap::new();
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

        let sign_key = match config::get_keypair_from_db(&address.to_string()) {
            Some(key) => {
                debug!("loaded key for address: {:?}", address);
                key.priv_key
            }
            None => {
                error!("Failed to get signing key for address: {}", address);
                return;
            }
        };

        let mut rng = thread_rng();
        let (nonce, commitments) = frost::round1::commit(sign_key.signing_share(), &mut rng);

        let mut commitments_map = BTreeMap::new();
        commitments_map.insert(signer.identifier().clone(), commitments.clone());
        let session = SignSession {
            task_id: task_id.clone(),
            index: i,
            sig_hash: hash.to_raw_hash().to_byte_array().to_vec(),
            address: address.to_string(),
            nonces: nonce,
            commitments: commitments_map,
            signatures: BTreeMap::new(),
        };
        sessions.insert(i, session);
    });

    let task = SignTask {
        id: task_id.clone(),
        psbt: request.psbt.clone(),
        batchs: vec![SignTaskBatch{
            round: Round::Initial,
            sessions,
        }],
        status: SignTaskStatus::Initial,
    };
    save_sign_task(&task);
}

pub fn prepare_response_for_request(task_id: String) -> Option<SignResponse> {
    let task = match get_sign_task(&task_id) {
        Some(task) => task,
        None => return None,
    };
    let mut commitments = BTreeMap::new();
    let sessions = &task.batchs.last().unwrap().sessions;

    sessions.iter().for_each(|(_i, s)| {commitments.insert(s.index.clone(), s.commitments.clone());});
    let mut signature_shares = BTreeMap::new();
    sessions.iter().for_each(|(_i, s)| {signature_shares.insert(s.index.clone(), s.signatures.clone());});
    Some(SignResponse {
        task_id: task.id.clone(),
        commitments,
        signature_shares,
        nonce: now(),
    })
}

pub fn received_sign_response(response: SignResponse) {
    let task_id = response.task_id.clone();
    let mut task = match get_sign_task(&task_id) {
        Some(task) => task,
        None => {
            debug!("task does not exist: {}", task_id);
            return;
        }
    };
    if task.status != SignTaskStatus::Pending {
        return;
    }

    let sessions = task.get_current_sessions();
    if response.commitments.len() > 0 {
        response.commitments.iter().for_each(|(i, c)| {
            if c.len() > 0 {
                if let Some(session) = sessions.get_mut(i) {
                    session.commitments.extend(c); // merge received commitments
                }
            }
        })
    }
    if response.signature_shares.len() > 0 {
        response.signature_shares.iter().for_each(|(i, sig)| {
            if sig.len() > 0 {
                if let Some(session) = sessions.get_mut(i) {
                    session.signatures.extend(sig); // merge received signature share
                }
            }
        })
    }

    debug!("Merged commitments and signatures: {:?} {:?} {:?}", task_id, 
        sessions.iter().map(|(_, s)| s.commitments.clone()).collect::<Vec<_>>(),
        sessions.iter().map(|(_, s)| s.signatures.clone()).collect::<Vec<_>>(),
    );
    save_sign_task(&task);
}

pub fn generate_signature_shares(task: &mut SignTask, identifier: Identifier) -> bool {
    let mut success = true;
    let task_id = task.id.clone();
    task.get_current_sessions().iter_mut().for_each(|(i, session)| {
        // filter packets from unknown parties
        match config::get_keypair_from_db(&session.address) {
            Some(keypair) => {
                if session.commitments.len() < *keypair.priv_key.min_signers() as usize {
                    debug!("skip task, have not received enough commitments for signing task: {:?} {}", task_id, i);
                    success = false;
                    return;
                }

                if session.signatures.contains_key(&identifier) {
                    debug!("skip task, already signed for task: {:?} {}", task_id, i);
                    return;
                }

                // when number of receved commitments is larger than min_signers
                // the following code will be executed or re-executed
                let signing_package = frost::SigningPackage::new(
                    session.commitments.clone(), 
                    frost::SigningTarget::new(
                        &session.sig_hash, 
                        frost::SigningParameters{
                            tapscript_merkle_root: match keypair.tweak {
                                Some(tweak) => Some(tweak.to_vec()),
                                None => None,
                            },
                        }
                    ));

                let signature_shares =
                    match frost::round2::sign(&signing_package, &session.nonces, &keypair.priv_key) {
                        Ok(shares) => shares,
                        Err(e) => {
                            error!("Error: {:?}", e);
                            success = false;
                            return;
                        }
                    };
                session.signatures.insert(identifier, signature_shares);
            }
            None => {
                error!("skip, I am not the signer of task: {:?}", task_id);
                success = false;
            }
        };
    });

    save_sign_task(task);
    return success;
}

pub fn aggregate_signature_shares(task: &mut SignTask) -> Option<Psbt> {
    if task.get_current_round() == Round::Closed {
        return None;
    }
    
    let psbt_bytes = from_base64(&task.psbt).unwrap();
    let mut psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return None;
        }
    };

    let task_id = task.id.clone();
    let sessions = task.get_current_sessions();
    for (index, session) in sessions.iter() {
        if session.commitments.len() != session.signatures.len() {
            return None;
        }

        let keypair = match config::get_keypair_from_db(&session.address) {
            Some(keypair) => keypair,
            None => {
                error!("Failed to get keypair for address: {}", session.address);
                return None;
            }
        };
        if session.signatures.len() < *keypair.priv_key.min_signers() as usize {
            return None;
        }

        let mut commits = BTreeMap::new();
        for key in session.signatures.keys() {
            if let Some(c) = session.commitments.get(key) {
                commits.insert(key.clone(), c.clone());
            } else {
                return None;
            }
        }

        let sig_target = frost::SigningTarget::new(
            &session.sig_hash,
            frost::SigningParameters {
                tapscript_merkle_root:  match keypair.tweak {
                        Some(tweak) => Some(tweak.to_vec()),
                        None => None,
                    },
                }
        );
        let signing_package = frost::SigningPackage::new(
            commits,
            sig_target
        );

        match frost::aggregate(&signing_package, &session.signatures, &keypair.pub_key) {
            Ok(signature) => {
                // println!("public key: {:?}", pub)
                // let sighash = &hex::decode(sig_shares_message.message).unwrap();
                let is_signature_valid = keypair.pub_key
                    .verifying_key()
                    .verify(signing_package.sig_target().clone(), &signature)
                    .is_ok();
                info!("Signature: {:?} verified: {:?}", signature, is_signature_valid);

                if !is_signature_valid {
                    error!("Signature is invalid");
                    return None;
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
                error!("Signature aggregation error: {:?} {:?}", task_id, e);
            }
        };
    };

    let is_complete = psbt.inputs.iter().all(|input| {
        input.final_script_witness.is_some()
    });
    debug!("Is {} completed: {:?}", task.id, is_complete);

    if is_complete {
        let batch = task.get_current_batch();
        batch.round = Round::Closed;
        save_sign_task(task);
        return Some(psbt.to_owned())
    }

    save_sign_task(task);
    None
}

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

pub fn turn_to_next_batch(task: &mut SignTask, signer: &Signer) {
    let task_id = task.id.clone();
    let psbt_bytes = from_base64(&task.psbt).unwrap();
    let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return;
        }
    };

    let mut sessions = BTreeMap::new();
    let preouts = psbt.inputs.iter()
        //.filter(|input| input.witness_utxo.is_some())
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect::<Vec<_>>();

    psbt.inputs.iter().enumerate().for_each(|(i, input)| {
        let prev_utxo = match input.witness_utxo.clone() {
            Some(utxo) => utxo,
            None => {
                error!("Failed to get witness_utxo {}-{}", task_id, i);
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

        let sign_key = match config::get_keypair_from_db(&address.to_string()) {
            Some(key) => {
                debug!("loaded key for address: {:?}", address);
                key.priv_key
            }
            None => {
                error!("Failed to get signing key for address: {}", address);
                return;
            }
        };

        let mut rng = thread_rng();
        let (nonce, commitments) = frost::round1::commit(sign_key.signing_share(), &mut rng);

        let mut commitments_map = BTreeMap::new();
        commitments_map.insert(signer.identifier().clone(), commitments.clone());
        let session = SignSession {
            task_id: task_id.clone(),
            index: i,
            sig_hash: hash.to_raw_hash().to_byte_array().to_vec(),
            address: address.to_string(),
            nonces: nonce,
            commitments: commitments_map,
            signatures: BTreeMap::new(),
        };
        sessions.insert(i, session);
    });

    task.batchs.push(SignTaskBatch{
        round: Round::Initial,
        sessions,
    });
    task.status = SignTaskStatus::Initial;
}

pub async fn collect_tss_packages(swarm: &mut libp2p::Swarm<TSSBehaviour>, signer: &Signer) {
    for item in DB_TASK.iter() {
        let mut task: SignTask = serde_json::from_slice(&item.unwrap().1).unwrap();
        if task.status == SignTaskStatus::Completed || task.status == SignTaskStatus:: Failure {
            continue;
        }
        
        debug!("Collecting task: {:?}", task);
        if task.status == SignTaskStatus::Initial {
            task.status = SignTaskStatus::Pending;
            task.get_current_batch().round = Round::Round1;
            save_sign_task(&task);
            publish_sign_package(swarm, &task);
            continue;
        }

        if task.status == SignTaskStatus::Pending {
            let round = task.get_current_round();
            if round == Round::Round1 {
                let success = generate_signature_shares(&mut task, signer.identifier().clone());
                if success {
                    task.get_current_batch().round = Round::Round2;
                    save_sign_task(&task);
                    publish_sign_package(swarm, &task);
                    continue;
                }
            }

            if round == Round::Round2 {
                if let Some(psbt) = aggregate_signature_shares(&mut task) {
                    submit_signatures(psbt, signer).await;
                    task.status = SignTaskStatus::Completed;
                    task.get_current_batch().round = Round::Closed;
                    save_sign_task(&task);
                    continue;
                } 
            }

            if task.batchs.len() >= 10 {
                task.status = SignTaskStatus::Failure;
                save_sign_task(&task);
            } else {
                turn_to_next_batch(&mut task, signer);
                save_sign_task(&task);
            }
            continue;
        }
    };
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

fn save_sign_task(task: &SignTask) {
    let value = serde_json::to_vec(&task).unwrap();
    DB_TASK.insert(task.id.as_bytes(), value).unwrap();
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