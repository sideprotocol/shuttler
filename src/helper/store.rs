use std::collections::BTreeMap;

use cosmos_sdk_proto::side::btcbridge::DkgRequest;
use frost_secp256k1_tr::{keys::dkg, round1, round2, Identifier, SigningPackage};
use bitcoin::Psbt;
use serde::{Deserialize, Serialize};
use sled::Db;
use tracing::info;
use std::sync::Mutex;
use lazy_static::lazy_static;

use crate::{app::config::{get_database_path, get_task_database_path}, protocols::dkg::DKGTask};

use super::messages::{SigningSteps, Task};

#[derive(Clone)]
pub struct TaskVariables {
    pub signing_nonces: round1::SigningNonces,
    pub address: String,
    // pub pubkey: PublicKeyPackage,
    pub sighash: Vec<u8>,
    pub group_task_id: String,
    pub step: SigningSteps,
}

lazy_static! {
    static ref DkgRound1SecretPacket: Mutex<BTreeMap<String, dkg::round1::SecretPackage>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DkgRound2SecretPacket: Mutex<BTreeMap<String, dkg::round2::SecretPackage>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DkgRound1Packets: Mutex<BTreeMap<String, BTreeMap<Identifier, dkg::round1::Package>>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DkgRound2Packets: Mutex<BTreeMap<String, BTreeMap<Identifier, dkg::round2::Package>>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref SigningTasks: Mutex<BTreeMap<String, Psbt>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref SigningTasksVariables: Mutex<BTreeMap<String, TaskVariables>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref SigningGroupTasks: Mutex<BTreeMap<String, String>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref SigningCommitments: Mutex<BTreeMap<String, BTreeMap<Identifier, round1::SigningCommitments>>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref SignPackage:  Mutex<BTreeMap<String, SigningPackage>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref SignShares:  Mutex<BTreeMap<String, BTreeMap<Identifier, round2::SignatureShare>>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DB: Db = {
        let path = get_database_path();
        sled::open(path).unwrap()
    };

    static ref TASK_DB: Db = {
        let path = get_task_database_path();
        info!("Task database path: {}", path);
        sled::open(path).unwrap()
    };
}

const LAST_SCANNED_HEIGHT_KEY: &str = "last_scanned_height";

fn save_to_db(key: &str, value: &str) {
    DB.insert(key, value.as_bytes()).unwrap();
    DB.flush().unwrap();
}

fn get_from_db(key: &str) -> Option<String> {
    match DB.get(key) {
        Ok(Some(value)) => {
            Some(String::from_utf8(value.to_vec()).unwrap())
        },
        Ok(None) => {
            None
        },
        Err(_) => {
            None
        }
    }
}

pub fn save_task(task: &DKGTask) {
   let se =  &serde_json::to_string(task).unwrap();
   TASK_DB.insert(task.id.as_str(), se.as_bytes()).expect("Failed to save task to database");
}

pub fn get_task(task_id: &str) -> Option<DKGTask> {
    match TASK_DB.get(task_id) {
        Ok(Some(task)) => {
            Some(serde_json::from_slice(&task).unwrap())
        },
        _ => {
            None
        }
    }
}

pub fn list_tasks() -> Vec<DKGTask> {
    let mut tasks = vec![];
    info!("Listing tasks from database, total: {:?}", TASK_DB.iter().count());
    for task in TASK_DB.iter() {
        let (_, task) = task.unwrap();
        tasks.push(serde_json::from_slice(&task).unwrap());
    }
    tasks
}

pub fn delete_tasks() {
    TASK_DB.clear().unwrap();
    TASK_DB.flush().unwrap();
}

pub fn save_last_scanned_height(height: u64) {
    save_to_db(LAST_SCANNED_HEIGHT_KEY, &height.to_string())
}

pub fn get_last_scanned_height() -> Option<u64> {
    match get_from_db(LAST_SCANNED_HEIGHT_KEY) {
        Some(height) => {
            Some(height.parse::<u64>().unwrap())
        },
        None => {
            None
        }
    }
}

pub fn has_dkg_preceeded(key: &str) -> bool {
    match TASK_DB.contains_key(key) {
        Ok(v) => {
            v
        },
        _ => {
            false
        }
    }
}

pub fn get_dkg_round1_secret_packet(task_id: &str) -> Option<dkg::round1::SecretPackage> {
    let map = DkgRound1SecretPacket.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round1_secret_packet(task_id: &str, secret_packet: dkg::round1::SecretPackage) {
    let mut map = DkgRound1SecretPacket.lock().unwrap();
    map.insert(task_id.to_string(), secret_packet);
}

pub fn get_dkg_round2_secret_packet(task_id: &str) -> Option<dkg::round2::SecretPackage> {
    let map = DkgRound2SecretPacket.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round2_secret_packet(task_id: &str, secret_packet: dkg::round2::SecretPackage) {
    let mut map = DkgRound2SecretPacket.lock().unwrap();
    map.insert(task_id.to_string(), secret_packet);
}

pub fn get_dkg_round1_packets(task_id: &str) -> Option<BTreeMap<Identifier, dkg::round1::Package>> {
    let map = DkgRound1Packets.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn get_all_dkg_round1_packets() -> BTreeMap<String, BTreeMap<Identifier, dkg::round1::Package>> {
    let map = DkgRound1Packets.lock().unwrap();
    map.clone()
}

pub fn set_dkg_round1_packets(task_id: &str, party_id: Identifier, packet: dkg::round1::Package) {
    let mut map = DkgRound1Packets.lock().unwrap();
    if let Some(packets) = map.get_mut(task_id) {
        packets.insert(party_id, packet);
    } else {
        let mut packets = BTreeMap::new();
        packets.insert(party_id, packet);
        map.insert(task_id.to_string(), packets);
    }
}

pub fn get_dkg_round2_packets(task_id: &str) -> Option<BTreeMap<Identifier, dkg::round2::Package>> {
    let map = DkgRound2Packets.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round2_packets(task_id: &str, party_id: Identifier, packet: dkg::round2::Package) {
    let mut map = DkgRound2Packets.lock().unwrap();
    if let Some(packets) = map.get_mut(task_id) {
        packets.insert(party_id, packet);
    } else {
        let mut packets = BTreeMap::new();
        packets.insert(party_id, packet);
        map.insert(task_id.to_string(), packets);
    }
}

pub fn clear_dkg_variables(task_id: &str) {
    let mut map = DkgRound1SecretPacket.lock().unwrap();
    map.remove(task_id);
    let mut map = DkgRound2SecretPacket.lock().unwrap();
    map.remove(task_id);
    let mut map = DkgRound1Packets.lock().unwrap();
    map.remove(task_id);
    let mut map = DkgRound2Packets.lock().unwrap();
    map.remove(task_id);
}

pub fn get_signing_task(task_id: &str) -> Option<Psbt> {
    let map = SigningTasks.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn has_signing_task(task_id: &str) -> bool {
    let map = SigningTasks.lock().unwrap();
    map.contains_key(task_id)
}

pub fn set_signing_task(task_id: &str, psbt: Psbt) {
    let mut map = SigningTasks.lock().unwrap();
    map.insert(task_id.to_string(), psbt);
}

pub fn get_signing_task_variables(task_id: &str) -> Option<TaskVariables> {
    let map = SigningTasksVariables.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_signing_task_variables(task_id: &str, variables: TaskVariables) {
    let mut map = SigningTasksVariables.lock().unwrap();
    map.insert(task_id.to_string(), variables);
}

pub fn get_signing_commitments(task_id: &str) -> Option<BTreeMap<Identifier, round1::SigningCommitments>> {
    let map = SigningCommitments.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_signing_commitments(task_id: &str, party_id: Identifier, commitment: round1::SigningCommitments) {
    let mut map = SigningCommitments.lock().unwrap();
    if let Some(commitments) = map.get_mut(task_id) {
        commitments.insert(party_id, commitment);
    } else {
        let mut commitments = BTreeMap::new();
        commitments.insert(party_id, commitment);
        map.insert(task_id.to_string(), commitments);
    }
}

pub fn get_all_signing_commitments() -> BTreeMap<String, BTreeMap<Identifier, round1::SigningCommitments>> {
    let map = SigningCommitments.lock().unwrap();
    map.clone()
}

pub fn get_sign_package(task_id: &str) -> Option<SigningPackage> {
    let map = SignPackage.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_sign_package(task_id: &str, package: SigningPackage) {
    let mut map = SignPackage.lock().unwrap();
    map.insert(task_id.to_string(), package);
}

pub fn get_sign_shares(task_id: &str) -> Option<BTreeMap<Identifier, round2::SignatureShare>> {
    let map = SignShares.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_sign_shares(task_id: &str, party_id: Identifier, share: round2::SignatureShare) {
    let mut map = SignShares.lock().unwrap();
    if let Some(shares) = map.get_mut(task_id) {
        shares.insert(party_id, share);
    } else {
        let mut shares = BTreeMap::new();
        shares.insert(party_id, share);
        map.insert(task_id.to_string(), shares);
    }
}

pub fn has_sign_shares(task_id: &str) -> bool {
    let map = SignShares.lock().unwrap();
    map.contains_key(task_id)
}

pub fn clear_signing_variables(task_id: &str) {
    let mut map = SigningTasksVariables.lock().unwrap();
    map.remove(task_id);
    let mut map = SigningTasks.lock().unwrap();
    map.remove(task_id);
    let mut map = SigningCommitments.lock().unwrap();
    map.remove(task_id);
    let mut map = SignPackage.lock().unwrap();
    map.remove(task_id);
    let mut map = SignShares.lock().unwrap();
    map.remove(task_id);
}

pub fn clear_signing_group_task(task_id: &str) {
    let mut map = SigningGroupTasks.lock().unwrap();
    map.remove(task_id);
}

