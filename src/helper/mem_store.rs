/// This is the store module. It is used to store the secret packets for DKG round 1 and 2.
/// The secret packets are stored in memory for security reasons. 
/// The secret packets should not shared with other nodes in the network.
/// If the node restarts during the DKG process, the secret packets will be lost and the DKG process will be failed.

use std::collections::BTreeMap;

use frost_secp256k1_tr::{keys::dkg, Identifier};
use std::sync::Mutex;
use lazy_static::lazy_static;

use crate::app::{config::TASK_INTERVAL, signer::Signer};

use super::{gossip::HeartBeatMessage, now};

lazy_static! {
    static ref DkgRound1SecretPacket: Mutex<BTreeMap<String, dkg::round1::SecretPackage>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DkgRound2SecretPacket: Mutex<BTreeMap<String, dkg::round2::SecretPackage>> = {
        Mutex::new(BTreeMap::new())
    };
    pub static ref AliveTable: Mutex<BTreeMap<Identifier, u64>> = {
        Mutex::new(BTreeMap::new())
    };
    pub static ref TrustedPeers: Mutex<Vec<Identifier>> = {
        Mutex::new(Vec::new())
    };
}

const ALIVE_WINDOW: u64 = TASK_INTERVAL.as_secs() * 2;

pub fn update_alive_table(alive: HeartBeatMessage) {
    let mut table= AliveTable.lock().unwrap();
    table.insert(alive.identifier, alive.last_seen);
    table.retain(|_, v| {*v + 1800u64 > now()});
}

pub fn count_alive_participants(keys: &Vec<&Identifier>) -> usize {
    let table= AliveTable.lock().unwrap();
    
    let alive = keys.iter().filter(|key| {
        let last_seen = table.get(key).unwrap_or(&0u64);
        now() - last_seen < ALIVE_WINDOW
    }).count();
    // debug!("alive table: {alive}, {:?}", table);
    alive
}

pub fn is_peer_alive(identifier: &Identifier) -> bool {
    let table= AliveTable.lock().unwrap();
    let last_seen = table.get(identifier).unwrap_or(&0u64);
    now() - last_seen < ALIVE_WINDOW
}

pub fn is_peer_trusted_peer(identifier: &Identifier, signer: &Signer) -> bool {
    let mut table= TrustedPeers.lock().unwrap();
    if table.contains(identifier) {
        true
    } else {
        signer.list_keypairs().iter().any(|(_, kp)| {
            if kp.pub_key.verifying_shares().contains_key(identifier) {
                table.push(identifier.clone());
                true
            } else {
                false
            }
        })
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

pub fn remove_dkg_round1_secret_packet(task_id: &str) {
    let mut map = DkgRound1SecretPacket.lock().unwrap();
    map.remove(task_id);
}

pub fn get_dkg_round2_secret_packet(task_id: &str) -> Option<dkg::round2::SecretPackage> {
    let map = DkgRound2SecretPacket.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round2_secret_packet(task_id: &str, secret_packet: dkg::round2::SecretPackage) {
    let mut map = DkgRound2SecretPacket.lock().unwrap();
    map.insert(task_id.to_string(), secret_packet);
}

pub fn remove_dkg_round2_secret_packet(task_id: &str) {
    let mut map = DkgRound2SecretPacket.lock().unwrap();
    map.remove(task_id);
}
