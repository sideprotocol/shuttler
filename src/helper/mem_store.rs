/// This is the store module. It is used to store the secret packets for DKG round 1 and 2.
/// The secret packets are stored in memory for security reasons. 
/// The secret packets should not shared with other nodes in the network.
/// If the node restarts during the DKG process, the secret packets will be lost and the DKG process will be failed.

use std::collections::BTreeMap;

use frost_secp256k1_tr::{keys::dkg, Identifier};
use tracing::debug;
use std::sync::Mutex;
use lazy_static::lazy_static;

use super::{gossip::{HeartBeatMessage, HEART_BEAT_DURATION}, now};

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
    pub static ref LastSendingTime: Mutex<u64> = {
        Mutex::new(0)
    };
}

pub fn update_last_sending_time() {
    let mut x= LastSendingTime.lock().unwrap();
    *x = now();
}

pub fn update_alive_table(alive: HeartBeatMessage) {
    let mut x= AliveTable.lock().unwrap();
    x.insert(alive.identifier, alive.last_seen);
}

pub fn get_alive_participants(keys: &Vec<&Identifier>) -> usize {
    let x= AliveTable.lock().unwrap();
    debug!("alive table: {:?}", x);
    keys.iter().filter(|key| {
        let last_seen = x.get(key).unwrap_or(&0u64);
        // debug!("is alive {:?} {}", key, now() - last_seen);
        now() - last_seen < HEART_BEAT_DURATION.as_secs() * 2
    }).count() + 1
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
