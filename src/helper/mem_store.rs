/// This is the store module. It is used to store the secret packets for DKG round 1 and 2.
/// The secret packets are stored in memory for security reasons. 
/// The secret packets should not shared with other nodes in the network.
/// If the node restarts during the DKG process, the secret packets will be lost and the DKG process will be failed.

use std::collections::BTreeMap;

use frost_secp256k1_tr::{keys::dkg, Identifier};
use std::sync::Mutex;
use lazy_static::lazy_static;

use crate::apps::signer::Signer;
use crate::config::TASK_INTERVAL;
use crate::helper::now;
use super::gossip::HeartBeatMessage;

lazy_static! {
    static ref DkgRound1SecretPacket: Mutex<BTreeMap<String, dkg::round1::SecretPackage>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DkgRound2SecretPacket: Mutex<BTreeMap<String, dkg::round2::SecretPackage>> = {
        Mutex::new(BTreeMap::new())
    };
    pub static ref AliveTable: Mutex<BTreeMap<Identifier, i64>> = {
        Mutex::new(BTreeMap::new())
    };
    pub static ref TrustedPeers: Mutex<Vec<Identifier>> = {
        Mutex::new(Vec::new())
    };
    pub static ref VALIDATOR_NAMES: Mutex<BTreeMap<Identifier, String>> = {
        Mutex::new(BTreeMap::new())
    };
    
}

pub const ALIVE_WINDOW: u64 = TASK_INTERVAL.as_secs() * 2;
pub const BLOCK_TOLERENCE: u64 = ALIVE_WINDOW / 6 + 1 ;

pub fn update_alive_table(self_identifier: &Identifier, hbm: HeartBeatMessage) {
    tracing::debug!("Received {}, {}, {}, {} ", get_name(&hbm.payload.identifier), hbm.payload.version, hbm.payload.block_height, if hbm.payload.last_seen > now() {hbm.payload.last_seen - now()} else {0} );
    let mut table= AliveTable.lock().unwrap();

    table.insert(hbm.payload.identifier, hbm.payload.block_height);
    
    if let Some(t) = table.get(&self_identifier).cloned() {
        table.retain(|_, v| v.abs_diff(t) <= BLOCK_TOLERENCE);
    }

    // tracing::debug!("Heartbeats: {:?}", table.iter().map(|(k, v) | (get_name(k), v)).collect::<Vec<_>>());

}

pub fn count_task_participants() -> Vec<Identifier> {
    let table= AliveTable.lock().unwrap();
    table.keys().map(|k| k.clone()).collect::<Vec<_>>()
}

pub fn is_peer_alive(identifier: &Identifier) -> bool {
    let table= AliveTable.lock().unwrap();
   table.contains_key(identifier)
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

pub fn add_name(id: Identifier, name: String) {
    let mut map = VALIDATOR_NAMES.lock().unwrap();
    map.insert(id, name);
}

pub fn get_name(id: &Identifier) -> String {
    let map = VALIDATOR_NAMES.lock().unwrap();
    map.get(id).unwrap_or(&format!("{:?}", id)).to_string()
}

pub fn set_dkg_round2_secret_packet(task_id: &str, secret_packet: dkg::round2::SecretPackage) {
    let mut map = DkgRound2SecretPacket.lock().unwrap();
    map.insert(task_id.to_string(), secret_packet);
}

pub fn remove_dkg_round2_secret_packet(task_id: &str) {
    let mut map = DkgRound2SecretPacket.lock().unwrap();
    map.remove(task_id);
}
