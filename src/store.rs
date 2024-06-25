use std::collections::BTreeMap;

use frost_secp256k1::{keys::dkg::{round1, round2}, Identifier};

use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref DkgRound1SecretPacket: Mutex<BTreeMap<String, round1::SecretPackage>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DkgRound2SecretPacket: Mutex<BTreeMap<String, round2::SecretPackage>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DkgRound1Packets: Mutex<BTreeMap<String, BTreeMap<Identifier, round1::Package>>> = {
        Mutex::new(BTreeMap::new())
    };
    static ref DkgRound2Packets: Mutex<BTreeMap<String, BTreeMap<Identifier, round2::Package>>> = {
        Mutex::new(BTreeMap::new())
    };
}

pub fn get_dkg_round1_secret_packet(task_id: &str) -> Option<round1::SecretPackage> {
    let map = DkgRound1SecretPacket.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round1_secret_packet(task_id: &str, secret_packet: round1::SecretPackage) {
    let mut map = DkgRound1SecretPacket.lock().unwrap();
    map.insert(task_id.to_string(), secret_packet);
}

pub fn get_dkg_round2_secret_packet(task_id: &str) -> Option<round2::SecretPackage> {
    let map = DkgRound2SecretPacket.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round2_secret_packet(task_id: &str, secret_packet: round2::SecretPackage) {
    let mut map = DkgRound2SecretPacket.lock().unwrap();
    map.insert(task_id.to_string(), secret_packet);
}

pub fn get_dkg_round1_packets(task_id: &str) -> Option<BTreeMap<Identifier, round1::Package>> {
    let map = DkgRound1Packets.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round1_packets(task_id: &str, party_id: Identifier, packet: round1::Package) {
    let mut map = DkgRound1Packets.lock().unwrap();
    if let Some(packets) = map.get_mut(task_id) {
        packets.insert(party_id, packet);
    } else {
        let mut packets = BTreeMap::new();
        packets.insert(party_id, packet);
        map.insert(task_id.to_string(), packets);
    }
}

pub fn get_dkg_round2_packets(task_id: &str) -> Option<BTreeMap<Identifier, round2::Package>> {
    let map = DkgRound2Packets.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_dkg_round2_packets(task_id: &str, party_id: Identifier, packet: round2::Package) {
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


