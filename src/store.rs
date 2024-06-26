use std::collections::BTreeMap;

use frost_secp256k1::{keys::dkg, {round1, round2}, Identifier, SigningPackage};
use bitcoin::Psbt;
use std::sync::Mutex;
use lazy_static::lazy_static;

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
    static ref SignNonces: Mutex<BTreeMap<String, round1::SigningNonces>> = {
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

pub fn set_signing_task(task_id: &str, psbt: Psbt) {
    let mut map = SigningTasks.lock().unwrap();
    map.insert(task_id.to_string(), psbt);
}

pub fn get_sign_nonces(task_id: &str) -> Option<round1::SigningNonces> {
    let map = SignNonces.lock().unwrap();
    map.get(task_id).cloned()
}

pub fn set_sign_nonces(task_id: &str, nonces: round1::SigningNonces) {
    let mut map = SignNonces.lock().unwrap();
    map.insert(task_id.to_string(), nonces);
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

pub fn clear_signing_variables(task_id: &str) {
    let mut map = SigningTasks.lock().unwrap();
    map.remove(task_id);
    let mut map = SignNonces.lock().unwrap();
    map.remove(task_id);
    let mut map = SigningCommitments.lock().unwrap();
    map.remove(task_id);
    let mut map = SignPackage.lock().unwrap();
    map.remove(task_id);
    let mut map = SignShares.lock().unwrap();
    map.remove(task_id);
}

