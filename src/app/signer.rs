use core::hash;

use bitcoin::{key::{TapTweak as _, UntweakedPublicKey}, secp256k1::{self, ecdsa::Signature}, sighash::{self, SighashCache}, Address, EcdsaSighashType, Psbt, PublicKey, Script, TxOut};
use bitcoin_hashes::Hash;
use frost_core::Field;
use libp2p::gossipsub::Message;
use toml::de;

use crate::{app::config::{self, Config}, commands::sign, helper::{messages::now, pbst::{self, get_group_address}}};
use crate::helper::{
    cipher::{decrypt, encrypt}, encoding::{self, from_base64}, messages::{DKGRoundMessage, SignMessage, SigningBehaviour, SigningSteps, Task}, store
};
use frost::Identifier;
use frost_secp256k1_tr as frost;

use ::bitcoin::secp256k1::schnorr::{Signature as SchnorrSignature};

use tracing::{debug, error, info};
use rand::thread_rng;
pub struct Signer {
    config: Config,
    msg_key: x25519_dalek::StaticSecret,
    // max_signers: usize,
    // min_signers: usize,
    participant_identifier: Identifier,
}

impl Signer {
    pub fn new(conf: Config) -> Self {
        let b = encoding::from_base64(&conf.p2p.local_key).unwrap();
        let sized: [u8; 32] = b.try_into().unwrap();
        let local_key = x25519_dalek::StaticSecret::from(sized);
        let pubkey = x25519_dalek::PublicKey::from(&local_key);
        // frost::Secp256K1Sha256::H1(m).to_bytes();
        let id = frost::Secp256K1ScalarField::deserialize(pubkey.as_bytes()).unwrap();
        let identifier = frost_core::Identifier::new(id).unwrap(); 
        // let identifier = frost::Identifier::derive(&[0; 32]).expect("Error in identifier");
        info!("identifier: {:?}", identifier);
        Self {
            config: conf,
            msg_key: local_key,
            // max_signers: 3,
            // min_signers: 2,
            participant_identifier: identifier,
        }
    }

    pub fn dkg_init(&mut self, behave: &mut SigningBehaviour, task: &Task) {
        let mut rng = thread_rng();
        let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
            self.participant_identifier.clone(),
            task.max_signers,
            task.min_signers,
            &mut rng,
        )
        .expect("error in DKG round 1");
        debug!(
            "round1_secret_package: {:?}, {:?}",
            &round1_secret_package, &round1_package
        );

        store::set_dkg_round1_secret_packet(&task.id, round1_secret_package.clone());

        let round1_message = DKGRoundMessage {
            task_id: task.id.clone(),
            max_signers: task.max_signers,
            min_signers: task.min_signers,
            from_party_id: self.participant_identifier,
            to_party_id: None,
            packet: &round1_package,
        };

        let new_msg = serde_json::to_string(&round1_message).expect("msg not serialized");
        behave
            .gossipsub
            .publish(SigningSteps::DkgRound1.topic(), new_msg.as_bytes())
            .expect("msg not published");
    }

    pub fn dkg_round1(&mut self, behave: &mut SigningBehaviour, msg: &Message) {
        let round1_package: DKGRoundMessage<frost::keys::dkg::round1::Package> =
            serde_json::from_slice(&msg.data).expect("msg not deserialized");
        debug!("round1_package: {:?}", round1_package);

        store::set_dkg_round1_packets(
            &round1_package.task_id,
            round1_package.from_party_id,
            round1_package.packet.clone(),
        );

        if let Some(received_round1_packages) =
            store::get_dkg_round1_packets(&round1_package.task_id)
        {
            if received_round1_packages.len() as u16 == round1_package.max_signers - 1 {
                let round1_secret_package =
                    store::get_dkg_round1_secret_packet(&round1_package.task_id);
                match round1_secret_package {
                    Some(secret_package) => {
                        let (round2_secret_package, round2_packages) =
                            frost::keys::dkg::part2(secret_package, &received_round1_packages)
                                .expect("error in DKG round 2");
                        debug!(
                            "round2_secret_package: {:?}, {:?}",
                            &round2_secret_package, &round2_packages
                        );
                        // self.round2_secret_package_store.push(round2_secret_package);
                        store::set_dkg_round2_secret_packet(
                            &round1_package.task_id,
                            round2_secret_package.clone(),
                        );

                        for (receiver_identifier, round2_package) in round2_packages {
                            let bz = receiver_identifier.serialize();
                            let sized: [u8; 32] = bz.try_into().unwrap();
                            let target = x25519_dalek::PublicKey::from(sized);

                            let share_key = self.msg_key.diffie_hellman(&target);

                            let byte = round2_package.serialize().unwrap();
                            let packet = encrypt(byte.as_slice(), share_key.as_bytes());

                            let round2_message = DKGRoundMessage {
                                task_id: round1_package.task_id.clone(),
                                min_signers: round1_package.min_signers,
                                max_signers: round1_package.max_signers,
                                from_party_id: self.participant_identifier.clone(),
                                to_party_id: Some(receiver_identifier.clone()),
                                packet: packet,
                            };

                            let new_msg =
                                serde_json::to_string(&round2_message).expect("msg not serialized");
                            behave
                                .gossipsub
                                .publish(SigningSteps::DkgRound2.topic(), new_msg.as_bytes())
                                .expect("msg not published");
                        }
                    }
                    None => {
                        error!("round1_secret_package not found");
                    }
                }
            }
        }
    }

    pub fn dkg_round2(&mut self, msg: &Message) {
        let round2_package: DKGRoundMessage<Vec<u8>> =
            serde_json::from_slice(&msg.data).expect("msg not deserialized");
        debug!("round2_package: {:?}", String::from_utf8_lossy(&msg.data));

        if let Some(to) = round2_package.to_party_id {
            if to != self.participant_identifier {
                return;
            }
        }

        let bz = round2_package.from_party_id.serialize();
        let sized: [u8; 32] = bz.try_into().unwrap();
        let source = x25519_dalek::PublicKey::from(sized);

        let share_key = self.msg_key.diffie_hellman(&source);

        let packet = decrypt(round2_package.packet.as_slice(), share_key.as_bytes());
        let received_round2_package =
            frost::keys::dkg::round2::Package::deserialize(&packet).unwrap();

        store::set_dkg_round2_packets(
            &round2_package.task_id,
            round2_package.from_party_id.clone(),
            received_round2_package,
        );

        if let Some(received_round2_packages) =
            store::get_dkg_round2_packets(&round2_package.task_id)
        {
            if received_round2_packages.len() as u16 == round2_package.max_signers - 1 {
                let round2_secret_package =
                    store::get_dkg_round2_secret_packet(&round2_package.task_id);
                match round2_secret_package {
                    Some(secret_package) => {
                        let received_round1_packages =
                            match store::get_dkg_round1_packets(round2_package.task_id.as_str()) {
                                Some(packages) => packages,
                                None => {
                                    error!("round1_secret_package not found");
                                    return;
                                }
                            };

                        let (key, pubkey) = frost::keys::dkg::part3(
                            &secret_package,
                            &received_round1_packages,
                            &received_round2_packages,
                        )
                        .expect("msg not deserialized");

                        // clean caches
                        store::clear_dkg_variables(&round2_package.task_id);

                        let address = get_group_address(pubkey.verifying_key(), self.config.network);
                        info!(
                            "DKG Completed: {:?}, {:?}",
                            address.to_string(),
                            &pubkey,
                        );

                        let privkey_bytes = key.serialize().expect("key not serialized");
                        let pubkey_bytes = pubkey.serialize().expect("pubkey not serialized");
                        
                        config::add_sign_key(&address.to_string(), key);
                        config::add_pub_key(&address.to_string(), pubkey);

                        self.config
                            .keys
                            .insert(address.to_string(), encoding::to_base64(&privkey_bytes));
                        self.config
                            .pubkeys
                            .insert(address.to_string(), encoding::to_base64(&pubkey_bytes));
                        self.config.save().expect("Failed to save generated keys");

                    }
                    None => {
                        error!("round2_secret_package not found");
                    }
                }
            }
        }
    }

    pub fn sign_init(&mut self, behave: &mut SigningBehaviour, psbt_str: &str) {

        let psbt_bytes = from_base64(psbt_str).unwrap();
        let group_task_id = bitcoin_hashes::sha256::Hash::hash(&psbt_bytes).to_string();
        // if store::has_signing_task(group_task_id.as_str()) {
        //     info!(group_task_id, "skip task, already exists");
        //     return;
        // }

        let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
            Ok(psbt) => psbt,
            Err(e) => {
                error!("Failed to deserialize PSBT: {}", e);
                return;
            }
        };

        store::set_signing_task(&group_task_id, psbt.clone());

        let len = psbt.inputs.len();
        debug!("(signing round 0) prepare for signing: {:?} tasks", len);
        for i in 0..len {

            let input = &psbt.inputs[i];
            if input.witness_utxo.is_none() {
                continue;
            }

            let prev_utxo = match psbt.inputs[i].witness_utxo.clone() {
                Some(utxo) => utxo,
                None => {
                    error!("Failed to get witness_utxo");
                    return;
                }
            };

            info!("prev_tx: {:?}", prev_utxo.script_pubkey);
            let script = input.witness_utxo.clone().unwrap().script_pubkey;
            let address: Address = Address::from_script(&script, self.config.network).unwrap();

            // get the message to sign
            let hash_ty = input
                .sighash_type
                .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
                .unwrap_or(bitcoin::TapSighashType::All);
            let hash = match SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
                i,
                &sighash::Prevouts::All(&[TxOut {
                    value: prev_utxo.value,
                    script_pubkey: script,
                }]),
                hash_ty,
            ) {
                Ok(hash) => hash,
                Err(e) => {
                    error!("failed to compute sighash: {}", e);
                    return;
                }
            };

            let sign_key = match config::get_sign_key(address.to_string().as_str()) {
                Some(key) => {
                    debug!("loaded key: {:?}", key);
                    key
                }
                None => {
                    error!("Failed to get signing key for address: {}", address);
                    continue;
                }
            };

            let mut rng = thread_rng();
            let (nonce, commitments) = frost::round1::commit(sign_key.signing_share(), &mut rng);

            // let task = Task::new(group_task.step, group_task.message);
            let sub_task_id = format!("{}-{}", group_task_id, i);

            // self.sign_nonces_store.insert(task.id.clone(), nonces);
            debug!("(signing round 0) save nonces for {:?} ", &sub_task_id);

            // let pubkey = match config::get_pub_key(address.to_string().as_str()) {
            //     Some(pk) => pk,
            //     None => {
            //         error!("Failed to get pubkey for address: {}", address);
            //         continue;
            //     }
            // };
            
            let variables = store::TaskVariables {
                signing_nonces: nonce,
                address: address.to_string(),
                // pubkey, 
                sighash: hash.to_raw_hash().to_byte_array().to_vec(),
                group_task_id: group_task_id.clone(),
                step: SigningSteps::SignInit,
            };
            store::set_signing_task_variables(&sub_task_id, variables);
            // store::set_sign_nonces(&sub_task_id, nonce);
            store::set_signing_commitments(&sub_task_id, self.participant_identifier, commitments);

            let sign_message = SignMessage {
                task_id: sub_task_id,
                party_id: self.participant_identifier,
                address: address.to_string(),
                // message: hex::encode(hash.to_raw_hash()),
                packet: commitments,
                timestamp : 0,
            };

            let new_msg = serde_json::to_string(&sign_message).expect("msg not serialized");
            match behave.gossipsub.publish(SigningSteps::SignRound1.topic(), new_msg.as_bytes()) {
                Ok(_) => {
                    debug!("Published commitments to gossip: {:?}", new_msg);
                }
                Err(e) => {
                    error!("Failed to publish message to gossip: {:?}", e);
                }
            };
        }
    }

    pub fn sign_round1(&mut self, msg: &Message) {

        let sign_message: SignMessage<frost::round1::SigningCommitments> =
            serde_json::from_slice(&msg.data).expect("error in sign_round1");

        // filter packets from unknown parties
        match config::get_pub_key(sign_message.address.as_str()) {
            Some(pubkey) => {
                if pubkey.verifying_shares().contains_key(&sign_message.party_id) {
                    store::set_signing_commitments(
                        &sign_message.task_id,
                        sign_message.party_id,
                        sign_message.packet.clone(),
                    );
                    debug!("(signing round 1) received commitments: {:?}", &sign_message);
                }
            }
            None => {
                error!("skip task, no pubkey found for task: {:?}", sign_message.task_id);
            }
        };

    }

    pub fn sign_round2(&mut self, msg: &Message) {
        let sig_shares_message: SignMessage<frost::round2::SignatureShare> =
            serde_json::from_slice(&msg.data).expect("msg not deserialized");

        let signing_package = match store::get_sign_package(&sig_shares_message.task_id) {
            Some(package) => package,
            None => {
                error!("Failed to get signing package for task: {}", sig_shares_message.task_id);
                return;
            }
        };

        if signing_package.signing_commitments().contains_key(&sig_shares_message.party_id) {
            debug!("found commitment for: {:?}", sig_shares_message.party_id);
            store::set_sign_shares(
                &sig_shares_message.task_id,
                sig_shares_message.party_id,
                sig_shares_message.packet.clone(),
            );
        } else {
            error!("commitment not found for: {:?}", sig_shares_message.party_id);
            return;
        }

        let signature_shares = match store::get_sign_shares(&sig_shares_message.task_id) {
            Some(shares) => shares,
            None => {
                error!(
                    "Failed to get shares for task: {}",
                    sig_shares_message.task_id
                );
                return;
            }
        };

        debug!("(signing round 2) received shares: {:?} {:?}", signature_shares.len(), &sig_shares_message);

        if signature_shares.len() == signing_package.signing_commitments().len()  {

            debug!("commentments keys: {:?}", signing_package.signing_commitments().keys());
            debug!("signature shares: {:?}", signature_shares.keys());

            let signing_variables = store::get_signing_task_variables(sig_shares_message.task_id.as_str()).unwrap();

            let pubkeys = match config::get_pub_key(&signing_variables.address) {
                Some(pk) => pk,
                None => {
                    error!("not found pubkey for : {:?}", &signing_variables.address);
                    return;
                }
            };

            match frost::aggregate(&signing_package, &signature_shares, &pubkeys) {
                Ok(signature) => {
                    // println!("public key: {:?}", pub)
                    // let sighash = &hex::decode(sig_shares_message.message).unwrap();
                    let is_signature_valid = pubkeys
                        .verifying_key()
                        .verify(signing_variables.sighash.as_slice(), &signature)
                        .is_ok();
                    info!(
                        "Signature: {:?} verified: {:?}",
                        signature, is_signature_valid
                    );
                  
                    match store::get_signing_task(&signing_variables.group_task_id) {
                        Some(psbt) => {
                            let mut psbt = psbt.clone();

                            let pubkey = PublicKey::from_slice(&pubkeys.verifying_key().serialize()).unwrap();
                            debug!("pubkey: {:?}", pubkey.to_bytes());

                            let sig_bytes = signature.serialize();
                            debug!("signature: {:?}, {}", sig_bytes, sig_bytes.len());

                            // verify signature
                            let secp = secp256k1::Secp256k1::new();
                            let utpk = UntweakedPublicKey::from(pubkey.inner);
                            let (tpk, _) = utpk.tap_tweak(&secp, None);
                            // let addr = Address::p2tr(&secp, tpk., None, Network::Bitcoin);
                            // let sig_b = group_signature.serialize();
                            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes[1..]).unwrap();
                            let msg = bitcoin::secp256k1::Message::from_digest_slice(&signing_variables.sighash).unwrap();
                            match secp.verify_schnorr(&sig, &msg, &tpk.to_inner()) {
                                Ok(_) => info!("Signature is valid"),
                                Err(e) => error!("Signature is invalid: {}", e),
                            }

                            // add sig to psbt
                            let hash_ty = bitcoin::sighash::TapSighashType::Default;
                            let sighash_type =  bitcoin::psbt::PsbtSighashType::from(hash_ty);
                            let sig = SchnorrSignature::from_slice(&sig_bytes[1..]).unwrap();
                            let index = extract_index_from_task_id(sig_shares_message.task_id.as_str());
                            psbt.inputs[index].sighash_type = Option::Some(sighash_type);
                            psbt.inputs[index].tap_key_sig = Option::Some(bitcoin::taproot::Signature {
                                signature: sig,
                                sighash_type: hash_ty,
                            });

                            let psbt_bytes = psbt.serialize();
                            let psbt_base64 = encoding::to_base64(&psbt_bytes);
                            info!("Signed PSBT: {:?}", psbt_base64);
                        }
                        None => {
                            error!("Failed to get group task: {}", &signing_variables.group_task_id);
                        }                    
                    };
                }
                Err(e) => {
                    error!("Signature aggregation error: {:?}", e);
                }
            };
            // store::clear_signing_variables(sig_shares_message.task_id.as_str());
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}

fn extract_index_from_task_id(task_id: &str) -> usize {
    let parts: Vec<&str> = task_id.split("-").collect();
    let index = parts[1].parse::<usize>().unwrap();
    index
}

pub fn broadcast_signing_commitments( 
    behave: &mut SigningBehaviour,
    signer: &mut Signer,
) {

    let pending_commitments = store::get_all_signing_commitments();

    pending_commitments.iter().for_each(|(task_id, commitments)| {
        let mut signing_variables = match store::get_signing_task_variables(task_id) {
            Some(variables) => variables,
            None => {
                error!("Failed to get signing variables for task: {}", task_id);
                // store::clear_signing_variables(task_id);
                return;
            }        
        };

        let sign_key = match config::get_sign_key(&signing_variables.address) {
            Some(pk) => pk,
            None => {
                error!("not found signing key for {}", &signing_variables.address);
                return;
            }
        };

        if signing_variables.step == SigningSteps::SignInit && commitments.len() as u16 >= *sign_key.min_signers() {
            debug!("(signing round 1) collected enough commitment {:?} for tasks {:?}", commitments.len(), task_id);

            // update step
            signing_variables.step = SigningSteps::SignRound1;
            store::set_signing_task_variables(task_id, signing_variables.clone());

            let signing_package = frost::SigningPackage::new(
                commitments.clone(), 
                &signing_variables.sighash
            );

            store::set_sign_package(task_id, signing_package.clone());

            let key_package = match config::get_sign_key(&signing_variables.address) {
                Some(pk) => pk,
                None => {
                    error!("not found signing key for {}", &signing_variables.address);
                    return;
                }
            };

            if store::has_sign_shares(task_id) {
                info!("skip task, already signed");
                return;
            }

            let signature_shares =
                match frost::round2::sign(&signing_package, &signing_variables.signing_nonces, &key_package) {
                    Ok(shares) => shares,
                    Err(e) => {
                        error!("Error: {:?}", e);
                        return;
                    }
                };

            store::set_sign_shares(
                task_id.as_str(),
                signer.participant_identifier,
                signature_shares,
            );

            let addr = &signing_variables.address.clone();
            let sig_shares_message = SignMessage {
                task_id: task_id.clone(),
                party_id: signer.participant_identifier,
                address: addr.to_string(),
                packet: signature_shares,
                timestamp: now(),
            };

            let new_msg = serde_json::to_string(&sig_shares_message).unwrap();
            match behave.gossipsub.publish(SigningSteps::SignRound2.topic(), new_msg.as_bytes()) {
                Ok(_) => {
                    info!("Published signature share to gossip: {:?}", new_msg);
                }
                Err(e) => {
                    error!("Failed to publish message to gossip: {:?}", e);
                }
            };
        }
    });

}