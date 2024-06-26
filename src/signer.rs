use bitcoin::{ psbt::raw::Key, sighash::SighashCache, Psbt};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use libp2p::gossipsub::Message;

use crate::{
    cipher::{decrypt, encrypt}, config::Config, messages::{DKGRoundMessage, SignMessage, SigningBehaviour, SigningSteps, Task}, store
};
use frost::Identifier;
use frost_secp256k1 as frost;
use frost_secp256k1::{keys::{PublicKeyPackage, KeyPackage}, Field};

use log::{debug, error, info};
use rand::thread_rng;
pub struct Signer {
    config: Config,
    msg_key: x25519_dalek::StaticSecret,
    max_signers: usize,
    min_signers: usize,
    participant_identifier: Identifier,
}

impl Signer {
    pub fn new(conf: Config) -> Self {
        let b = STANDARD.decode(&conf.p2p.local_key).unwrap();
        let sized: [u8; 32] = b.try_into().unwrap();
        let local_key = x25519_dalek::StaticSecret::from(sized);

        let pubkey = x25519_dalek::PublicKey::from(&local_key);
        // frost::Secp256K1Sha256::H1(m).to_bytes();
        let id = frost_secp256k1::Secp256K1ScalarField::deserialize(pubkey.as_bytes()).unwrap();

        let identifier = frost::Identifier::new(id).unwrap();
        info!("identifier: {:?}", identifier);
        Self {
            config: conf,
            msg_key: local_key,
            max_signers: 3,
            min_signers: 2,
            participant_identifier: identifier,
        }
    }

    pub fn dkg_init(&mut self, behave: &mut SigningBehaviour, task: &Task) {
        let mut rng = thread_rng();
        let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
            self.participant_identifier.clone(),
            self.max_signers as u16,
            self.min_signers as u16,
            &mut rng,
        )
        .expect("Error in DKG round 1");
        debug!(
            "round1_secret_package: {:?}, {:?}",
            &round1_secret_package, &round1_package
        );

        store::set_dkg_round1_secret_packet(&task.id, round1_secret_package.clone());

        let round1_message = DKGRoundMessage {
            task_id: task.id.clone(),
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
            if received_round1_packages.len() == self.max_signers.clone() - 1 {
                let round1_secret_package =
                    store::get_dkg_round1_secret_packet(&round1_package.task_id);
                match round1_secret_package {
                    Some(secret_package) => {
                        let (round2_secret_package, round2_packages) =
                            frost::keys::dkg::part2(secret_package, &received_round1_packages)
                                .expect("error in DKG round 2");

                        debug!("**********\n");
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
            if received_round2_packages.len() == self.min_signers {
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

                        // info!("Generated Signing Key: {:?}", &key);
                        // info!("Generated Public Key: {:?}", &pubkey.serialize().unwrap());

                        let store_key_bytes = &pubkey
                            .verifying_key()
                            .serialize()
                            .expect("msg not serialized");
                        let store_key_hex = hex::encode(&store_key_bytes);
                        let privkey_bytes = key.serialize().expect("key not serialized");
                        let pubkey_bytes = pubkey.serialize().expect("pubkey not serialized");

                        self.config
                            .keys
                            .insert(store_key_hex.clone(), STANDARD.encode(&privkey_bytes));
                        self.config
                            .pubkeys
                            .insert(store_key_hex.clone(), STANDARD.encode(&pubkey_bytes));
                        self.config.save().expect("Failed to save generated keys");


                        info!("DKG Completed: {:?}, {}", store_key_hex, &store_key_bytes.len());

                        // match PublicKey::from_slice(&text[..]) {
                        //     Ok(pk) => {
                        //         debug!("pk: {:?}", pk);
                        //     }
                        //     Err(e) => {
                        //         error!("Error: {:?}", e);
                        //     }
                        // };
                    }
                    None => {
                        error!("round2_secret_package not found");
                    }
                }
            }
        }
    }

    pub fn sign_init(&mut self, behave: &mut SigningBehaviour, task: &Task) {
        let psbt_bytes = STANDARD.decode(task.message.clone()).unwrap();
        let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
            Ok(psbt) => psbt,
            Err(e) => {
                error!("Failed to deserialize PSBT: {}", e);
                return;
            }
        };

        store::set_signing_task(&task.id, psbt.clone());

        let len = psbt.inputs.len();
        for i in 0..len {
            let input = &psbt.inputs[i];
            if input.witness_utxo.is_none() {
                continue;
            }

            let prev_tx = match psbt
                .inputs[i]
                .witness_utxo
                .clone() {
                Some(utxo) => utxo,
                None => {
                    error!("Failed to get witness_utxo");
                    return;
                }
            };

            info!("prev_tx: {:?}", prev_tx.script_pubkey);

            // Calculate the signature hash (sighash)
            let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
            let sighash = match sighash_cache.p2wpkh_signature_hash(i, &prev_tx.script_pubkey, prev_tx.value, bitcoin::EcdsaSighashType::All) {
                Ok(sighash) => sighash,
                Err(e) => {
                    error!("Failed to get sighash: {}", e);
                    return;
                }            
            };

            for (pubkey, _) in &input.bip32_derivation {
                debug!("  Public Key (hex): {}", pubkey.to_string());

                let sign_key = match self.config.keys.get(pubkey.to_string().as_str()) {
                    Some(key) => {
                        let bytes = STANDARD.decode(key).unwrap();
                        frost::keys::KeyPackage::deserialize(bytes.as_slice()).expect("key package not deserialized")
                    }
                    None => {
                        error!("Failed to get signing key for pubkey: {}", pubkey);
                        continue;
                    }
                };
    
                let mut rng = thread_rng();
                let (nonce, commitments) =
                    frost::round1::commit(sign_key.signing_share(), &mut rng);
    
                // self.sign_nonces_store.insert(task.id.clone(), nonces);
                store::set_sign_nonces(&task.id, nonce);
                store::set_signing_commitments(&task.id, self.participant_identifier, commitments);
    
                let sign_message = SignMessage {
                    task_id: task.id.clone(),
                    party_id: self.participant_identifier,
                    pubkey: pubkey.to_string(),
                    packet: commitments,
                    message: sighash.to_string(),
                };
    
                let new_msg = serde_json::to_string(&sign_message).expect("msg not serialized");
                behave
                    .gossipsub
                    .publish(SigningSteps::SignRound1.topic(), new_msg.as_bytes())
                    .expect("msg not published");
            }
        }
                
    }

    pub fn sign_round1(&mut self, behave: &mut SigningBehaviour, msg: &Message) {

        let sign_message: SignMessage<frost::round1::SigningCommitments> =
            serde_json::from_slice(&msg.data).expect("error in sign_round1");

        // self.sign_commitment_store
        //     .insert(sign_message.party_id, sign_message.packet);
        store::set_signing_commitments(&sign_message.task_id, sign_message.party_id, sign_message.packet.clone());
        debug!("recieved commitment: {:?}", sign_message);

        let signing_commitments = match store::get_signing_commitments(&sign_message.task_id) {
            Some(commitments) => commitments,
            None => {
                error!("Failed to get commitments for task: {}", sign_message.task_id);
                return;
            }
        };
        if signing_commitments.len() == self.min_signers {
            // let signing_package = frost::SigningPackage::new(commitment_store.clone(), sign_message.message.clone().as_bytes());
            // let raw = hex::decode(sign_message.message.clone()).unwrap();
            let signing_package = frost::SigningPackage::new(
                signing_commitments.clone(),
                &sign_message.message.as_bytes(),
            );

            debug!("sign_message: {:?}", sign_message);
            // self.sign_package_store.insert(
            //     sign_message.message.clone().digest(),
            //     signing_package.clone(),
            // );
            store::set_sign_package(&sign_message.task_id, signing_package.clone());

            let signer_nonces = match store::get_sign_nonces(&sign_message.task_id) {
                Some(n) => n,
                None => {
                    error!("Failed to get nonces for task: {}", sign_message.task_id);
                    return;
                }
            };
            let key_text = match self.config.keys.get(&sign_message.pubkey) {
                Some(text) => text,
                None => {
                    error!("not found pubkey for task: {}", sign_message.task_id);
                    return;
                }
            };
            let key_bytes = STANDARD.decode(key_text).unwrap();
            let key_package = match KeyPackage::deserialize(&key_bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    error!("Error: {:?}", e);
                    return;
                }            
            };

            let signature_shares = match frost::round2::sign(&signing_package, &signer_nonces, &key_package) {
                Ok(shares) => shares,
                Err(e) => {
                    error!("Error: {:?}", e);
                    return;
                }
            };

            // self.sign_shares_store
            //     .insert(sign_message.party_id, sign_message.packet.clone());
            store::set_sign_shares(&sign_message.task_id, self.participant_identifier, signature_shares);

            let sig_shares_message = SignMessage {
                task_id: sign_message.message.clone(),
                party_id: self.participant_identifier,
                pubkey: sign_message.pubkey.clone(),
                packet: signature_shares,
                message: sign_message.message.clone(),
            };

            let new_msg = serde_json::to_string(&sig_shares_message).unwrap();
            behave
                .gossipsub
                .publish(SigningSteps::SignRound2.topic(), new_msg.as_bytes())
                .expect("msg not published");
        }
    }

    pub fn sign_round2(&mut self, msg: &Message) {
        let sig_shares_message: SignMessage<frost::round2::SignatureShare> =
            serde_json::from_slice(&msg.data).expect("msg not deserialized");
        debug!("sign_message: {:?}", &sig_shares_message);

        // self.sign_shares_store
        //     .insert(sig_shares_message.party_id, sig_shares_message.packet.clone());
        // debug!("sign_shares_store: {:?}", self.sign_shares_store.len());
        store::set_sign_shares(&sig_shares_message.task_id, sig_shares_message.party_id, sig_shares_message.packet.clone());

        let signature_shares = match store::get_sign_shares(&sig_shares_message.task_id) {
            Some(shares) => shares,
            None => {
                error!("Failed to get shares for task: {}", sig_shares_message.task_id);
                return;
            }
        };
        if signature_shares.len() == self.min_signers {
            debug!("=============================");
            let signing_package = match store::get_sign_package(&sig_shares_message.task_id) {
                Some(package) => package,
                None => {
                    error!("not found signing package for task: {}", sig_shares_message.task_id);
                    return;
                }
            };
            // println!("signing_package: {:?}", signing_package);
            let pubkey_text = match self.config.pubkeys.get(&sig_shares_message.pubkey) {
                Some(text) => text,
                None => {
                    error!("not found pubkey for task: {}", sig_shares_message.task_id);
                    return;
                }
            };
            let pubkey_bytes = STANDARD.decode(pubkey_text).unwrap();
            let pubkeys = match PublicKeyPackage::deserialize(&pubkey_bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    error!("Error: {:?}", e);
                    return;
                }            
            };
            match frost::aggregate( &signing_package, &signature_shares, &pubkeys) {
                Ok(signature) => {
                    // println!("public key: {:?}", pub)
                    let is_signature_valid = pubkeys
                        .verifying_key()
                        .verify(sig_shares_message.message.as_bytes(), &signature)
                        .is_ok();
                    info!("Signature: {:?} verified: {:?}", signature, is_signature_valid);

                    // let text = public_key_package[0]
                    //     .verifying_key().serialize();
                    // XOnlyPublicKey::from_slice(&text).unwrap();

                    // let text = &self.public_key_package[0]
                    //     .verifying_key()
                    //     .serialize()
                    //     .expect("msg not serialized");
                    // debug!("verify key: {:?}, {}", &text, &text.len());
                    // match PublicKey::from_slice(&text[..]) {
                    //     Ok(pk) => {
                    //         debug!("pk: {:?}", pk);

                    //         // println!("messege: {:?}", &text_bytes);

                    //         // let secp = Secp256k1::verification_only();
                    //         // let msg = Message::from_digest_slice(text_bytes.to_vec().as_slice()).unwrap();
                    //         // let sig = bitcoin::ecdsa::Signature::from_slice(&signature.serialize()[..]).unwrap();
                    //         // match pk.verify(&secp, &msg, &sig) {
                    //         //     Ok(_) => println!("Signature is valid!"),
                    //         //     Err(e) => println!("Error: {:?}", e),
                    //         // };
                    //     }
                    //     Err(e) => {
                    //         error!("Error: {:?}", e);
                    //     }
                    // };
                }
                Err(e) => {
                    error!("Error: {:?}", e);
                }
            };
        }
    }
}

// fn sign_psbt(psbt_base64: &str, wif: &str) -> Result<Psbt, std::io::Error> {
//     // Deserialize the PSBT
//     let psbt_bytes = base64::decode(psbt_base64).unwrap();
//     let psbt = Psbt::deserialize(psbt_bytes.as_slice()).unwrap();

//     // Sign the PSBT
//     for input in &psbt.inputs {
//         if input.witness_utxo.is_none() {
//             continue;
//         }

//         // let sighash = input.;

//         let pk = PublicKey::from_slice(vec![0; 33].as_slice()).unwrap();
//         let sig = Signature::from_slice(&[0; 64].as_slice()).unwrap();

//         input.partial_sigs.insert(pk, sig);
//     }

//     Ok(psbt)
// }
