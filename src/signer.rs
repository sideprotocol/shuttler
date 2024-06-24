use std::collections::BTreeMap;
use frost_core::Ciphersuite;
use libp2p::{gossipsub, PeerId};
use sha256::Sha256Digest;

use crate::messages::{DKGRound2Message, DKGRoundMessage, SignMessage, SigningBehaviour, SigningSteps};
use bitcoin::PublicKey;
use frost_secp256k1 as frost;

use rand::thread_rng;
use log::{debug, error, info};


pub struct Signer {
    max_signers: usize,
    min_signers: usize,
    participant_identifier: frost::Identifier,
    received_round1_packages: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    received_round2_packages: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    round2_secret_package_store: Vec<frost::keys::dkg::round2::SecretPackage>,
    local_key: Vec<frost::keys::KeyPackage>,
    public_key_package: Vec<frost::keys::PublicKeyPackage>,
    sign_nonces_store: BTreeMap<String, frost::round1::SigningNonces>,
    sign_commitment_store: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    sign_package_store: BTreeMap<String, frost::SigningPackage>,
    sign_shares_store: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    round1_secret_package: Vec<frost::keys::dkg::round1::SecretPackage>,
}

impl Signer {
    pub fn new(peer_id: PeerId, max_signer: usize, min_signer: usize) -> Self {
        let identifier: frost::Identifier = frost::Identifier::new(frost::Secp256K1Sha256::H1(peer_id.to_bytes().as_slice())).unwrap();
        info!("identifier: {:?}", identifier);
        Self {
            max_signers: max_signer,
            min_signers: min_signer,
            participant_identifier: identifier,
            received_round1_packages: BTreeMap::new(),
            received_round2_packages: BTreeMap::new(),
            round2_secret_package_store: vec![],
            round1_secret_package: vec![],
            local_key: vec![],
            public_key_package: vec![],
            sign_nonces_store: BTreeMap::new(),
            sign_commitment_store: BTreeMap::new(),
            sign_package_store: BTreeMap::new(),
            sign_shares_store: BTreeMap::new(),
        }
    }

    pub fn dkg_init(&mut self, behave: &mut SigningBehaviour) {
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

        let round1_message = DKGRoundMessage {
            party_id: self.participant_identifier,
            packet: &round1_package,
        };

        let new_msg = serde_json::to_string(&round1_message).expect("msg not serialized");
        behave.gossipsub
            .publish(SigningSteps::DkgRound1.topic(), new_msg.as_bytes())
            .expect("msg not published");
    }

    pub fn dkg_round1(&mut self, behave: &mut SigningBehaviour, msg: &Vec<u8>) {
        let round1_package: DKGRoundMessage<frost::keys::dkg::round1::Package> =
            serde_json::from_slice(msg).expect("msg not deserialized");
        debug!("round1_package: {:?}", round1_package);
        self.received_round1_packages
            .insert(round1_package.party_id, round1_package.packet);

        if self.received_round1_packages.len() == self.max_signers.clone() - 1 {
            let (round2_secret_package, round2_packages) = frost::keys::dkg::part2(
                self.round1_secret_package[0].clone(),
                &self.received_round1_packages,
            )
            .expect("error in DKG round 2");

            debug!("**********\n");
            debug!(
                "round2_secret_package: {:?}, {:?}",
                &round2_secret_package, &round2_packages
            );
            self.round2_secret_package_store.push(round2_secret_package);

            for (receiver_identifier, round2_package) in round2_packages {
                let round2_message = DKGRound2Message {
                    sender_party_id: self.participant_identifier.clone(),
                    receiver_party_id: receiver_identifier.clone(),
                    packet: round2_package.clone(),
                };

                let new_msg = serde_json::to_string(&round2_message).expect("msg not serialized");
                behave.gossipsub
                    .publish(SigningSteps::DkgRound2.topic(), new_msg.as_bytes())
                    .expect("msg not published");
            }
        }
    }

    pub fn dkg_round2(&mut self, msg: &Vec<u8>) {
        let round2_package: DKGRound2Message =
            serde_json::from_slice(msg).expect("msg not deserialized");
        debug!("round2_package: {:?}", String::from_utf8_lossy(msg));

        if round2_package.receiver_party_id != self.participant_identifier {
            return;
        }
        self.received_round2_packages
            .insert(round2_package.sender_party_id, round2_package.packet);

        if self.received_round2_packages.len() == &self.max_signers - 1 {
            let round2_secret_package = self.round2_secret_package_store.pop().unwrap();
            let (key, pubkey) = frost::keys::dkg::part3(
                &round2_secret_package,
                &self.received_round1_packages,
                &self.received_round2_packages,
            )
            .expect("msg not deserialized");
            debug!("**********");
            debug!("round3_secret_package: {:?},\n\n {:?}", &key, &pubkey);
            self.local_key.push(key);
            self.public_key_package.push(pubkey.clone());

            let text = &pubkey
                .verifying_key()
                .serialize()
                .expect("msg not serialized");
            debug!("text: {:?}, {}", &text, &text.len());
            match PublicKey::from_slice(&text[..]) {
                Ok(pk) => {
                    debug!("pk: {:?}", pk);
                }
                Err(e) => {
                    error!("Error: {:?}", e);
                }
            };
        }
    }

    pub fn sign_init(&mut self, behave: &mut SigningBehaviour, msg: &Vec<u8>) {
        let mut rng = thread_rng();
        let (nonces, commitments) =
            frost::round1::commit(self.local_key[0].signing_share(), &mut rng);
        self.sign_nonces_store.insert(msg.digest(), nonces);

        let sign_message = SignMessage {
            party_id: self.participant_identifier,
            packet: commitments,
            message: msg.digest(),
        };

        // sha256::Hash::hash(msg.as_bytes()).clone();
        self.sign_commitment_store
            .insert(sign_message.party_id, sign_message.packet);

        let new_msg = serde_json::to_string(&sign_message).expect("msg not serialized");
        behave.gossipsub
            .publish(
                SigningSteps::SignRound1.topic(),
                new_msg.as_bytes(),
            )
            .expect("msg not published");
        // Ok(())
    }

    pub fn sign_round1(&mut self, behave: &mut SigningBehaviour, msg: &Vec<u8>) {
        let sign_message: SignMessage<frost::round1::SigningCommitments> =
            serde_json::from_slice(&msg).expect("Error in sign_round1");

        self.sign_commitment_store
            .insert(sign_message.party_id, sign_message.packet);
        debug!("commitment_store: {:?}", self.sign_commitment_store.len());

        if self.sign_commitment_store.len() >= self.max_signers as usize {
            // let signing_package = frost::SigningPackage::new(commitment_store.clone(), sign_message.message.clone().as_bytes());
            // let raw = hex::decode(sign_message.message.clone()).unwrap();
            let signing_package = frost::SigningPackage::new(
                self.sign_commitment_store.clone(),
                &sign_message.message.as_bytes(),
            );

            debug!("sign_message: {:?}", sign_message);
            self.sign_package_store.insert(
                sign_message.message.clone().digest(),
                signing_package.clone(),
            );

            let nonces = self
                .sign_nonces_store
                .get(&sign_message.message.to_string())
                .unwrap();
            let signature_shares =
                frost::round2::sign(&signing_package, &nonces, &self.local_key[0])
                    .expect("signing error in round 2");
            debug!("signature_shares: {:?}", signature_shares);

            let sign_message = SignMessage {
                party_id: self.participant_identifier,
                packet: signature_shares,
                message: sign_message.message.clone(),
            };
            self.sign_shares_store
                .insert(sign_message.party_id, sign_message.packet.clone());

            let new_msg = serde_json::to_string(&sign_message).unwrap();
            behave.gossipsub
                .publish(
                    SigningSteps::SignRound2.topic(),
                    new_msg.as_bytes(),
                )
                .expect("msg not published");
        }
    }

    pub fn sign_round2(&mut self, msg: &Vec<u8>) {
        let sign_message: SignMessage<frost::round2::SignatureShare> =
            serde_json::from_slice(msg).expect("msg not deserialized");
        debug!("sign_message: {:?}", &sign_message);

        self.sign_shares_store
            .insert(sign_message.party_id, sign_message.packet.clone());
        debug!("sign_shares_store: {:?}", self.sign_shares_store.len());

        if self.sign_shares_store.len() == self.max_signers as usize {
            debug!("=============================");
            let signing_package = self
                .sign_package_store
                .get(&sign_message.message.to_string())
                .unwrap();
            // println!("signing_package: {:?}", signing_package);
            match frost::aggregate(
                signing_package,
                &self.sign_shares_store,
                &self.public_key_package[0],
            ) {
                Ok(signature) => {
                    // println!("public key: {:?}", pub)
                    debug!("signature: {:?}", signature.serialize());

                    let is_signature_valid = &self.public_key_package[0]
                        .verifying_key()
                        .verify(sign_message.message.as_bytes(), &signature)
                        .is_ok();
                    debug!("is_signature_valid: {:?}", is_signature_valid);

                    // let text = public_key_package[0]
                    //     .verifying_key().serialize();
                    // XOnlyPublicKey::from_slice(&text).unwrap();

                    let text = &self.public_key_package[0]
                        .verifying_key()
                        .serialize()
                        .expect("msg not serialized");
                    debug!("verify key: {:?}, {}", &text, &text.len());
                    match PublicKey::from_slice(&text[..]) {
                        Ok(pk) => {
                            debug!("pk: {:?}", pk);

                            // println!("messege: {:?}", &text_bytes);

                            // let secp = Secp256k1::verification_only();
                            // let msg = Message::from_digest_slice(text_bytes.to_vec().as_slice()).unwrap();
                            // let sig = bitcoin::ecdsa::Signature::from_slice(&signature.serialize()[..]).unwrap();
                            // match pk.verify(&secp, &msg, &sig) {
                            //     Ok(_) => println!("Signature is valid!"),
                            //     Err(e) => println!("Error: {:?}", e),
                            // };
                        }
                        Err(e) => {
                            error!("Error: {:?}", e);
                        }
                    };
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
