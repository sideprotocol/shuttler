use std::collections::BTreeMap;

use cosmrs::Any;
use frost_adaptor_signature::VerifyingKey;
use side_proto::side::dlc::MsgSubmitAgencyPubKey;
use side_proto::side::lending::{MsgSubmitLiquidationCetSignatures, MsgSubmitRepaymentAdaptorSignatures};
use tracing::error;
use crate::config::VaultKeypair;
use crate::helper::encoding::{from_base64, hash, pubkey_to_identifier, to_base64};
use crate::helper::store::Store;
use crate::protocols::sign::{SignAdaptor, StandardSigner};
use crate::protocols::dkg::{DKGAdaptor, DKG};

use crate::apps::{App, Context, FrostSignature, SubscribeMessage, Task};

use super::event::get_attribute_value;
use super::{Input, SideEvent, SignMode};

/// DCM stands for Distributed Collateral Manager
pub struct DCM {
    pub keygen: DKG<KeygenHander>,
    pub signer: StandardSigner<SignatureHandler>,
}

impl DCM {
    pub fn new() -> Self {
        Self {
            keygen: DKG::new("dcm_dkg", KeygenHander{}),
            signer: StandardSigner::new("attestation2", SignatureHandler {  }),
        }
    }
}

impl App for DCM {

    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()>{
        self.keygen.on_message(ctx, message)?;
        self.signer.on_message(ctx, message)
        // Ok(())
    }
    fn subscribe_topics(&self) -> Vec<libp2p::gossipsub::IdentTopic> {
        vec![self.keygen.topic(), self.signer.topic()]
    }
    fn on_event(&self, ctx: &mut Context, event: &SideEvent) {
       self.keygen.execute(ctx, event);
       self.signer.execute(ctx, event);
    }
}

pub struct KeygenHander{}
impl DKGAdaptor for KeygenHander {
    fn new_task(&self, _ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("create_agency.id") {
                    println!("Events: {:?}", events);

                    let mut tasks = vec![];
                    for ((id, ps), t) in events.get("create_agency.id")?.iter()
                        .zip(events.get("create_agency.participants")?)
                        .zip(events.get("create_agency.threshold")?) {
                        
                            let mut participants = vec![];
                            for p in ps.split(",") {
                                if let Ok(identifier) = from_base64(p) {
                                    participants.push(pubkey_to_identifier(&identifier));
                                }
                            };
                            if let Ok(threshold) = t.parse() {
                                if threshold as usize * 3 >= participants.len() * 2  {
                                    tasks.push(Task::new_dkg(format!("agency-{}", id), participants, threshold));
                                }
                            }
                        };
                    return Some(tasks);
                }
            },
            _ => {},
        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, priv_key: &frost_adaptor_signature::keys::KeyPackage, pub_key: &frost_adaptor_signature::keys::PublicKeyPackage) {
        let tweak = None;
        let rawkey = pub_key.verifying_key().serialize().unwrap();
        let pubkey = hex::encode(&rawkey[1..]);
        let keyshare = VaultKeypair {
            pub_key: pub_key.clone(),
            priv_key: priv_key.clone(),
            tweak,
        };
        ctx.keystore.save(&pubkey, &keyshare);

        let id: u64 = task.id.replace("agency-", "").parse().unwrap();
        let message = hash(&[&id.to_be_bytes()[..], &rawkey[1..]].concat());
        let signature = hex::encode(ctx.node_key.sign(&hex::decode(message).unwrap(), None));

        let cosm_msg = MsgSubmitAgencyPubKey {
            sender: ctx.conf.relayer_bitcoin_address(),
            pub_key: to_base64(ctx.node_key.public_key().as_slice()),
            signature,
            agency_id: id,
            agency_pubkey: pubkey,
        };
        let any = Any::from_msg(&cosm_msg).unwrap();
        if let Err(e) = ctx.tx_sender.send(any) {
            tracing::error!("{:?}", e)
        }

    }
    
}

pub struct SignatureHandler {}
impl SignAdaptor for SignatureHandler {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("liquidate.loan_id") {
                    println!("Liquidate:{:?}", events);
                    let mut tasks = vec![];
                    for ((id, agency_pubkey), sig_hashes) in events.get("liquidate.loan_id")?.iter()
                        .zip(events.get("liquidate.agency_pub_key")?)
                        .zip(events.get("liquidate.sig_hashes")?) {
                            if let Some(keypair) = ctx.keystore.get(&agency_pubkey) {                            
                                let mut sign_inputs = BTreeMap::new();
                                let participants = keypair.pub_key.verifying_shares().keys().map(|p| p.clone()).collect::<Vec<_>>();
                                for sig_hash in sig_hashes.split(",") {
                                    if let Ok(message) = from_base64(sig_hash) {
                                        sign_inputs.insert(0, Input::new_with_message_mode(agency_pubkey.to_owned(), message, participants.clone(), SignMode::Sign));
                                    }
                                }
                                let task= Task::new_signing(format!("liquidate-{}", id), "" , sign_inputs);
                                tasks.push(task);
                            }
                        };
                    return Some(tasks);
                }
                // if events.contains_key("repay.loan_id") {
                //     println!("Repay:{:?}", events);
                //     let mut tasks = vec![];
                //     for (((id, agency_pubkey), adaptor_point), sig_hashes) in events.get("repay.loan_id")?.iter()
                //         .zip(events.get("repay.agency_pub_key")?)
                //         .zip(events.get("repay.adaptor_point")?)
                //         .zip(events.get("repay.sig_hashes")?) {
                //             if let Some(keypair) = ctx.keystore.get(&agency_pubkey) {    
                //                 let participants = keypair.pub_key.verifying_shares().keys().map(|p| p.clone()).collect::<Vec<_>>();
                //                 let adaptor = ctx.keystore.get(adaptor_point)?;
                //                 let mode = SignMode::SignWithAdaptorPoint(adaptor.pub_key.verifying_key().clone());                        
                //                 let mut sign_inputs = BTreeMap::new();
                //                 for sig_hash in sig_hashes.split(",") {
                //                     if let Ok(message) = from_base64(sig_hash) {
                //                         sign_inputs.insert(0, Input::new_with_message_mode(agency_pubkey.to_owned(), message, participants.clone(), mode.clone()));
                //                     }
                //                 }
                //                 let task= Task::new_signing(format!("repay-{}", id), "" , sign_inputs);
                //                 tasks.push(task);
                //             }
                //         };
                //     return Some(tasks);
                // }
            },
            SideEvent::TxEvent(events) => {
                let mut tasks = vec![];
                for e in events.iter().filter(|e| e.kind == "repay") {
                    let loan_id = get_attribute_value(&e.attributes, "loan_id")?;
                    let agency_pubkey = get_attribute_value(&e.attributes, "agency_pub_key")?;
                    let adaptor_point = get_attribute_value(&e.attributes, "adaptor_point")?;
                    let sig_hashes = get_attribute_value(&e.attributes, "sig_hashes")?;

                    if let Some(keypair) = ctx.keystore.get(&agency_pubkey) {
                        let participants = keypair.pub_key.verifying_shares().keys().map(|p| p.clone()).collect::<Vec<_>>();
                        let hex_adaptor = hex::decode(adaptor_point).ok()?;
                        
                        if let Ok(adaptor) = VerifyingKey::deserialize(&hex_adaptor) {
                            let mode = SignMode::SignWithAdaptorPoint(adaptor);                        
                            let mut sign_inputs = BTreeMap::new();
                            for sig_hash in sig_hashes.split(",") {
                                if let Ok(message) = from_base64(sig_hash) {
                                    sign_inputs.insert(0, Input::new_with_message_mode(agency_pubkey.to_owned(), message, participants.clone(), mode.clone()));
                                }
                            }
                            let task= Task::new_signing(format!("repay-{}", loan_id), "" , sign_inputs);
                            tasks.push(task);
                        } else {
                            error!("Invalid adaptor point");
                        }
                    }

                };
                return Some(tasks);
            },
        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task)-> anyhow::Result<()> {
        let cosm_msg = if task.id.starts_with("liquidate") { 
            let mut sigs = vec![];
            for (_, input) in task.sign_inputs.iter() {
                if let Some(FrostSignature::Standard(sig)) = &input.signature  {
                    sigs.push(hex::encode(&sig.serialize()?));
                }
            }
            Any::from_msg(&MsgSubmitLiquidationCetSignatures {
                loan_id: task.id.replace("liquidate-", ""),
                sender: ctx.conf.relayer_bitcoin_address(),
                signatures: sigs,
            })?
        } else {
            let mut sigs = vec![];
            for (_, input) in task.sign_inputs.iter() {
                if let Some(FrostSignature::Adaptor(sig)) = &input.signature  {
                    sigs.push(hex::encode(&sig.0.serialize()?));
                }
            }
            Any::from_msg(&MsgSubmitRepaymentAdaptorSignatures {
                loan_id: task.id.replace("repay-", ""),
                sender: ctx.conf.relayer_bitcoin_address(),
                adaptor_signatures: sigs,
            })?
        };
        if let Err(e) = ctx.tx_sender.send(cosm_msg) {
            tracing::error!("{:?}", e)
        }
        Ok(())
    }
}

