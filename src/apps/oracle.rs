
use std::collections::BTreeMap;

use bitcoin::hex::DisplayHex;
use cosmrs::Any;
use ord::base64_decode;
use side_proto::side::dlc::{DlcEventType, MsgSubmitAttestation, MsgSubmitNonce, MsgSubmitOraclePubKey};
use tracing::debug;

use crate::config::{Config, VaultKeypair};
use crate::helper::encoding::{from_base64, hash, hash_byte, pubkey_to_identifier, to_base64};
use crate::helper::store::Store;
use crate::protocols::sign::{SignAdaptor, StandardSigner};
use crate::protocols::dkg::{DKGAdaptor, DKG};

use crate::apps::{App, Context, FrostSignature, Input, SignMode, SubscribeMessage, Task};

use super::SideEvent;

pub struct Oracle {
    pub keygen: DKG<KeygenHander>,
    pub signer: StandardSigner<AttestationHandler>,
    pub nonce_gen: DKG<NonceHander>,
}

impl Oracle {
    pub fn new(conf: Config) -> Self {
        Self {
            keygen: DKG::new("oracle_dkg", KeygenHander{}),
            signer: StandardSigner::new("attestation", AttestationHandler{}),

            nonce_gen: DKG::new("nonce_gen", NonceHander { 
                conf,
                signer: StandardSigner::new("nonce_signing", NonceSigningHandler {  }) 
            }),
        }
    }
}

impl App for Oracle {

    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()>{
        self.signer.on_message(ctx, message)?;
        self.keygen.on_message(ctx, message)?;
        self.nonce_gen.on_message(ctx, message)?;
        self.nonce_gen.hander().signer.on_message(ctx, message)
        // Ok(())
    }
    fn subscribe_topics(&self) -> Vec<libp2p::gossipsub::IdentTopic> {
        vec![self.keygen.topic(), self.signer.topic(), self.nonce_gen.topic(), self.nonce_gen.hander().signer.topic()]
    }
    fn on_event(&self, ctx: &mut Context, event: &SideEvent) {
        self.signer.execute(ctx, event);
        self.keygen.execute(ctx, event);
        self.nonce_gen.execute(ctx, event);
    }
}
pub struct KeygenHander{}
impl DKGAdaptor for KeygenHander {
    fn new_task(&self, _ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("create_oracle.id") {
                    println!("Events: {:?}", events);

                    let mut tasks = vec![];
                    for ((id, ps), t) in events.get("create_oracle.id")?.iter()
                        .zip(events.get("create_oracle.participants")?)
                        .zip(events.get("create_oracle.threshold")?) {
                        
                            let mut participants = vec![];
                            for p in ps.split(",") {
                                if let Ok(identifier) = from_base64(p) {
                                    participants.push(pubkey_to_identifier(&identifier));
                                }
                            };
                            if let Ok(threshold) = t.parse() {
                                if threshold as usize * 3 >= participants.len() * 2  {
                                    tasks.push(Task::new_dkg(format!("oracle-{}", id), participants, threshold));
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
        let hexkey = hex::encode(&rawkey[1..]);
        let keyshare = VaultKeypair {
            pub_key: pub_key.clone(),
            priv_key: priv_key.clone(),
            tweak,
        };
        ctx.keystore.save(&hexkey, &keyshare);

        debug!("Oracle pubkey >>>: {:?}", hexkey);

        let id: u64 = task.id.replace("oracle-", "").parse().unwrap();
        let message = hash(&[&id.to_be_bytes()[..], &rawkey[1..]].concat());
        let signature = hex::encode(ctx.node_key.sign(&hex::decode(message).unwrap(), None));

        let cosm_msg = MsgSubmitOraclePubKey {
            oracle_id: id,
            sender: ctx.conf.relayer_bitcoin_address(),
            pub_key: to_base64(ctx.node_key.public_key().as_slice()),
            signature,
            oracle_pubkey: hexkey,
        };

        let any = Any::from_msg(&cosm_msg).unwrap();
        if let Err(e) = ctx.tx_sender.send(any) {
            tracing::error!("{:?}", e)
        }

    }
}
pub struct AttestationHandler{}
impl SignAdaptor for AttestationHandler {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        if let SideEvent::BlockEvent(events) = event {
            if events.contains_key("trigger_dlc_event.event_id") {
                println!("Trigger DLC Event: {:?}", events);
                let mut tasks = vec![];
                for (((id, nonce), sig_hash), oracle_key) in events.get("trigger_price_event.event_id")?.iter()
                    .zip(events.get("trigger_dlc_event.nonce")?)
                    .zip(events.get("trigger_dlc_event.outcome_hash")?)
                    .zip(events.get("trigger_dlc_event.pub_key")?) {
                        if let Some(keypair) = ctx.keystore.get(&oracle_key) {
                            if let Some(nonce_keypair) = ctx.keystore.get(&nonce) {                          
                                let mut sign_inputs = BTreeMap::new();
                                let participants = keypair.pub_key.verifying_shares().keys().map(|p| p.clone()).collect::<Vec<_>>();
                                
                                let mode = SignMode::SignWithGroupcommitment(nonce_keypair.pub_key.verifying_key().clone());
                                if let Ok(message) = from_base64(&sig_hash) {
                                    println!("Trigger DLC Event Message: {:?}", message.to_lower_hex_string());
                                    sign_inputs.insert(0, Input::new_with_message_mode(oracle_key.to_owned(), message, participants, mode));
                                    let task= Task::new_signing(format!("attest-{}", id), "" , sign_inputs);
                                    tasks.push(task);
                                }
                            }   
                        }
                    };
                return Some(tasks);
            }
        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task)-> anyhow::Result<()> {
        for (_, input) in task.sign_inputs.iter() {
            if let Some(FrostSignature::Standard(sig)) = input.signature  {
                let cosm_msg = MsgSubmitAttestation {
                    event_id: task.id.replace("attest-", "").parse()?,
                    sender: ctx.conf.relayer_bitcoin_address(),
                    signature: hex::encode(&sig.serialize()?),
                };
                let any = Any::from_msg(&cosm_msg)?;
                if let Err(e) = ctx.tx_sender.send(any) {
                    tracing::error!("{:?}", e)
                }
            }
        }
        Ok(())
    }
}

pub struct NonceHander{
    pub conf: Config,
    pub signer: StandardSigner<NonceSigningHandler>
}
impl DKGAdaptor for NonceHander {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        // tracing::debug!("event: {:?}", event);
        if let SideEvent::BlockEvent(events) = event {
            if events.contains_key("generate_nonce.id") {
                let mut tasks = vec![];
                for (id, oracle_key) in events.get("generate_nonce.id")?.iter()
                    .zip(events.get("generate_nonce.oracle_pub_key")?) {
                        if let Some(keypair) = ctx.keystore.get(&oracle_key) {
                            let participants = keypair.pub_key.verifying_shares().keys().map(|i| i.clone()).collect::<Vec<_>>();
                            let threshold = keypair.priv_key.min_signers().clone();
                            tasks.push(Task::new_dkg(format!("{}-{}", oracle_key , id ), participants , threshold));
                        }
                    };
                return Some(tasks);
            }
        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, priv_key: &frost_adaptor_signature::keys::KeyPackage, pub_key: &frost_adaptor_signature::keys::PublicKeyPackage) {
        let tweak = None;
        let pubkey = pub_key.verifying_key().serialize().unwrap();
        let nonce = hex::encode(&pubkey[1..]);
        let keyshare = VaultKeypair {
            pub_key: pub_key.clone(),
            priv_key: priv_key.clone(),
            tweak,
        };
        ctx.keystore.save(&nonce, &keyshare);
        
        let oracle_pubkey = task.id.split("-").collect::<Vec<_>>();

        let message = hex::decode(hash(&pubkey[1..])).unwrap();
        task.sign_inputs.insert(0, Input::new_with_message(oracle_pubkey[0].to_string(), message, task.dkg_input.participants.clone()));
        task.psbt = nonce; // store the nonce in PSBT, since PSBT dese not exists in this signing process.
        ctx.task_store.save(&task.id, task);    

        self.signer.generate_commitments(ctx, task);   
    }
}

pub struct NonceSigningHandler{}
impl SignAdaptor for NonceSigningHandler{
    fn new_task(&self, _ctx: &mut Context,  _event: &SideEvent) -> Option<Vec<Task>> {
        // no need to implement, because it share same task as nonce DKG
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task) -> anyhow::Result<()> {
        for (_, input) in task.sign_inputs.iter() {
            if let Some(FrostSignature::Standard(signature)) = input.signature  {
                let cosm_msg = MsgSubmitNonce {
                    sender: ctx.conf.relayer_bitcoin_address(),
                    event_type: task.id.rsplit('-').next().unwrap().parse().unwrap(),
                    nonce: task.psbt.clone(),
                    signature: hex::encode(&signature.serialize()?),
                    oracle_pubkey: input.key.clone(),
                };
                let any = Any::from_msg(&cosm_msg)?;
                ctx.tx_sender.send(any)?
            }
        };
        Ok(())
    }
}
