

use cosmrs::Any;
use frost_adaptor_signature::VerifyingKey;
use side_proto::side::tss::{MsgCompleteDkg, MsgSubmitSignatures, SigningType};
use tracing::debug;

use crate::config::{VaultKeypair, APP_NAME_LENDING};
use crate::helper::encoding::{from_base64, hash, pubkey_to_identifier};
use crate::helper::mem_store;
use crate::helper::store::Store;
use crate::protocols::refresh::{ParticipantRefresher, RefreshAdaptor};
use crate::protocols::sign::{SignAdaptor, StandardSigner};
use crate::protocols::dkg::{DKGAdaptor, DKG};

use crate::apps::{App, Context, FrostSignature, Input, SignMode, SubscribeMessage, Task};

use super::{SideEvent, TaskInput};

pub struct LendingApp {
    pub keygen: DKG<KeygenHander>,
    pub signer: StandardSigner<SignerHandler>,
    pub refresher: ParticipantRefresher<RefreshHandler>,
}

impl LendingApp {
    pub fn new() -> Self {
        Self {
            keygen: DKG::new("lending_key_generator", KeygenHander{}),
            signer: StandardSigner::new("lending_signer", SignerHandler{}),
            refresher: ParticipantRefresher::new("lending_refresh", RefreshHandler{})
        }
    }
}

impl App for LendingApp {

    fn name(&self) -> String {
        APP_NAME_LENDING.to_string()
    }

    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()>{
        self.signer.on_message(ctx, message)?;
        self.keygen.on_message(ctx, message)?;
        self.refresher.on_message(ctx, message)
    }
    fn subscribe_topics(&self) -> Vec<libp2p::gossipsub::IdentTopic> {
        vec![self.keygen.topic(), self.signer.topic(), self.refresher.topic()]
    }
    fn on_event(&self, ctx: &mut Context, event: &SideEvent) {
        self.signer.on_event(ctx, event);
        self.keygen.on_event(ctx, event);
        // self.refresher.
    }
    fn execute(&self, ctx: &mut Context, tasks: Vec<Task>) -> anyhow::Result<()> {
        self.signer.execute(ctx, &tasks);
        Ok(())
    }
}
pub struct KeygenHander{}
impl DKGAdaptor for KeygenHander {
    fn new_task(&self, _ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("initiate_dkg.id") {
                    println!("Events: {:?}", events);

                    let mut tasks = vec![];
                    for (((id, ps), t), b) in events.get("initiate_dkg.id")?.iter()
                        .zip(events.get("initiate_dkg.participants")?)
                        .zip(events.get("initiate_dkg.threshold")?)
                        .zip(events.get("initiate_dkg.batch_size")?) {
                        
                            let mut participants = vec![];
                            for p in ps.split(",") {
                                if let Ok(identifier) = from_base64(p) {
                                    participants.push(pubkey_to_identifier(&identifier));
                                }
                            };
                            if let Ok(threshold) = t.parse() {
                                if threshold as usize * 3 >= participants.len() * 2  {
                                    if let Ok(batch_size) = b.parse() {
                                        tasks.push(Task::new_dkg(format!("lending-dkg-{}", id), participants, threshold, batch_size));
                                    }
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
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(frost_adaptor_signature::keys::KeyPackage,frost_adaptor_signature::keys::PublicKeyPackage)>) {
        let mut pub_keys = vec![];
        keys.into_iter().for_each(|(priv_key, pub_key)| {
            
            let tweak = None;
            let rawkey = pub_key.verifying_key().serialize().unwrap();
            let hexkey = hex::encode(&rawkey[1..]);
            let keyshare = VaultKeypair {
                pub_key: pub_key.clone(),
                priv_key: priv_key.clone(),
                tweak,
            };
            ctx.keystore.save(&hexkey, &keyshare);
            pub_keys.push(hexkey);
        });

        debug!("Oracle pubkey >>>: {:?}", pub_keys);

        let id: u64 = task.id.replace("lending-dkg-", "").parse().unwrap();

        // save dkg id and keys for refresh
        ctx.general_store.save(&format!("{}",id).as_str(), &pub_keys.join(","));
        
        // convert string array to bytes
        let mut message_keys = id.to_be_bytes()[..].to_vec();
        for key in pub_keys.iter() {
            let key_bytes = hex::decode(key).unwrap();
            message_keys.extend(key_bytes);
        };
        let message = hex::decode(hash(&message_keys)).unwrap();
        let signature = hex::encode(ctx.node_key.sign(&message, None));

        let cosm_msg = MsgCompleteDkg {
            id: id,
            sender: ctx.conf.relayer_bitcoin_address(),
            pub_keys: pub_keys,
            signature,
            consensus_pubkey: ctx.id_base64.clone()
        };

        let any = Any::from_msg(&cosm_msg).unwrap();
        if let Err(e) = ctx.tx_sender.send(any) {
            tracing::error!("{:?}", e)
        }

    }
}
pub struct SignerHandler{}
impl SignAdaptor for SignerHandler {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        if let SideEvent::BlockEvent(events) = event {
            if events.contains_key("initiate_signing.id") {
                println!("Trigger Price Event: {:?}", events);
                let mut tasks = vec![];
                for ((((id, pub_key), sig_hashes), mode), option ) in events.get("initiate_signing.id")?.iter()
                    .zip(events.get("initiate_signing.pub_key")?)
                    .zip(events.get("initiate_signing.sig_hashes")?)
                    .zip(events.get("initiate_signing.type")?)
                    .zip(events.get("initiate_signing.option")?) {

                        let mut sign_mode = SignMode::Sign;                      
                        if mode.eq(SigningType::SchnorrWithCommitment.as_str_name()) {
                            if let Some(nonce_keypair) = ctx.keystore.get(&option) {    
                                sign_mode = SignMode::SignWithGroupcommitment(nonce_keypair.pub_key.verifying_key().clone())
                            }
                        } else if mode.eq(SigningType::SchnorrAdaptor.as_str_name()) {
                            let hex_adaptor = hex::decode(&option).ok()?;
                            if let Ok(adaptor) = VerifyingKey::deserialize(&hex_adaptor) {
                                // let mode = SignMode::SignWithAdaptorPoint(adaptor);    
                                sign_mode = SignMode::SignWithAdaptorPoint(adaptor)
                            }
                        };

                        let participants = mem_store::count_task_participants(ctx, pub_key);
                        if participants.len() > 0 {
                            let mut sign_inputs = vec![];
                            sig_hashes.split(",").enumerate().for_each(|(index, sig)| {
                                if let Ok(message) = from_base64(sig) {
                                        sign_inputs.insert(index, Input::new_with_message_mode(pub_key.clone(), message, participants.clone(), sign_mode.clone()));
                                    }
                                }
                            );
                            if sign_inputs.len() > 0 {
                                let task= Task::new_signing(format!("lending-{}", id), "" , sign_inputs);
                                tasks.push(task);
                            }
                        }
                    };
                return Some(tasks);
            }
        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task)-> anyhow::Result<()> {
        let mut signatures = vec![];

        if let TaskInput::SIGN(sign_inputs) = &task.input {
            for input in sign_inputs.iter() {
                if let Some(signature) = input.signature.clone() {
                    match signature {
                        FrostSignature::Standard(sig) => {
                            signatures.push(hex::encode(&sig.serialize()?));
                        }
                        FrostSignature::Adaptor(sig) => {
                            signatures.push(hex::encode(&sig.0.default_serialize()?));
                        }
                    }
                }
            }
            let cosm_msg = MsgSubmitSignatures {
                id: task.id.replace("lending-", "").parse()?,
                sender: ctx.conf.relayer_bitcoin_address(),
                signatures ,
            };
            let any = Any::from_msg(&cosm_msg)?;
            if let Err(e) = ctx.tx_sender.send(any) {
                tracing::error!("{:?}", e)
            }
        }
        
        Ok(())
    }
}

pub struct RefreshHandler;
impl RefreshAdaptor for RefreshHandler {
    fn new_task(&self, ctx: &mut Context, events: &SideEvent) -> Option<Vec<Task>> {
        todo!()
    }

    fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(frost_adaptor_signature::keys::KeyPackage, frost_adaptor_signature::keys::PublicKeyPackage)>) {
        todo!()
    }
}

// pub struct NonceHander{
//     pub conf: Config,
//     pub signer: StandardSigner<NonceSigningHandler>
// }
// impl DKGAdaptor for NonceHander {
//     fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
//         // tracing::debug!("event: {:?}", event);
//         if let SideEvent::BlockEvent(events) = event {
//             if events.contains_key("generate_nonce.id") {
//                 let mut tasks = vec![];
//                 for (id, oracle_key) in events.get("generate_nonce.id")?.iter()
//                     .zip(events.get("generate_nonce.oracle_pub_key")?) {
//                         if let Some(keypair) = ctx.keystore.get(&oracle_key) {
//                             let participants = keypair.pub_key.verifying_shares().keys().map(|i| i.clone()).collect::<Vec<_>>();
//                             let threshold = keypair.priv_key.min_signers().clone();
//                             tasks.push(Task::new_dkg(format!("{}-{}", oracle_key , id ), participants , threshold));
//                         }
//                     };
//                 return Some(tasks);
//             }
//         }
//         None
//     }
    
//     fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(frost_adaptor_signature::keys::KeyPackage,frost_adaptor_signature::keys::PublicKeyPackage)>) {
//         let (priv_key, pub_key) = keys.into_iter().next().unwrap();
//         let tweak = None;
//         let pubkey = pub_key.verifying_key().serialize().unwrap();
//         let nonce = hex::encode(&pubkey[1..]);
//         let keyshare = VaultKeypair {
//             pub_key: pub_key.clone(),
//             priv_key: priv_key.clone(),
//             tweak,
//         };
//         ctx.keystore.save(&nonce, &keyshare);
        
//         let oracle_pubkey = task.id.split("-").collect::<Vec<_>>();

//         let message = hex::decode(hash(&pubkey[1..])).unwrap();
//         task.sign_inputs.insert(0, Input::new_with_message(oracle_pubkey[0].to_string(), message, task.dkg_input.participants.clone()));
//         task.psbt = nonce; // store the nonce in PSBT, since PSBT dese not exists in this signing process.
//         ctx.task_store.save(&task.id, task);    

//         self.signer.generate_commitments(ctx, task);   
//     }
// }

// pub struct NonceSigningHandler{}
// impl SignAdaptor for NonceSigningHandler{
//     fn new_task(&self, _ctx: &mut Context,  _event: &SideEvent) -> Option<Vec<Task>> {
//         // no need to implement, because it share same task as nonce DKG
//         None
//     }
//     fn on_complete(&self, ctx: &mut Context, task: &mut Task) -> anyhow::Result<()> {
//         for (_, input) in task.sign_inputs.iter() {
//             if let Some(FrostSignature::Standard(signature)) = input.signature  {
//                 let cosm_msg = MsgSubmitNonce {
//                     sender: ctx.conf.relayer_bitcoin_address(),
//                     nonce: task.psbt.clone(),
//                     signature: hex::encode(&signature.serialize()?),
//                     oracle_pubkey: input.key.clone(),
//                 };
//                 let any = Any::from_msg(&cosm_msg)?;
//                 ctx.tx_sender.send(any)?
//             }
//         };
//         Ok(())
//     }
// }
