
use cosmrs::Any;
use side_proto::side::dlc::{MsgSubmitAttestation, MsgSubmitNonce, MsgSubmitOraclePubKey};
use tracing::debug;

use crate::config::{Config, VaultKeypair};
use crate::helper::encoding::{from_base64, hash, pubkey_to_identifier, to_base64};
use crate::helper::store::Store;
use crate::protocols::sign::{SignAdaptor, StandardSigner};
use crate::protocols::dkg::{DKGAdaptor, DKG};

use crate::apps::{App, Context, FrostSignature, Input, SubscribeMessage, Task};

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
    fn new_task(&self, event: &SideEvent) -> Option<Vec<Task>> {
        let mut tasks = vec![];
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("create_oracle.id") {
                    let id = format!("oracle-{}", events.get("create_oracle.id")?.get(0)?.to_owned());
                    let mut participants = vec![];
                    for p in events.get("create_oracle.participants")? {
                        if let Ok(identifier) = from_base64(p) {
                            participants.push(pubkey_to_identifier(&identifier));
                        }
                    };
                    if let Ok(threshold) = events.get("create_oracle.threshold")?.get(0)?.parse() {
                        if threshold as usize * 3 >= participants.len() * 2  {
                            tasks.push(Task::new_dkg(id, participants, threshold));
                        }
                    }
                }
            },
            _ => {},
        }
        Some(tasks)
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
    fn new_task(&self, _ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        if let SideEvent::BlockEvent(_events) = event {
            
        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task)-> anyhow::Result<()> {
        for (_, input) in task.sign_inputs.iter() {
            if let Some(FrostSignature::Standard(sig)) = input.signature  {
                let cosm_msg = MsgSubmitAttestation {
                    event_id: task.id.replace("attest-", "").parse()?,
                    sender: ctx.conf.relayer_bitcoin_address(),
                    signature: to_base64(&sig.serialize()?),
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
    fn new_task(&self, event: &SideEvent) -> Option<Vec<Task>> {
        let mut tasks = vec![];
        // tracing::debug!("event: {:?}", event);
        if let SideEvent::BlockEvent(events) = event {
            if events.contains_key("generate_nonce.id") {
                let oracle_key = events.get("generate_nonce.oracle_pub_key")?.get(0)?.to_owned();
                let sequence = events.get("generate_nonce.id")?.get(0)?.to_owned();
                let id = format!("{}-{}", oracle_key , sequence );
                let mut participants = vec![];
                for p in events.get("generate_nonce.participants")? {
                    if let Ok(identifier) = from_base64(p) {
                        participants.push(pubkey_to_identifier(&identifier));
                    }
                };
                if let Ok(threshold) = events.get("generate_nonce.threshold")?.get(0)?.parse() {
                    if threshold as usize * 3 >= participants.len() * 2  {
                        tasks.push(Task::new_dkg(id, participants, threshold));
                    }
                }
            }
        }
        Some(tasks)
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
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task) -> anyhow::Result<()> {
        for (_, input) in task.sign_inputs.iter() {
            if let Some(FrostSignature::Standard(signature)) = input.signature  {
                let cosm_msg = MsgSubmitNonce {
                    sender: ctx.conf.relayer_bitcoin_address(),
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
