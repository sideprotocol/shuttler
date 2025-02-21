use cosmrs::Any;
use side_proto::side::dlc::{MsgSubmitAgencyPubKey, MsgSubmitAttestation};
use crate::config::VaultKeypair;
use crate::helper::encoding::{from_base64, hash, pubkey_to_identifier, to_base64};
use crate::helper::store::Store;
use crate::protocols::sign::{SignAdaptor, StandardSigner};
use crate::protocols::dkg::{DKGAdaptor, DKG};

use crate::apps::{App, Context, FrostSignature, SubscribeMessage, Task};

use super::SideEvent;

pub struct Agency {
    pub keygen: DKG<KeygenHander>,
    pub signer: StandardSigner<SignatureHandler>,
}

impl Agency {
    pub fn new() -> Self {
        Self {
            keygen: DKG::new("agency_dkg", KeygenHander{}),
            signer: StandardSigner::new("attestation2", SignatureHandler {  }),
        }
    }
}

impl App for Agency {

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
    fn new_task(&self, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("create_agency.id") {
                    let id = format!("agency-{}", events.get("create_agency.id")?.get(0)?.to_owned());
                    let mut participants = vec![];
                    for p in events.get("create_agency.participants")? {
                        if let Ok(identifier) = from_base64(p) {
                            participants.push(pubkey_to_identifier(&identifier));
                        }
                    };
                    if let Ok(threshold) = events.get("create_agency.threshold")?.get(0)?.parse() {
                        if threshold as usize * 3 >= participants.len() * 2  {
                            return Some(vec![Task::new_dkg(id, participants, threshold)])
                        }
                    }
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
    fn new_task(&self, _ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("create_agency.id") {
                    // let id = format!("agency-{}", events.get("create_agency.id")?.get(0)?.to_owned());
                    // let mut participants = vec![];
                    // for p in events.get("create_agency.participants")? {
                    //     if let Ok(identifier) = from_base64(p) {
                    //         participants.push(pubkey_to_identifier(&identifier));
                    //     }
                    // };
                    // if let Ok(threshold) = events.get("create_agency.threshold")?.get(0)?.parse() {
                    //     if threshold as usize * 3 >= participants.len() * 2  {
                    //         return Some(vec![Task::new_dkg(id, participants, threshold)])
                    //     }
                    // }
                }
            },
            _ => {},
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

