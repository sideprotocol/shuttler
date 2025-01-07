use std::time::Duration;
use cosmrs::Any;
use futures::executor::block_on;
use side_proto::side::dlc::{MsgSubmitAgencyPubKey, MsgSubmitAttestation};
use crate::config::VaultKeypair;
use crate::helper::encoding::to_base64;
use crate::helper::store::Store;
use crate::protocols::sign::{SigningHandle, StandardSigner};
use crate::protocols::dkg::{DKGHandle, DKG};

use crate::apps::{App, Context, FrostSignature, SubscribeMessage, Task};

pub struct Agency {
    pub keygen: DKG<KeygenHander>,
    pub signer: StandardSigner<SignatureHandler>,
}

impl Agency {
    pub fn new() -> Self {
        Self {
            keygen: DKG::new("oracle_dkg", KeygenHander{}),
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
    fn tick(&self) -> Duration {
        Duration::from_secs(30)
    }
    fn on_tick(&self, ctx: &mut Context) {
        block_on(self.fetch_new_agency(ctx))
    }
}

pub struct KeygenHander{}
impl DKGHandle for KeygenHander {
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, priv_key: &frost_adaptor_signature::keys::KeyPackage, pub_key: &frost_adaptor_signature::keys::PublicKeyPackage) {
        let tweak = None;
        let rawkey = pub_key.verifying_key().serialize().unwrap();
        let pubkey = hex::encode(&rawkey);
        let keyshare = VaultKeypair {
            pub_key: pub_key.clone(),
            priv_key: priv_key.clone(),
            tweak,
        };
        ctx.keystore.save(&pubkey, &keyshare);

        let signature = hex::encode(ctx.node_key.sign(&rawkey, None));

        let cosm_msg = MsgSubmitAgencyPubKey {
            id: task.id.replace("agency-", "").parse().unwrap(),
            sender: ctx.conf.relayer_bitcoin_address(),
            pub_key: pubkey,
            signature,
        };
        let any = Any::from_msg(&cosm_msg).unwrap();
        if let Err(e) = ctx.tx_sender.send(any) {
            tracing::error!("{:?}", e)
        }

    }
}

pub struct SignatureHandler {}
impl SigningHandle for SignatureHandler {
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

