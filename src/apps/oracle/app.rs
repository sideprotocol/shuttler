use std::time::Duration;
use cosmrs::Any;
use futures::executor::block_on;
use side_proto::side::dlc::{MsgSubmitAttestation, MsgSubmitNonce, MsgSubmitOraclePubKey};

use crate::config::VaultKeypair;
use crate::helper::encoding::to_base64;
use crate::helper::store::Store;
use crate::protocols::sign::StandardSigner;
use crate::protocols::dkg::DKG;

use crate::apps::{App, Context, FrostSignature, SubscribeMessage, Task};

pub struct Oracle {
    pub keygen: DKG,
    pub signer: StandardSigner,
    pub nonce_gen: DKG,
    pub nonce_signer: StandardSigner,
}

impl Oracle {
    pub fn new() -> Self {
        Self {
            keygen: DKG::new("oracle_dkg", Box::new(keygen_handle_fn)),
            signer: StandardSigner::new("attestation", Box::new(attestation_handle_fn)),

            nonce_gen: DKG::new("nonce_gen", Box::new(nonce_gen_handle_fn)),
            nonce_signer: StandardSigner::new("nonce_signing", Box::new(nonce_signing_handle_fn)),
        }
    }
}

impl App for Oracle {

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
        block_on(self.fetch_new_attestation(ctx));
        block_on(self.fetch_new_nonce_generation(ctx));
        block_on(self.fetch_new_key_generation(ctx));
    }
}

fn keygen_handle_fn(ctx: &mut Context, task: &mut Task, priv_key: &frost_adaptor_signature::keys::KeyPackage, pub_key: &frost_adaptor_signature::keys::PublicKeyPackage) {
    let tweak = None;
    let rawkey = pub_key.verifying_key().serialize().unwrap();
    let hexkey = hex::encode(&rawkey);
    let keyshare = VaultKeypair {
        pub_key: pub_key.clone(),
        priv_key: priv_key.clone(),
        tweak,
    };
    ctx.keystore.save(&hexkey, &keyshare);

    let signature = hex::encode(ctx.node_key.sign(&rawkey, None));

    let cosm_msg = MsgSubmitOraclePubKey {
        oracle_id: task.id.replace("oracle-", "").parse().unwrap(),
        sender: ctx.conf.relayer_bitcoin_address(),
        pub_key: hexkey,
        signature,
    };

    let any = Any::from_msg(&cosm_msg).unwrap();
    if let Err(e) = ctx.tx_sender.send(any) {
        tracing::error!("{:?}", e)
    }

}

fn attestation_handle_fn(ctx: &mut Context, task: &mut Task)-> anyhow::Result<()> {
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

fn nonce_gen_handle_fn(ctx: &mut Context, task: &mut Task, priv_key: &frost_adaptor_signature::keys::KeyPackage, pub_key: &frost_adaptor_signature::keys::PublicKeyPackage) {
    let tweak = None;
    let message = pub_key.verifying_key().serialize().unwrap();
    let store_key = hex::encode(&message);
    let keyshare = VaultKeypair {
        pub_key: pub_key.clone(),
        priv_key: priv_key.clone(),
        tweak,
    };
    ctx.keystore.save(&store_key, &keyshare);
    
    task.sign_inputs.iter_mut().for_each(|(_, input)| {
        input.message = message.clone();
    });
    ctx.task_store.save(&task.id, task);

    // NonceSigner::generate_commitments(ctx, task);   
}

fn nonce_signing_handle_fn(ctx: &mut Context, task: &mut Task) -> anyhow::Result<()> {
    for (_, input) in task.sign_inputs.iter() {
        if let Some(FrostSignature::Standard(signature)) = input.signature  {
            let cosm_msg = MsgSubmitNonce {
                sender: ctx.conf.relayer_bitcoin_address(),
                nonce: to_base64(&input.message),
                signature: to_base64(&signature.serialize()?),
            };
            let any = Any::from_msg(&cosm_msg)?;
            ctx.tx_sender.send(any)?
        }
    };
    Ok(())
}