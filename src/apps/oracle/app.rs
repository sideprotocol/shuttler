use cosmrs::Any;
use side_proto::side::dlc::{MsgSubmitAttestation, MsgSubmitNonce, MsgSubmitOraclePubKey};
use tendermint::abci::Event;

use crate::config::VaultKeypair;
use crate::helper::encoding::to_base64;
use crate::helper::store::Store;
use crate::protocols::sign::{SignAdaptor, StandardSigner};
use crate::protocols::dkg::{DKGAdaptor, DKG};

use crate::apps::{App, Context, FrostSignature, Status, SubscribeMessage, Task};

pub struct Oracle {
    pub keygen: DKG<KeygenHander>,
    pub signer: StandardSigner<AttestationHandler>,
    pub nonce_gen: DKG<NonceHander>,
}

impl Oracle {
    pub fn new() -> Self {
        Self {
            keygen: DKG::new("oracle_dkg", KeygenHander{}),
            signer: StandardSigner::new("attestation", AttestationHandler{}),

            nonce_gen: DKG::new("nonce_gen", NonceHander { 
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
    fn on_event(&self, ctx: &mut Context, events: &Vec<Event>) {
        self.signer.execute(ctx, events);
        self.keygen.execute(ctx, events);
        self.nonce_gen.execute(ctx, events);
    }
}
pub struct KeygenHander{}
impl DKGAdaptor for KeygenHander {
    fn new_task(&self, events: &Vec<Event>) -> Option<Task> {
        todo!()
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, priv_key: &frost_adaptor_signature::keys::KeyPackage, pub_key: &frost_adaptor_signature::keys::PublicKeyPackage) {
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
            pub_key: hexkey.clone(),
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
    fn new_task(&self, events: &Vec<Event>) -> Option<Task> {
        todo!()
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
    pub signer: StandardSigner<NonceSigningHandler>
}
impl DKGAdaptor for NonceHander {
    fn new_task(&self, events: &Vec<Event>) -> Option<Task> {
        todo!()
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, priv_key: &frost_adaptor_signature::keys::KeyPackage, pub_key: &frost_adaptor_signature::keys::PublicKeyPackage) {
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
            input.participants = task.dkg_input.participants.clone();
        });
        task.status = Status::SignRound1;
        ctx.task_store.save(&task.id, task);

        self.signer.generate_commitments(ctx, task);   
    }
}

pub struct NonceSigningHandler{}
impl SignAdaptor for NonceSigningHandler{
    fn new_task(&self, events: &Vec<Event>) -> Option<Task> {
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task) -> anyhow::Result<()> {
        for (_, input) in task.sign_inputs.iter() {
            if let Some(FrostSignature::Standard(signature)) = input.signature  {
                let cosm_msg = MsgSubmitNonce {
                    sender: ctx.conf.relayer_bitcoin_address(),
                    nonce: hex::encode(&input.message),
                    signature: to_base64(&signature.serialize()?),
                    oracle_pubkey: input.key.clone(),
                };
                let any = Any::from_msg(&cosm_msg)?;
                ctx.tx_sender.send(any)?
            }
        };
        Ok(())
    }
}
