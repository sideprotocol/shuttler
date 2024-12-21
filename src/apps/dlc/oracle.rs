use cosmrs::Any;
use libp2p::gossipsub::IdentTopic;
use side_proto::side::dlc::MsgSubmitOraclePubkey;
use tracing::error;

use crate::{
    apps::{Context, DKGHander, Task, TopicAppHandle}, 
    config::VaultKeypair, helper::store::Store, 
    protocols::dkg::DKG
};

pub struct OracleHandler {}
pub type OracleGenerator = DKG<OracleHandler>;

impl DKGHander for OracleHandler {

    fn on_completed(ctx: &mut Context, task: &mut Task, priv_key: frost_adaptor_signature::keys::KeyPackage, pub_key: frost_adaptor_signature::keys::PublicKeyPackage) {
        let tweak = None;
        let rawkey = pub_key.verifying_key().serialize().unwrap();
        let hexkey = hex::encode(&rawkey);
        let keyshare = VaultKeypair {
            pub_key,
            priv_key,
            tweak,
        };
        ctx.keystore.save(&hexkey, &keyshare);

        let signature = hex::encode(ctx.node_key.sign(&rawkey, None));

        let cosm_msg = MsgSubmitOraclePubkey {
            oracle_id: task.id.clone(),
            sender: ctx.conf.relayer_bitcoin_address(),
            pubkey: hexkey,
            signature,
        };
        let any = Any::from_msg(&cosm_msg).unwrap();
        if let Err(e) = ctx.tx_sender.blocking_send(any) {
            error!("{:?}", e)
        }

    }
}

impl TopicAppHandle for OracleHandler {
    fn topic() -> IdentTopic {
        IdentTopic::new("nonce")
    }
}