use cosmrs::Any;
use libp2p::gossipsub::IdentTopic;
use side_proto::side::dlc::{MsgSubmitAgencyAddress, MsgSubmitOraclePubkey};
use tracing::error;

use crate::{
    apps::{Context, DKGHander, Task, TopicAppHandle}, 
    config::VaultKeypair, helper::store::Store, 
    protocols::dkg::DKG
};

pub type AgencyGenerator = DKG<AgencyHandler>;

pub struct AgencyHandler {}
impl DKGHander for AgencyHandler {

    fn on_completed(ctx: &mut Context, task: &mut Task, priv_key: frost_adaptor_signature::keys::KeyPackage, pub_key: frost_adaptor_signature::keys::PublicKeyPackage) {
        let tweak = None;
        let rawkey = pub_key.verifying_key().serialize().unwrap();
        let address = hex::encode(&rawkey);
        let keyshare = VaultKeypair {
            pub_key,
            priv_key,
            tweak,
        };
        ctx.keystore.save(&address, &keyshare);

        let signature = hex::encode(ctx.node_key.sign(&rawkey, None));

        let cosm_msg = MsgSubmitAgencyAddress {
            id: task.id.replace("agency-", ""),
            sender: ctx.conf.relayer_bitcoin_address(),
            address,
            signature,
        };
        let any = Any::from_msg(&cosm_msg).unwrap();
        if let Err(e) = ctx.tx_sender.blocking_send(any) {
            error!("{:?}", e)
        }

    }
}

impl TopicAppHandle for AgencyHandler {
    fn topic() -> IdentTopic {
        IdentTopic::new("agency")
    }
}