use cosmrs::Any;
use libp2p::gossipsub::IdentTopic;
use side_proto::side::dlc::MsgSubmitAgencyPubKey;
use tracing::error;

use crate::{
    apps::{Context, Task}, 
    config::VaultKeypair, helper::store::Store, 
    protocols::dkg::DKG
};



    fn on_completed(ctx: &mut Context, task: &mut Task, priv_key: frost_adaptor_signature::keys::KeyPackage, pub_key: frost_adaptor_signature::keys::PublicKeyPackage) {
        let tweak = None;
        let rawkey = pub_key.verifying_key().serialize().unwrap();
        let pubkey = hex::encode(&rawkey);
        let keyshare = VaultKeypair {
            pub_key,
            priv_key,
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
        if let Err(e) = ctx.tx_sender.blocking_send(any) {
            error!("{:?}", e)
        }

    }
