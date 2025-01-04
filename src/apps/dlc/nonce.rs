
use cosmrs::Any;
use side_proto::side::dlc::MsgSubmitNonce;
use tracing::error;

use crate::{apps::{Context, FrostSignature, Task}, config::VaultKeypair, helper::{encoding::to_base64, store::Store}};


    fn on_completed(ctx: &mut Context, task: &mut Task, priv_key: frost_adaptor_signature::keys::KeyPackage, pub_key: frost_adaptor_signature::keys::PublicKeyPackage) {
        let tweak = None;
        let message = pub_key.verifying_key().serialize().unwrap();
        let store_key = hex::encode(&message);
        let keyshare = VaultKeypair {
            pub_key,
            priv_key,
            tweak,
        };
        ctx.keystore.save(&store_key, &keyshare);
        
        task.sign_inputs.iter_mut().for_each(|(_, input)| {
            input.message = message.clone();
        });
        ctx.task_store.save(&task.id, task);

        // NonceSigner::generate_commitments(ctx, task);   
    }

    fn on_completed2(ctx: &mut Context, task: &mut Task) {
        task.sign_inputs.iter().for_each(|(_, input)| {
            if let Some(FrostSignature::Standard(signature)) = input.signature  {
                let cosm_msg = MsgSubmitNonce {
                    sender: ctx.conf.relayer_bitcoin_address(),
                    nonce: to_base64(&input.message),
                    signature: to_base64(&signature.serialize().unwrap()),
                };
                let any = Any::from_msg(&cosm_msg).unwrap();
                if let Err(e) = ctx.tx_sender.blocking_send(any) {
                    error!("{:?}", e)
                }
            }
        });
    }
