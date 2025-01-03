use cosmrs::Any;
use side_proto::side::dlc::MsgSubmitAttestation;
use tracing::error;

use crate::{
    apps::{Context, FrostSignature, SigningHandler, Task}, helper::encoding::to_base64, protocols::sign::StandardSigner};

pub struct AttestationSignatureHandler{}
pub type AttestationSigner = StandardSigner<AttestationSignatureHandler>;

impl SigningHandler for AttestationSignatureHandler {
    fn on_completed(ctx: &mut Context, task: &mut Task) {
        task.sign_inputs.iter().for_each(|(_, input)| {
            if let Some(FrostSignature::Standard(sig)) = input.signature  {
                let cosm_msg = MsgSubmitAttestation {
                    event_id: task.id.replace("attest-", "").parse().unwrap(),
                    sender: ctx.conf.relayer_bitcoin_address(),
                    signature: to_base64(&sig.serialize().unwrap()),
                };
                let any = Any::from_msg(&cosm_msg).unwrap();
                if let Err(e) = ctx.tx_sender.blocking_send(any) {
                    error!("{:?}", e)
                }
            }
        });
    }
}
