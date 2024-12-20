
use libp2p::gossipsub::IdentTopic;
use side_proto::side::dlc::{DlcOracle, DlcOracleStatus, QueryCountNoncesRequest, QueryOraclesRequest, QueryParamsRequest};

use crate::{
    apps::{Context, DKGHander, Input, SignMode, SigningHandler, Task, TopicAppHandle}, config::VaultKeypair, helper::{encoding::pubkey_to_identifier, store::Store}, protocols::{dkg::DKG, sign::StandardSigner}};
use super::DLC;

impl DLC {
    pub async fn fetch_new_nonce_generation(&mut self, ctx: &mut Context ) {
        let response = self.dlc_client.count_nonces(QueryCountNoncesRequest{}).await;
        let nonces = match response {
            Ok(resp) => resp.into_inner(),
            Err(_e) => return,
        };
        let response2 = self.dlc_client.params(QueryParamsRequest{}).await;
        let param = match response2 {
            Ok(resp) => match resp.into_inner().params {
                Some(p) => p,
                None => return,
            },
            Err(_) => return,
        };
        let response3 = self.dlc_client.oracles(QueryOraclesRequest{status: DlcOracleStatus::OracleStatusEnable as i32}).await;
        let oracles = match response3 {
            Ok(resp) => resp.into_inner().oracles,
            Err(_) => return,
        };
        if nonces.counts.len() != oracles.len() {return};

        oracles.iter().zip(nonces.counts.iter()).for_each(|(oracle, count)| {
            if count >= &param.nonce_queue_size { return }

            if let Some(task) = new_task_from_oracle(oracle) {
                if ctx.task_store.exists(&task.id) { return }
                ctx.task_store.save(&task.id, &task);
                self.nonce_generator.generate(ctx, &task);
            }
        });
    }

    pub async fn fetch_new_key_generation(&mut self, ctx: &mut Context) {
        let response3 = self.dlc_client.oracles(QueryOraclesRequest{status: DlcOracleStatus::OracleStatusPending as i32}).await;
        let oracles = match response3 {
            Ok(resp) => resp.into_inner().oracles,
            Err(_) => return,
        };
        oracles.iter().for_each(|oracle| {
            if let Some(task) = new_task_from_oracle(oracle) {
                if ctx.task_store.exists(&task.id) { return }
                ctx.task_store.save(&task.id, &task);

                self.keyshare_generator.generate(ctx, &task);
            }
        });
    }

}

fn new_task_from_oracle(oracle: &DlcOracle) -> Option<Task> {
    let id = if oracle.status == DlcOracleStatus::OracleStatusEnable as i32{
        format!("{}", oracle.id)
    } else {
        format!("{}-{}", oracle.id, oracle.nonce_index + 1)
    };

    let mut participants = vec![];
    for p in &oracle.participants {
        let x = match hex::decode(p) {
            Ok(b) => {
               participants.push(pubkey_to_identifier(&b))
            },
            Err(e) => return None,
        };
    }
    Some(Task::new_dkg(id, participants, oracle.threshold as u16, SignMode::Sign))
}

pub struct NonceHandler {}
pub type NonceGenerator = DKG<NonceHandler>;

impl DKGHander for NonceHandler {
    fn on_completed(ctx: &mut Context, task: &mut Task, priv_key: frost_adaptor_signature::keys::KeyPackage, pub_key: frost_adaptor_signature::keys::PublicKeyPackage) {
        let tweak = None;
        let hexkey = hex::encode(pub_key.verifying_key().serialize().unwrap());
        let keyshare = VaultKeypair {
            pub_key,
            priv_key,
            tweak,
        };
        ctx.keystore.save(&hexkey, &keyshare);
        // task.sign_inputs = vec![Input { key: todo!(), message: todo!(), signature: todo!(), adaptor_signature: todo!() }];
        NonceSigner::generate_commitments(ctx, task);   
    }
}

impl TopicAppHandle for NonceHandler {
    fn topic() -> IdentTopic {
        IdentTopic::new("nonce")
    }
}

pub struct NonceSignatureHandler{}
pub type NonceSigner = StandardSigner<NonceSignatureHandler>;

impl SigningHandler for NonceSignatureHandler {
    fn on_completed(ctx: &mut Context, task: &mut Task) {
        todo!()
    }
}

