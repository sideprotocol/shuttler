
use serde::{Deserialize, Serialize};
use side_proto::{cosmos::base::query::v1beta1::PageRequest, side::dlc::{AnnouncementStatus, DlcAnnouncement, QueryAnnouncementsRequest, QueryCountNoncesRequest, QueryNoncesRequest, QueryParamsRequest}};


use crate::{apps::Context, config::VaultKeypair, helper::{cipher::encrypt, mem_store, store::Store}, protocols::dkg::{DKGTask, KeyHander, Round}};
use tracing::error;
use super::Oracle;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceGeneration {
    pub index: u64,
    pub oracle_pubkey: String,
    pub nonce: String,
    pub event_id: Option<String>,
    pub generate_at: u64,
}

impl NonceGeneration {
    pub fn id(&self) -> String {
        format!("{}-{}", self.oracle_pubkey, self.index)
    }
}

impl Into<DKGTask> for NonceGeneration {
    fn into(self) -> DKGTask {
        DKGTask {
            id: self.id(),
            participants: todo!(),
            threshold: todo!(),
            round: todo!(),
        }
    }
}

impl Oracle {
    pub async fn fetch_new_nonce_generation(&mut self, ctx: &mut Context ) {
        let response = self.dlc_client.count_nonces(QueryCountNoncesRequest{}).await;
        let nonces = match response {
            Ok(resp) => resp.into_inner(),
            Err(e) => return,
        };
        let response2 = self.dlc_client.params(QueryParamsRequest{}).await;
        let param = match response2 {
            Ok(resp) => match resp.into_inner().params {
                Some(p) => p,
                None => return,
            },
            Err(e) => return,
        };
        if nonces.counts.len() != param.recommended_oracles.len() && nonces.indexs.len() != nonces.counts.len() {return};

        param.recommended_oracles.iter().zip(nonces.counts.iter()).zip(nonces.indexs.iter()).for_each(|((oracle, count), index)| {
            if count >= &param.nonce_queue_size { return }
            if let Some(keyshare) = self.db_keyshare.get(oracle) {
                let mut task = new_task(&keyshare, oracle, index);
                self.nonce_generator.generate(ctx, &mut task);
            }
        });
    }

}

fn new_task(keyshare: &VaultKeypair, oracle: &String, index: &u64) -> DKGTask {
    let participants = keyshare.pub_key.verifying_shares().keys().map(|k| {hex::encode(k.serialize())}).collect();
    DKGTask {
        id: format!("{}-{}", oracle, index),
        participants,
        threshold: keyshare.priv_key.min_signers().clone(),
        round: Round::Round1,
    }
}



