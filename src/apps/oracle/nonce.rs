
use serde::{Deserialize, Serialize};
use side_proto::side::dlc::{DlcOracle, DlcOracleStatus, QueryCountNoncesRequest, QueryOraclesRequest, QueryParamsRequest};


use crate::{apps::Context, protocols::dkg::{DKGTask, Round}};
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

impl Oracle {
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
            let mut task = new_task_for_queue(oracle);
            self.nonce_generator.generate(ctx, &mut task);
        });
    }

    pub async fn fetch_new_key_generation(&mut self, ctx: &mut Context) {
        let response3 = self.dlc_client.oracles(QueryOraclesRequest{status: DlcOracleStatus::OracleStatusPending as i32}).await;
        let oracles = match response3 {
            Ok(resp) => resp.into_inner().oracles,
            Err(_) => return,
        };
        oracles.iter().for_each(|oracle| {
            let mut task = new_task_for_queue(oracle);
            self.keyshare_generator.generate(ctx, &mut task);
        });
    }

}

fn new_task_for_queue(oracle: &DlcOracle ) -> DKGTask {
    DKGTask {
        id: format!("{}-{}", oracle.id, oracle.nonce_index + 1),
        participants: oracle.participants.clone(),
        threshold: oracle.threshold as u16,
        round: Round::Round1,
    }
}



