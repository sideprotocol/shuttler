
use side_proto::side::dlc::{DlcOracle, DlcOracleStatus, QueryAttestationsRequest, QueryCountNoncesRequest, QueryOraclesRequest, QueryParamsRequest};
use side_proto::side::dlc::query_client::QueryClient as DLCQueryClient;
use tracing::error;

use crate::{
    apps::{Context, Input, Task}, helper::{encoding::pubkey_to_identifier, store::Store}};
use super::Oracle;

impl Oracle {
    pub async fn fetch_new_nonce_generation(&self, ctx: &mut Context ) {
        let mut dlc_client = match DLCQueryClient::connect(ctx.conf.side_chain.grpc.clone()).await {
            Ok(c) => c,
            Err(e) => {
                error!("{:?}", e);
                return
            },
        };
        let response = dlc_client.count_nonces(QueryCountNoncesRequest{}).await;
        let nonces = match response {
            Ok(resp) => resp.into_inner(),
            Err(e) => {
                error!("{:?}", e);
                return
            },
        };
        let response2 = dlc_client.params(QueryParamsRequest{}).await;
        let param = match response2 {
            Ok(resp) => match resp.into_inner().params {
                Some(p) => p,
                None => return,
            },
            Err(e) => {
                error!("{:?}", e);
                return
            },
        };
        let response3 = dlc_client.oracles(QueryOraclesRequest{status: DlcOracleStatus::OracleStatusEnable as i32, pagination: None}).await;
        let oracles = match response3 {
            Ok(resp) => resp.into_inner().oracles,
            Err(e) => {
                error!("{:?}", e);
                return
            },
        };
        if nonces.counts.len() != oracles.len() {return};

        oracles.iter().zip(nonces.counts.iter()).for_each(|(oracle, count)| {
            if count >= &param.nonce_queue_size { return }

            if let Some(mut task) = new_task_from_oracle(oracle) {
                if ctx.task_store.exists(&task.id) { return }
                // oracle should sign the new nonce.
                task.sign_inputs.insert(0, Input::new(oracle.pubkey.clone()));
                ctx.task_store.save(&task.id, &task);
                self.nonce_gen.generate(ctx, &task);
            }
        });
    }

    pub async fn fetch_new_key_generation(&self, ctx: &mut Context) {
        let mut dlc_client = match DLCQueryClient::connect(ctx.conf.side_chain.grpc.clone()).await {
            Ok(c) => c,
            Err(e) => {
                error!("{:?}", e);
                return
            },
        };
        let response3 = dlc_client.oracles(QueryOraclesRequest{status: DlcOracleStatus::OracleStatusPending as i32, pagination: None}).await;
        let oracles = match response3 {
            Ok(resp) => resp.into_inner().oracles,
            Err(e) => {
                error!("{:?}", e);
                return
            },
        };
        oracles.iter().for_each(|oracle| {
            if let Some(task) = new_task_from_oracle(oracle) {
                if ctx.task_store.exists(&task.id) { return }
                ctx.task_store.save(&task.id, &task);

                self.keygen.generate(ctx, &task);
            }
        });
    }

    pub async fn fetch_new_attestation(&self, ctx: &mut Context) {
        let mut dlc_client = match DLCQueryClient::connect(ctx.conf.side_chain.grpc.clone()).await {
            Ok(c) => c,
            Err(e) => {
                error!("{}", e);
                return
            },
        };
        let response3 = dlc_client.attestations(QueryAttestationsRequest{pagination: None}).await;
        let attestations = match response3 {
            Ok(resp) => resp.into_inner().attestations,
            Err(_) => return,
        };
        attestations.iter().for_each(|a| {

            let signer = match ctx.keystore.get(&a.pubkey) {
                Some(s) => s,
                None => return,
            };
            let participants = signer.pub_key.verifying_shares().keys().map(|k| k.clone()).collect::<Vec<_>>();

            let mut task = Task::new_dkg(format!("attest-{}", a.id), participants, *signer.priv_key.min_signers());
            let message = a.outcome.clone().into_bytes();
            task.sign_inputs.insert(0, Input::new_with_message(a.pubkey.clone(), message));

            if ctx.task_store.exists(&task.id) { return }
            ctx.task_store.save(&task.id, &task);

            self.signer.generate_commitments(ctx, &task);
        });
    }


}

fn new_task_from_oracle(oracle: &DlcOracle) -> Option<Task> {
    let id = if oracle.status == DlcOracleStatus::OracleStatusEnable as i32{
        format!("oracle-{}", oracle.id)
    } else {
        format!("{}-{}", oracle.id, oracle.nonce_index + 1)
    };

    let mut participants = vec![];
    for p in &oracle.participants {
        match hex::decode(p) {
            Ok(b) => {
               participants.push(pubkey_to_identifier(&b))
            },
            Err(_) => return None,
        };
    }
    Some(Task::new_dkg(id, participants, oracle.threshold as u16))
}


