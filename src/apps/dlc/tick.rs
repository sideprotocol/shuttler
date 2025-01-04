
use side_proto::side::dlc::{AgencyStatus, DlcOracle, DlcOracleStatus, QueryAgenciesRequest, QueryAttestationsRequest, QueryCountNoncesRequest, QueryOraclesRequest, QueryParamsRequest};

use crate::{
    apps::{Context, Input, Task}, helper::{encoding::pubkey_to_identifier, store::Store}};
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
        let response3 = self.dlc_client.oracles(QueryOraclesRequest{status: DlcOracleStatus::OracleStatusEnable as i32, pagination: None}).await;
        let oracles = match response3 {
            Ok(resp) => resp.into_inner().oracles,
            Err(_) => return,
        };
        if nonces.counts.len() != oracles.len() {return};

        oracles.iter().zip(nonces.counts.iter()).for_each(|(oracle, count)| {
            if count >= &param.nonce_queue_size { return }

            if let Some(mut task) = new_task_from_oracle(oracle) {
                if ctx.task_store.exists(&task.id) { return }
                // oracle should sign the new nonce.
                task.sign_inputs.insert(0, Input::new(oracle.pubkey.clone()));
                ctx.task_store.save(&task.id, &task);
                //self.nonce_generator.generate(ctx, &task);
            }
        });
    }

    pub async fn fetch_new_key_generation(&mut self, ctx: &mut Context) {
        let response3 = self.dlc_client.oracles(QueryOraclesRequest{status: DlcOracleStatus::OracleStatusPending as i32, pagination: None}).await;
        let oracles = match response3 {
            Ok(resp) => resp.into_inner().oracles,
            Err(_) => return,
        };
        oracles.iter().for_each(|oracle| {
            if let Some(task) = new_task_from_oracle(oracle) {
                if ctx.task_store.exists(&task.id) { return }
                ctx.task_store.save(&task.id, &task);

                // self.keyshare_generator.generate(ctx, &task);
            }
        });
    }

    pub async fn fetch_new_agency(&mut self, ctx: &mut Context) {
        let response3 = self.dlc_client.agencies(QueryAgenciesRequest{status: AgencyStatus::Pending as i32, pagination: None}).await;
        let agencies = match response3 {
            Ok(resp) => resp.into_inner().agencies,
            Err(_) => return,
        };
        agencies.iter().for_each(|agency| {

            let mut participants = vec![];
            for p in &agency.participants {
                match hex::decode(p) {
                    Ok(b) => {
                       participants.push(pubkey_to_identifier(&b))
                    },
                    Err(_) => return,
                };
            }

            let task = Task::new_dkg(format!("agency-{}", agency.id), participants, agency.threshold as u16);

            if ctx.task_store.exists(&task.id) { return }
            ctx.task_store.save(&task.id, &task);

            // self.agency_generator.generate(ctx, &task);
        });
    }

    pub async fn fetch_new_attestation(&mut self, ctx: &mut Context) {
        let response3 = self.dlc_client.attestations(QueryAttestationsRequest{pagination: None}).await;
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

            // AttestationSigner::generate_commitments(ctx, &task);
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


