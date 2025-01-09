
use std::collections::BTreeMap;

use anyhow::anyhow;
use bitcoin::{hashes::Hash, sighash::{Prevouts, SighashCache}, Address, Psbt, TapSighashType};
use side_proto::side::btcbridge::{query_client::QueryClient as BtcQueryClient, DkgRequest, DkgRequestStatus, QueryDkgRequestsRequest, SigningRequest};
use tracing::{debug, error, info};

use crate::{
    apps::{Context, Input, SignMode, Task}, 
    helper::{bitcoin::new_task_from_psbt, client_side::get_signing_requests, encoding::{from_base64, pubkey_to_identifier}, mem_store, store::Store}, 
};

use super::BridgeSigner;

impl BridgeSigner {
    pub async fn tasks_executor(&self, ctx: &mut Context) {
        
        if ctx.swarm.connected_peers().count() == 0 {
            return
        }

        // // 1. dkg tasks
        self.fetch_dkg_requests(ctx).await;

        // // fetch request for next execution
        self.fetch_signing_requests(ctx).await;
        // broadcast_sign_packages(swarm);
        
    }

    pub async fn fetch_signing_requests(
        &self,
        ctx: &mut Context,
    ) {
        let host = ctx.conf.side_chain.grpc.as_str();

        match get_signing_requests(&host).await {
            Ok(response) => {
                let requests = response.into_inner().requests;
                let tasks_in_process = requests.iter().map(|r| r.txid.clone() ).collect::<Vec<_>>();
                debug!("In-process signing tasks: {:?} {:?}", tasks_in_process.len(), tasks_in_process);
                for request in requests {
                    // create a dkg task
                    match new_task_from_psbt(ctx, &request.psbt, SignMode::SignWithTweak) {
                        Ok(task) => {
                            if ctx.task_store.exists(&task.id) { continue; }
                            ctx.task_store.save(&task.id, &task);
            
                            debug!("start sign: {}", task.id);
                            self.signer.generate_commitments(ctx, &task);                       
                        },
                        Err(e) => error!("{:?}", e),

                    }
                }
            }
            Err(e) => {
                error!("Failed to fetch signing requests: {:?}", e);
                return;
            }
        };
    }

    async fn fetch_dkg_requests(&self, ctx: &mut Context) {
        let host = ctx.conf.side_chain.grpc.clone();
        let mut client = match BtcQueryClient::connect(host.to_owned()).await {
            Ok(client) => client,
            Err(e) => {
                error!("Failed to create btcbridge query client: {host} {}", e);
                return;
            }
        };
        if let Ok(requests_response) = client
            .query_dkg_requests(QueryDkgRequestsRequest {
                status: DkgRequestStatus::Pending as i32,
            })
            .await
        {
            let requests = requests_response.into_inner().requests;
            debug!("DKG Requests, {:?}", requests);

            for request in requests {
                if request
                    .participants
                    .iter()
                    .find(|p| p.consensus_pubkey == ctx.id_base64)
                    .is_some()
                {
                    // create a dkg task
                    if let Some(mut task) = new_task_from_vault_dkg(&request) {

                        if ctx.task_store.exists(&task.id) { continue; }
                        task.dkg_input.tweaks = request.vault_types;
                        ctx.task_store.save(&task.id, &task);
        
                        self.keygen.generate(ctx, &task);
                    }
                }
            }
        };
    }
}

// fn task_id_to_request_id(task_id: &String) -> u64 {
//     task_id.replace("dkg-", "").parse().unwrap()
// }

fn request_id_to_task_id(id: u64) -> String {
    format!("dkg-{}", id)
}

fn new_task_from_vault_dkg(request: &DkgRequest) -> Option<Task> {

    let mut participants = vec![];
    for p in &request.participants {
        match from_base64(&p.consensus_pubkey) {
            Ok(b) => {
               participants.push(pubkey_to_identifier(&b))
            },
            Err(_) => return None,
        };
    }
    Some(Task::new_dkg(request_id_to_task_id(request.id), participants, request.threshold as u16 ))
}


