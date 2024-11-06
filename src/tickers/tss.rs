
use cosmos_sdk_proto::side::btcbridge::{query_client::QueryClient as BtcQueryClient, DkgRequestStatus, MsgCompleteDkg, QueryDkgRequestsRequest};
use cosmrs::Any;
use libp2p:: Swarm;
use tracing::{debug, error, info};

use crate::{
    app::signer::Signer, 
    helper::client_side::{get_signing_requests, send_cosmos_transaction}, 
    protocols::{dkg::{broadcast_dkg_packages, generate_round1_package, DKGTask}, 
    sign::{process_tasks, save_task_into_signing_queue}, Round, TSSBehaviour
}};
pub async fn time_free_tasks_executor(
    signer: &Signer,
) {
    debug!("start");
    if signer.config().get_validator_key().is_none() {
        return;
    }

    debug!("querying...");

    // 1. fetch dkg request
    fetch_dkg_requests(signer).await;
    fetch_signing_requests(signer).await;
    // broadcast_sign_packages(swarm);
    submit_dkg_address(signer).await;
}

pub async fn time_aligned_tasks_executor(
    swarm : &mut Swarm<TSSBehaviour>,
    signer: &Signer,
) {

    debug!("Start time aligned task!");
    if signer.config().get_validator_key().is_none() {
        return;
    }

    debug!("Connected peers: {:?}", swarm.connected_peers().collect::<Vec<_>>());

    // 1. collect dkg packages
    broadcast_dkg_packages(swarm, signer);
    // 2. collect signing requests tss packages
    process_tasks(swarm, signer).await;

}

pub async fn fetch_signing_requests(
    signer: &Signer,
) {
    let host = signer.config().side_chain.grpc.as_str();

    match get_signing_requests(&host).await {
        Ok(response) => {
            let requests = response.into_inner().requests;
            let tasks_in_process = requests.iter().map(|r| r.txid.clone() ).collect::<Vec<_>>();
            debug!("In-process signing tasks: {:?} {:?}", tasks_in_process.len(), tasks_in_process);
            signer.list_signing_tasks().iter().for_each(|task| {
                if !tasks_in_process.contains(&task.id) {
                    debug!("Removing expired signing task: {:?}", task.id);
                    signer.remove_signing_task(&task.id);
                }
            });
            for request in requests {
                save_task_into_signing_queue(request, signer);
            }
        }
        Err(e) => {
            error!("Failed to fetch signing requests: {:?}", e);
            return;
        }
    };
}

async fn fetch_dkg_requests(signer: &Signer) {
    let host = signer.config().side_chain.grpc.clone();
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
        let tasks_in_process = requests.iter().map(|r| format!("dkg-{}", r.id)).collect::<Vec<_>>();
        signer.list_dkg_tasks().iter().for_each(|task| {
            if !tasks_in_process.contains(&task.id) {
                debug!("Removing completed task: {:?}", task.id);
                signer.remove_dkg_task(&task.id);
            }
        });

        let x: Vec<u64> = requests.iter().map(|a| a.id).collect::<Vec<_>>();
        debug!("In-process DKGs: {:?}", x);
        for request in requests {
            if request
                .participants
                .iter()
                .find(|p| p.consensus_address == signer.validator_address())
                .is_some()
            {
                // create a dkg task
                let task = DKGTask::from_request(&request);
                if signer.has_task_preceeded(&task.id) {
                    continue;
                };
                generate_round1_package(signer, &task);
                info!("Start DKG {:?}, {:?}", &task.id, task.participants);
                signer.save_dkg_task(&task);
            }
        }
    };
}

async fn submit_dkg_address(signer: &Signer) {
    for task in signer.list_dkg_tasks().iter_mut() {
        if task.round != Round::Closed {
            continue;
        }

        if task.submitted {
            continue;
        }

        let task_id = task.id.replace("dkg-", "").parse().unwrap();
        // submit the vault address to sidechain
        let cosm_msg = MsgCompleteDkg {
            id: task_id,
            sender: signer.config().relayer_bitcoin_address(),
            vaults: task.dkg_vaults.clone(),
            consensus_address: signer.validator_address(),
            signature: signer.get_complete_dkg_signature(task_id, &task.dkg_vaults),
        };

        let any = Any::from_msg(&cosm_msg).unwrap();
        match send_cosmos_transaction(signer.config(), any).await {
            Ok(resp) => {
                let tx_response = resp.into_inner().tx_response.unwrap();
                if tx_response.code == 0 {
                    task.submitted = true;
                    signer.save_dkg_task(task);
                
                    info!("Sent dkg vault: {:?}", tx_response);
                    continue;
                }

                error!("Failed to send dkg vault: {:?}", tx_response);
            },
            Err(e) => {
                error!("Failed to send dkg vault: {:?}", e);
            },
        };
    };
    
}
