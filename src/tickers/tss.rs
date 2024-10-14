
use cosmos_sdk_proto::side::btcbridge::{query_client::QueryClient as BtcQueryClient, DkgRequestStatus, MsgCompleteDkg, QueryDkgRequestsRequest};
use cosmrs::Any;
use libp2p:: Swarm;
use tracing::{debug, error, info};

use crate::{
    app::signer::Signer, 
    helper::client_side::{get_signing_requests, send_cosmos_transaction}, 
    protocols::{dkg::{self, collect_dkg_packages, generate_round1_package, list_tasks, save_task, DKGTask}, 
    sign::{self, broadcast_packages, list_sign_tasks, process_tasks, save_task_into_signing_queue}, Round, TSSBehaviour
}};
pub async fn time_free_tasks_executor(
    swarm : &mut Swarm<TSSBehaviour>,
    signer: &Signer,
) {
    if signer.config().get_validator_key().is_none() {
        return;
    }

    // 1. fetch dkg request
    fetch_dkg_requests(signer).await;
    fetch_signing_requests(signer).await;
    broadcast_packages(swarm);
    submit_dkg_address(signer).await;
}

pub async fn time_aligned_tasks_executor(
    swarm : &mut Swarm<TSSBehaviour>,
    signer: &Signer,
) {

    if signer.config().get_validator_key().is_none() {
        return;
    }

    debug!("Connected peers: {:?}", swarm.connected_peers().collect::<Vec<_>>());

    // 1. collect dkg packages
    collect_dkg_packages(swarm);
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
            debug!("In-process signing tasks: {:?}", tasks_in_process);
            list_sign_tasks().iter().for_each(|task| {
                if !tasks_in_process.contains(&task.id) {
                    debug!("Removing expired signing task: {:?}", task.id);
                    sign::remove_task(&task.id);
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
        let tasks_in_process = requests.iter().map(|r| format!("dkg-{}", r.id)).collect::<Vec<_>>();
        list_tasks().iter().for_each(|task| {
            if !tasks_in_process.contains(&task.id) {
                debug!("Removing expired task: {:?}", task.id);
                dkg::remove_task(&task.id);
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
                if dkg::has_task_preceeded(task.id.as_str()) {
                    continue;
                };
                generate_round1_package(signer.identifier().clone(), &task);
                info!("Start DKG {:?}, {:?}", &task.id, task.participants);
                dkg::save_task(&task);
            }
        }
    };
}

async fn submit_dkg_address(signer: &Signer) {
    for task in list_tasks().iter_mut() {
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
                    save_task(task);
                
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
