
use cosmos_sdk_proto::side::btcbridge::{query_client::QueryClient as BtcQueryClient, BitcoinWithdrawRequest, DkgRequestStatus, QueryDkgRequestsRequest};
use libp2p:: Swarm;
use tracing::{debug, error};

use crate::{app::signer::Signer, helper::client_side::get_withdraw_requests, protocols::{dkg::{self, collect_dkg_packages, generate_round1_package, DKGTask}, sign::{collect_tss_packages, generate_nonce_and_commitments}, TSSBehaviour}};

async fn fetch_withdraw_signing_requests(
    _behave: &mut TSSBehaviour,
    shuttler: &Signer,
) {
    let host = shuttler.config().side_chain.grpc.as_str();

    match get_withdraw_requests(&host).await {
        Ok(response) => {
            let mut requests = response.into_inner().requests;
            // mock for testing
            if requests.len() == 0 {
                requests.push(BitcoinWithdrawRequest {
                    address: "tb1pr8auk03a54w547e3q7w4xqu0wj57skgp3l8sfeus0skhdhltrq5qxtur6k".to_string(),
                    psbt: "cHNidP8BAI8CAAAAA+67aDQ4JUktcSgEunL5O7FG5T2plGO95wYDt2aIajrAAQAAAAD/////7rtoNDglSS1xKAS6cvk7sUblPamUY73nBgO3ZohqOsABAAAAAP/////uu2g0OCVJLXEoBLpy+TuxRuU9qZRjvecGA7dmiGo6wAEAAAAA/////wEAAAAAAAAAAAFqAAAAAAABASsQJwAAAAAAACJRIBn7yz49pV1K+zEHnVMDj3Sp6FkBj88E55B8LXbf6xgoAAEBKxAnAAAAAAAAIlEgGfvLPj2lXUr7MQedUwOPdKnoWQGPzwTnkHwtdt/rGCgAAQErECcAAAAAAAAiUSAZ+8s+PaVdSvsxB51TA490qehZAY/PBOeQfC123+sYKAAA".to_string(),
                    status: 1,
                    sequence: 0,
                    txid: "123455".to_string(),
                });
            }
            for request in requests {
                generate_nonce_and_commitments(request, shuttler);
            }
        }
        Err(e) => {
            error!("Failed to fetch signing requests: {:?}", e);
            return;
        }
    };
}

async fn fetch_dkg_requests(shuttler: &Signer) {
    let host = shuttler.config().side_chain.grpc.clone();
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
        debug!("Fetched DKG requests: {:?}", &requests);
        for request in requests {
            if request
                .participants
                .iter()
                .find(|p| p.consensus_address == shuttler.validator_address())
                .is_some()
            {
                // create a dkg task
                let task = DKGTask::from_request(&request);
                if dkg::has_task_preceeded(task.id.as_str()) {
                    continue;
                };
                generate_round1_package(shuttler.identifier().clone(), &task);
                debug!("generated a new key: {:?}", request);
                dkg::save_task(&task);
            }
        }
    };
}


pub async fn tss_tasks_fetcher(
    // peers: Vec<&PeerId>,
    // behave: &mut TSSBehaviour,
    swarm : &mut Swarm<TSSBehaviour>,
    shuttler: &Signer,
) {

    if shuttler.config().get_validator_key().is_none() {
        return;
    }
    // ===========================
    // all participants tasks:
    // ===========================

    // 1. fetch dkg requests
    fetch_dkg_requests(shuttler).await;
    // 2. collect dkg packages
    collect_dkg_packages(swarm);
    // 3. fetch withdraw signing requests
    fetch_withdraw_signing_requests( swarm.behaviour_mut(), shuttler).await;
    // 4. collect withdraw tss packages
    collect_tss_packages(swarm, shuttler).await;

}
