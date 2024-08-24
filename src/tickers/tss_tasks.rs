use std:: sync::Mutex;

use libp2p:: Swarm;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use tracing::{debug, error, info};

use crate::{app::shuttler::Shuttler, helper::client_side::get_withdraw_requests, protocols::{dkg::{self, collect_dkg_packages, generate_round1_package, DKGTask}, sign::{collect_tss_packages, generate_nonce_and_commitments}, TSSBehaviour}};

use cosmos_sdk_proto::{
    cosmos:: base::tendermint::v1beta1::{
            service_client::ServiceClient as TendermintServiceClient, GetLatestValidatorSetRequest,
            Validator,
        },
    side::btcbridge::{
        query_client::QueryClient as BtcQueryClient, BitcoinWithdrawRequest, DkgRequestStatus, QueryDkgRequestsRequest
    },
};
use lazy_static::lazy_static;

#[derive(Debug)]
struct Lock {
    loading: bool,
}

lazy_static! {
    static ref LOADING: Mutex<Lock> = Mutex::new(Lock { loading: false });
}

async fn fetch_withdraw_signing_requests(
    behave: &mut TSSBehaviour,
    shuttler: &mut Shuttler,
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

async fn fetch_dkg_requests(shuttler: &mut Shuttler) {
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


pub async fn tasks_fetcher(
    // peers: Vec<&PeerId>,
    // behave: &mut TSSBehaviour,
    swarm : &mut Swarm<TSSBehaviour>,
    shuttler: &mut Shuttler,
) {

    

    // ===========================
    // all participants tasks:
    // ===========================

    // 1. fetch dkg requests
    collect_dkg_packages(swarm);

    fetch_dkg_requests(shuttler).await;
    fetch_withdraw_signing_requests( swarm.behaviour_mut(), shuttler).await;
    collect_tss_packages(swarm, shuttler).await;

    // broadcast_dkg_commitments(behave, shuttler);

    // ===========================
    // coordinator tasks:
    // ===========================
    // if !is_coordinator(&validator_set, shuttler.validator_address(), rng).await {
    //     info!("Not a coordinator in this round, skip!");
    //     return;
    // }

    // broadcast_signing_commitments(behave, shuttler);
    // fetch_latest_withdraw_requests(cli, behave, shuttler).await;
    // sync_btc_blocks(shuttler).await;
}
