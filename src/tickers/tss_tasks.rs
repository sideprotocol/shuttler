use std:: sync::Mutex;

use bitcoincore_rpc::RpcApi;
use chrono::{Timelike, Utc};
use libp2p::{PeerId, Swarm};
use prost_types::Any;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use tonic::{Response, Status};
use tracing::{debug, error, info};

use crate::{
    app::{
        config,
        shuttler::{broadcast_dkg_commitments, broadcast_signing_commitments, Shuttler},
    },
    commands::Cli,
    helper::{
        client_side::{self, send_cosmos_transaction}, messages::SigningBehaviour, store,
        client_side::get_withdraw_requests,
        messages::{SigningSteps, Task},
    }, protocols::{dkg::{collect_dkg_packages, generate_round1_package, DKGRequest, DKGTask}, Round, TSSBehaviour},
};

use cosmos_sdk_proto::{
    cosmos::{
        base::tendermint::v1beta1::{
            service_client::ServiceClient as TendermintServiceClient, GetLatestValidatorSetRequest,
            Validator,
        },
        tx::v1beta1::BroadcastTxResponse,
    },
    side::btcbridge::{
        query_client::QueryClient as BtcQueryClient, BlockHeader, DkgRequest, DkgRequestStatus, MsgSubmitBlockHeaders, QueryDkgRequestsRequest
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

async fn fetch_latest_withdraw_requests(
    cli: &Cli,
    behave: &mut TSSBehaviour,
    signer: &mut Shuttler,
) {
    let host = signer.config().side_chain.grpc.as_str();

    if cli.mock {
        return;
    }

    match get_withdraw_requests(&host).await {
        Ok(response) => {
            let requests = response.into_inner().requests;
            for request in requests {
                // let task = Task::new(SigningSteps::SignInit, request.psbt);
                // signer.sign_init(behave, &task);
                // let message = serde_json::to_string(&task).unwrap();
                // match behave
                //     .gossipsub
                //     .publish(task.step.topic(), message.as_bytes())
                // {
                //     Ok(_) => {
                //         info!("Published sign init message to gossip: {:?}", message);
                //     }
                //     Err(e) => {
                //         error!("Failed to publish sign init message to gossip: {:?}", e);
                //     }
                // }
            }
        }
        Err(e) => {
            error!("Failed to fetch signing requests: {:?}", e);
            return;
        }
    };
}

async fn sync_btc_blocks(signer: &mut Shuttler) {
    let tip_on_bitcoin = match signer.bitcoin_client.get_block_count() {
        Ok(height) => height,
        Err(e) => {
            error!(error=%e);
            return;
        }
    };

    let mut tip_on_side =
        match client_side::get_bitcoin_tip_on_side(&signer.config().side_chain.grpc).await {
            Ok(res) => res.get_ref().height,
            Err(e) => {
                error!(error=%e);
                return;
            }
        };

    let mut lock = LOADING.lock().unwrap();
    if lock.loading {
        info!("a previous task is running, skip!");
        return;
    }
    lock.loading = true;

    let mut block_headers: Vec<BlockHeader> = vec![];

    let batch = if tip_on_side + 10 > tip_on_bitcoin {
        tip_on_bitcoin
    } else {
        tip_on_side + 10
    };

    info!("==========================================================");
    info!("Syncing blocks from {} to {}", tip_on_side, batch);
    info!("==========================================================");

    while tip_on_side < batch {
        tip_on_side = tip_on_side + 1;
        let hash = match signer.bitcoin_client.get_block_hash(tip_on_side) {
            Ok(hash) => hash,
            Err(e) => {
                error!(error=%e);
                return;
            }
        };

        let header = match signer.bitcoin_client.get_block_header(&hash) {
            Ok(b) => b,
            Err(e) => {
                error!(error=%e);
                return;
            }
        };

        block_headers.push(BlockHeader {
            version: header.version.to_consensus() as u64,
            hash: header.block_hash().to_string(),
            height: tip_on_side,
            previous_block_hash: header.prev_blockhash.to_string(),
            merkle_root: header.merkle_root.to_string(),
            nonce: header.nonce as u64,
            bits: format!("{:x}", header.bits.to_consensus()),
            time: header.time as u64,
            ntx: 0u64,
        });

        // setup a batch of 1 block headers
        // if block_headers.len() >= 1 {
        //     break;
        // }

        match send_block_headers(signer, &block_headers).await {
            Ok(resp) => {
                let tx_response = resp.into_inner().tx_response.unwrap();
                if tx_response.code != 0 {
                    error!("Failed to send block headers: {:?}", tx_response);
                    return;
                }
                info!("Sent block headers: {:?}", tx_response);
                block_headers = vec![] //reset
            }
            Err(e) => {
                error!("Failed to send block headers: {:?}", e);
                return;
            }
        };
    }

    lock.loading = false;
}

async fn send_block_headers(
    shuttler: &Shuttler,
    block_headers: &Vec<BlockHeader>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let submit_block_msg = MsgSubmitBlockHeaders {
        sender: shuttler.config().signer_cosmos_address().to_string(),
        block_headers: block_headers.clone(),
    };

    info!("Submitting block headers: {:?}", submit_block_msg);
    let any_msg = Any::from_msg(&submit_block_msg).unwrap();
    send_cosmos_transaction(shuttler, any_msg).await
}

async fn fetch_dkg_requests(shuttler: &mut Shuttler) {
    let host = shuttler.config().side_chain.grpc.clone();
    let mut client = BtcQueryClient::connect(host.to_owned()).await.unwrap();
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
                if store::has_dkg_preceeded(task.id.as_str()) {
                    continue;
                };
                generate_round1_package(shuttler.identifier().clone(), &task);
                debug!("generated a new key: {:?}", request);
                store::save_task(&task);
            }
        }
    };
}

async fn is_coordinator(
    validator_set: &Vec<Validator>,
    address: &[u8],
    rng: &mut ChaCha8Rng,
) -> bool {
    let len = if validator_set.len() > 21 {
        21
    } else {
        validator_set.len()
    };

    let index = rng.gen_range(0..len);
    debug!("generated index: {}", index);

    match validator_set.iter().nth(index) {
        Some(v) => {
            debug!("Selected coordinator: {:?}", v);
            let b = bech32::decode(v.address.as_str()).unwrap().1;
            return b == address;
        }
        None => {
            return false;
        }
    }
}

pub async fn tasks_fetcher(
    cli: &Cli,
    // peers: Vec<&PeerId>,
    // behave: &mut TSSBehaviour,
    swarm : &mut Swarm<TSSBehaviour>,
    shuttler: &mut Shuttler,
    rng: &mut ChaCha8Rng,
) {

    
    // fetch latest active validator setx
    // let host = shuttler.config().side_chain.grpc.clone();
    // let mut client = TendermintServiceClient::connect(host.to_owned())
    //     .await
    //     .unwrap();
    // let response = client
    //     .get_latest_validator_set(GetLatestValidatorSetRequest { pagination: None })
    //     .await
    //     .unwrap();

    // let mut validator_set = response.into_inner().validators;
    // validator_set.sort_by(|a, b| a.voting_power.cmp(&b.voting_power));

    // ===========================
    // all participants tasks:
    // ===========================

    // 1. fetch dkg requests
    fetch_dkg_requests(shuttler).await;
    collect_dkg_packages(swarm);
    fetch_latest_withdraw_requests(cli, behave, signer)
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
