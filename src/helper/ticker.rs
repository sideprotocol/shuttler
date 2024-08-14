


use std::{sync::Mutex, thread::sleep, time::Duration};

use bitcoin::{consensus::encode, BlockHash, Transaction};
use bitcoincore_rpc::RpcApi;
use chrono::{Timelike, Utc};
use prost_types::Any;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use tonic::{Response, Status};
use tracing::{debug, error, info};

use crate::{app::{config,
    signer::{broadcast_signing_commitments, Shuttler}}, 
    commands::Cli, 
    helper::{client_side::get_withdraw_requests, encoding::to_base64, messages::{SigningSteps, Task}}};

use super::{bitcoin::{self as bitcoin_utils}, client_side::{self, send_cosmos_transaction}, messages::SigningBehaviour};
use cosmos_sdk_proto::{
    cosmos::{
        base::tendermint::v1beta1::{service_client::ServiceClient as TendermintServiceClient, GetLatestValidatorSetRequest, Validator}, tx::v1beta1::BroadcastTxResponse
    }, 
    side::btcbridge::{query_client::QueryClient as BtcQueryClient, BlockHeader, DkgRequestStatus, MsgSubmitBlockHeaders, MsgSubmitDepositTransaction, MsgSubmitWithdrawTransaction, QueryChainTipRequest, QueryChainTipResponse, QueryDkgRequestsRequest, QueryWithdrawRequestsRequest, QueryWithdrawRequestsResponse, Vault}};
use lazy_static::lazy_static;


#[derive(Debug)]
struct Lock {
    loading: bool
}

lazy_static! {
    static ref LOADING: Mutex<Lock> = {
        Mutex::new(Lock { loading: false })
    };
    static ref SCAN_VAULT_TXS_LOCK: Mutex<Lock> = {
        Mutex::new(Lock { loading: false })
    };
}

async fn fetch_latest_withdraw_requests(cli: &Cli, behave: &mut SigningBehaviour, signer: &mut Shuttler) {
    let host = signer.config().side_chain.rest_url.as_str();

    if cli.mock {
        return 
    }

    let seed = Utc::now().minute() as usize;
    debug!("Seed: {:?}", seed);

    match config::get_pub_key_by_index(0) {
        Some(k) => {
            let n = k.verifying_shares().len();

            debug!("Key: {:?} {}", k, seed % n);
            let coordinator = match k.verifying_shares().iter().nth(seed % n) {
                Some((k, v)) => {
                    debug!("Verifying share: {:?} {:?}", k, v);
                    k
                },
                None => {
                    error!("No verifying share found");
                    return 
                }                
            };
            if coordinator != signer.identifier() {
                return
            }
        },
        None => {
            error!("No public key found, skip!");
            return 
        }
    }

    match get_withdraw_requests(&host).await {
        Ok(response) => {
            for request in response.into_inner().requests {
                let task = Task::new(SigningSteps::SignInit, request.psbt);
                signer.sign_init(behave, &task);
                let message = serde_json::to_string(&task).unwrap();
                behave.gossipsub.publish(task.step.topic(), message.as_bytes()).expect("Failed to publish message");
            }
        },
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
            return 
        }
    };

    let mut tip_on_side = match client_side::get_bitcoin_tip_on_side(&signer.config().side_chain.grpc).await {
        Ok(res) => {
            res.get_ref().height
        }
        Err(e) => {
            error!(error=%e);
            return 
        }
    };

    let mut lock = LOADING.lock().unwrap();
    if lock.loading {
        info!("a previous task is running, skip!");
        return
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
                return
            }
        };

        let header = match signer.bitcoin_client.get_block_header(&hash) {
            Ok(b) => b,
            Err(e) => {
                error!(error=%e);
                return
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
                    return
                }
                info!("Sent block headers: {:?}", tx_response);
                block_headers = vec![] //reset
            },
            Err(e) => {
                error!("Failed to send block headers: {:?}", e);
                return
            },
        };

    }

    lock.loading = false;

}

async fn send_block_headers(shuttler: &Shuttler, block_headers: &Vec<BlockHeader>) -> Result<Response<BroadcastTxResponse>, Status> {
    let submit_block_msg = MsgSubmitBlockHeaders {
        sender: shuttler.relayer_address().as_ref().to_string(),
        block_headers: block_headers.clone()
    };

    info!("Submitting block headers: {:?}", submit_block_msg);
    let any_msg = Any::from_msg(&submit_block_msg).unwrap();
    send_cosmos_transaction(shuttler, any_msg).await
}

async fn scan_vault_txs(shuttler: &mut Shuttler, height: u64) {
    let block_hash = match shuttler.bitcoin_client.get_block_hash(height) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to get block hash: {:?}, err: {:?}", height, e);
            return;
        }
    };

    let block = match shuttler.bitcoin_client.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to get block: {}, err: {}", height, e);
            return;
        }
    };

    for tx in &block.txdata {
        if bitcoin_utils::may_be_withdraw_tx(&tx) {
            match bitcoin_utils::get_tx_proof(&shuttler.bitcoin_client, tx.compute_txid(), &block_hash) {
                Some(proof) => {
                    send_withdraw_tx(shuttler, &block_hash, &tx, proof).await;
                }
                None => {
                    error!("Failed to get tx proof");
                }
            }

            continue;
        }

        if bitcoin_utils::is_deposit_tx(tx, shuttler.config().bitcoin.network) {
            let prev_txid = tx.input[0].previous_output.txid;
            match shuttler.bitcoin_client.get_raw_transaction(&prev_txid, Some(&block_hash)) {
                Ok(prev_tx) => {
                    match bitcoin_utils::get_tx_proof(&shuttler.bitcoin_client, tx.compute_txid(), &block_hash) {
                        Some(proof) => {
                            send_deposit_tx(shuttler, &block_hash, &prev_tx, &tx, proof).await;
                        }
                        None => {
                            error!("Failed to get tx proof");
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get the previous tx: {:?}, err: {:?}", prev_txid, e);
                }
            }
        }
    }
}

async fn scan_vault_txs_loop(shuttler: &mut Shuttler) {
    let mut lock = SCAN_VAULT_TXS_LOCK.lock().unwrap();
    if lock.loading {
        info!("a previous vault tx scanning task is running, skip!");
        return
    }
    lock.loading = true;
    
    let mut height = shuttler.config().last_scanned_height + 1;

    loop {
        let side_tip = match client_side::get_bitcoin_tip_on_side (&shuttler.config().side_chain.grpc).await {
            Ok(res) => res.get_ref().height,
            Err(e) => {
                error!("Failed to get tip from side chain: {}", e);
                continue;
            }
        };

        if height > side_tip - 1 {
            continue
        }

        scan_vault_txs(shuttler, height).await;

        shuttler.config_mut().save_last_scanned_height(height);
        height += 1;

        sleep(Duration::from_secs(6));
    }
}

async fn send_withdraw_tx(shuttler: &Shuttler, block_hash: &BlockHash, tx: &Transaction, proof: Vec<String>) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgSubmitWithdrawTransaction {
        sender: shuttler.relayer_address().as_ref().to_string(),
        blockhash: block_hash.to_string(),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting withdrawal tx: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(shuttler, any_msg).await
}

async fn send_deposit_tx(shuttler: &Shuttler, block_hash: &BlockHash, prev_tx: &Transaction, tx: &Transaction, proof: Vec<String>) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgSubmitDepositTransaction {
        sender: shuttler.relayer_address().as_ref().to_string(),
        blockhash: block_hash.to_string(),
        prev_tx_bytes: to_base64(encode::serialize(prev_tx).as_slice()),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting deposit tx: {:?}", msg);
    
    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(shuttler, any_msg).await
}

async fn fetch_dkg_requests(shuttler: &mut Shuttler, behave: &mut SigningBehaviour) {
    let host = shuttler.config().side_chain.grpc.clone();
    let mut client = BtcQueryClient::connect(host.to_owned()).await.unwrap();
    if let Ok(requests) = client.query_dkg_requests(QueryDkgRequestsRequest {
        status: DkgRequestStatus::Pending as i32,
    }).await {
        for request in requests.into_inner().requests {
            if request.participants.iter().find(|p| p.consensus_address == hex::encode_upper(shuttler.validator_address())).is_some() {
                // create a dkg task
                let mut task = Task::new(SigningSteps::DkgInit, request.id.to_string());
                task.id = request.id.to_string();
                task.max_signers = request.participants.len() as u16;
                task.min_signers = request.threshold as u16;
                shuttler.dkg_init(behave, &task)
            }
        }
    };
    
}

async fn is_coordinator(validator_set: &Vec<Validator>, address: &[u8], rng: &mut ChaCha8Rng) -> bool {

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
        },
        None => {
            return false;
        }
    }
}

pub async fn tasks_fetcher(cli: &Cli , behave: &mut SigningBehaviour, shuttler: &mut Shuttler, rng: &mut ChaCha8Rng) {

    // fetch latest active validator setx
    let host = shuttler.config().side_chain.grpc.clone();
    let mut client = TendermintServiceClient::connect(host.to_owned()).await.unwrap();
    let response = client.get_latest_validator_set(GetLatestValidatorSetRequest{
        pagination: None
    }).await.unwrap();

    let mut validator_set = response.into_inner().validators;
    validator_set.sort_by(|a, b| a.voting_power.cmp(&b.voting_power));


    // ===========================
    // all participants tasks:
    // ===========================
    // 1. fetch dkg requests
    fetch_dkg_requests(shuttler, behave).await;


    // ===========================
    // coordinator tasks:
    // ===========================
    if !is_coordinator(&validator_set, shuttler.validator_address(), rng).await {
        info!("Not a coordinator in this round, skip!");
        return
    }

    broadcast_signing_commitments(behave, shuttler);
    fetch_latest_withdraw_requests(cli, behave, shuttler).await;
    sync_btc_blocks(shuttler);
    
    scan_vault_txs_loop(shuttler);
}
