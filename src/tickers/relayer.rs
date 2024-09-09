use std::time::Duration;

use bitcoin::{consensus::encode, Address, BlockHash, OutPoint, Transaction};
use bitcoincore_rpc::{Error, RpcApi};
use futures::join;
use prost_types::Any;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use tokio::{sync::Mutex, time::sleep};
use tonic::{Response, Status};
use tracing::{debug, error, info};

use crate::{
    app::{config::{get_database_with_name, Config}, relayer::Relayer},
    helper::{
        bitcoin::{self as bitcoin_utils}, client_side::{self, send_cosmos_transaction}, encoding::to_base64, 
    },
};

use cosmos_sdk_proto::{
    cosmos::{base::tendermint::v1beta1::{
        service_client::ServiceClient as TendermintServiceClient, GetLatestValidatorSetRequest,
        Validator,
    }, tx::v1beta1::BroadcastTxResponse},
    side::btcbridge::{BlockHeader, MsgSubmitBlockHeaders, MsgSubmitDepositTransaction, MsgSubmitWithdrawTransaction, QueryParamsRequest},
};
use lazy_static::lazy_static;

#[derive(Debug)]
struct Lock {
    loading: bool,
}

const DB_KEY_BITCOIN_TIP: &str = "bitcoin_tip";
const DB_KEY_VAULTS: &str = "bitcoin_vaults";
const DB_KEY_VAULTS_LAST_UPDATE: &str = "bitcoin_vaults_last_update";

lazy_static! {
    static ref LOADING: Mutex<Lock> = Mutex::new(Lock { loading: false });
    static ref DB: sled::Db = {
        let path = get_database_with_name("relayer");
        sled::open(path).unwrap()
    };
}

/// Start relayer tasks
/// 1. Sync BTC blocks
/// 2. Scan vault txs
/// Only the coordinator will run the tasks, the coordinator is selected randomly from the active validator set
pub async fn start_relayer_tasks(relayer: &Relayer) {
    // fetch latest active validator setx
    let host = relayer.config().side_chain.grpc.clone();
    let mut client = match TendermintServiceClient::connect(host.to_owned()).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create tendermint query client: {host} {}", e);
            return;
        }
    };
    let response = match client.get_latest_validator_set(GetLatestValidatorSetRequest { pagination: None }).await {
        Ok(response) => response,
        Err(e) => {
            error!("Failed to get latest validator set: {:?}", e);
            return;
        }
    };
    let mut validator_set = response.into_inner().validators;
    validator_set.sort_by(|a, b| a.voting_power.cmp(&b.voting_power));
    
    join!(
        sync_btc_blocks(&relayer),
        scan_vault_txs_loop(&relayer)
    );
}

fn _is_coordinator(
    validator_set: &Vec<Validator>,
    address: String,
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
            // let b = bech32::decode(&v.address).unwrap().1;
            // return b == address;
            v.address == address
        }
        None => {
            return false;
        }
    }
}

pub async fn sync_btc_blocks(relayer: &Relayer) {
    let tip_on_bitcoin = match relayer.bitcoin_client.get_block_count() {
        Ok(height) => height - 1,
        Err(e) => {
            error!(error=%e);
            return;
        }
    };

    let mut tip_on_side =
        match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
            Ok(res) => res.get_ref().height,
            Err(e) => {
                error!(error=%e);
                return;
            }
        };

    if tip_on_bitcoin == tip_on_side {
        check_block_hash_is_corrent(&relayer, tip_on_side).await;
        debug!("No new blocks to sync, sleep for 60 seconds...");
        sleep(Duration::from_secs(60)).await;
        return;
    }
    
    let batch = if tip_on_side + 10 > tip_on_bitcoin {
        tip_on_bitcoin
    } else {
        tip_on_side + 10
    };
    debug!("Syncing blocks from {} to {}", tip_on_side, batch);
    
    let mut block_headers: Vec<BlockHeader> = vec![];
    while tip_on_side < batch {
        tip_on_side = tip_on_side + 1;
        let header = match fetch_block_header_by_height(relayer, tip_on_side).await {
            Ok(header) => header,
            Err(e) => {
                error!("Failed to fetch block header: {:?}", e);
                return;
            }
        };
        block_headers.push(header);
    }
    if block_headers.is_empty() {
        return;
    }

    // submit block headers in a batch
    match send_block_headers(relayer, &block_headers).await {
        Ok(resp) => {
            let tx_response = resp.into_inner().tx_response.unwrap();
            if tx_response.code != 0 {
                error!("Failed to send block headers: {:?}", tx_response);
                return;
            }
            info!("Sent block headers: {:?}", tx_response);
        }
        Err(e) => {
            error!("Failed to send block headers: {:?}", e);
            return;
        }
    };
}

pub async fn fetch_block_header_by_height(relayer: &Relayer, height: u64) -> Result<BlockHeader, Error> {
    let hash = match relayer.bitcoin_client.get_block_hash(height) {
        Ok(hash) => hash,
        Err(e) => {
            error!(error=%e);
            return Err(e);
        }
    };

    let header = match relayer.bitcoin_client.get_block_header(&hash) {
        Ok(b) => b,
        Err(e) => {
            error!(error=%e);
            return Err(e);
        }
    };

    Ok(BlockHeader {
        version: header.version.to_consensus() as u64,
        hash: header.block_hash().to_string(),
        height,
        previous_block_hash: header.prev_blockhash.to_string(),
        merkle_root: header.merkle_root.to_string(),
        nonce: header.nonce as u64,
        bits: format!("{:x}", header.bits.to_consensus()),
        time: header.time as u64,
        ntx: 0u64,
    })
}

pub async fn check_block_hash_is_corrent(relayer: &Relayer, height: u64) {
    let hash = match relayer.bitcoin_client.get_block_hash(height) {
        Ok(hash) => hash,
        Err(e) => {
            error!(error=%e);
            return;
        }
    };
    let bitcoin_hash = hash.to_string();
    let side_hash =
        match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
            Ok(res) => res.get_ref().hash.clone(),
            Err(e) => {
                error!(error=%e);
                return;
            }
        };

    if bitcoin_hash != side_hash {
        let header = match relayer.bitcoin_client.get_block_header(&hash) {
            Ok(b) => b,
            Err(e) => {
                error!(error=%e);
                return;
            }
        };

        let mut block_headers: Vec<BlockHeader> = vec![];
        block_headers.push(BlockHeader {
            version: header.version.to_consensus() as u64,
            hash: header.block_hash().to_string(),
            height,
            previous_block_hash: header.prev_blockhash.to_string(),
            merkle_root: header.merkle_root.to_string(),
            nonce: header.nonce as u64,
            bits: format!("{:x}", header.bits.to_consensus()),
            time: header.time as u64,
            ntx: 0u64,
        });

        match send_block_headers(relayer, &block_headers).await {
            Ok(_) => {
                debug!("Resend block headers to fix block hash, {:?}", block_headers.iter().map(|b| b.height).collect::<Vec<_>>());
                return;
            }
            Err(e) => {
                error!("Failed to resend block headers: {:?}", e);
                return;
            }
        }
    }
}

pub async fn send_block_headers(
    relayer: &Relayer,
    block_headers: &Vec<BlockHeader>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let submit_block_msg = MsgSubmitBlockHeaders {
        sender: relayer.config().relayer_bitcoin_address().to_string(),
        block_headers: block_headers.clone(),
    };

    info!("Submitting block headers: {:?}", submit_block_msg);
    let any_msg = Any::from_msg(&submit_block_msg).unwrap();
    send_cosmos_transaction(relayer.config(), any_msg).await
}

pub async fn scan_vault_txs_loop(relayer: &Relayer) {
    let height = get_last_scanned_height(relayer.config()) + 1;
    debug!("Start to scan vault txs from height: {}", height);

    let side_tip =
        match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
            Ok(res) => res.get_ref().height,
            Err(e) => {
                error!("Failed to get tip from side chain: {}", e);
                return;
            }
        };
    if height > side_tip - 1 {
        debug!("No new txs to sync, sleep for 60 seconds...");
        sleep(Duration::from_secs(60)).await;
        return;
    }

    debug!("Scanning height: {:?}, side tip: {:?}", height, side_tip);
    scan_vault_txs(relayer, height).await;
    save_last_scanned_height(height);
}

pub async fn scan_vault_txs(relayer: &Relayer, height: u64) {
    let block_hash = match relayer.bitcoin_client.get_block_hash(height) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to get block hash: {:?}, err: {:?}", height, e);
            return;
        }
    };

    let block = match relayer.bitcoin_client.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to get block: {}, err: {}", height, e);
            return;
        }
    };

    let vaults = get_cached_vaults(relayer.config().side_chain.grpc.clone()).await;

    for (i, tx) in block.txdata.iter().enumerate() {
        debug!(
            "Checking tx {:?}, height: {:?}, index: {:?}",
            tx.compute_txid(),
            height,
            i
        );

        if bitcoin_utils::may_be_withdraw_tx(&tx) {
            let prev_txid = tx.input[0].previous_output.txid;
            let prev_vout=tx.input[0].previous_output.vout;

            let address = match relayer
                .bitcoin_client
                .get_raw_transaction (&prev_txid, None)
            {
                Ok(prev_tx) => {
                    if prev_tx.output.len() <= prev_vout as usize {
                        error!("Invalid previous tx");
                        continue;
                    }

                    match Address::from_script(prev_tx.output[prev_vout as usize].script_pubkey.as_script(), relayer.config().bitcoin.network) {
                        Ok(addr) => Some(addr),
                        Err(e) => {
                            error!("Failed to parse public key script: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to get the previous tx: {:?}, err: {:?}",
                        prev_txid, e
                    );

                    None
                }
            };

            if address.is_some() {
                let address = address.unwrap().to_string();
                if vaults.contains(&address) {
                    debug!("Withdrawal tx found... {:?}", &tx);

                    let proof = bitcoin_utils::compute_tx_proof(
                        block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
                        i,
                    );

                    match send_withdraw_tx(relayer, &block_hash, &tx, proof).await {
                        Ok(resp) => {
                            let tx_response = resp.into_inner().tx_response.unwrap();
                            if tx_response.code != 0 {
                                error!("Failed to submit withdrawal tx: {:?}", tx_response);
                                continue;
                            }
        
                            info!("Submitted withdrawal tx: {:?}", tx_response);
                        }
                        Err(e) => {
                            error!("Failed to submit withdrawal tx: {:?}", e);
                        }
                    }

                    continue;
                }
            }
        }

        if bitcoin_utils::is_deposit_tx(tx, relayer.config().bitcoin.network, &vaults) {
            debug!("Deposit tx found... {:?}", &tx);

            if bitcoin_utils::is_runes_deposit(tx) {
                if !relayer.config().relay_runes {
                    debug!("Skip the tx due to runes relaying not enabled");
                    continue;
                }

                let edict = match bitcoin_utils::parse_runes(tx) {
                    Some(edict) => edict,
                    None => {
                        debug!("Failed to parse runes deposit tx {}", tx.compute_txid());
                        continue;
                    }
                };

                // get the rune by id
                let rune =match relayer.ordinals_client.get_rune(edict.id).await {
                    Ok(rune) => rune.entry.spaced_rune,
                    Err(e) => {
                        error!("Failed to get rune {}: {}", edict.id, e);
                        continue;
                    }
                };

                // get the runes output
                let output = match relayer.ordinals_client.get_output(OutPoint::new(tx.compute_txid(), edict.output)).await {
                    Ok(output) => output,
                    Err(e) => {
                        error!("Failed to get output {}:{} from ord: {}", tx.compute_txid(), edict.output, e);
                        continue;
                    }
                };

                // validate if the runes deposit is valid
                if !bitcoin_utils::validate_runes(&edict, &rune, &output) {
                    debug!("Failed to validate runes deposit tx {}", tx.compute_txid());
                    continue;
                }
            }

            let proof = bitcoin_utils::compute_tx_proof(
                block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
                i,
            );

            let prev_txid = tx.input[0].previous_output.txid;
            let prev_tx = match relayer
                .bitcoin_client
                .get_raw_transaction(&prev_txid, None)
            {
                Ok(prev_tx) => prev_tx,
                Err(e) => {
                    error!(
                        "Failed to get the previous tx: {:?}, err: {:?}",
                        prev_txid, e
                    );

                    continue;
                }
            };

            match send_deposit_tx(relayer, &block_hash, &prev_tx, &tx, proof).await {
                Ok(resp) => {
                    let tx_response = resp.into_inner().tx_response.unwrap();
                    if tx_response.code != 0 {
                        error!("Failed to submit deposit tx: {:?}", tx_response);
                        continue;
                    }

                    info!("Submitted deposit tx: {:?}", tx_response);
                }
                Err(e) => {
                    error!("Failed to submit deposit tx: {:?}", e);
                }
            }
        }
    }
}

pub async fn send_withdraw_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgSubmitWithdrawTransaction {
        sender: relayer.config().relayer_bitcoin_address().to_string(),
        blockhash: block_hash.to_string(),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting withdrawal tx: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(relayer.config(), any_msg).await
}

pub async fn send_deposit_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    prev_tx: &Transaction,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgSubmitDepositTransaction {
        sender: relayer.config().relayer_bitcoin_address(),
        blockhash: block_hash.to_string(),
        prev_tx_bytes: to_base64(encode::serialize(prev_tx).as_slice()),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting deposit tx: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(&relayer.config(), any_msg).await
}

pub(crate) fn get_last_scanned_height(config: &Config) -> u64 {
    match DB.get(DB_KEY_BITCOIN_TIP) {
        Ok(Some(tip)) => {
            serde_json::from_slice(&tip).unwrap_or(config.last_scanned_height)
        }
        _ => {
            config.last_scanned_height
        }
    }
}

fn save_last_scanned_height(height: u64) {
    let _ = DB.insert(DB_KEY_BITCOIN_TIP, serde_json::to_vec(&height).unwrap());
}

async fn get_cached_vaults(grpc: String) -> Vec<String> {
    if let Ok(Some(last_update)) = DB.get(DB_KEY_VAULTS_LAST_UPDATE) {
        let last_update: u64 = serde_json::from_slice(&last_update).unwrap_or(0);
        let now = chrono::Utc::now().timestamp() as u64;
        if now - last_update < 60 * 60 * 24 { // 24 hours
            if let Ok(Some(vaults)) =  DB.get(DB_KEY_VAULTS) {
                return serde_json::from_slice(&vaults).unwrap_or(vec![])
            };
        }
    }
    let mut client = cosmos_sdk_proto::side::btcbridge::query_client::QueryClient::connect(grpc).await.unwrap();
    let x = client.query_params(QueryParamsRequest{}).await.unwrap().into_inner();
    match x.params {
        Some(params) => {
            let vaults = params.vaults.iter().map(|v| v.address.clone()).collect::<Vec<_>>();
            let _ = DB.insert(DB_KEY_VAULTS, serde_json::to_vec(&vaults).unwrap());
            let _ = DB.insert(DB_KEY_VAULTS_LAST_UPDATE, serde_json::to_vec(&chrono::Utc::now().timestamp()).unwrap());
            vaults
        }
        None => vec![]
    }
}
