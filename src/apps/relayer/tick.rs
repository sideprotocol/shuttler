use std::sync::{atomic::{AtomicU64, Ordering}, LazyLock};

use bitcoin::{consensus::encode, Address, Block, BlockHash, OutPoint, Psbt, Transaction, Txid};
use bitcoincore_rpc::{jsonrpc::error::Error as RpcError, Error, RpcApi};
use prost_types::Any;
use tonic::{Response, Status};
use tracing::{debug, error, info};

use cosmos_sdk_proto::{cosmos::base::query::v1beta1::PageRequest, side::btcbridge::{query_client::QueryClient as BridgeQueryClient, QuerySigningRequestRequest, QuerySigningRequestsRequest}};

use crate::{
    apps::relayer::Relayer,
    helper::{
        bitcoin::{self as bitcoin_utils}, client_side::{self, send_cosmos_transaction}, encoding::{from_base64, to_base64}, 
    },
};

use cosmos_sdk_proto::{
    cosmos::tx::v1beta1::BroadcastTxResponse,
    side::btcbridge::{BlockHeader, MsgSubmitBlockHeaders, MsgSubmitDepositTransaction, MsgSubmitFeeRate, MsgSubmitWithdrawTransaction, QueryParamsRequest, SigningStatus},
};

const DB_KEY_BITCOIN_TIP: &str = "bitcoin_tip";
const DB_KEY_VAULTS: &str = "bitcoin_vaults";
const DB_KEY_VAULTS_LAST_UPDATE: &str = "bitcoin_vaults_last_update";

/// Start relayer tasks
/// 1. Sync BTC blocks
/// 2. Scan vault txs
// pub async fn start_relayer_tasks(relayer: &Relayer) {
//     join!(
//         sync_btc_blocks_loop(&relayer),
//         scan_vault_txs_loop(&relayer),
//         submit_fee_rate_loop(&relayer),
//     );
// }

static SEQUENCE: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));


pub async fn sync_signed_transactions(relayer: &Relayer) {

    let host = relayer.config().side_chain.grpc.as_str();

    let bitcoin_client = match &relayer.bitcoin_client {
        Some(c) => c,
        None => {
            error!("Haven't set bitcoin RPC endpoint");
            return
        },
    };

    let mut bridge_client = match BridgeQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            error!("Error: {:?}", e);
            return;
        }
    };

    if SEQUENCE.load(Ordering::Relaxed) == 0 {

        let x = bridge_client.query_signing_requests(QuerySigningRequestsRequest {
            status: SigningStatus::Broadcasted as i32,
            pagination: Some(PageRequest {
                key: vec![],
                offset: 0,
                limit: 1,
                count_total: false,
                reverse: false,
            }),
        }).await;

        let resp = match x {
            Ok(r) => r.into_inner(),
            Err(e) => {
                error!("Error: {:?}", e);
                return
            },
        };

        println!("{:?}", resp.requests);

        if resp.requests.len() > 0 {
            let s = resp.requests[0].sequence;
            if s >= 1 { 
                // latest sequence on chain
                SEQUENCE.fetch_add(s - 1, Ordering::Relaxed); 
            };
        }
        
    }

    let mut sequence = SEQUENCE.fetch_add( 1, Ordering::SeqCst); 

    loop {

        info!("Start sync signed transaction {}", sequence);

        match bridge_client.query_signing_request(QuerySigningRequestRequest { sequence }).await {
            Ok(r) => {

                if let Some(sr) = r.into_inner().request {
                    
                    if sr.status != SigningStatus::Broadcasted as i32 && sr.psbt.len() == 0{
                        return
                    }

                    let psbt_bytes = from_base64(&sr.psbt).unwrap();
                    let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
                        Ok(psbt) => psbt,
                        Err(e) => {
                            error!("Failed to deserialize PSBT: {}", e);
                            return;
                        }
                    };

                    let signed_tx = psbt.clone().extract_tx().expect("failed to extract signed tx");

                    match bitcoin_client.send_raw_transaction(&signed_tx) {
                        Ok(txid) => {
                            sequence = SEQUENCE.fetch_add( 1, Ordering::SeqCst); 
                            info!("PSBT broadcasted to Bitcoin: {}", txid);
                        }
                        Err(err) => {
                            error! ("Failed to broadcast PSBT: {:?}, err: {:?}", signed_tx.compute_txid(), err);
                            return;
                        }
                    }
                } else {
                    return
                }
            },
            Err(e) => {
                error!("Error: {:?}", e);
                return
            } 
        };
    }

}

pub async fn sync_btc_blocks(relayer: &Relayer) {
    if !is_trusted_btc_relayer(relayer, &relayer.config().relayer_bitcoin_address()).await {
        return;
    }

    let interval = relayer.config().loop_interval;

    let client = match &relayer.bitcoin_client {
        Some(c) => c,
        None => return,
    };

    let tip_on_bitcoin = match client.get_block_count() {
        Ok(height) => height,
        Err(e) => {
            error!(error=%e);
            return;
        }
    };

    let mut tip_on_side = match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
        Ok(res) => res.get_ref().height,
        Err(e) => {
            error!(error=%e);
            return;
        }
    };

    if tip_on_bitcoin == tip_on_side {
        debug!(
            "No new blocks to sync, tip_on_bitcoin: {}, tip_on_side: {}, sleep for {} seconds...",
            tip_on_bitcoin, tip_on_side, interval
        );
        return
    }
    
    let batch_relayer_count = relayer.config().batch_relayer_count;
    let batch = if tip_on_side + batch_relayer_count > tip_on_bitcoin {
        tip_on_bitcoin
    } else {
        tip_on_side + batch_relayer_count
    };
    debug!("Syncing blocks from {} to {}", tip_on_side, batch);

    // check reorg before syncing blocks
    let max_depth = client_side::get_max_reorg_depth(&relayer.config().side_chain.grpc).await;
    for n in 1..=max_depth {
        if check_reorg(&relayer, tip_on_side + n - max_depth).await {
            handle_reorg(relayer, tip_on_side + n - max_depth, tip_on_side).await;
        }
    }

    let mut block_headers: Vec<BlockHeader> = vec![];
    while tip_on_side < batch {
        tip_on_side = tip_on_side + 1;
        let header = match fetch_block_header_by_height(relayer, tip_on_side).await {
            Ok(header) => header,
            Err(e) => {
                error!("Failed to fetch block header: {:?}", e);
                break;
            }
        };
        block_headers.push(header);
    }
    if block_headers.is_empty() {
        debug!("Block headers is empty, sleep for {} seconds...", interval);
        return;
    }

    // submit block headers in a batch
    match send_block_headers(relayer, &block_headers).await {
        Ok(resp) => {
            let tx_response = resp.into_inner().tx_response.unwrap();
            if tx_response.code != 0 {
                error!("Failed to send block headers: {:?}", tx_response);
            } else {
                info!("Sent block headers: {:?}", tx_response);
            }
        }
        Err(e) => {
            error!("Failed to send block headers: {:?}", e);
        }
    };
}

pub async fn fetch_block_header_by_height(relayer: &Relayer, height: u64) -> Result<BlockHeader, Error> {
    let client = match &relayer.bitcoin_client {
        Some(c) => c,
        None => return Err(Error::JsonRpc(RpcError::EmptyBatch)),
    };

    let hash = match client.get_block_hash(height) {
        Ok(hash) => hash,
        Err(e) => {
            error!(error=%e);
            return Err(e);
        }
    };

    let header = match client.get_block_header(&hash) {
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

pub async fn check_reorg(relayer: &Relayer, height: u64) -> bool {

    let client = match &relayer.bitcoin_client {
        Some(c) => c,
        None => return false,
    };

    let bitcoin_hash = match client.get_block_hash(height) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            error!(error=%e);
            return false;
        }
    };

    let side_hash =
        match client_side::get_bitcoin_block_header_on_side(&relayer.config().side_chain.grpc, height).await {
            Ok(res) => res.get_ref().block_header.clone().unwrap().hash,
            Err(e) => {
                error!(error=%e);
                return false;
            }
        };

    return side_hash.len() != 0 && bitcoin_hash != side_hash;
}

pub async fn handle_reorg(relayer: &Relayer, height: u64, side_tip: u64) {
    let mut block_headers: Vec<BlockHeader> = vec![];

    let client = match &relayer.bitcoin_client {
        Some(c) => c,
        None => return,
    };

    for h in height..=side_tip+1 {
        let hash = match client.get_block_hash(h) {
            Ok(hash) => hash,
            Err(e) => {
                error!(error=%e);
                return;
            }
        };

        let header = match client.get_block_header(&hash) {
            Ok(b) => b,
            Err(e) => {
                error!(error=%e);
                return;
            }
        };

        block_headers.push(BlockHeader {
            version: header.version.to_consensus() as u64,
            hash: header.block_hash().to_string(),
            height: h,
            previous_block_hash: header.prev_blockhash.to_string(),
            merkle_root: header.merkle_root.to_string(),
            nonce: header.nonce as u64,
            bits: format!("{:x}", header.bits.to_consensus()),
            time: header.time as u64,
            ntx: 0u64,
        })
    }

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

pub async fn scan_vault_txs(relayer: &Relayer) {
    let interval = relayer.config().loop_interval;
    let height = get_last_scanned_height(relayer ) + 1;

    let side_tip =
        match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
            Ok(res) => res.get_ref().height,
            Err(e) => {
                error!("Failed to get tip from side chain: {}", e);
                return;
            }
        };

    let confirmations = client_side::get_confirmation_depth(&relayer.config().side_chain.grpc).await;
    if height > side_tip - confirmations + 1 {
        debug!("No new txs to sync, height: {}, side tip: {}, sleep for {} seconds...", height, side_tip, interval);
        return;
    }

    debug!("Scanning height: {:?}, side tip: {:?}", height, side_tip);
    if scan_vault_txs_by_height(relayer, height).await {
        save_last_scanned_height(relayer, height);
    }
}

pub async fn scan_vault_txs_by_height(relayer: &Relayer, height: u64) -> bool {
    let client = match &relayer.bitcoin_client {
        Some(c) => c,
        None => return false,
    };
    let block_hash = match client.get_block_hash(height) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to get block hash: {:?}, err: {:?}", height, e);
            return false
        }
    };

    let block = match client.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to get block: {}, err: {}", height, e);
            return false;
        }
    };

    let vaults = get_cached_vaults(relayer ).await;

    for (i, tx) in block.txdata.iter().enumerate() {
        debug!(
            "Checking tx {:?}, height: {:?}, index: {:?}",
            tx.compute_txid(),
            height,
            i
        );

        check_and_handle_tx_with_retry(relayer, &block_hash, &block, tx, i, &vaults).await;
    }

    return true;
}

pub async fn check_and_handle_tx_with_retry(relayer: &Relayer, block_hash: &BlockHash, block: &Block, tx: &Transaction, index: usize, vaults: &Vec<String>) {
    let mut attempts = 0;

    loop {
        if check_and_handle_tx(relayer, &block_hash, &block, tx, index, &vaults).await {
            return;
        }

        attempts += 1;
        if attempts >= relayer.config.max_attempts {
            return;
        }
    }
}

pub async fn check_and_handle_tx(relayer: &Relayer, block_hash: &BlockHash, block: &Block, tx: &Transaction, index: usize, vaults: &Vec<String>) -> bool {
    if bitcoin_utils::may_be_withdraw_tx(&tx) {
        let client = match &relayer.bitcoin_client {
            Some(c) => c,
            None => return false,
        };

        let prev_txid = tx.input[0].previous_output.txid;
        let prev_vout = tx.input[0].previous_output.vout;

        let address = match client.get_raw_transaction (&prev_txid, None) {
            Ok(prev_tx) => {
                if prev_tx.output.len() <= prev_vout as usize {
                    error!("Invalid previous tx");

                    // continue due to the tx is invalid
                    return true;
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
                    index,
                );

                match send_withdraw_tx(relayer, &block_hash, &tx, proof).await {
                    Ok(resp) => {
                        let tx_response = resp.into_inner().tx_response.unwrap();
                        if tx_response.code != 0 {
                            error!("Failed to submit withdrawal tx: {:?}", tx_response);
                            return false;
                        }
    
                        info!("Submitted withdrawal tx: {:?}", tx_response);
                        return true;
                    }
                    Err(e) => {
                        error!("Failed to submit withdrawal tx: {:?}", e);
                        return false;
                    }
                }
            }
        }
    }

    if bitcoin_utils::is_deposit_tx(tx, relayer.config().bitcoin.network, &vaults) {
        debug!("Deposit tx found... {:?}", &tx);

        if bitcoin_utils::is_runes_deposit(tx) {
            if !relayer.config().relay_runes {
                debug!("Skip the tx due to runes relaying not enabled");
                return true;
            }

            let edict = match bitcoin_utils::parse_runes(tx) {
                Some(edict) => edict,
                None => {
                    debug!("Failed to parse runes deposit tx {}", tx.compute_txid());

                    // continue due to the deposit is invalid
                    return true; 
                }
            };

            // get the rune by id
            let rune = match relayer.ordinals_client.get_rune(edict.id).await {
                Ok(rune) => rune.entry.spaced_rune,
                Err(e) => {
                    error!("Failed to get rune {}: {}", edict.id, e);

                    // continue due to the deposit may be invalid
                    // or this can be correctly handled for other relayers
                    return true;
                }
            };

            // get the runes output
            let output = match relayer.ordinals_client.get_output(OutPoint::new(tx.compute_txid(), edict.output)).await {
                Ok(output) => output,
                Err(e) => {
                    error!("Failed to get output {}:{} from ord: {}", tx.compute_txid(), edict.output, e);

                    // continue due to the deposit may be invalid
                    // or this can be correctly handled for other relayers
                    return true;
                }
            };

            // validate if the runes deposit is valid
            if !bitcoin_utils::validate_runes(&edict, &rune, &output) {
                debug!("Failed to validate runes deposit tx {}", tx.compute_txid());

                // continue due to the deposit is invalid
                return true;
            }
        }

        let proof = bitcoin_utils::compute_tx_proof(
            block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
            index,
        );
        let client = match &relayer.bitcoin_client {
            Some(c) => c,
            None => return false,
        };
        let prev_txid = tx.input[0].previous_output.txid;
        let prev_tx = match client.get_raw_transaction(&prev_txid, None) {
            Ok(prev_tx) => prev_tx,
            Err(e) => {
                error!(
                    "Failed to get the previous tx: {:?}, err: {:?}",
                    prev_txid, e
                );

                return false;
            }
        };

        match send_deposit_tx(relayer, &block_hash, &prev_tx, &tx, proof).await {
            Ok(resp) => {
                let tx_response = resp.into_inner().tx_response.unwrap();
                if tx_response.code != 0 {
                    error!("Failed to submit deposit tx: {:?}", tx_response);
                    return false;
                }

                info!("Submitted deposit tx: {:?}", tx_response);
                return true;
            }
            Err(e) => {
                error!("Failed to submit deposit tx: {:?}", e);
                return false;
            }
        }
    }

    return true;
}

pub async fn check_and_handle_tx_by_hash(relayer: &Relayer, hash: &Txid) {
    let client = match &relayer.bitcoin_client {
        Some(c) => c,
        None => return,
    };

    let tx_info = match client.get_raw_transaction_info(&hash, None) {
        Ok(tx_info) => tx_info,
        Err(e) => {
            error!(
                "Failed to get the raw tx info: {}, err: {}",
                hash, e
            );

            return;
        }
    };

    let tx = match tx_info.transaction() {
        Ok(tx) => tx,
        Err(e) => {
            error!(
                "Failed to get the raw tx: {}, err: {}",
                hash, e
            );

            return;
        }
    };

    let block_hash = match tx_info.blockhash {
        Some(block_hash) => block_hash,
        None => {
            error!("Failed to get the block hash of the tx: {}", hash);
            return;
        }
    };
    let client = match &relayer.bitcoin_client {
        Some(c) => c,
        None => return,
    };
    let block = match client.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to get block: {}, err: {}", &block_hash, e);
            return;
        }
    };

    let tx_index = block.txdata.iter().position(|tx_in_block| tx_in_block == &tx).expect("the tx should be included in the block");

    let vaults = get_cached_vaults(relayer).await;

    check_and_handle_tx(relayer, &block_hash, &block, &tx, tx_index, &vaults).await;
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

pub(crate) fn get_last_scanned_height(relayer: &Relayer ) -> u64 {
    match relayer.db_relayer.get(DB_KEY_BITCOIN_TIP) {
        Ok(Some(tip)) => {
            serde_json::from_slice(&tip).unwrap_or(relayer.config().last_scanned_height)
        }
        _ => {
            relayer.config().last_scanned_height
        }
    }
}

fn save_last_scanned_height(relayer: &Relayer, height: u64) {
    let _ = relayer.db_relayer.insert(DB_KEY_BITCOIN_TIP, serde_json::to_vec(&height).unwrap());
}

async fn get_cached_vaults(relayer: &Relayer) -> Vec<String> {
    if let Ok(Some(last_update)) = relayer.db_relayer.get(DB_KEY_VAULTS_LAST_UPDATE) {
        let last_update: u64 = serde_json::from_slice(&last_update).unwrap_or(0);
        let now = chrono::Utc::now().timestamp() as u64;
        if now - last_update < 60 * 60 * 24 { // 24 hours
            if let Ok(Some(vaults)) =  relayer.db_relayer.get(DB_KEY_VAULTS) {
                return serde_json::from_slice(&vaults).unwrap_or(vec![])
            };
        }
    }

    let grpc = relayer.config().side_chain.grpc.clone();
    let mut client = cosmos_sdk_proto::side::btcbridge::query_client::QueryClient::connect(grpc).await.unwrap();
    let x = client.query_params(QueryParamsRequest{}).await.unwrap().into_inner();
    match x.params {
        Some(params) => {
            let vaults = params.vaults.iter().map(|v| v.address.clone()).collect::<Vec<_>>();
            let _ = relayer.db_relayer.insert(DB_KEY_VAULTS, serde_json::to_vec(&vaults).unwrap());
            let _ = relayer.db_relayer.insert(DB_KEY_VAULTS_LAST_UPDATE, serde_json::to_vec(&chrono::Utc::now().timestamp()).unwrap());
            vaults
        }
        None => vec![]
    }
}

async fn is_trusted_btc_relayer(relayer: &Relayer, sender: &String) -> bool {
    let grpc = relayer.config().side_chain.grpc.clone();
    let mut client = match cosmos_sdk_proto::side::btcbridge::query_client::QueryClient::connect(grpc).await {
        Ok(client) => client,
        Err(_) => {
            return false;
        }
    };

    let res = match client.query_params(QueryParamsRequest{}).await {
        Ok(res) => res.into_inner(),
        Err(_) => {
            return false;
        }
    };

    match res.params {
        Some(params) => {
            let trusted_btc_relayers = params.trusted_btc_relayers;
            return trusted_btc_relayers.is_empty() || trusted_btc_relayers.contains(sender)
        }
        None => return false
    };
}

pub async fn submit_fee_rate(relayer: &Relayer) {
    let submit_fee_rate = relayer.config().fee_provider.submit_fee_rate;
    if !submit_fee_rate {
        return;
    }

    match relayer.fee_provider_client.get_fees().await {
        Ok(bitcoin_fees) => {
            let fee_rate = bitcoin_fees.fastest_fee;
            submit_fee_rate_to_side(relayer, fee_rate).await;
        }
        Err(e) => {
            error!("Failed to get fee rates: {}", e);
        }
    };
}

pub async fn submit_fee_rate_to_side(relayer: &Relayer, fee_rate: i64) {
    let msg_submit_fee_rate = MsgSubmitFeeRate {
        sender: relayer.config().relayer_bitcoin_address().to_string(),
        fee_rate
    };

    info!("Submitting fee rate: {:?}", msg_submit_fee_rate);
    let any_msg = Any::from_msg(&msg_submit_fee_rate).unwrap();
    match send_cosmos_transaction(relayer.config(), any_msg).await {
        Ok(resp) => {
            let tx_response = resp.into_inner().tx_response.unwrap();
            if tx_response.code != 0 {
                error!("Failed to submit fee rate: {:?}", tx_response);
                return;
            }
            info!("Success to submit fee rate: {:?}", tx_response);
        }
        Err(e) => {
            error!("Failed to submit fee rate: {:?}", e);
        }
    }
}
