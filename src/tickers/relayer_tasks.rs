use std::{sync::Mutex, thread::sleep, time::Duration};

use bitcoin::{consensus::encode, BlockHash, Transaction};
use bitcoincore_rpc::RpcApi;
use prost_types::Any;
use tonic::{Response, Status};
use tracing::{error, info};

use crate::{
    app::{config::Config, shuttler::Shuttler},
    helper::{
        bitcoin::{self as bitcoin_utils},
        client_side::{self, send_cosmos_transaction},
        store, encoding::to_base64,
    },
};

use cosmos_sdk_proto::{
    cosmos::tx::v1beta1::BroadcastTxResponse,
    side::btcbridge::{BlockHeader, MsgSubmitBlockHeaders, MsgSubmitDepositTransaction, MsgSubmitWithdrawTransaction},
};
use lazy_static::lazy_static;

#[derive(Debug)]
struct Lock {
    loading: bool,
}

lazy_static! {
    static ref LOADING: Mutex<Lock> = Mutex::new(Lock { loading: false });
}

pub async fn sync_btc_blocks(signer: &mut Shuttler) {
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

pub async fn send_block_headers(
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

//

pub async fn start_loop_tasks(config: Config) {
    let shuttler = Shuttler::new(config);

    // scan vault txs
    // scan_vault_txs_loop(&shuttler).await;
}

pub async fn scan_vault_txs_loop(shuttler: &Shuttler) {
    let mut height = get_last_scanned_height(shuttler.config()) + 1;

    info!("Start to scan vault txs from height: {}", height);

    loop {
        let side_tip =
            match client_side::get_bitcoin_tip_on_side(&shuttler.config().side_chain.grpc).await {
                Ok(res) => res.get_ref().height,
                Err(e) => {
                    error!("Failed to get tip from side chain: {}", e);
                    continue;
                }
            };

        if height > side_tip - 1 {
            sleep(Duration::from_secs(6));
            continue;
        }

        info!("Scanning height: {:?}, side tip: {:?}", height, side_tip);

        scan_vault_txs(shuttler, height).await;

        store::save_last_scanned_height(height);
        height += 1;
    }
}

pub async fn scan_vault_txs(shuttler: &Shuttler, height: u64) {
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

    for (i, tx) in block.txdata.iter().enumerate() {
        info!(
            "Checking tx {:?}, height: {:?}, index: {:?}",
            tx.compute_txid(),
            height,
            i
        );

        if bitcoin_utils::may_be_withdraw_tx(&tx) {
            info!("Withdrawal tx found...");

            let proof = bitcoin_utils::compute_tx_proof(
                block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
                i,
            );

            match send_withdraw_tx(shuttler, &block_hash, &tx, proof).await {
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

        if bitcoin_utils::is_deposit_tx(tx, shuttler.config().bitcoin.network) {
            info!("Deposit tx found...");

            let proof = bitcoin_utils::compute_tx_proof(
                block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
                i,
            );

            let prev_txid = tx.input[0].previous_output.txid;
            let prev_tx = match shuttler
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

            match send_deposit_tx(shuttler, &block_hash, &prev_tx, &tx, proof).await {
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
    shuttler: &Shuttler,
    block_hash: &BlockHash,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgSubmitWithdrawTransaction {
        sender: shuttler.config().signer_cosmos_address().to_string(),
        blockhash: block_hash.to_string(),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting withdrawal tx: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(shuttler, any_msg).await
}

pub async fn send_deposit_tx(
    shuttler: &Shuttler,
    block_hash: &BlockHash,
    prev_tx: &Transaction,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgSubmitDepositTransaction {
        sender: shuttler.config().signer_cosmos_address().to_string(),
        blockhash: block_hash.to_string(),
        prev_tx_bytes: to_base64(encode::serialize(prev_tx).as_slice()),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting deposit tx: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(shuttler, any_msg).await
}

pub(crate) fn get_last_scanned_height(config: &Config) -> u64 {
    store::get_last_scanned_height().unwrap_or(config.last_scanned_height)
}
