use std::{thread::sleep, time::Duration};

use bitcoin::{consensus::encode, BlockHash, Transaction};
use bitcoincore_rpc::RpcApi;
use prost_types::Any;
use tonic::{Response, Status};
use tracing::{error, info};

use crate::{
    app::{config::Config, signer::Shuttler},
    helper::encoding::to_base64,
};

use super::{
    bitcoin::{self as bitcoin_utils},
    client_side::{self, send_cosmos_transaction}, store,
};
use cosmos_sdk_proto::{
    cosmos::tx::v1beta1::BroadcastTxResponse,
    side::btcbridge::{MsgSubmitDepositTransaction, MsgSubmitWithdrawTransaction},
};

pub async fn start_loop_tasks(config: Config) {
    let shuttler = Shuttler::new(config);

    // scan vault txs
    scan_vault_txs_loop(&shuttler).await;
}

async fn scan_vault_txs_loop(shuttler: &Shuttler) {
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

async fn scan_vault_txs(shuttler: &Shuttler, height: u64) {
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
            match bitcoin_utils::get_tx_proof(
                &shuttler.bitcoin_client,
                tx.compute_txid(),
                &block_hash,
            ) {
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
            match shuttler
                .bitcoin_client
                .get_raw_transaction(&prev_txid, Some(&block_hash))
            {
                Ok(prev_tx) => {
                    match bitcoin_utils::get_tx_proof(
                        &shuttler.bitcoin_client,
                        tx.compute_txid(),
                        &block_hash,
                    ) {
                        Some(proof) => {
                            send_deposit_tx(shuttler, &block_hash, &prev_tx, &tx, proof).await;
                        }
                        None => {
                            error!("Failed to get tx proof");
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to get the previous tx: {:?}, err: {:?}",
                        prev_txid, e
                    );
                }
            }
        }
    }
}

async fn send_withdraw_tx(
    shuttler: &Shuttler,
    block_hash: &BlockHash,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
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

async fn send_deposit_tx(
    shuttler: &Shuttler,
    block_hash: &BlockHash,
    prev_tx: &Transaction,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
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

fn get_last_scanned_height(config: &Config) -> u64 {
    store::get_last_scanned_height().unwrap_or(config.last_scanned_height)
}
