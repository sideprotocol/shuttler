use bitcoin::{Block, BlockHash, Network, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use futures::join;
use tendermint::abci;
use tokio::time::{sleep, Duration};
use tonic::{Response, Status};
use tracing::{debug, error, info};

use crate::{
    apps::relayer::Relayer,
    helper::{
        bitcoin::{self as bitcoin_utils},
        client_side::{self, send_cosmos_transaction},
    },
};

use cosmos_sdk_proto::{cosmos::tx::v1beta1::BroadcastTxResponse, Any};
use side_proto::side::lending::MsgApprove;

const EVENT_TYPE_APPLY: &str = "apply";
const EVENT_ATTRIBUTE_KEY_VAULT: &str = "vault";

const DB_KEY_SIDE_BLOCK_HEIGHT: &str = "side_block_height";
const DB_KEY_BITCOIN_BLOCK_HEIGHT: &str = "bitcoin_block_height";
const DB_KEY_VAULT_PREFIX: &str = "vault";

pub async fn start_relayer_tasks(relayer: &Relayer) {
    join!(
        scan_vaults_on_side(&relayer),
        scan_deposit_txs_on_bitcoin(&relayer),
    );
}

pub async fn scan_vaults_on_side(relayer: &Relayer) {
    let interval = 6;

    loop {
        let height = get_last_scanned_height_side(relayer) + 1;

        let latest_block_height =
            match client_side::get_latest_block(&relayer.config.side_chain.rpc).await {
                Ok(resp) => resp.block.header.height.value(),
                Err(e) => {
                    error!("Failed to get the latest block: {}", e);

                    sleep(Duration::from_secs(interval)).await;
                    continue;
                }
            };

        if height > latest_block_height {
            debug!(
                "No new side blocks to sync, height: {}, latest height: {}",
                height, latest_block_height
            );

            sleep(Duration::from_secs(interval)).await;
            continue;
        }

        scan_side_blocks_by_range(relayer, height, latest_block_height).await;
    }
}

pub async fn scan_deposit_txs_on_bitcoin(relayer: &Relayer) {
    let interval = relayer.config().loop_interval;

    loop {
        let height = get_last_scanned_height_bitcoin(relayer) + 1;

        let side_tip =
            match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
                Ok(res) => res.get_ref().height,
                Err(e) => {
                    error!("Failed to get tip from side chain: {}", e);

                    sleep(Duration::from_secs(interval)).await;
                    continue;
                }
            };

        let confirmations =
            client_side::get_confirmations_on_side(&relayer.config().side_chain.grpc).await;
        if height > side_tip - confirmations + 1 {
            debug!(
                "No new bitcoin txs to sync, height: {}, side tip: {}, sleep for {} seconds...",
                height, side_tip, interval
            );

            sleep(Duration::from_secs(interval)).await;
            continue;
        }

        debug!("Scanning height: {:?}, side tip: {:?}", height, side_tip);
        scan_deposit_txs_by_height(relayer, height).await;
        save_last_scanned_height_bitcoin(relayer, height);
    }
}

pub async fn scan_side_blocks_by_range(relayer: &Relayer, start_height: u64, end_height: u64) {
    let interval = 6;

    let mut current_height = start_height;

    while current_height <= end_height {
        let block_results_resp =
            match client_side::get_block_results(&relayer.config.side_chain.rpc, current_height)
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    error!(
                        "Failed to get the block results: {}, err: {}",
                        current_height, e
                    );

                    sleep(Duration::from_secs(interval)).await;
                    continue;
                }
            };

        parse_and_save_vaults(relayer, block_results_resp.txs_results);

        save_last_scanned_height_side(relayer, current_height);
        current_height += 1;
    }
}

fn parse_and_save_vaults(relayer: &Relayer, txs_results: Option<Vec<abci::types::ExecTxResult>>) {
    txs_results.unwrap_or(vec![]).iter().for_each(|result| {
        result.events.iter().for_each(|event| {
            if event.kind == EVENT_TYPE_APPLY {
                event.attributes.iter().for_each(|attr| {
                    if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_VAULT {
                        save_vault(relayer, attr.value_str().unwrap().to_string());
                    }
                })
            };
        });
    })
}

pub async fn scan_deposit_txs_by_height(relayer: &Relayer, height: u64) {
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

    for (i, tx) in block.txdata.iter().enumerate() {
        debug!(
            "Checking tx {:?}, height: {:?}, index: {:?}",
            tx.compute_txid(),
            height,
            i
        );

        check_and_handle_deposit_tx(relayer, &block_hash, &block, tx, i).await
    }
}

pub async fn check_and_handle_deposit_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    block: &Block,
    tx: &Transaction,
    index: usize,
) {
    if is_deposit_tx(relayer, tx, relayer.config().bitcoin.network) {
        debug!("Deposit tx found... {:?}", &tx);

        let proof = bitcoin_utils::compute_tx_proof(
            block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
            index,
        );

        match send_deposit_tx(relayer, &block_hash, &tx.compute_txid(), proof).await {
            Ok(resp) => {
                let tx_response = resp.into_inner().tx_response.unwrap();
                if tx_response.code != 0 {
                    error!("Failed to submit deposit tx: {:?}", tx_response);
                    return;
                }

                info!("Submitted deposit tx: {:?}", tx_response);
            }
            Err(e) => {
                error!("Failed to submit deposit tx: {:?}", e);
            }
        }
    }
}

pub async fn check_and_handle_deposit_tx_by_hash(relayer: &Relayer, hash: &Txid) {
    let tx_info = match relayer.bitcoin_client.get_raw_transaction_info(&hash, None) {
        Ok(tx_info) => tx_info,
        Err(e) => {
            error!("Failed to get the raw tx info: {}, err: {}", hash, e);

            return;
        }
    };

    let tx = match tx_info.transaction() {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to get the raw tx: {}, err: {}", hash, e);

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

    let block = match relayer.bitcoin_client.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to get block: {}, err: {}", &block_hash, e);
            return;
        }
    };

    let tx_index = block
        .txdata
        .iter()
        .position(|tx_in_block| tx_in_block == &tx)
        .expect("the tx should be included in the block");

    check_and_handle_deposit_tx(relayer, &block_hash, &block, &tx, tx_index).await
}

pub async fn send_deposit_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    tx_id: &Txid,
    proof: Vec<String>,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgApprove {
        relayer: relayer.config().relayer_bitcoin_address(),
        deposit_tx_id: tx_id.to_string(),
        block_hash: block_hash.to_string(),
        proof,
    };

    info!("submit deposit tx to approve loan: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(&relayer.config(), any_msg).await
}

fn is_deposit_tx(relayer: &Relayer, tx: &Transaction, network: Network) -> bool {
    tx.output.iter().any(|out| {
        is_vault(
            relayer,
            bitcoin_utils::get_address_from_pk_script(out.clone().script_pubkey, network),
        )
    })
}

fn is_vault(relayer: &Relayer, address: String) -> bool {
    relayer
        .db_relayer
        .get(format!("{}:{}", DB_KEY_VAULT_PREFIX, address))
        .is_ok()
}

pub(crate) fn get_last_scanned_height_bitcoin(relayer: &Relayer) -> u64 {
    match relayer.db_relayer.get(DB_KEY_BITCOIN_BLOCK_HEIGHT) {
        Ok(Some(tip)) => {
            serde_json::from_slice(&tip).unwrap_or(relayer.config().last_scanned_height_bitcoin)
        }
        _ => relayer.config().last_scanned_height_bitcoin,
    }
}

fn save_last_scanned_height_bitcoin(relayer: &Relayer, height: u64) {
    let _ = relayer.db_relayer.insert(
        DB_KEY_BITCOIN_BLOCK_HEIGHT,
        serde_json::to_vec(&height).unwrap(),
    );
}

pub(crate) fn get_last_scanned_height_side(relayer: &Relayer) -> u64 {
    match relayer.db_relayer.get(DB_KEY_SIDE_BLOCK_HEIGHT) {
        Ok(Some(tip)) => {
            serde_json::from_slice(&tip).unwrap_or(relayer.config().last_scanned_height_side)
        }
        _ => relayer.config().last_scanned_height_side,
    }
}

fn save_last_scanned_height_side(relayer: &Relayer, height: u64) {
    let _ = relayer.db_relayer.insert(
        DB_KEY_SIDE_BLOCK_HEIGHT,
        serde_json::to_vec(&height).unwrap(),
    );
}

fn save_vault(relayer: &Relayer, vault: String) {
    let _ = relayer.db_relayer.insert(
        format!("{}:{}", DB_KEY_VAULT_PREFIX, vault),
        serde_json::to_vec(&vault).unwrap(),
    );
}
