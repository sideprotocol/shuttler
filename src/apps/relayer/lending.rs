use bitcoin::{consensus::Decodable, Block, BlockHash, Network, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use futures::join;
use tendermint::abci;
use tokio::time::{sleep, Duration};
use tonic::{Response, Status};
use tracing::{debug, error, info};

use crate::{
    apps::relayer::Relayer,
    helper::{
        bitcoin::{self as bitcoin_utils, get_signed_tx_from_psbt},
        client_side::{self, get_auction, get_loan_dlc_meta, send_cosmos_transaction},
    },
};

use cosmos_sdk_proto::{cosmos::tx::v1beta1::BroadcastTxResponse, Any};
use side_proto::side::{
    auction::AuctionStatus,
    lending::{MsgApprove, MsgClose},
};

const EVENT_TYPE_APPLY: &str = "apply";
const EVENT_ATTRIBUTE_KEY_VAULT: &str = "vault";

const EVENT_TYPE_REPAY: &str = "repay";
const EVENT_ATTRIBUTE_KEY_REPAYMENT_TX_HASH: &str = "repayment_tx_hash";
const EVENT_ATTRIBUTE_KEY_LOAN_ID: &str = "loan_id";

const EVENT_TYPE_GENERATE_SIGNED_LIQUIDATION_CET: &str = "generate_signed_liquidation_cet";
const _EVENT_ATTRIBUTE_KEY_TX_HASH: &str = "tx_hash";

const EVENT_TYPE_GENERATE_SIGNED_PAYMENT_TRANSACTION: &str = "generate_signed_payment_transaction";
const EVENT_ATTRIBUTE_KEY_AUCTION_ID: &str = "auction_id";

const DB_KEY_SIDE_BLOCK_HEIGHT: &str = "side_block_height";
const DB_KEY_BITCOIN_BLOCK_HEIGHT: &str = "bitcoin_block_height";
const DB_KEY_VAULT_PREFIX: &str = "vault";
const DB_KEY_REPAYMENT_TX_PREFIX: &str = "repayment_tx";

pub async fn start_relayer_tasks(relayer: &Relayer) {
    join!(scan_blocks_on_side(&relayer), scan_txs_on_bitcoin(&relayer),);
}

pub async fn scan_blocks_on_side(relayer: &Relayer) {
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

pub async fn scan_txs_on_bitcoin(relayer: &Relayer) {
    let interval = relayer.config().loop_interval;

    loop {
        let height = get_last_scanned_height_bitcoin(relayer) + 1;

        let tip_on_bitcoin = match relayer.bitcoin_client.get_block_count() {
            Ok(height) => height,
            Err(e) => {
                error!("Failed to get the block count: {}", e);
                continue;
            }
        };

        if height > tip_on_bitcoin {
            debug!(
                "No new bitcoin txs to sync, height: {}, bitcoin tip: {}, sleep for {} seconds",
                height, tip_on_bitcoin, interval
            );

            sleep(Duration::from_secs(interval)).await;
            continue;
        }

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
        if side_tip < confirmations || height > side_tip - confirmations + 1 {
            debug!(
                "No new bitcoin txs to sync, height: {}, side tip: {}, sleep for {} seconds...",
                height, side_tip, interval
            );

            sleep(Duration::from_secs(interval)).await;
            continue;
        }

        debug!(
            "Scanning bitcoin height: {:?}, side tip: {:?}",
            height, side_tip
        );
        scan_bitcoin_txs_by_height(relayer, height).await;
        save_last_scanned_height_bitcoin(relayer, height);
    }
}

pub async fn scan_side_blocks_by_range(relayer: &Relayer, start_height: u64, end_height: u64) {
    let interval = 6;

    let mut current_height = start_height;

    while current_height <= end_height {
        debug!("Scanning side height: {}", current_height);

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

        parse_and_save_vaults(relayer, block_results_resp.clone().txs_results);
        parse_and_save_repayment_txs(relayer, block_results_resp.clone().txs_results);
        parse_and_handle_liquidation_cets(relayer, block_results_resp.clone().end_block_events)
            .await;
        parse_and_handle_auction_payment_txs(relayer, block_results_resp.clone().txs_results).await;

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
                        let vault = attr.value_str().unwrap().to_string();

                        debug!("Vault found on side: {}", vault);
                        save_vault(relayer, vault);
                    }
                })
            };
        });
    })
}

fn parse_and_save_repayment_txs(
    relayer: &Relayer,
    txs_results: Option<Vec<abci::types::ExecTxResult>>,
) {
    txs_results.unwrap_or(vec![]).iter().for_each(|result| {
        result.events.iter().for_each(|event| {
            if event.kind == EVENT_TYPE_REPAY {
                let mut loan_id = "".to_string();
                let mut tx_hash = "".to_string();

                event.attributes.iter().for_each(|attr| {
                    if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_LOAN_ID {
                        loan_id = attr.value_str().unwrap().to_string();
                    }

                    if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_REPAYMENT_TX_HASH {
                        tx_hash = attr.value_str().unwrap().to_string();
                    }
                });

                debug!(
                    "Repayment tx found on side, loan id: {}, tx hash: {}",
                    loan_id, tx_hash
                );
                save_repayment_tx(relayer, loan_id, tx_hash);
            };
        });
    })
}

async fn parse_and_handle_liquidation_cets(
    relayer: &Relayer,
    end_block_events: Option<Vec<abci::Event>>,
) {
    let mut loan_ids = vec![];

    end_block_events.unwrap_or(vec![]).iter().for_each(|event| {
        if event.kind == EVENT_TYPE_GENERATE_SIGNED_LIQUIDATION_CET {
            event.attributes.iter().for_each(|attr| {
                if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_LOAN_ID {
                    let loan_id = attr.value_str().unwrap().to_string();

                    debug!("Signed liquidation cet found on side, loan id: {}", loan_id);
                    loan_ids.push(loan_id);
                }
            })
        };
    });

    for loan_id in loan_ids {
        handle_liquidation_cet(relayer, loan_id).await;
    }
}

async fn parse_and_handle_auction_payment_txs(
    relayer: &Relayer,
    txs_results: Option<Vec<abci::types::ExecTxResult>>,
) {
    let mut auction_ids = vec![];

    txs_results.unwrap_or(vec![]).iter().for_each(|result| {
        result.events.iter().for_each(|event| {
            if event.kind == EVENT_TYPE_GENERATE_SIGNED_PAYMENT_TRANSACTION {
                event.attributes.iter().for_each(|attr| {
                    if attr.key_str().unwrap() == EVENT_ATTRIBUTE_KEY_AUCTION_ID {
                        let auction_id = attr.value_str().unwrap().parse().unwrap();

                        debug!(
                            "Signed auction payment tx found on side, auction id: {}",
                            auction_id,
                        );
                        auction_ids.push(auction_id);
                    }
                });
            };
        });
    });

    for auction_id in auction_ids {
        handle_auction_payment_tx(relayer, auction_id).await;
    }
}

pub async fn scan_bitcoin_txs_by_height(relayer: &Relayer, height: u64) {
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

        check_and_handle_bitcoin_tx(relayer, &block_hash, &block, tx, i).await
    }
}

pub async fn check_and_handle_bitcoin_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    block: &Block,
    tx: &Transaction,
    index: usize,
) {
    if is_deposit_tx(relayer, tx, relayer.config().bitcoin.network) {
        debug!("Deposit tx found on bitcoin: {}", tx.compute_txid());

        let proof = bitcoin_utils::compute_tx_proof(
            block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
            index,
        );

        match send_deposit_tx(relayer, &block_hash, &tx.compute_txid(), proof).await {
            Ok(resp) => {
                let tx_response = resp.into_inner().tx_response.unwrap();
                if tx_response.code != 0 {
                    error!("Failed to submit deposit tx to side: {:?}", tx_response);
                    return;
                }

                info!("Submitted deposit tx to side: {:?}", tx_response);
            }
            Err(e) => {
                error!("Failed to submit deposit tx to side: {:?}", e);
            }
        }

        return;
    }

    if is_repayment_tx(relayer, tx) {
        debug!("Repayment tx found on bitcoin: {}", tx.compute_txid());

        let loan_id = get_repayment_loan_id(relayer, tx.compute_txid().to_string());
        if loan_id.is_empty() {
            error!(
                "Failed to get loan id for repayment tx {}",
                tx.compute_txid()
            );
            return;
        }

        let decrypted_signature = extract_repayment_tx_signature(tx);

        match send_close_loan_tx(relayer, loan_id, decrypted_signature).await {
            Ok(resp) => {
                let tx_response = resp.into_inner().tx_response.unwrap();
                if tx_response.code != 0 {
                    error!("Failed to submit close loan tx to side: {:?}", tx_response);
                    return;
                }

                info!("Submitted close loan tx to side: {:?}", tx_response);
            }
            Err(e) => {
                error!("Failed to submit close loan tx to side: {:?}", e);
            }
        }
    }
}

pub async fn check_and_handle_bitcoin_tx_by_hash(relayer: &Relayer, hash: &Txid) {
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

    check_and_handle_bitcoin_tx(relayer, &block_hash, &block, &tx, tx_index).await
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

    info!("submit deposit tx to side: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(&relayer.config(), any_msg).await
}

pub async fn send_close_loan_tx(
    relayer: &Relayer,
    loan_id: String,
    signature: String,
) -> Result<Response<BroadcastTxResponse>, Status> {
    let msg = MsgClose {
        relayer: relayer.config().relayer_bitcoin_address(),
        loan_id,
        signature,
    };

    info!("submit close loan tx to side: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    send_cosmos_transaction(&relayer.config(), any_msg).await
}

pub async fn handle_liquidation_cet(relayer: &Relayer, loan_id: String) {
    let dlc_meta = match get_loan_dlc_meta(&relayer.config.side_chain.grpc, loan_id.clone()).await {
        Ok(resp) => match resp.into_inner().dlc_meta {
            Some(dlc_meta) => dlc_meta,
            None => {
                error!("No dlc meta exists on side, loan id: {}", loan_id);
                return;
            }
        },
        Err(e) => {
            error!("Failed to query dlc meta, loan id: {}, err: {}", loan_id, e);
            return;
        }
    };

    if dlc_meta.signed_liquidation_cet_hex.is_empty() {
        error!("Liquidation cet not signed yet, loan id: {}", loan_id);
        return;
    }

    let signed_tx = Transaction::consensus_decode(
        &mut hex::decode(dlc_meta.signed_liquidation_cet_hex)
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    match relayer.bitcoin_client.send_raw_transaction(&signed_tx) {
        Ok(txid) => {
            debug!("Liquidation cet sent to bitcoin: {}", txid);
        }
        Err(e) => {
            error!("Failed to send liquidation cet to bitcoin: {}", e);
        }
    }
}

pub async fn handle_auction_payment_tx(relayer: &Relayer, auction_id: u64) {
    let auction = match get_auction(&relayer.config.side_chain.grpc, auction_id).await {
        Ok(resp) => match resp.into_inner().auction {
            Some(auction) => auction,
            None => {
                error!("No auction exists on side, auction id: {}", auction_id);
                return;
            }
        },
        Err(e) => {
            error!(
                "Failed to query auction, auction id: {}, err: {}",
                auction_id, e
            );
            return;
        }
    };

    if auction.status != AuctionStatus::Settled as i32 {
        error!("Auction not settled yet, auction id: {}", auction_id);
        return;
    }

    let signed_payment_tx = match get_signed_tx_from_psbt(&auction.payment_tx) {
        Ok(signed_tx) => signed_tx,
        Err(e) => {
            error!(
                "Failed to extract signed payment tx, auction id: {}, err: {}",
                auction_id, e
            );
            return;
        }
    };

    match relayer
        .bitcoin_client
        .send_raw_transaction(&signed_payment_tx)
    {
        Ok(txid) => {
            debug!("Auction payment tx sent to bitcoin: {}", txid);
        }
        Err(e) => {
            error!("Failed to send auction payment tx to bitcoin: {}", e);
        }
    }
}

pub fn is_deposit_tx(relayer: &Relayer, tx: &Transaction, network: Network) -> bool {
    tx.output.iter().any(|out| {
        is_vault(
            relayer,
            bitcoin_utils::get_address_from_pk_script(out.clone().script_pubkey, network),
        )
    })
}

pub fn is_vault(relayer: &Relayer, address: String) -> bool {
    relayer
        .db_relayer
        .get(format!("{}:{}", DB_KEY_VAULT_PREFIX, address))
        .map_or(false, |v| v.is_some())
}

pub fn is_repayment_tx(relayer: &Relayer, tx: &Transaction) -> bool {
    relayer
        .db_relayer
        .get(format!(
            "{}:{}",
            DB_KEY_REPAYMENT_TX_PREFIX,
            tx.compute_txid().to_string()
        ))
        .map_or(false, |v| v.is_some())
}

pub fn extract_repayment_tx_signature(tx: &Transaction) -> String {
    hex::encode(tx.input[0].witness.nth(0).unwrap())
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
    let _ = relayer
        .db_relayer
        .insert(format!("{}:{}", DB_KEY_VAULT_PREFIX, vault), vec![]);
}

fn save_repayment_tx(relayer: &Relayer, loan_id: String, txid: String) {
    let _ = relayer.db_relayer.insert(
        format!("{}:{}", DB_KEY_REPAYMENT_TX_PREFIX, txid),
        loan_id.as_str(),
    );
}

fn get_repayment_loan_id(relayer: &Relayer, txid: String) -> String {
    relayer
        .db_relayer
        .get(format!("{}:{}", DB_KEY_REPAYMENT_TX_PREFIX, txid))
        .map_or("".to_string(), |v| {
            v.map_or("".to_string(), |v| String::from_utf8_lossy(&v).into_owned())
        })
}
