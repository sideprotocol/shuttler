

use bitcoincore_rpc::RpcApi;
use chrono::{Timelike, Utc};
use cosmrs::Any;
use tracing::{debug, error};

use crate::{app::{config, 
    signer::{broadcast_signing_commitments, Signer}}, 
    commands::Cli, 
    helper::{client_side::get_signing_requests, messages::{SigningSteps, Task}}};

use super::{client_side::{self, send_cosmos_transaction}, messages::SigningBehaviour};
use cosmos_sdk_proto::side::btcbridge::{BlockHeader, MsgSubmitBlockHeaders};

async fn fetch_latest_signing_requests(cli: &Cli, behave: &mut SigningBehaviour, signer: &mut Signer) {
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

    match get_signing_requests(&host).await {
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

async fn sync_btc_blocks(signer: &mut Signer) {
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

    let mut block_headers: Vec<BlockHeader> = vec![];

    while tip_on_side < tip_on_bitcoin {

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
            bits: header.bits.to_consensus().to_string(),
            ntx: 0u64,
            time: header.time as u64,
        })

    }

    let submit_block_msg = MsgSubmitBlockHeaderRequest {
        sender: "sender".to_string(),
        block_headers
    };


    let any_msg = Any::from_msg(&submit_block_msg).unwrap();
    send_cosmos_transaction(signer.config(), any_msg).await


}

pub async fn tasks_fetcher(cli: &Cli , behave: &mut SigningBehaviour, signer: &mut Signer) {
    broadcast_signing_commitments(behave, signer);
    fetch_latest_signing_requests(cli, behave, signer).await;
    sync_btc_blocks(signer).await
}
