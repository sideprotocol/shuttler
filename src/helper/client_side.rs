use std::{thread, time::Duration};

use bitcoin::{hashes::{Hash, sha256d, HashEngine}, consensus::Encodable, key::Secp256k1, secp256k1::Message, sign_message::BITCOIN_SIGNED_MSG_PREFIX, PrivateKey};
use cosmrs::{ crypto::secp256k1::SigningKey, tx::{self, Fee, ModeInfo, Raw, SignDoc, SignerInfo, SignerPublicKey}, Coin};
use cosmos_sdk_proto::{Any, cosmos::{
    base::{query::v1beta1::PageRequest, tendermint::v1beta1::{GetLatestBlockRequest, GetLatestValidatorSetRequest, GetLatestValidatorSetResponse}}, 
    tx::v1beta1::{service_client::ServiceClient as TxServiceClient, BroadcastMode, BroadcastTxRequest, BroadcastTxResponse}
}};
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient as TendermintServiceClient;
use futures::SinkExt;
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tonic::{Response, Status};
use side_proto::side::{
    btcbridge::{
        query_client::QueryClient as BtcQueryClient, QueryBlockHeaderByHeightRequest, QueryBlockHeaderByHeightResponse, QueryChainTipRequest, QueryChainTipResponse, QueryParamsRequest, QuerySigningRequestByTxHashRequest, QuerySigningRequestByTxHashResponse
    },
    tss::{query_client::QueryClient as LendingQueryClient, QuerySigningRequestsRequest, QuerySigningRequestsResponse, SigningStatus},
};
use tokio_tungstenite::tungstenite::protocol::Message as WebSocketMessage;

use lazy_static::lazy_static;

use crate::config;

lazy_static! {
    static ref lock: Mutex<()> = Mutex::new(());
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Pagination {
    pub limit: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningRequest {
    pub address: String,
    pub psbt: String,
    pub status: String,
    pub sequence: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningRequestsResponse {
    requests: Vec<SigningRequest>,
    pagination: Option<Pagination>,
}

impl SigningRequestsResponse {
    pub fn requests(&self) -> &Vec<SigningRequest> {
        &self.requests
    }

    pub fn pagination(&self) -> Option<&Pagination> {
        self.pagination.as_ref()
    }
}

pub async fn connect_ws_client(endpoint: &str) -> WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
    let host= format!("{}/websocket", endpoint.replace("http", "ws"));
    let sub_msg = r#"{"jsonrpc":"2.0","method":"subscribe","id":0,"params":{"query":"tm.event='NewBlock'"}}"#;
    loop {
        if let Ok((mut ws_stream , _)) = connect_async(&host).await {
            if ws_stream.send(WebSocketMessage::Text(sub_msg.into())).await.is_ok() {
                return ws_stream;
            }
        }
        tracing::error!("sidechain websocket client disconnected: {}", host);
        thread::sleep(Duration::from_secs(5));
    }
}

pub async fn get_bitcoin_tip_on_side(host: &str) -> Result<Response<QueryChainTipResponse>, Status> {
    let mut btc_client = match BtcQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    btc_client.query_chain_tip(QueryChainTipRequest {}).await
}

pub async fn get_bitcoin_block_header_on_side(host: &str, height: u64) -> Result<Response<QueryBlockHeaderByHeightResponse>, Status> {
    let mut btc_client = match BtcQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    btc_client.query_block_header_by_height(QueryBlockHeaderByHeightRequest { height }).await
}

pub async fn get_confirmations_on_side(host: &str) -> u64 {
    let mut btc_client = match BtcQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(_) => {
            return 1 as u64;
        }
    };
    let x = btc_client.query_params(QueryParamsRequest{}).await.unwrap().into_inner();
    x.params.unwrap().confirmations as u64
}

pub async fn get_latest_validators(host: &str) -> Result<Response<GetLatestValidatorSetResponse>, Status> {
    let mut client = match TendermintServiceClient::connect(host.to_string()).await {
        Ok(c) => c,
        Err(_) => {
            return Err(Status::cancelled(format!("Could not connect to {host}")));
        }
    };
    let mut page_request = PageRequest::default();
    page_request.limit = 100;
    client.get_latest_validator_set(GetLatestValidatorSetRequest{pagination: Some(page_request)}).await
}

pub async fn get_bridge_signing_request_by_txid(host: &str, txid: String) -> Result<Response<QuerySigningRequestByTxHashResponse>, Status> {
    let mut btc_client = match BtcQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    btc_client.query_signing_request_by_tx_hash(QuerySigningRequestByTxHashRequest {
        txid,
    }).await
}

pub async fn get_lending_signing_requests(host: &str) -> Result<Response<QuerySigningRequestsResponse>, Status> {
    let mut lending_client = match LendingQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    lending_client.signing_requests(QuerySigningRequestsRequest {
        module: "".to_string(),
        status: SigningStatus::Pending as i32,
        pagination: None
    }).await
}

pub async fn send_cosmos_transaction(conf: &config::Config, msg : Any) -> Result<tonic::Response<BroadcastTxResponse>, Status> {
    // let conf = shuttler.config();

    if conf.side_chain.grpc.is_empty() {
        return Err(Status::cancelled("GRPC URL is empty"));
        // return None;
    }

    // Generate sender private key.
    // In real world usage, this account would need to be funded before use.
    let sender_private_key = conf.relayer_bitcoin_privkey();
    // let sender_account_id = shuttler.relayer_address();

    ///////////////////////////
    // Building transactions //
    ///////////////////////////

    let _l = lock.lock().await;
    let base_account = config::get_relayer_account(conf).await;
    
    let mut base_client = match TendermintServiceClient::connect(conf.side_chain.grpc.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::aborted(format!("Failed to create tendermint client: {}", e)));
        }
    };

    let resp_b = match base_client.get_latest_block(GetLatestBlockRequest {
    }).await {
        Ok(resp) => resp,
        Err(e) => {
            return Err(Status::aborted(format!("Failed to get latest block: {}", e)));
        }
    };
    
    let chain_id = resp_b.into_inner().block.unwrap().header.unwrap().chain_id.parse().unwrap();
    let account_number = base_account.account_number;
    let sequence_number = base_account.sequence;
    let gas = conf.side_chain.gas;
    let fee = Coin::new(conf.side_chain.fee.amount as u128, conf.side_chain.fee.denom.as_str()).unwrap();
    let timeout_height = 0u16;
    let memo = "tss_signer";

    // Create transaction body from the MsgSend, memo, and timeout height.
    let tx_body = tx::Body::new(vec![msg].into_iter(), memo, timeout_height);

    let signing_key = SigningKey::from_slice(&sender_private_key.to_bytes()).unwrap();
    let mut any = signing_key.public_key().to_any().unwrap();
    any.type_url = "/cosmos.crypto.segwit.PubKey".to_string();
    let pubkey = SignerPublicKey::Any(any);
    let signer_info = SignerInfo {
        public_key: Some(pubkey),
        mode_info: ModeInfo::single(tx::SignMode::Direct),
        sequence: sequence_number,
    };

    // let signer_info = SignerInfo::single_direct(Some(signing_key.public_key()), sequence_number);
    // Compute auth info from signer info by associating a fee.
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(fee, gas as u64));

    //////////////////////////
    // Signing transactions //
    //////////////////////////

    // The "sign doc" contains a message to be signed.
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number).unwrap();

    // Sign the "sign doc" with the sender's private key, producing a signed raw transaction.
    // let tx_signed = sign_doc.sign(&signing_key).unwrap();
    let tx_signed = sign_with_bitcoin_algo(&sign_doc, &sender_private_key);

    // Serialize the raw transaction as bytes (i.e. `Vec<u8>`).
    let tx_bytes = tx_signed.to_bytes().unwrap();

    let mut tx_client = match TxServiceClient::connect(conf.side_chain.grpc.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::aborted(format!("Failed to create tx client: {}", e)));
        }
    };

    match tx_client.broadcast_tx(BroadcastTxRequest {
        tx_bytes,
        mode: BroadcastMode::Sync.into(),    
    }).await {
        Ok(response) => {
            let tx_response = response.into_inner().tx_response;
            let tx_response_clone = tx_response.clone();
            if tx_response.is_some() && tx_response.unwrap().code == 0 {
                let mut new_account  = base_account.clone();
                new_account.sequence += 1;
                config::save_relayer_account(&new_account);
            }
            return Ok(tonic::Response::new(BroadcastTxResponse {
                tx_response: tx_response_clone,
            }));
        }
        Err(e) => {
            if e.message().contains("account sequence mismatch") {
                config::remove_relayer_account();
            }
            return Err(Status::aborted(format!("Failed to broadcast tx: {}", e)));
        }
    }
}

fn sign_with_bitcoin_algo(doc: &SignDoc, priv_key: &PrivateKey) -> Raw {
    let sign_doc_bytes = doc.clone().into_bytes().expect("Failed to serialize sign doc");
    let secp = Secp256k1::new();

    let msg_hash = signed_msg_hash(sign_doc_bytes);
    let msg = Message::from_digest(*msg_hash.as_byte_array());
    let signature = secp.sign_ecdsa_recoverable(&msg, &priv_key.inner);

    let mut sig_bytes: Vec<u8> = vec![];
    sig_bytes.push(signature.serialize_compact().0.to_i32() as u8 + 27 + 4);
    sig_bytes.append(&mut signature.serialize_compact().1.to_vec());

    cosmos_sdk_proto::cosmos::tx::v1beta1::TxRaw {
        body_bytes: doc.body_bytes.clone(),
        auth_info_bytes: doc.auth_info_bytes.clone(),
        signatures: vec![sig_bytes],
    }.into()
}

pub fn signed_msg_hash(msg: Vec<u8>) -> sha256d::Hash {
    let mut engine = bitcoin::hashes::sha256d::Hash::engine();
    engine.input(BITCOIN_SIGNED_MSG_PREFIX);
    let msg_len = bitcoin::consensus::encode::VarInt::from(msg.len());
    msg_len.consensus_encode(&mut engine).expect("engines don't error");
    engine.input(msg.as_slice());
    sha256d::Hash::from_engine(engine)
}

#[cfg(test)]
#[tokio::test]
async fn test_signature() {

    use side_proto::side::btcbridge::MsgSubmitSignatures;
    use crate::config::Config;

    let conf = Config::from_file(".side3").expect("not found config file");
    let msg = MsgSubmitSignatures {
        sender: conf.relayer_bitcoin_address(),
        txid: "abcd".to_string(),
        psbt: "123".to_string(),
    };

    let msg = Any::from_msg(&msg).unwrap();
    let ret = send_cosmos_transaction(&conf, msg).await.unwrap();
    let res = ret.into_inner().tx_response;

    assert_eq!(res.is_some(), true);
    println!("Response: {:?}", res.clone().unwrap().txhash);
    println!("Response: {:?}", res.clone().unwrap().raw_log);
    assert_eq!(res.unwrap().code, 0);  

}
