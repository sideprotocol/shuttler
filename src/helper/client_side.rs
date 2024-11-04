use bitcoin::{ consensus::Encodable, key::Secp256k1, secp256k1::Message, sign_message::BITCOIN_SIGNED_MSG_PREFIX, PrivateKey};
use bitcoin_hashes::{sha256d, Hash, HashEngine};
use cosmrs::{ crypto::secp256k1::SigningKey, tx::{self, Fee, ModeInfo, Raw, SignDoc, SignerInfo, SignerPublicKey}, Coin};
use cosmos_sdk_proto::{cosmos::{
    base::{query::v1beta1::PageRequest, tendermint::v1beta1::GetLatestBlockRequest}, tx::v1beta1::{service_client::ServiceClient as TxServiceClient, BroadcastMode, BroadcastTxRequest, BroadcastTxResponse}
}, side::btcbridge::QueryParamsRequest};
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient as TendermintServiceClient;
use reqwest::Error;
use tokio::sync::Mutex;
use tonic::{Response, Status};
use cosmos_sdk_proto::side::btcbridge::{
    query_client::QueryClient as BtcQueryClient,
    QueryBlockHeaderByHeightRequest, QueryBlockHeaderByHeightResponse,
    QueryChainTipRequest, QueryChainTipResponse, 
    QuerySigningRequestsRequest, QuerySigningRequestsResponse, 
    QuerySigningRequestByTxHashRequest, QuerySigningRequestByTxHashResponse
};

use prost_types::Any;
use lazy_static::lazy_static;

use crate::app::config::{self, get_database_with_name};

const DB_KEY_TASK_ROUND_WINDOW_LAST_UPDATE: &str = "task_round_window_last_update";
const DB_KEY_TASK_ROUND_WINDOW: &str = "task_round_window";

lazy_static! {
    static ref lock: Mutex<()> = Mutex::new(());
    static ref DB_SIDE_PARAMS: sled::Db = {
        let path = get_database_with_name("side-params");
        sled::open(path).unwrap()
    };
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

pub async fn get_task_round_window_on_side(host: &str) -> u64 {
    let mut btc_client = match BtcQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(_) => {
            return 300 as u64;
        }
    };
    let x = btc_client.query_params(QueryParamsRequest{}).await.unwrap().into_inner();
    match x.params.unwrap().tss_params.unwrap().signing_epoch_duration {
        Some(duration) => {
            return duration.seconds as u64;
        }
        None => {
            return 300;
        }
    }
}

pub async fn get_cached_task_round_window(host: &str) -> u64 {
    if let Ok(Some(last_update)) = DB_SIDE_PARAMS.get(DB_KEY_TASK_ROUND_WINDOW_LAST_UPDATE) {
        let last_update: u64 = serde_json::from_slice(&last_update).unwrap_or(0);
        let now = chrono::Utc::now().timestamp() as u64;
        if now - last_update < 60 * 60 * 1 { // 1 hours
            if let Ok(Some(seconds)) =  DB_SIDE_PARAMS.get(DB_KEY_TASK_ROUND_WINDOW) {
                return serde_json::from_slice(&seconds).unwrap_or(300);
            };
        }
    }
    let task_round_window = get_task_round_window_on_side(host).await;
    let _ = DB_SIDE_PARAMS.insert(DB_KEY_TASK_ROUND_WINDOW, 
        serde_json::to_vec(&task_round_window).unwrap()
    );
    let _ = DB_SIDE_PARAMS.insert(DB_KEY_TASK_ROUND_WINDOW_LAST_UPDATE, 
        serde_json::to_vec(&chrono::Utc::now().timestamp()).unwrap()
    );
    return task_round_window;
}

pub async fn get_signing_requests(host: &str) -> Result<Response<QuerySigningRequestsResponse>, Status> {
    let mut btc_client = match BtcQueryClient::connect(host.to_string()).await {
        Ok(client) => client,
        Err(e) => {
            return Err(Status::cancelled(format!("Failed to create btcbridge query client: {}", e)));
        }
    };

    btc_client.query_signing_requests(QuerySigningRequestsRequest {
        pagination: Some(PageRequest {
            key: vec![],
            offset: 0,
            limit: 50,
            count_total: false,
            reverse: false,
        }),
        status: 1i32
    }).await
}

pub async fn get_signing_request_by_txid(host: &str, txid: String) -> Result<Response<QuerySigningRequestByTxHashResponse>, Status> {
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

pub async fn mock_signing_requests() -> Result<SigningRequestsResponse, Error> {
    Ok(SigningRequestsResponse {
        requests: vec![
            SigningRequest {
                address: "bc1q5wgdhplnzn075eq7xep4zes7lnk5jy2ke0scsm".to_string(),
                psbt: "cHNidP8BAIkCAAAAARuMLk06K1ufndtymk3RaWdbLy21UYs9vUs8D6o8HjtNAAAAAAAAAAAAAkCcAAAAAAAAIlEglUAPVXmsEIekhIthcGwg/vRxs93mpUYfH3vFVlGNjiEoIwAAAAAAACJRIJVAD1V5rBCHpISLYXBsIP70cbPd5qVGHx97xVZRjY4hAAAAAAABAStQwwAAAAAAACJRIJVAD1V5rBCHpISLYXBsIP70cbPd5qVGHx97xVZRjY4hAQMEAAAAAAAAAA==".to_string(),
                status: "pending".to_string(),
                sequence: 1,
            }],
        pagination: None,
    })
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
    let tx_body = tx::Body::new(vec![msg], memo, timeout_height);

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
    let mut engine = sha256d::Hash::engine();
    engine.input(BITCOIN_SIGNED_MSG_PREFIX);
    let msg_len = bitcoin::consensus::encode::VarInt::from(msg.len());
    msg_len.consensus_encode(&mut engine).expect("engines don't error");
    engine.input(msg.as_slice());
    sha256d::Hash::from_engine(engine)
}

#[cfg(test)]
#[tokio::test]
async fn test_signature() {

    use cosmos_sdk_proto::side::btcbridge::MsgSubmitSignatures;
    use crate::app::config::Config;

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

// #[test]
// fn test_basic_sign() {

//     // Replace with your mnemonic and HD path
//     let hd_path = DerivationPath::from_str("m/84'/0'/0'/0/0").expect("invalid HD path");
//     // Generate seed from mnemonic
//     let mnemonic = Mnemonic::from_str(&"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("Invalid mnemonic");

//     // Derive HD key
//     let secp = Secp256k1::new();
//     // let derivation_path = DerivationPath::from_str(hd_path).expect("Invalid HD path");
//     let master = Xpriv::new_master(Network::Bitcoin, &mnemonic.to_seed("")).expect("failed to create master key");
//     let priv_key = master.derive_priv(&secp, &hd_path).expect("Failed to derive key").to_priv();
//     // RgS0txD+kfWE//CE4akVn+T4QI//OAWWpgSUhHTOT6M=
//     println!("Priv Key: {:?}", to_base64(priv_key.to_bytes().as_slice()));
    
//     let secp = Secp256k1::new();
//     let msg_hash = signed_msg_hash(b"1234".to_vec());
//     let msg = Message::from_digest_slice(msg_hash.as_byte_array()).unwrap();
//     // slcH5qITi0nbdS1O1wLcpYbcT/zrKrT8stRyjoNcDGk=
//     println!("Msg Hash: {:?} {:?}", to_base64(msg_hash.as_byte_array()), msg);
    
//     // H4K6oH19PE4lp8YmXOpJeMlIZ/zy4AnLVAJ0NvTgq1ftHG6kcsuKF9m2H2zlKPCOdXJSanYc0ZkmYhwjOrIstPk=
//     let signature = secp.sign_ecdsa_recoverable(&msg, &priv_key.inner);
//     // let mut sig_raw = signature.serialize_compact().1;
//     let mut v = vec![];
//     println!("Signature: {:?}", signature.serialize_compact().0.to_i32() as u8);
//     v.push((signature.serialize_compact().0.to_i32() + 27 + 4) as u8);
//     v.append(&mut signature.serialize_compact().1.to_vec());
//     println!("Signature: {:?}", to_base64(v.as_slice()));
//     println!("Signature: {:?}", signature);
//     println!("Signature: {:?}", to_base64(&signature.to_standard().serialize_compact()));
//     // priv_key.inner.keypair(&secp).public_key().verify(&secp, &msg, &signature).expect("failed to verify signature");
//     // println!("pubkey: {:?} {}", priv_key.public_key(&secp), to_base64(&priv_key.public_key(&secp).to_bytes()[..]));

//     // signing key
//     let sign_key = SigningKey::from_slice(&priv_key.to_bytes()).expect("Failed to create signing key");
//     println!("Sign key {}", to_base64(sign_key.public_key().to_bytes().as_slice()));
//     let sig = sign_key.sign(msg_hash.as_byte_array()).expect("Failed to sign message");
//     println!("Signature: {:?}", sig.to_string());
//     println!("Signature: {:?}", to_base64(sig.to_vec().as_slice()));

//     // let pk = CompressedPublicKey::from_private_key(&secp, priv_key).expect("failed to get pubkey");
// }