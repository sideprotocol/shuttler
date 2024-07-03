
use cosmrs::{crypto::secp256k1, tx::{self, Fee, SignDoc, SignerInfo}, Any, Coin};
use cosmos_sdk_proto::cosmos::{
    auth::v1beta1::{query_client::QueryClient as AuthQueryClient, BaseAccount, QueryAccountRequest}, 
    base::tendermint::v1beta1::GetLatestBlockRequest, tx::v1beta1::{BroadcastMode, BroadcastTxRequest},
    tx::v1beta1::service_client::ServiceClient as TxServiceClient
};
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient as TendermintServiceClient;
use reqwest::Error;

use crate::app::config::Config;

use super::encoding::from_base64;

pub fn get_http_client() -> reqwest::Client {
    reqwest::Client::new()
}

pub async fn get<T>(url: &str) -> Result<T, Error> where T: serde::de::DeserializeOwned {
    let response = match reqwest::get(url).await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!("Failed to send request: {:?}", error);
            return Err(error);
        }
    };

    response.json::<T>().await
}

pub async fn post<I, O>(url: &str, data: I) -> Result<O, Error> where I: serde::Serialize, O: serde::de::DeserializeOwned {

    let client = get_http_client();
    let response = match client.post(url).json(&data).send().await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!("Failed to send request: {:?}", error);
            return Err(error);
        }
    };    
    response.json::<O>().await
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
    pub vault_address: String,
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

pub async fn get_signing_requests(host: &str ) -> Result<SigningRequestsResponse, Error> {
    let url = format!("{}/signing_requests", host);
    get::<SigningRequestsResponse>(url.as_str()).await
}

pub async fn mock_signing_requests() -> Result<SigningRequestsResponse, Error> {
    Ok(SigningRequestsResponse {
        requests: vec![
            SigningRequest {
                address: "bc1q5wgdhplnzn075eq7xep4zes7lnk5jy2ke0scsm".to_string(),
                psbt: "cHNidP8BAIkCAAAAARuMLk06K1ufndtymk3RaWdbLy21UYs9vUs8D6o8HjtNAAAAAAAAAAAAAkCcAAAAAAAAIlEglUAPVXmsEIekhIthcGwg/vRxs93mpUYfH3vFVlGNjiEoIwAAAAAAACJRIJVAD1V5rBCHpISLYXBsIP70cbPd5qVGHx97xVZRjY4hAAAAAAABAStQwwAAAAAAACJRIJVAD1V5rBCHpISLYXBsIP70cbPd5qVGHx97xVZRjY4hAQMEAAAAAAAAAA==".to_string(),
                status: "pending".to_string(),
                sequence: 1,
                vault_address: "bc1q5wgdhplnzn075eq7xep4zes7lnk5jy2ke0scsm".to_string(),
            }],
        pagination: None,
    })
}

pub async fn send_cosmos_transaction(conf: &Config, msg : Any) {
    // let url = format!("{}/txs", conf.side_chain.);

    if conf.side_chain.grpc.is_empty() {
        tracing::error!("GRPC URL is empty");
        return;
    }

    // Generate sender private key.
    // In real world usage, this account would need to be funded before use.
    let key_bytes = from_base64(&conf.side_chain.priv_key).unwrap();
    let sender_private_key = secp256k1::SigningKey::from_slice(&key_bytes).unwrap();
    let sender_public_key = sender_private_key.public_key();
    let sender_account_id = sender_public_key.account_id(&conf.side_chain.addr_prefix).unwrap();

    ///////////////////////////
    // Building transactions //
    ///////////////////////////

    let mut client = AuthQueryClient::connect(conf.side_chain.grpc.to_string()).await.unwrap();
    let resp = client.account(QueryAccountRequest {
        address: sender_account_id.as_ref().to_string(),
    }).await.unwrap();

    // let acc_resp = resp.into_inner().account.unwrap();
    // acc_resp.account.unwrap().
    let base_account: BaseAccount = resp.into_inner().account.unwrap().to_msg().unwrap();
    

    let mut base_client = TendermintServiceClient::connect(conf.side_chain.grpc.to_string()).await.unwrap();
    let resp_b = base_client.get_latest_block(GetLatestBlockRequest {
    }).await.unwrap();
    
    let chain_id = resp_b.into_inner().block.unwrap().header.unwrap().chain_id.parse().unwrap();
    let account_number = base_account.account_number;
    let sequence_number = base_account.sequence;
    let gas = conf.side_chain.gas;
    let timeout_height = 0u16;
    let memo = "tss_signer";

    let fees = Coin {
        amount: 2_000u128,
        denom: "uside".parse().unwrap(),
    };

    // Create transaction body from the MsgSend, memo, and timeout height.
    let tx_body = tx::Body::new(vec![msg], memo, timeout_height);

    // Create signer info from public key and sequence number.
    // This uses a standard "direct" signature from a single signer.
    let signer_info = SignerInfo::single_direct(Some(sender_public_key), sequence_number);

    // Compute auth info from signer info by associating a fee.
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(fees, gas as u16));

    //////////////////////////
    // Signing transactions //
    //////////////////////////

    // The "sign doc" contains a message to be signed.
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number).unwrap();

    // Sign the "sign doc" with the sender's private key, producing a signed raw transaction.
    let tx_signed = sign_doc.sign(&sender_private_key).unwrap();

    // Serialize the raw transaction as bytes (i.e. `Vec<u8>`).
    let tx_bytes = tx_signed.to_bytes().unwrap();

    let mut tx_client = TxServiceClient::connect(conf.side_chain.grpc.to_string()).await.unwrap();
    match tx_client.broadcast_tx(BroadcastTxRequest {
        tx_bytes,
        mode: BroadcastMode::Sync.into(),    
    }).await {
        Ok(resp) => {
            tracing::info!("Transaction sent: {:?}", resp.into_inner());
        },
        Err(error) => {
            tracing::error!("Failed to send transaction: {:?}", error);
        }    
    };
    
   // post::<>(url.as_str(), tx).await
}