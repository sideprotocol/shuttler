use cosmos_sdk_proto::cosmos::{
    auth::v1beta1::{
        query_client::QueryClient as AuthQueryClient, 
        BaseAccount, QueryAccountRequest
    }, bank::v1beta1::MsgSend, base::tendermint::v1beta1::{service_client::ServiceClient as TendermintServiceClient, GetLatestBlockRequest}
};
use cosmrs::{
    crypto::secp256k1, tx::{self, Fee, SignDoc, SignerInfo, Tx}, AccountId, Any, Coin
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TestMsg {
    pub from_address: AccountId,
    pub to_address: AccountId,
    pub amount: Vec<Coin>,
}

#[tokio::test]
async fn test_grpc_query() {

    // let btcClient = BtcQueryClient::connect("").await.unwrap();
    // btcClient.q
    
    let mut client = AuthQueryClient::connect("http://202.182.105.108:9090").await.unwrap();
    let resp = client.account(QueryAccountRequest {
        address: "tb1q6lxtawadyve6a9mfqntwgz6sx3n6k4cp83hhd4".to_string(),
    }).await.unwrap();

    // acc_resp.account.unwrap().
    let msg: BaseAccount = resp.into_inner().account.unwrap().to_msg().unwrap();
    println!("Account: {:?}", msg);

    let mut base_client = TendermintServiceClient::connect("http://localhost:9090").await.unwrap();
    let resp_b = base_client.get_latest_block(GetLatestBlockRequest {
    }).await.unwrap();
    
    let chain_id: String = resp_b.into_inner().block.unwrap().header.unwrap().chain_id.parse().unwrap();
    println!("Chain ID: {:?}", chain_id);

    // let mut btc_client = BtcQueryClient::connect("http://localhost:9090").await.unwrap();
    // let resp_c = btc_client.query_signing_request(QuerySigningRequestRequest {
    //     pagination: None,
    //     status: 2
    // }).await.unwrap();

    // println!("Signing Request: {:?}", resp_c.into_inner().requests.len()  );

    // resp_c.into_inner().requests.iter().for_each(|x| {
    //     println!("Request: {:?}", x);
    // });

    // let mut tx_client = cosmos::tx::v1beta1::service_client::ServiceClient::connect("http://localhost:9090").await.unwrap();
    // let resp = tx_client.broadcast_tx(BroadcastTxRequest {
    //     tx_bytes: vec![],
    //     mode: BroadcastMode::Sync.into(),
    
    // }).await.unwrap();


    
}

#[test]
fn test_cosmrs() {

}
