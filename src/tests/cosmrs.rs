use cosmos_sdk_proto::cosmos::{
    auth::v1beta1::{
        query_client::QueryClient as AuthQueryClient, 
        BaseAccount, QueryAccountRequest
    }, 
    base::tendermint::v1beta1::{service_client::ServiceClient as TendermintServiceClient, GetLatestBlockRequest},
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
    
    let mut client = AuthQueryClient::connect("http://localhost:9090").await.unwrap();
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
    // Generate sender private key.
    // In real world usage, this account would need to be funded before use.
    let sender_private_key = secp256k1::SigningKey::random();
    let sender_public_key = sender_private_key.public_key();
    let sender_account_id = sender_public_key.account_id("side").unwrap();

    println!("sender_account_id: {:?}", sender_account_id.as_ref());

    // Parse recipient address from Bech32.
    let recipient_account_id =
        "cosmos19dyl0uyzes4k23lscla02n06fc22h4uqsdwq6z".parse::<AccountId>().unwrap();

    ///////////////////////////
    // Building transactions //
    ///////////////////////////

    // We'll be doing a simple send transaction.
    // First we'll create a "Coin" amount to be sent, in this case 1 million uatoms.
    let amount = Coin {
        amount: 1_000_000u128,
        denom: "uatom".parse().unwrap(),
    };

    // Next we'll create a send message (from the "bank" module) for the coin
    // amount we created above.
    // let msg_send = MsgSend {
    //     from_address: sender_account_id.clone(),
    //     to_address: recipient_account_id,
    //     amount: vec![amount.clone()],
    // };
    let msg_send = &Any {
        type_url: "/side.btcbridge.MsgSubmitWithdrawSignaturesRequest".to_string(),
        value: serde_json::to_vec(&TestMsg {
            from_address: sender_account_id.clone(),
            to_address: recipient_account_id,
            amount: vec![amount.clone()],
        }).unwrap(),
    };

    // Transaction metadata: chain, account, sequence, gas, fee, timeout, and memo.
    let chain_id = "cosmoshub-4".parse().unwrap();
    let account_number = 1;
    let sequence_number = 0;
    let gas = 100_000u64;
    let timeout_height = 01u16;
    let memo = "example memo";

    // Create transaction body from the MsgSend, memo, and timeout height.
    let tx_body = tx::Body::new(vec![msg_send.to_owned()], memo, timeout_height);

    // Create signer info from public key and sequence number.
    // This uses a standard "direct" signature from a single signer.
    let signer_info = SignerInfo::single_direct(Some(sender_public_key), sequence_number);

    // Compute auth info from signer info by associating a fee.
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(amount, gas));

    //////////////////////////
    // Signing transactions //
    //////////////////////////

    // The "sign doc" contains a message to be signed.
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number).unwrap();

    // Sign the "sign doc" with the sender's private key, producing a signed raw transaction.
    let tx_signed = sign_doc.sign(&sender_private_key).unwrap();

    // Serialize the raw transaction as bytes (i.e. `Vec<u8>`).
    let tx_bytes = tx_signed.to_bytes().unwrap();

    //////////////////////////
    // Parsing transactions //
    //////////////////////////

    // Parse the serialized bytes from above into a `cosmrs::Tx`
    let tx_parsed = Tx::from_bytes(&tx_bytes).unwrap();
    assert_eq!(tx_parsed.body, tx_body);
    assert_eq!(tx_parsed.auth_info, auth_info);

}
