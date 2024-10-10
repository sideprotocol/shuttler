use std::path::PathBuf;
use std::fs;
use std::str::FromStr;

use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountResponse};
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_sdk_proto::side::btcbridge::query_server::Query;
use cosmos_sdk_proto::side::btcbridge::{DkgParticipant, DkgRequest, DkgRequestStatus, MsgCompleteDkg, QueryDkgRequestsResponse, QuerySigningRequestsResponse, SigningRequest};
use cosmos_sdk_proto::cosmos::auth::v1beta1::query_server::Query as AuthService;
use cosmos_sdk_proto::cosmos::tx::v1beta1::service_server::Service as TxService;
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_server::Service as BlockService;

use cosmos_sdk_proto::tendermint::v0_34::types::{Block, Header};
use cosmrs::{Any, Tx};
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};

use bitcoin::{
    opcodes, psbt::PsbtSighashType, transaction::Version, Amount, OutPoint, Psbt, Sequence, TxIn,
    TxOut, Address, ScriptBuf, Transaction, Txid
};
use bitcoin_hashes::Hash;

use crate::helper::encoding::to_base64;

use crate::helper::now;

pub const SINGING_FILE_NAME: &str = "signing-requests.json";
pub const DKG_FILE_NAME: &str = "dkg-request.json";
pub const VAULT_FILE_NAME: &str = "address.txt";

#[derive(Serialize, Deserialize)]
pub struct DKG {
    pub id: u64,
    pub participants: Vec<String>,
    pub threshold: u32,
}

#[derive(Serialize, Deserialize)]
pub struct SR { 
    address: String, 
    sequence: u64, 
    txid: String, 
    psbt: String, 
    status: i32, 
}

#[derive(Clone)]
pub struct MockQuery {
    home: String
}

pub struct MockTxService {
    pub home: String
}

pub struct MockBlockService;

impl MockQuery {
    pub fn new(home: String) -> Self {
        Self {
            home
        }
    }
}

// produce mock data

fn mock_psbt(home: &str, tx_bytes: &Vec<u8>) {
    if let Ok(tx) = Tx::from_bytes(tx_bytes) {
        tx.body.messages.iter().for_each(|m| {
            if m.type_url == "/side.btcbridge.MsgCompleteDKG" {
                if let Ok(msg) = m.to_msg::<MsgCompleteDkg>() {
                    let mut path = PathBuf::new();
                    path.push(home);
                    path.push("test.txt");
                    let _ = fs::write(path, msg.vaults.join(","));
                }
            }
        })
    }
}

// 1. signing requests
async fn load_signing_requests(home: &str) -> Result<tonic::Response<QuerySigningRequestsResponse>, tonic::Status> {
    let mut path = PathBuf::new();
    path.push(home);
    path.push(SINGING_FILE_NAME);

    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => "[]".to_string(),
    };
    let mut srs: Vec<SR> = serde_json::from_str(&text).unwrap();

    let mut path_2 = PathBuf::new();
    path_2.push(home);
    path_2.push(VAULT_FILE_NAME);
    if let Ok(address) = fs::read_to_string(path_2) {
        srs.push(SR {
            address,
            sequence: 3,
            status: 1,
            txid: "".to_string(),
            psbt: "".to_string(),
        });
    }

    let requests = srs.iter().map(|i| {
        SigningRequest { 
            address: i.address.clone(), 
            sequence: i.sequence, 
            txid: i.txid.clone(), 
            psbt: i.psbt.clone(), 
            status: i.status, 
        }
    }).collect::<Vec<_>>();
    let res: QuerySigningRequestsResponse = QuerySigningRequestsResponse { requests, pagination: None };
    Ok(tonic::Response::new(res))
}

// mock dkg request
async fn loading_dkg_request(home: &str) -> Result<tonic::Response<QueryDkgRequestsResponse>, tonic::Status> {
    let mut path = PathBuf::new();
    path.push(home);
    path.push(DKG_FILE_NAME);

    let text = fs::read_to_string(path).unwrap();
    let dkg: DKG = serde_json::from_str(&text).unwrap();
    let participants = dkg.participants.iter().map(|i: &String| DkgParticipant {
        moniker: i.clone(),
        operator_address: i.clone(),
        consensus_address: i.to_string(),
    }).collect::<Vec<_>>();

    let timeout = Timestamp {
        seconds: now() as i64 + 3600,
        nanos: 0,
    };
    let res = QueryDkgRequestsResponse { requests: vec![
        DkgRequest { 
            id: dkg.id, 
            participants,
            threshold: dkg.threshold,
            vault_types: vec![0], 
            disable_bridge: false, 
            enable_transfer: true, 
            target_utxo_num: 100, 
            fee_rate: "1000".to_string(), 
            expiration: Some(timeout), 
            status: DkgRequestStatus::Pending as i32 
        },
    ] };
    Ok(tonic::Response::new(res))
}

async fn loading_account(address: String) -> Result<tonic::Response<QueryAccountResponse>, tonic::Status> {
    let mut ba = BaseAccount::default();
    ba.address = address;
    let res = QueryAccountResponse {
        account: Some(Any::from_msg(&ba).unwrap()),
    };
    Ok(tonic::Response::new(res))
}

async fn mock_broadcast_tx() -> Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::BroadcastTxResponse>, tonic::Status> {
    Ok(tonic::Response::new(cosmos_sdk_proto::cosmos::tx::v1beta1::BroadcastTxResponse {
        tx_response: Some(TxResponse::default())
    }))
}

async fn mock_latest_block() -> Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse>, tonic::Status> {
    
    let mut header = Header::default();
    header.chain_id = "mock-testnet".to_owned();
    header.height = 123;
    // header.time
    
    let res = cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse {
        block_id: None,
        block: Some(Block {
            header: Some(header),
            data: None,
            evidence: None,
            last_commit: None,
        }),
        sdk_block: None,
    };
    Ok(tonic::Response::new(res))
}

// implementing gRPC services
// 
impl Query for MockQuery {
    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_params<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryParamsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryParamsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_chain_tip<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryChainTipRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryChainTipResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_block_header_by_height<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryBlockHeaderByHeightRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryBlockHeaderByHeightResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_block_header_by_hash<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryBlockHeaderByHashRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryBlockHeaderByHashResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_fee_rate<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryFeeRateRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryFeeRateResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_withdrawal_network_fee<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryWithdrawalNetworkFeeRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryWithdrawalNetworkFeeResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_withdraw_requests_by_address<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryWithdrawRequestsByAddressRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryWithdrawRequestsByAddressResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_withdraw_requests_by_tx_hash<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryWithdrawRequestsByTxHashRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryWithdrawRequestsByTxHashResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_pending_btc_withdraw_requests<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryPendingBtcWithdrawRequestsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryPendingBtcWithdrawRequestsResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_signing_requests<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QuerySigningRequestsRequest> ,) ->  
    ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QuerySigningRequestsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let x = load_signing_requests(&self.home.as_str());
        Box::pin(x)
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_signing_requests_by_address<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QuerySigningRequestsByAddressRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QuerySigningRequestsByAddressResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_signing_request_by_tx_hash<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QuerySigningRequestByTxHashRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QuerySigningRequestByTxHashResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_utx_os<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryUtxOsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryUtxOsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_utx_os_by_address<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryUtxOsByAddressRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryUtxOsByAddressResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_utxo_count_and_balances_by_address<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryUtxoCountAndBalancesByAddressRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryUtxoCountAndBalancesByAddressResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_dkg_request<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryDkgRequestRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryDkgRequestResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_dkg_requests<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryDkgRequestsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryDkgRequestsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let x = loading_dkg_request(&self.home.as_str());
        Box::pin(x)
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_all_dkg_requests<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryAllDkgRequestsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryAllDkgRequestsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn query_dkg_completion_requests<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::side::btcbridge::QueryDkgCompletionRequestsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::side::btcbridge::QueryDkgCompletionRequestsResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
}

impl AuthService for MockQuery {
    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn accounts<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn account<'life0,'async_trait>(&'life0 self,request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let addr = request.get_ref().address.clone();
        let x = loading_account(addr);
        Box::pin(x)
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn account_address_by_id<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountAddressByIdRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryAccountAddressByIdResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn params<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryParamsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryParamsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn module_accounts<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryModuleAccountsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryModuleAccountsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn module_account_by_name<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryModuleAccountByNameRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::QueryModuleAccountByNameResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn bech32_prefix<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::Bech32PrefixRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::Bech32PrefixResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn address_bytes_to_string<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::AddressBytesToStringRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::AddressBytesToStringResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn address_string_to_bytes<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::auth::v1beta1::AddressStringToBytesRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::auth::v1beta1::AddressStringToBytesResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
}

impl TxService for MockTxService {
    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn simulate<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::SimulateRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::SimulateResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_tx<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::GetTxRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::GetTxResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn broadcast_tx<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::BroadcastTxRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::BroadcastTxResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        
        mock_psbt(self.home.as_str(), &_request.get_ref().tx_bytes);

        let x = mock_broadcast_tx();
        Box::pin(x)
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_txs_event<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::GetTxsEventRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::GetTxsEventResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_block_with_txs<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::tx::v1beta1::GetBlockWithTxsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::tx::v1beta1::GetBlockWithTxsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
}

impl BlockService for MockBlockService {
    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_node_info<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetNodeInfoRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetNodeInfoResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_syncing<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetSyncingRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetSyncingResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_latest_block<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestBlockRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestBlockResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let x = mock_latest_block();
        Box::pin(x)
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_block_by_height<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetBlockByHeightRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetBlockByHeightResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_latest_validator_set<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestValidatorSetRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetLatestValidatorSetResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn get_validator_set_by_height<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetValidatorSetByHeightRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::GetValidatorSetByHeightResponse> ,tonic::Status, > > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn abci_query<'life0,'async_trait>(&'life0 self,_request:tonic::Request<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::AbciQueryRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = std::result::Result<tonic::Response<cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::AbciQueryResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }
}

fn generate_mock_psbt(addr: &str, input_num: Option<u32>) -> (String, String) {
    let address = Address::from_str(addr).unwrap().assume_checked();
    
    let num = match input_num {
        Some(num) => num,
        None => 1
    };

    let sequence: u32 = (1 << 31) + 0xde;

    let mut inputs = Vec::<TxIn>::new();
    for i in 1..num {
        let tx_in = TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: i,
            },
            sequence: Sequence(sequence),
            ..Default::default()
        };

        inputs.push(tx_in);
    }

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: [TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::builder()
                .push_opcode(opcodes::all::OP_RETURN)
                .into_script(),
        }]
        .to_vec(),
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx.clone()).unwrap();

    psbt.inputs.iter_mut().for_each(|input| {
        input.sighash_type = Some(PsbtSighashType::from_u32(0));
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: address.script_pubkey(),
        })
    });

    let tx_id = unsigned_tx.compute_txid().to_string();
    let psbt_b64 = to_base64(psbt.serialize().as_slice());

    (tx_id, psbt_b64)
}
