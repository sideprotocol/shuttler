use std::path::PathBuf;
use std::fs;

use cosmos_sdk_proto::side::btcbridge::query_server:: Query;
use cosmos_sdk_proto::side::btcbridge::{DkgParticipant, DkgRequest, DkgRequestStatus, QueryDkgRequestsResponse, QuerySigningRequestsResponse, SigningRequest};

use serde::{Deserialize, Serialize};

pub const SINGING_FILE_NAME: &str = "signing-requests.json";
pub const DKG_FILE_NAME: &str = "dkg-request.json";

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

pub struct MockQuery {
    home: String
}

impl MockQuery {
    pub fn new(home: String) -> Self {
        Self {
            home
        }
    }
}

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
        let x = async move {
            let mut path = PathBuf::new();
            path.push(self.home.as_str());
            path.push(SINGING_FILE_NAME);
    
            let text = match fs::read_to_string(path) {
                Ok(t) => t,
                Err(_) => "[]".to_string(),
            };
            let srs: Vec<SR> = serde_json::from_str(&text).unwrap();

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
        };
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
    let x = async move {
        let mut path = PathBuf::new();
        path.push(self.home.as_str());
        path.push(DKG_FILE_NAME);

        let text = fs::read_to_string(path).unwrap();
        let dkg: DKG = serde_json::from_str(&text).unwrap();
        let participants = dkg.participants.iter().map(|i| DkgParticipant {
            moniker: i.clone(),
            operator_address: i.clone(),
            consensus_address: i.to_string(),
        }).collect::<Vec<_>>();

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
                expiration: None, 
                status: DkgRequestStatus::Pending as i32 
            },
        ] };
        Ok(tonic::Response::new(res))
    };
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
