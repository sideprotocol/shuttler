use std::{fs, path::{Path, PathBuf}};

use cosmrs::{tx::MessageExt, Any};
use side_proto::{prost::Message, side::dlc::{query_server::Query as OracleQuery, Agency, DlcNonce, DlcOracle, DlcOracleStatus, MsgSubmitNonce, MsgSubmitOraclePubKey, Params, PriceInterval, QueryAgenciesResponse, QueryAttestationsResponse, QueryCountNoncesResponse, QueryOraclesResponse, QueryParamsResponse}};

use crate::helper::encoding::from_base64;

use super::{fullpath,  MockQuery};

const ORACLE_DKG_FILE_NAME: &str = "oracle.json";
const AGENCY_DKG_FILE_NAME: &str = "agency.json";
const NONCE_DKG_FILE_NAME: &str = "nonces.json";

pub fn generate_oracle_file(testdir: &Path, participants: Vec<String>) {
    let mut oracle = DlcOracle::default(); 
    oracle.id = 1;
    oracle.threshold = (participants.len() * 2 / 3 ) as u32;
    oracle.participants = participants;
    oracle.status = DlcOracleStatus::OracleStatusPending as i32;
    
    let mut path = PathBuf::new();
    path.push(testdir);
    path.push("mock");
    let _ = fs::create_dir_all(&path);
    path.push(ORACLE_DKG_FILE_NAME);

    fs::write(path, oracle.encode_to_vec()).unwrap();
}

pub fn handle_oracle_dkg_submission(home: &str, m: &Any) {
    if let Ok(msg) = m.to_msg::<MsgSubmitOraclePubKey>() {
        let key = fullpath(home, &msg.pub_key);
        println!("Received: {:?} from {}", msg.pub_key, msg.sender);
        
        if fs::exists(&key).unwrap_or(false) {
            return
        }
        fs::create_dir_all(fullpath(home, key)).unwrap();

        let bytes = fs::read(fullpath(home, ORACLE_DKG_FILE_NAME)).unwrap();
        let mut o = DlcOracle::decode(bytes.as_slice()).unwrap();
        o.pubkey = msg.pub_key;
        o.status = DlcOracleStatus::OracleStatusEnable as i32;

        fs::write(fullpath(home, ORACLE_DKG_FILE_NAME ), o.encode_to_vec()).unwrap();
    }
}

pub fn handle_nonce_submission(home: &str, m: &Any) {
    if let Ok(msg) = m.to_msg::<MsgSubmitNonce>() {
        let hex_str = hex::encode(from_base64(&msg.nonce).unwrap());
        let key = fullpath(home, hex_str);
        println!("Received: {:?} from {}", msg.nonce, msg.sender);
        
        if fs::exists(&key).unwrap_or(false) {
            return
        }
        fs::create_dir_all(fullpath(home, key)).unwrap();
        let bytes = fs::read(fullpath(home, ORACLE_DKG_FILE_NAME)).unwrap();
        let mut o = DlcOracle::decode(bytes.as_slice()).unwrap();
        o.nonce_index = o.nonce_index + 1;
        fs::write(fullpath(home, ORACLE_DKG_FILE_NAME), o.encode_to_vec()).unwrap();

        let mut nonces: Vec<Vec<u8>> = match fs::read(fullpath(home, NONCE_DKG_FILE_NAME)) {
            Ok(data) => serde_json::from_slice(&data).unwrap(),
            Err(_) => vec![],
        };

        nonces.push(DlcNonce {
            index: nonces.len() as u64,
            nonce: msg.nonce,
            oracle_pubkey: o.pubkey.clone(),
            time: None,
        }.encode_to_vec());
        let contents = serde_json::to_vec(&nonces).unwrap();

        fs::write(fullpath(home, NONCE_DKG_FILE_NAME), contents).unwrap();
    }
}

impl MockQuery {

    async fn loading_oracle(&self, status: i32) -> Result<tonic::Response<QueryOraclesResponse>, tonic::Status> {
        
        let bytes = fs::read(self.fullpath(ORACLE_DKG_FILE_NAME)).unwrap();
        let o = DlcOracle::decode(bytes.as_slice()).unwrap();
        let mut oracles = vec![];
        if o.status == status {
            oracles.push(o);
        }
        let res = QueryOraclesResponse { oracles, pagination: None };
        Ok(tonic::Response::new(res))
    }

    async fn loading_agency(&self, status: i32) -> Result<tonic::Response<QueryAgenciesResponse>, tonic::Status> {
        
        let bytes = fs::read(self.fullpath(AGENCY_DKG_FILE_NAME)).unwrap();
        let o = Agency::decode(bytes.as_slice()).unwrap();
        let mut agencies = vec![];
        if o.status == status {
            agencies.push(o);
        }
        let res = QueryAgenciesResponse { agencies, pagination: None };
        Ok(tonic::Response::new(res))
    }

    async fn count_nonces(&self) -> Result<tonic::Response<QueryCountNoncesResponse>, tonic::Status> {
        let mut counts = vec![];
        let bytes = fs::read(self.fullpath(ORACLE_DKG_FILE_NAME)).unwrap();
        let o = DlcOracle::decode(bytes.as_slice()).unwrap();
        if o.pubkey.len() > 0 {
            if let Ok(raw) = fs::read(self.fullpath(NONCE_DKG_FILE_NAME)) {
                let nonces: Vec<Vec<u8>> = serde_json::from_slice(&raw).unwrap();
                counts.push(nonces.len() as u32);
            } else {
                counts.push(0);
            };
        }

        let res = QueryCountNoncesResponse { counts };
        Ok(tonic::Response::new(res))
    }

    async fn load_param(&self) -> Result<tonic::Response<QueryParamsResponse>, tonic::Status> {

        let res = QueryParamsResponse { params: Some(Params {
            nonce_queue_size: 3,
            price_intervals: vec![PriceInterval { price_pair: "BTC/USDT".to_string(), interval: 100 }],
        }) };
        Ok(tonic::Response::new(res))
    }

    async fn load_atestations(&self) -> Result<tonic::Response<QueryAttestationsResponse>, tonic::Status> {

        let res = QueryAttestationsResponse { attestations: vec![], pagination: None };
        Ok(tonic::Response::new(res))
    }

}
impl OracleQuery for MockQuery {
    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn params<'life0,'async_trait>(&'life0 self,_request:tonic::Request<side_proto::side::dlc::QueryParamsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryParamsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let x = self.load_param();
        Box::pin(x)
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn event<'life0,'async_trait>(&'life0 self,_request:tonic::Request<side_proto::side::dlc::QueryEventRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryEventResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn events<'life0,'async_trait>(&'life0 self,_request:tonic::Request<side_proto::side::dlc::QueryEventsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryEventsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn attestation<'life0,'async_trait>(&'life0 self,_request:tonic::Request<side_proto::side::dlc::QueryAttestationRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryAttestationResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn attestations<'life0,'async_trait>(&'life0 self,_request:tonic::Request<side_proto::side::dlc::QueryAttestationsRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryAttestationsResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let x = self.load_atestations();
        Box::pin(x)
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn price<'life0,'async_trait>(&'life0 self,_request:tonic::Request<side_proto::side::dlc::QueryPriceRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryPriceResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn nonce<'life0,'async_trait>(&'life0 self,_request:tonic::Request<side_proto::side::dlc::QueryNonceRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryNonceResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn nonces<'life0,'async_trait>(&'life0 self,_request:tonic::Request<side_proto::side::dlc::QueryNoncesRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryNoncesResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        todo!()
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn count_nonces<'life0,'async_trait>(&'life0 self,_request:tonic::Request<side_proto::side::dlc::QueryCountNoncesRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryCountNoncesResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {

        let x = self.count_nonces();
        Box::pin(x)
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn oracles<'life0,'async_trait>(&'life0 self,request:tonic::Request<side_proto::side::dlc::QueryOraclesRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryOraclesResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let status = request.get_ref().status;
        let x = self.loading_oracle(status);
        Box::pin(x)
    }

    #[must_use]
#[allow(elided_named_lifetimes,clippy::type_complexity,clippy::type_repetition_in_bounds)]
fn agencies<'life0,'async_trait>(&'life0 self,request:tonic::Request<side_proto::side::dlc::QueryAgenciesRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryAgenciesResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let status = request.get_ref().status;
        let x = self.loading_agency(status);
        Box::pin(x)
    }
}