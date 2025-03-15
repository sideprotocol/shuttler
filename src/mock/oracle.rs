use std::{collections::BTreeMap, fs};

use cosmrs::Any;
use side_proto::{prost::Message, 
    side::dlc::{query_server::Query as OracleQuery, Agency, DlcAttestation, DlcNonce, DlcOracle, 
        DlcOracleStatus, DlcPriceEvent, MsgSubmitNonce, MsgSubmitOraclePubKey, Params, PriceInterval, 
        QueryAgenciesResponse, QueryAttestationsResponse, QueryCountNoncesResponse, QueryEventResponse, 
        QueryOraclesResponse, QueryParamsResponse}, tendermint::google::protobuf::Duration,
    };

use crate::apps::SideEvent;

use super::{fullpath, EventQueue, MockEnv, MockQuery};

const ORACLE_DKG_FILE_NAME: &str = "oracle.data";
const AGENCY_DKG_FILE_NAME: &str = "agency.data";
const NONCE_DKG_FILE_NAME: &str = "nonces.data";
const EVENT_FILE_NAME: &str = "event.prost";

pub fn oracle_task_queue() -> EventQueue {
    // height, event
    let mut queue: EventQueue = EventQueue::new();
    queue.insert(3, create_oracle_event);
    queue.insert(5, create_nonces_event);
    queue.insert(6, create_nonces_event);
    queue.insert(7, create_nonces_event);
    queue
}

pub fn handle_oracle_dkg_submission(home: &str, m: &Any) {
    if let Ok(msg) = m.to_msg::<MsgSubmitOraclePubKey>() {
        let key = fullpath(home, &msg.oracle_pubkey);
        println!("Received: {:?} from {}", msg.oracle_pubkey, msg.sender);
        
        if fs::exists(&key).unwrap_or(false) {
            return
        }
        fs::create_dir_all(fullpath(home, key)).unwrap();

        // let bytes = fs::read(fullpath(home, ORACLE_DKG_FILE_NAME)).unwrap();
        // let mut o = DlcOracle::decode(bytes.as_slice()).unwrap();
        let mut o = DlcOracle::default();
        o.id = 1;
        o.pubkey = msg.oracle_pubkey;
        o.status = DlcOracleStatus::OracleStatusEnable as i32;

        fs::write(fullpath(home, ORACLE_DKG_FILE_NAME ), o.encode_to_vec()).unwrap();
    }
}

pub fn handle_nonce_submission(home: &str, m: &Any) {
    if let Ok(msg) = m.to_msg::<MsgSubmitNonce>() {
        let hex_str = &msg.nonce;
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

        // save nonce
        nonces.push(DlcNonce {
            index: nonces.len() as u64,
            nonce: msg.nonce.clone(),
            oracle_pubkey: o.pubkey.clone(),
            time: None,
        }.encode_to_vec());
        let contents = serde_json::to_vec(&nonces).unwrap();

        fs::write(fullpath(home, NONCE_DKG_FILE_NAME), contents).unwrap();

        // create a mock event
        let event = DlcPriceEvent {
            id: nonces.len() as u64,
            trigger_price: "10000".to_owned(),
            price_decimal: "2".to_owned(),
            nonce: msg.nonce,
            pubkey: o.pubkey.clone(),
            description: "test event".to_owned(),
            has_triggered: true,
            publish_at: None,
        };

        fs::write(fullpath(home, EVENT_FILE_NAME), event.encode_to_vec()).unwrap()

    }
}

pub fn create_oracle_event(env: MockEnv) -> SideEvent {
    let mut creation = BTreeMap::new();
    creation.insert("create_oracle.id".to_owned(), vec!["1".to_owned()]);
    creation.insert("create_oracle.participants".to_owned(), vec![env.participants.join(",")]);
    creation.insert("create_oracle.threshold".to_owned(), vec![(env.participants.len() * 2 / 3).to_string()]);
    SideEvent::BlockEvent(creation)
}

pub fn create_nonces_event(env: MockEnv) -> SideEvent {
    let mut creation = BTreeMap::new();
    if let Ok(bytes) = fs::read(fullpath(&env.home, ORACLE_DKG_FILE_NAME)) {
        if let Ok(o) = DlcOracle::decode(bytes.as_slice()) {
            creation.insert("generate_nonce.id".to_owned(), vec![o.nonce_index.to_string()]);
            creation.insert("generate_nonce.oracle_pub_key".to_owned(), vec![o.pubkey]);
        };
    }
    SideEvent::BlockEvent(creation)
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
            nonce_queue_size: 1,
            price_intervals: vec![PriceInterval { price_pair: "BTC/USDT".to_string(), interval: 100 }],
            dkg_timeout_period: Some(Duration::default()),
        }) };
        Ok(tonic::Response::new(res))
    }

    async fn load_event(&self, _id: u64) -> Result<tonic::Response<QueryEventResponse>, tonic::Status> {
        let bytes = fs::read(self.fullpath(EVENT_FILE_NAME)).unwrap();
        let o = DlcPriceEvent::decode(bytes.as_slice()).unwrap();
        let res = QueryEventResponse { event: Some(o) };
        Ok(tonic::Response::new(res))
    }

    async fn load_atestations(&self) -> Result<tonic::Response<QueryAttestationsResponse>, tonic::Status> {
        let mut attestations = vec![];
        if let Ok(bytes) = fs::read(self.fullpath(EVENT_FILE_NAME)) {
            let o = DlcPriceEvent::decode(bytes.as_slice()).unwrap();
            if o.has_triggered {
                attestations.push(DlcAttestation {
                    event_id: o.id,
                    id: o.id,
                    time: None,
                    pubkey: o.pubkey,
                    outcome: "10000".to_string(),
                    signature: "".to_owned(),
                });
            }
        };
        
        let res = QueryAttestationsResponse { attestations, pagination: None };
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
fn event<'life0,'async_trait>(&'life0 self,request:tonic::Request<side_proto::side::dlc::QueryEventRequest> ,) ->  ::core::pin::Pin<Box<dyn ::core::future::Future<Output = core::result::Result<tonic::Response<side_proto::side::dlc::QueryEventResponse> ,tonic::Status> > + ::core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        let id = request.get_ref().id;
        let x = self.load_event(id);
        Box::pin(x)
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