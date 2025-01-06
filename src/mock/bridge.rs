use std::{fs, path::{Path, PathBuf}};

use cosmrs::Any;
use serde::{Deserialize, Serialize};
use side_proto::{side::btcbridge::{DkgParticipant, DkgRequest, DkgRequestStatus, MsgCompleteDkg, QueryDkgRequestsResponse, QuerySigningRequestsResponse, SigningRequest}, Timestamp};

use crate::{helper::now, mock::{fullpath, generate_mock_psbt}};

use super::{BRIDGE_DKG_FILE_NAME, SINGING_FILE_NAME, VAULT_FILE_NAME};

#[derive(Serialize, Deserialize)]
pub struct KeygenParameter {
    pub id: u64,
    pub participants: Vec<String>,
    pub threshold: u32,
}

#[derive(Serialize, Deserialize)]
pub struct BridgeSigningRequest { 
    pub address: String, 
    pub sequence: u64, 
    pub txid: String, 
    pub psbt: String, 
    pub status: i32, 
}

pub fn generate_bridge_file(testdir: &Path, participants: Vec<String>) {
    let dkg = KeygenParameter{
        id: 1,
        threshold: (participants.len() * 2/3 ) as u32,
        participants,
    };
    let contents = serde_json::to_string(&dkg).unwrap();
    let mut path = PathBuf::new();
    path.push(testdir);
    path.push("mock");
    let _ = fs::create_dir_all(&path);
    path.push(BRIDGE_DKG_FILE_NAME);
    fs::write(path, contents).unwrap();
}

// 1. signing requests
pub async fn load_signing_requests(home: &str) -> Result<tonic::Response<QuerySigningRequestsResponse>, tonic::Status> {
    let mut path = PathBuf::new();
    path.push(home);
    path.push("mock");
    path.push(SINGING_FILE_NAME);

    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => "[]".to_string(),
    };
    let mut srs: Vec<BridgeSigningRequest> = serde_json::from_str(&text).unwrap();

    let mut path_2 = PathBuf::new();
    path_2.push(home);
    path_2.push(VAULT_FILE_NAME);
    if let Ok(address) = fs::read_to_string(path_2) {
        srs.push(BridgeSigningRequest {
            address,
            sequence: 3,
            status: 1,
            txid: "".to_string(),
            psbt: "".to_string(),
        });
    }

    let requests: Vec<SigningRequest> = srs.iter().map(|i| {
        SigningRequest { 
            address: i.address.clone(), 
            sequence: i.sequence, 
            txid: i.txid.clone(), 
            psbt: i.psbt.clone(), 
            status: i.status,
            creation_time: Some(Timestamp {
                seconds: now() as i64,
                nanos: 0,
            }) 
        }
    }).collect::<Vec<_>>();
    let res: QuerySigningRequestsResponse = QuerySigningRequestsResponse { requests, pagination: None };
    Ok(tonic::Response::new(res))
}

// mock dkg request
pub async fn loading_dkg_request(home: &str) -> Result<tonic::Response<QueryDkgRequestsResponse>, tonic::Status> {
    let mut path = PathBuf::new();
    path.push(home);
    path.push("mock");
    path.push(BRIDGE_DKG_FILE_NAME);

    let text = fs::read_to_string(path).unwrap();
    let mut requests = vec![];
    if text.len() > 5 {
        let timeout = Timestamp {
            seconds: now() as i64 + 180,
            nanos: 0,
        };
        let dkg: KeygenParameter = serde_json::from_str(&text).unwrap();
        let participants = dkg.participants.iter().map(|i: &String| DkgParticipant {
            moniker: i.clone(),
            operator_address: i.clone(),
            consensus_pubkey: i.to_string(),
        }).collect::<Vec<_>>();

        requests.push( DkgRequest { 
            id: dkg.id, 
            participants,
            threshold: dkg.threshold,
            vault_types: vec![0], 
            enable_transfer: true, 
            target_utxo_num: 100,
            expiration: Some(timeout), 
            status: DkgRequestStatus::Pending as i32 
        })
    }

    let res = QueryDkgRequestsResponse { requests };
    Ok(tonic::Response::new(res))
}

pub fn handle_bridge_dkg_submission(home: &str, tx_num: u32, m : &Any) {
    if let Ok(msg) = m.to_msg::<MsgCompleteDkg>() {
        let key = fullpath(home, msg.vaults.join("").as_str());
        println!("Received: {:?} from {}", key, msg.sender);
        
        if fs::exists(&key).unwrap_or(false) {
            return
        }
        fs::create_dir_all(fullpath(home, key)).unwrap();

        let num = rand::random::<u32>() % 5 + 1;
        // num = 1;
        let mut srs = vec![];
        msg.vaults.iter().for_each(|addr| {
            
            // check duplication
            let mut path = PathBuf::new();
            path.push(home);
            path.push("mock");
            path.push("addresses");
            path.push(addr);
            
            if path.is_dir() {
                return
            }
            let _ = fs::create_dir_all(path.as_path());

            // clear dkg request.
            let mut path_dkg = PathBuf::new();
            path_dkg.push(home);
            path_dkg.push("mock");
            path_dkg.push(BRIDGE_DKG_FILE_NAME);
            let _ = fs::write(path_dkg, "");

            // generate psbt
            for _i in 0..tx_num {
                let (txid, psbt) = generate_mock_psbt(addr, Some(num));
                srs.push(BridgeSigningRequest {
                    address: addr.clone(),
                    sequence: num as u64,
                    txid,
                    psbt,
                    status: 1,
                })
            }
        });

        if srs.len() == 0 {
            return
        }
        if let Ok(contents) = serde_json::to_string_pretty(&srs) {

            let mut path = PathBuf::new();
            path.push(home);
            path.push("mock");
            path.push(SINGING_FILE_NAME);

            println!("txs: {}", contents);
            let _ = fs::write(path, &contents);
        }
    }
}