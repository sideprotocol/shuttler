use std::{collections::BTreeMap, fs, path::{Path, PathBuf}};

use cosmrs::Any;
use serde::{Deserialize, Serialize};
use side_proto::{side::btcbridge::{DkgParticipant, DkgRequest, DkgRequestStatus, MsgCompleteDkg, QueryDkgRequestsResponse, QuerySigningRequestsResponse, SigningRequest}, Timestamp};
use tendermint::abci::{Event, EventAttribute};

use crate::{apps::SideEvent, helper::now, mock::{fullpath, generate_mock_psbt}};

use super::{EventQueue, MockEnv, BRIDGE_DKG_FILE_NAME, SINGING_FILE_NAME, VAULT_FILE_NAME};

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
pub fn bridge_task_queue() -> EventQueue {
    // height, event
    let mut queue: EventQueue = EventQueue::new();
    queue.insert(3, create_vault_event);
    queue.insert(5, create_transaction_event);
    // queue.insert(7, create_transaction_event);
    // queue.insert(8, exit_queue);
    queue
}

pub fn create_vault_event(env: MockEnv) -> SideEvent {
    let mut creation = BTreeMap::new();
    creation.insert("create_bridge_vault.id".to_owned(), vec!["1".to_owned()]);
    creation.insert("create_bridge_vault.participants".to_owned(), vec![env.participants.join(",")]);
    creation.insert("create_bridge_vault.tweaks".to_owned(), vec!["1".to_owned()]);
    creation.insert("create_bridge_vault.threshold".to_owned(), vec![(env.participants.len() * 2 / 3).to_string()]);
    SideEvent::BlockEvent(creation)
}

pub fn create_transaction_event(env: MockEnv) -> SideEvent {

    let mut events = vec![];
    if let Ok(txs) = fs::read_to_string(fullpath(&env.home, SINGING_FILE_NAME)) {
        // generate psbt
        txs.split(",").for_each(|t| {
            let tt = t.split("##").collect::<Vec<_>>();
            if tt.len() == 2 {
                events.push( Event::new("bridge_transaction".to_owned(), vec![
                    EventAttribute::from(("txid", tt[0], false)),
                    EventAttribute::from(("psbt", tt[1], false)),
                ]));
            }
        });
    }
    
    SideEvent::TxEvent(events)
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

        println!("received vault: {:?}", msg.vaults);
        // let num = rand::random::<u32>() % 5 + 1;
        let path_addr = fullpath(home, VAULT_FILE_NAME);
        if let Ok(addresses) = fs::read_to_string(&path_addr) {
            if msg.vaults.iter().any(|v| addresses.contains(v)) {
                return
            }
        }
        if fs::write(path_addr, msg.vaults.join(",").as_bytes()).is_ok() {
            println!("saved vault: {:?}", msg.vaults)
        }

        let mut content = vec![];
        for addr in msg.vaults {
            let (txid, psbt) = generate_mock_psbt(&addr, Some(tx_num));
            content.push(format!("{}##{}", txid, psbt));
        }
        if fs::write(fullpath(home, SINGING_FILE_NAME), content.join(",").as_bytes()).is_ok() {
            println!("generated txs for signing");
        }
        // if let Ok(addresses) = fs::read_to_string(path_2) {

        // num = 1;
        // let mut srs = vec![];
        // msg.vaults.iter().for_each(|addr| {
            
        //     // check duplication
        //     let mut path = PathBuf::new();
        //     path.push(home);
        //     path.push("mock");
        //     path.push("addresses");
        //     path.push(addr);
            
        //     if path.is_dir() {
        //         return
        //     }
        //     let _ = fs::create_dir_all(path.as_path());

        //     // clear dkg request.
        //     let mut path_dkg = PathBuf::new();
        //     path_dkg.push(home);
        //     path_dkg.push("mock");
        //     path_dkg.push(BRIDGE_DKG_FILE_NAME);
        //     let _ = fs::write(path_dkg, "");

        //     // generate psbt
        //     for _i in 0..tx_num {
        //         let (txid, psbt) = generate_mock_psbt(addr, Some(num));
        //         srs.push(BridgeSigningRequest {
        //             address: addr.clone(),
        //             sequence: num as u64,
        //             txid,
        //             psbt,
        //             status: 1,
        //         })
        //     }
        // });

        // if srs.len() == 0 {
        //     return
        // }
        // if let Ok(contents) = serde_json::to_string_pretty(&srs) {

        //     let mut path = PathBuf::new();
        //     path.push(home);
        //     path.push("mock");
        //     path.push(SINGING_FILE_NAME);

        //     println!("txs: {}", contents);
        //     let _ = fs::write(path, &contents);
        // }
    }
}