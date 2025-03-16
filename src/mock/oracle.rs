use std::{collections::BTreeMap, fs};

use cosmrs::Any;
use side_proto::{prost::Message, 
    side::dlc::{DlcNonce, DlcOracle, 
        DlcOracleStatus, DlcPriceEvent, MsgSubmitNonce, MsgSubmitOraclePubKey},
    };

use crate::apps::SideEvent;

use super::{fullpath, EventQueue, MockEnv};

const ORACLE_DKG_FILE_NAME: &str = "oracle.data";
// const AGENCY_DKG_FILE_NAME: &str = "agency.data";
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
