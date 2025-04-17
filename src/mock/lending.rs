use std::{collections::BTreeMap, fs};

use cosmrs::Any;
use side_proto::{prost::Message, 
    side::{
        dlc::{DlcOracle, DlcOracleStatus}, 
        tss::{MsgCompleteDkg, MsgSubmitSignatures}},
    };

use crate::apps::SideEvent;

use super::{fullpath, EventQueue, MockEnv};

const ORACLE_DKG_FILE_NAME: &str = "oracle.data";
// const EVENT_FILE_NAME: &str = "event.prost";

pub fn lending_task_queue() -> EventQueue {
    // height, event
    let mut queue: EventQueue = EventQueue::new();
    queue.insert(3, create_oracle_event);
    queue.insert(5, create_signing_event);
    queue
}

pub fn handle_lending_dkg_submission(home: &str, m: &Any) {
    if let Ok(msg) = m.to_msg::<MsgCompleteDkg>() {
        let key = fullpath(home, &msg.pub_keys[0]);
        println!("Received: {:?} from {}", key, msg.sender);
        
        if fs::exists(&key).unwrap_or(false) {
            return
        }
        fs::create_dir_all(fullpath(home, key)).unwrap();

        // let bytes = fs::read(fullpath(home, ORACLE_DKG_FILE_NAME)).unwrap();
        // let mut o = DlcOracle::decode(bytes.as_slice()).unwrap();
        let mut o = DlcOracle::default();
        o.id = 1;
        o.pubkey = msg.pub_keys[0].clone();
        o.status = DlcOracleStatus::OracleStatusEnable as i32;

        fs::write(fullpath(home, ORACLE_DKG_FILE_NAME ), o.encode_to_vec()).unwrap();
    }
}

pub fn handle_signature_submission(_home: &str, m: &Any) {
    if let Ok(msg) = m.to_msg::<MsgSubmitSignatures>() {
        println!("Received: {:?}", msg);
    }
}

pub fn create_oracle_event(env: MockEnv) -> SideEvent {
    let mut creation = BTreeMap::new();
    creation.insert("initiate_dkg.id".to_owned(), vec!["1".to_owned()]);
    creation.insert("initiate_dkg.participants".to_owned(), vec![env.participants.join(",")]);
    creation.insert("initiate_dkg.threshold".to_owned(), vec![(env.participants.len() * 2 / 3).to_string()]);
    creation.insert("initiate_dkg.batch_size".to_owned(), vec!["2".to_owned()]);

    SideEvent::BlockEvent(creation)
}

pub fn create_signing_event(env: MockEnv) -> SideEvent {
    let mut creation = BTreeMap::new();
    creation.insert("initiate_signing.id".to_owned(), vec!["1".to_owned()]);
    creation.insert("initiate_signing.participants".to_owned(), vec![env.participants.join(",")]);
    creation.insert("initiate_signing.threshold".to_owned(), vec![(env.participants.len() * 2 / 3).to_string()]);
    creation.insert("initiate_signing.type".to_owned(), vec!["0".to_owned()]);
    creation.insert("initiate_signing.option".to_owned(), vec!["".to_owned()]);

    SideEvent::BlockEvent(creation)
}