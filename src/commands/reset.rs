
use crate::{config::Config, helper::store::{DefaultStore, Store}};

pub fn execute(home: &str) {

    let conf = Config::from_file(home).unwrap();

    let mut task_store = DefaultStore::<String, String>::new(conf.get_database_with_name("tasks"));
    task_store.clear();
    let mut nonce_store = DefaultStore::<String, String>::new(conf.get_database_with_name("nonces"));
    nonce_store.clear();
    let mut commitment_store = DefaultStore::<String, String>::new(conf.get_database_with_name("commitments"));
    commitment_store.clear();
    let mut signature_store = DefaultStore::<String, String>::new(conf.get_database_with_name("signature_shares"));
    signature_store.clear();
    println!("Reset all tasks");
}