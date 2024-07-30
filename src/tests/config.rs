use std::fs;

use crate::app::config::{compute_relayer_address, PrivValidatorKey};

#[test]
fn test_priv_key_loading () {
    let text = fs::read_to_string("/Users/developer/.side/config/priv_validator_key.json").expect("loaded failed");
    let key = serde_json::from_str::<PrivValidatorKey>(text.as_str()).expect("failed to parse json");

    assert_ne!(key.priv_key.r#type.len(), 0);
    println!("{:?}", key);
    println!("{:?}", key.priv_key.value);

    let addr = compute_relayer_address(key.priv_key.value.as_str(), bitcoin::Network::Bitcoin);
    println!("{:?}", addr);
    
}