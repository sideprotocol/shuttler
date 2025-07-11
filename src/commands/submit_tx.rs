use std::str::FromStr;

use bitcoin::Txid;
use tracing::Level;
use tracing_subscriber;

use crate::{
    apps::relayer::{bridge, lending, Relayer},
    config::Config,
};

pub async fn execute(home: &str, hash: &String) {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let txid = Txid::from_str(hash).expect("invalid tx hash");

    let conf = Config::from_file(home).unwrap();
    let relayer = Relayer::new(conf);

    bridge::check_and_handle_bitcoin_tx_by_hash(&relayer, &txid).await;
    lending::check_and_handle_bitcoin_tx_by_hash(&relayer, &txid).await;
}
