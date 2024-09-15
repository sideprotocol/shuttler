use std::str::FromStr;

use bitcoin::Txid;
use tracing::Level;
use tracing_subscriber;

use crate::{app::{config::Config, relayer::Relayer}, tickers::relayer};

pub async fn execute(home: &str, hash: &String) {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let txid = Txid::from_str(hash).expect("invalid tx hash");

    let conf = Config::from_file(home).unwrap();
    let relayer = Relayer::new(conf);

    relayer::check_and_handle_tx_by_hash(&relayer, &txid).await
}
