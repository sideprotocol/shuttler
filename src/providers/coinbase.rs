use std::collections::BTreeMap;

use chrono::DateTime;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;
use tracing::error;

use super::{Price, Provider};

pub const COINBASE: &'static str = "coinbase";

pub static COINBASE_PROVIDER: Lazy<Provider> = Lazy::new(|| {
    Provider {
        ws_url: "wss://ws-feed.exchange.coinbase.com".to_string(),
        sub_event: r#"{"type":"subscribe","product_ids":["BTC-USD"],"channels":[{"name":"ticker","product_ids":["BTC-USD"]}]}"#.to_string(),
        handle: |msg, store| {
            if let Message::Text(text) = msg {
                match serde_json::from_slice::<PriceTicker>(text.as_bytes()) {
                    Ok(p) => {
                        let symbol = symbol_standard(&p.product_id);
                        let mut prices = store.get(&symbol).unwrap_or_default();
                        let rfc3339 = DateTime::parse_from_rfc3339(&p.time)?;
                        prices.insert(COINBASE.to_string(), Price { symbol: symbol.to_string(), price: p.price, time: rfc3339.timestamp_millis() as u64 });
                        store.save(&symbol, &prices);
                    },
                    Err(e) => error!("Unmarshall error: {}", e),
                };
            }
            Ok(())
        },
    }
});

pub static STANDARDS : Lazy<BTreeMap<String, String>> = Lazy::new(|| {
    let mut map = BTreeMap::new();
    map.insert("BTC-USD".to_owned(), "BTCUSD".to_owned());
    map
});

fn symbol_standard(symbol: &String) -> String {
    STANDARDS.get(symbol).unwrap_or(symbol).to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
// #[serde(deny_unknown_fields)]
struct PriceTicker {
    #[serde(rename = "type")]
    types: String,
    // event time
    sequence: u64,
    // symbol
    product_id: String,
    // close price
    price: String,
    // open price
    open_24h: String,
    // high price in 24h
    volume_24h: String,
    // low price in 24h
    low_24h: String,
    // volumn
    high_24h: String,
    time: String,
}