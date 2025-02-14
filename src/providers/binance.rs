use std::collections::BTreeMap;

use anyhow::anyhow;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;

use super::{Price, Provider};

pub const BINANCE: &'static str = "binance";

pub static BINANCE_PROVIDER: Lazy<Provider> = Lazy::new(|| {
    Provider {
        ws_url: "wss://stream.binance.com/ws".to_string(),
        sub_event: r#"{"method": "SUBSCRIBE","params":["btcusdt@miniTicker"],"id": 1}"#.to_string(),
        handle: |msg, store| {
            if let Message::Text(text) = msg {
                match serde_json::from_slice::<BinancePriceTicker>(text.as_bytes()) {
                    Ok(p) => {
                        let symbol = symbol_standard(&p.s);
                        let mut prices = store.get(&symbol).unwrap_or_default();
                        prices.insert(BINANCE.to_string(), Price { symbol: symbol.clone(), price: p.c, time: p.E });
                        store.save(&symbol, &prices);
                    },
                    Err(e) => return Err(anyhow!("{}", e)),
                };
            }
            Ok(())
        },
    }
});

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone)]
struct BinancePriceTicker {
    // event
    e: String,
    // event time
    E: u64,
    // symbol
    s: String,
    // close price
    c: String,
    // open price
    o: String,
    // high price in 24h
    h: String,
    // low price in 24h
    l: String,
    // volumn
    v: String,
    q: String,
}

pub static STANDARDS : Lazy<BTreeMap<String, String>> = Lazy::new(|| {
    let mut map = BTreeMap::new();
    map.insert("BTCUSDT".to_owned(), "BTCUSD".to_owned());
    map
});

fn symbol_standard(symbol: &String) -> String {
    STANDARDS.get(symbol).unwrap_or(symbol).to_string()
}