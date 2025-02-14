use std::collections::BTreeMap;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;
use tracing::error;

use super::{Price, Provider};

pub const MEXC: &'static str = "mexc";

pub static MEXC_PROVIDER: Lazy<Provider> = Lazy::new(|| {
    Provider {
        ws_url: "wss://wbs.mexc.com/ws".to_string(),
        sub_event: r#"{ "method":"SUBSCRIPTION", "params":["spot@public.miniTicker.v3.api@BTCUSDT"] }"#.to_string(),
        handle: |msg, db| {
            if let Message::Text(text) = msg {
                match serde_json::from_slice::<MexcPriceTicker>(text.as_bytes()) {
                    Ok(p) => {
                        let symbol = symbol_standard(&p.d.s);
                        let mut prices = db.get(&symbol).unwrap_or_default();
                        prices.insert(MEXC.to_string(), Price { symbol: symbol.clone(), price: p.d.p, time: p.t });
                        db.save(&symbol, &prices);
                    },
                    Err(e) => error!("Unmarshall error: {}", e),
                };
            }
            Ok(())
        },
    }
});

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone)]
struct MexcPriceTicker {
    // data
    d: Ticker, 
    // symbol
    s: String,
    // close price
    c: String,
    t: u64,
}

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Ticker {
    s: String,
    p: String,
    r: String,
    tr: String,
    h: String,
    l: String,
    v: String,
    q: String,
    lastRT: String,
    MT: String,
    NV: String,
    t: u64
}


pub static STANDARDS : Lazy<BTreeMap<String, String>> = Lazy::new(|| {
    let mut map = BTreeMap::new();
    map.insert("BTCUSDT".to_owned(), "BTCUSD".to_owned());
    map
});

fn symbol_standard(symbol: &String) -> String {
    STANDARDS.get(symbol).unwrap_or(symbol).to_string()
}