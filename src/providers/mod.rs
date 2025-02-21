use std::{collections::BTreeMap, ops::Deref};

use binance::BINANCE_PROVIDER;
use coinbase::COINBASE_PROVIDER;
use mexc::MEXC_PROVIDER;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::helper::store::{DefaultStore, Store};
use std::time::Duration;

use tokio::{net::TcpStream, time::sleep};
use tokio_tungstenite::{connect_async, tungstenite::{client::IntoClientRequest, protocol::Message}, MaybeTlsStream, WebSocketStream};
use futures::{stream::StreamExt, SinkExt};
use tracing::{debug, error};

pub mod binance;
pub mod mexc;
pub mod coinbase;

pub type Symbol = String;
pub type Exchange = String;


pub static PRICE_PROVIDERS: Lazy<Vec<Provider>> = Lazy::new(|| {vec![BINANCE_PROVIDER.deref().clone(), COINBASE_PROVIDER.deref().clone(), MEXC_PROVIDER.deref().clone()]});

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct Price {
    pub symbol: String,
    pub price: String,
    pub time: u64,
}
pub type PriceStore = DefaultStore<Symbol, BTreeMap<Exchange, Price>>;


#[derive(Clone, Debug)]
pub struct Provider {
    ws_url: String,
    sub_event: String,
    handle: fn(Message, &dyn Store<String, BTreeMap<String, Price>>) -> anyhow::Result<()>,
}

pub struct PriceSubscriber {
    provider: Provider,
}

impl PriceSubscriber {
    pub fn new(provider: Provider) -> Self {
        Self { provider }
    }
}

impl PriceSubscriber {
    async fn connect(&self) -> anyhow::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let (mut ws_stream, _) = connect_async(self.provider.ws_url.clone().into_client_request()?).await?;
        ws_stream.send(Message::Text(self.provider.sub_event.clone().into())).await?;
        Ok(ws_stream)
    }

    async fn handle_stream(&self, mut ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>, store: &PriceStore) {
        loop {
            match ws_stream.next().await {
                Some(Ok(msg)) => {
                    if let Err(e) = (self.provider.handle)(msg, store) {
                        error!("parse error: {}", e)
                    }
                }
                Some(Err(e)) => {
                    error!("Error receiving message: {}", e);
                    break;
                }
                None => {
                    error!("Connection closed by server");
                    break;
                }
            }
        }
    }

    pub async fn start(&self, store: &PriceStore) {
        loop {
            debug!("Connecting to WebSocket server... {}", self.provider.ws_url);
            match self.connect().await {
                Ok(ws_stream) => {
                    debug!("{} connected!", self.provider.ws_url);
                    self.handle_stream(ws_stream, store).await;
                }
                Err(e) => {
                    error!("Failed to connect: {}", e);
                }
            }
    
            // 等待一段时间后重连
            sleep(Duration::from_secs(5)).await;
        }
    }

}
