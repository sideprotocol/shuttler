use std::{collections::BTreeMap, sync::Arc};

use axum::{Router, routing::get, extract::State};
use tracing::info;

use crate::{helper::store::Store, providers::{Price, PriceStore}};


#[derive(Clone)]
pub struct AppState {
    price_store: Arc<PriceStore>,
}

impl AppState {
    pub fn new(price_store: Arc<PriceStore>) -> Self {
        Self { price_store }
    }
    pub fn list_prices(&self) -> Vec<BTreeMap<String, Price>> {
        self.price_store.as_ref().list()
    } 
}

pub async fn home() -> &'static str  {
    "Welcome to Shuttler"
}

pub async fn health() -> &'static str {
    "hello health"
}
pub async fn metrics(State(state): State<AppState>) -> &'static str {
    "hello metrics"
}

pub async fn prices(State(s): State<AppState>) -> String {
    let x: Vec<BTreeMap<String, Price>> = s.list_prices();
    match serde_json::to_string(&x) {
        Ok(t) => t,
        Err(e) => "error".to_string(),
    }
}

pub async fn addresses(State(state): State<AppState>) -> &'static str {

    // ...
    "hello metrics"
}

pub async fn run_rpc_server(price_store: Arc<PriceStore>) -> Result<(), std::io::Error> {
    // let rpc_server = new_web_app().with_state::<AppState>(state);
    let state = AppState::new(price_store);
    let app = Router::new()
        .route("/", get(home))
        .route("/address", get(addresses))
        .route("/prices", get(prices))
        .route("/metrics", get(metrics))
        .route("/health", get(health))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8181").await.expect("RPC Port is unavailable.");
    info!("Starting RPC Server...");
    axum::serve(listener, app).await
}