
use std::sync::Arc;

use axum::{Router, routing::get, extract::State};
use tracing::info;

use crate::{apps::Task, helper::store::{DefaultStore, Store}};

#[derive(Clone)]
pub struct AppState {
    task_store: Arc<DefaultStore<String, Task>>,
}

impl AppState {
    pub fn new(task_store: Arc<DefaultStore<String, Task>>) -> Self {
        Self { task_store }
    }
}

pub async fn home() -> &'static str  {
    "Welcome to Shuttler"
}

pub async fn health() -> &'static str {
    "hello health"
}
pub async fn metrics(State(state): State<AppState>) -> String {
    let list= state.task_store.list();
    
    format!("hello metrics: {}", list.len())
}

pub async fn addresses(_state: Arc<AppState>) -> &'static str {
    // ...
    "hello metrics"
}

pub async fn run_rpc_server(rpc: String, task_store: Arc<DefaultStore<String, Task>>) -> std::result::Result<(), std::io::Error>{

    let state2 = AppState::new(task_store);
    // let shared_state = Arc::new(Context{});

    let app = Router::new()
        // .route("/address", get(addresses))
        .route("/metrics", get(metrics))
        // .route("path", get( async { let x= db.get(&"ss".to_string()); return "hello metrics"}))
        .route("/health", get(health))
        // .layer(Extension(state2))
        .with_state(state2)
        .route("/", get(home));
    let listener = tokio::net::TcpListener::bind(rpc).await.expect("RPC Port is unavailable.");
    info!("Starting RPC Server...");
    axum::serve(listener, app).await

}