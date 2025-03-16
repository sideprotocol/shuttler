
use axum::{Router, routing::get, extract::State};
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    // price_store: Arc<PriceStore>,
}

impl AppState {
    pub fn new() -> Self {
        Self { }
    }
}

pub async fn home() -> &'static str  {
    "Welcome to Shuttler"
}

pub async fn health() -> &'static str {
    "hello health"
}
pub async fn metrics(State(_state): State<AppState>) -> &'static str {
    "hello metrics"
}

pub async fn addresses(State(_state): State<AppState>) -> &'static str {

    // ...
    "hello metrics"
}

pub async fn run_rpc_server(rpc: String) -> Result<(), std::io::Error> {
    // let rpc_server = new_web_app().with_state::<AppState>(state);
    let state = AppState::new();
    let app = Router::new()
        .route("/", get(home))
        .route("/address", get(addresses))
        .route("/metrics", get(metrics))
        .route("/health", get(health))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(rpc).await.expect("RPC Port is unavailable.");
    info!("Starting RPC Server...");
    axum::serve(listener, app).await
}