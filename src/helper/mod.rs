pub mod cipher;
pub mod encoding;
pub mod gossip;
pub mod mem_store;
pub mod bitcoin;
pub mod merkle_proof;
pub mod http;
pub mod client_bitcoin;
pub mod client_side;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
