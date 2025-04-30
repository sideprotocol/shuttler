
pub const BLOCK_HEIGHT: &[u8] = b"block_height";
pub const TASK_INTERVAL: u64 = 300u64;
pub const HEART_BEAT_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(60);

pub const BLOCK_TOLERENCE: u64 = 5;

pub const APP_NAME_BRIDGE: &str = "bridge_app";
pub const APP_NAME_LENDING: &str = "lending_app";