use bitcoincore_rpc::jsonrpc::base64;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Mutex};

const CONFIG_FILE: &str = "config.toml";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub command_server: String,
    pub log_level: String,
    pub p2p: P2P,
    pub keys: BTreeMap<String, String>,
    pub pubkeys: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct P2P {
    pub local_key: String,
    pub public_key: String,
}

lazy_static! {
    static ref STATIC_STRING: Mutex<String> = Mutex::new(String::from(".tssigner"));
}

pub fn update_app_home(app_home: &str) {
    let mut string: std::sync::MutexGuard<String> = STATIC_STRING.lock().unwrap();
    *string = String::from(app_home);
}

impl Config {
    pub fn from_file(app_home: &str) -> Result<Self, std::io::Error> {
        update_app_home(app_home);

        if !home_dir(app_home).join(CONFIG_FILE).exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Config file not found",
            ));
        }
        let contents = fs::read_to_string(home_dir(app_home).join(CONFIG_FILE))?;
        let config: Config = toml::from_str(&contents).expect("Failed to parse config file");
        Ok(config)
    }

    pub fn default(port: u16) -> Self {
        let privkey = x25519_dalek::StaticSecret::random_from_rng(&mut rand::thread_rng());
        let encoded = base64::encode(privkey.to_bytes());
        let pubkey = hex::encode(x25519_dalek::PublicKey::from(&privkey).to_bytes());

        Self {
            command_server: format!("localhost:{}", port),
            log_level: "debug".to_string(),
            keys: BTreeMap::new(),
            pubkeys: BTreeMap::new(),
            p2p: P2P {
                local_key: encoded,
                public_key: pubkey,
            },
        }
    }

    pub fn to_string(&self) -> String {
        toml::to_string(self).unwrap()
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        let app_home = STATIC_STRING.lock().unwrap();
        let path = home_dir(app_home.as_str());
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        let contents = self.to_string();
        fs::write(path.join(CONFIG_FILE), contents)
    }
}

pub fn home_dir(app_home: &str) -> PathBuf {
    dirs::home_dir().map(|path| path.join(app_home)).unwrap()
}
