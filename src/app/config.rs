use bitcoin::Network;
use bitcoincore_rpc::jsonrpc::base64;
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Mutex};
use tracing::{debug, error};

use crate::helper::encoding::from_base64;

const CONFIG_FILE: &str = "config.toml";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub network: Network,
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
    static ref APPLICATION_PATH: Mutex<String> = Mutex::new(String::from(".tssigner"));
    static ref KEYS : Mutex<BTreeMap<String, KeyPackage>> = Mutex::new(BTreeMap::new());
    static ref PUBKEYS : Mutex<BTreeMap<String, PublicKeyPackage>> = Mutex::new(BTreeMap::new());
}

pub fn update_app_home(app_home: &str) {
    let mut string: std::sync::MutexGuard<String> = APPLICATION_PATH.lock().unwrap();
    *string = String::from(app_home);
}

pub fn get_sign_key(address: &str) -> Option<KeyPackage> {
    KEYS.lock().unwrap().get(address).cloned()
}
pub fn add_sign_key(address: &str, key: KeyPackage) {
    KEYS.lock().unwrap().insert(address.to_string(), key);
}

pub fn get_pub_key(address: &str) -> Option<PublicKeyPackage> {
    PUBKEYS.lock().unwrap().get(address).cloned()
}

pub fn add_pub_key(address: &str, key: PublicKeyPackage) {
    PUBKEYS.lock().unwrap().insert(address.to_string(), key);
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

        config.keys.iter().for_each(|(k, v)| {
            let b = from_base64(v).unwrap();
            let kp = match KeyPackage::deserialize(&b) {
                Ok(kp) => kp,
                Err(e) => {
                    error!("failed to load key package: {:?} {:?}", k, e);
                    return;
                }            
            };
            debug!("Loaded key package for {}, {:?}", k, kp);
            KEYS.lock().unwrap().insert(k.clone(), kp);
        });

        config.pubkeys.iter().for_each(|(k, v)| {
            let b = from_base64(v).unwrap();
            let pkp = match PublicKeyPackage::deserialize(&b) {
                Ok(pkp) => pkp,
                Err(e) => {
                    error!("failed to load pubkey package: {:?} {:?}", k, e);
                    return;
                }            
            };
            debug!("Loaded public key package for {}, {:?}", k, pkp);
            PUBKEYS.lock().unwrap().insert(k.clone(), pkp);
        });

        Ok(config)
    }

    pub fn default(port: u16, network: Network) -> Self {
        let privkey = x25519_dalek::StaticSecret::random_from_rng(&mut rand::thread_rng());
        let encoded = base64::encode(privkey.to_bytes());
        let pubkey = hex::encode(x25519_dalek::PublicKey::from(&privkey).to_bytes());

        Self {
            network,
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
        let app_home = APPLICATION_PATH.lock().unwrap();
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
