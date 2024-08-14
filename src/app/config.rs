use bitcoin::{bip32::DerivationPath, key::Secp256k1, Address, CompressedPublicKey, Network, NetworkKind};
use bip39::{self, Mnemonic};
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Mutex};
use tracing::{debug, error};

use crate::helper::{cipher::random_bytes, encoding::from_base64};

const CONFIG_FILE: &str = "config.toml";

/// Threshold Signature Configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    /// Internal command listener
    pub mock_server: String,
    /// logger level
    pub log_level: String,
    pub mnemonic: String,
    pub priv_validator_key_path: String,

    pub bitcoin: BitcoinCfg,
    pub side_chain: CosmosChain,
    pub keys: BTreeMap<String, String>,
    pub pubkeys: BTreeMap<String, String>,
}

/// Bitcoin Configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BitcoinCfg {
    /// Bitcoin network type
    pub network: Network,
    /// Bitcoin RPC endpoint
    pub rpc: String,
    /// RPC User
    pub user: String,
    /// RPC password
    pub password: String,
}

/// Side Chain Configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CosmosChain {
    /// the cosmos rest endpoint, http://localhost:1317
    pub rest_url: String,
    /// the cosmos grpc endpoint, http://localhost:9001
    pub grpc: String,
    /// Transaction gas
    pub gas: usize,
    pub fee: Fee,
    pub address_prefix: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Fee {
    pub amount: usize,
    pub denom: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnyKey {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrivValidatorKey {
    pub address: String,
    pub pub_key: AnyKey,
    pub priv_key: AnyKey,
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

pub fn get_app_home() -> String {
    APPLICATION_PATH.lock().unwrap().clone()
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

pub fn get_pub_key_by_index(index: usize) -> Option<PublicKeyPackage> {
    PUBKEYS.lock().unwrap().values().nth(index).cloned()
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
        let entropy = random_bytes(32);
        let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_slice()).expect("failed to create mnemonic");

        Self {
            mock_server: format!("localhost:{}", port),
            log_level: "debug".to_string(),
            mnemonic: mnemonic.to_string(),
            priv_validator_key_path: "priv_validator_key.json".to_string(),
            keys: BTreeMap::new(),
            pubkeys: BTreeMap::new(),
            bitcoin: BitcoinCfg {
                network,
                rpc: "http://signet:38332".to_string(),
                user: "side".to_string(),
                password: "12345678".to_string(),
            },
            side_chain: CosmosChain {
                rest_url: "http://localhost:1317".to_string(), 
                grpc: "http://localhost:9090".to_string(),
                gas: 200000,
                fee: Fee {
                    amount: 1000,
                    denom: "uside".to_string(),
                },
                address_prefix: "side".to_string(),
            }
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

    pub fn signer_address(&self) -> String {
        let mnemonic = Mnemonic::parse(self.mnemonic.as_str()).expect("Mnemonic is invalid!");

        let master = bitcoin::bip32::Xpriv::new_master(NetworkKind::Main, &mnemonic.to_seed("")).expect("invalid seed");

        let secp = Secp256k1::new();
        let path = DerivationPath::master();
        let sk = master.derive_priv(&secp, &path).expect("failed to derive pk");

        let pubkey = CompressedPublicKey::from_private_key(&secp, &sk.to_priv()).unwrap();
        Address::p2wpkh(&pubkey, self.bitcoin.network).to_string()
        // let sender_private_key = secp256k1::SigningKey::from_slice().unwrap();
        // let sender_public_key = sender_private_key.public_key();
        // let sender_account_id = sender_public_key.account_id(&self.side_chain.addr_prefix).unwrap();
        // sender_account_id.to_string()
    }
}

pub fn compute_relayer_address(mnemonic: &str, network: Network) -> Address {
    // let entropy = from_base64(&validator_priv_key).unwrap();
    // let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_slice()).unwrap();
    let mnemonic = Mnemonic::parse(mnemonic).expect("Mnemonic is invalid!");

    // derive the master key
    let master = bitcoin::bip32::Xpriv::new_master(NetworkKind::Main, &mnemonic.to_seed("")).expect("invalid seed");

    let secp = Secp256k1::new();
    let path = DerivationPath::master();
    let sk = master.derive_priv(&secp, &path).expect("failed to derive pk");

    let pubkey = CompressedPublicKey::from_private_key(&secp, &sk.to_priv()).unwrap();
    Address::p2wpkh(&pubkey, network)
}

pub fn home_dir(app_home: &str) -> PathBuf {
    dirs::home_dir().map(|path| path.join(app_home)).unwrap()
}
