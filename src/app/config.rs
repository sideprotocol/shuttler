use bitcoin::{bip32::{DerivationPath, Xpriv}, key::Secp256k1, Address, CompressedPublicKey, Network, PrivateKey};
use bip39::{self, Mnemonic};
use cosmos_sdk_proto::cosmos::auth::v1beta1::{query_client::QueryClient as AuthQueryClient, BaseAccount, QueryAccountRequest};

use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use serde::{Deserialize, Serialize};
use sled::IVec;
use tracing::error;
use std::{fs, path::PathBuf, str::FromStr, sync::Mutex};

use crate::helper::{cipher::random_bytes, encoding::to_base64};

const CONFIG_FILE: &str = "config.toml";

use lazy_static::lazy_static;

lazy_static! {
    static ref DB_KEYPAIRS: sled::Db = {
        let path = get_database_with_name("keypairs");
        sled::open(path).unwrap()
    };
    static ref PRIV_VALIDATOR_KEY: Mutex<Option<PrivValidatorKey>> = Mutex::new(None);
    static ref BASE_ACCOUNT: Mutex<Option<BaseAccount>> = {
        Mutex::new(None)
    };
}

/// Threshold Signature Configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub p2p_keypair: String,
    pub port: u32,
    pub bootstrap_nodes: Vec<String>,
    /// logger level
    pub log_level: String,
    pub mnemonic: String,
    pub priv_validator_key_path: String,

    pub bitcoin: BitcoinCfg,
    pub side_chain: CosmosChain,
    
    pub ordinals: OrdinalsCfg,
    pub oracle: OracleCfg,

    pub relay_runes: bool,

    pub last_scanned_height: u64,

    pub loop_interval: u64,
    pub batch_relayer_count: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Keypair {
    pub priv_key: KeyPackage,
    pub pub_key: PublicKeyPackage,
    pub tweak: Option<[u8; 32]>,
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
    /// the cosmos grpc endpoint, http://localhost:9001
    pub grpc: String,
    /// Transaction gas
    pub gas: usize,
    pub fee: Fee,
}

/// Ordinals Configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OrdinalsCfg {
    /// Ord API endpoint
    pub endpoint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OracleCfg {
    pub submit_fee_rate: bool,
    pub submit_fee_rate_interval: u64,
    pub fetch_fee_rate_url: String,
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
    static ref APPLICATION_PATH: Mutex<String> = Mutex::new(String::from(".shuttler"));
}

pub fn update_app_home(app_home: &str) {
    let mut string: std::sync::MutexGuard<String> = APPLICATION_PATH.lock().unwrap();
    *string = String::from(app_home);
}

pub fn get_app_home() -> String {
    APPLICATION_PATH.lock().unwrap().clone()
}

pub fn get_database_with_name(db_name: &str) -> String {
    let mut home = APPLICATION_PATH.lock().unwrap().clone();
    home.push_str("/data/");
    home.push_str(db_name);
    home
}

pub fn list_keypairs() -> Vec<String> {
    let mut keys = vec![];
    for key in DB_KEYPAIRS.iter() {
        keys.push(String::from_utf8(key.unwrap().0.to_vec()).unwrap());
    }
    keys
}

pub fn get_keypair_from_db(address: &str) -> Option<Keypair> {
    match DB_KEYPAIRS.get(address) {
        Ok(Some(value)) => {
            Some(serde_json::from_slice(value.as_ref()).unwrap())
        },
        _ => {
            error!("Not found keypair for address: {}", address);
            None
        }
    }
}
pub fn save_keypair_to_db(address: String, keypair: &Keypair) -> sled::Result<Option<IVec>>{
    let value = serde_json::to_vec(keypair).unwrap();
    DB_KEYPAIRS.insert(address, value)
}

/// relayer account will be used to sign transactions on the side chain,
/// such as sending block headers, depositing and withdrawing transactions
pub async fn get_relayer_account(conf: &Config) -> BaseAccount {

    let cache = BASE_ACCOUNT.lock().unwrap().clone().map(|account| account);
    match cache {
        Some(account) => {
            let new_account  = account.clone();
            // new_account.sequence += 1;
            // BASE_ACCOUNT.lock().unwrap().replace(new_account.clone());
            return new_account;
        }
        None => {
            let mut client = AuthQueryClient::connect(conf.side_chain.grpc.clone()).await.unwrap();
            let request = QueryAccountRequest {
                // address: conf.signer_cosmos_address().to_string(),
                address: conf.relayer_bitcoin_address()
            };
    
            match client.account(request).await {
                Ok(response) => {
    
                    let base_account: BaseAccount = response.into_inner().account.unwrap().to_msg().unwrap();
                    // BASE_ACCOUNT.lock().unwrap().replace(base_account.clone());
                    base_account
                }
                Err(_) => {
                    panic!("===============================================\n Relayer account don't exist on side chain \n===============================================");
                }
            }
        }
    }
}

pub fn save_relayer_account(account: &BaseAccount) {
    BASE_ACCOUNT.lock().unwrap().replace(account.clone());
}

impl Config {
    pub fn load_validator_key(&self) {
        let priv_key_path = if self.priv_validator_key_path.starts_with("/") {
            self.priv_validator_key_path.clone()
        } else {
            format!("{}/{}", get_app_home(), self.priv_validator_key_path)
        };
        match fs::read_to_string(priv_key_path.clone()) {
            Ok(text) => {
                let prv_key = serde_json::from_str::<PrivValidatorKey>(text.as_str()).expect("Failed to parse priv_validator_key.json");
                PRIV_VALIDATOR_KEY.lock().unwrap().replace(prv_key.clone());
            },
            Err(e) => error!("Failed to read priv_validator_key.json: {}", e)
        };
    }

    pub fn get_validator_key(&self) -> Option<PrivValidatorKey> {
        PRIV_VALIDATOR_KEY.lock().unwrap().clone()
    }

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

    pub fn default(port: u32, network: Network) -> Self {
        let entropy = random_bytes(32);
        let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_slice()).expect("failed to create mnemonic");
        let p2p_keypair = to_base64(libp2p::identity::Keypair::generate_ed25519().to_protobuf_encoding().unwrap().as_slice());
        Self {
            p2p_keypair ,
            port: port as u32,
            bootstrap_nodes: vec!["/ip4/192.248.180.245/tcp/5158/p2p/12D3KooWMpMtmYQKSn1sZaSRn4CAcsraWZVrZ2zdNjEgsEPSd3Pv".to_string()],
            log_level: "debug".to_string(),
            mnemonic: mnemonic.to_string(),
            priv_validator_key_path: "priv_validator_key.json".to_string(),
            // keys: BTreeMap::new(),
            // pubkeys: BTreeMap::new(),
            bitcoin: BitcoinCfg {
                network,
                rpc: "http://192.248.150.102:18332".to_string(),
                user: "side".to_string(),
                password: "12345678".to_string(),
            },
            side_chain: CosmosChain {
                grpc: "http://localhost:9090".to_string(),
                gas: 1000000,
                fee: Fee {
                    amount: 1000,
                    denom: "uside".to_string(),
                },
            },
            ordinals: OrdinalsCfg {
                endpoint: "".to_string(),
            },
            oracle: OracleCfg {
                submit_fee_rate: false,
                submit_fee_rate_interval: 60,
                fetch_fee_rate_url: "https://mempool.space/testnet/api/v1/fees/recommended".to_string(),
            },
            relay_runes: false,
            // tweaks: BTreeMap::new(),
            last_scanned_height: 0,
            loop_interval: 60,
            batch_relayer_count: 10,
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

    pub fn relayer_bitcoin_privkey(&self) -> PrivateKey {
        // Replace with your mnemonic and HD path
        let hd_path = DerivationPath::from_str("m/84'/0'/0'/0/0").expect("invalid HD path");
        // Generate seed from mnemonic
        let mnemonic = Mnemonic::from_str(&self.mnemonic).expect("Invalid mnemonic");

        // Derive HD key
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(self.bitcoin.network, &mnemonic.to_seed("")).expect("failed to create master key");
        master.derive_priv(&secp, &hd_path).expect("Failed to derive key").to_priv()

    }

    pub fn relayer_bitcoin_pubkey(&self) -> CompressedPublicKey {
        let secp = Secp256k1::new();
        CompressedPublicKey::from_private_key(&secp, &self.relayer_bitcoin_privkey()).expect("failed to derive pubkey")
    }

    pub fn relayer_bitcoin_address(&self) -> String {
        let pubkey = self.relayer_bitcoin_pubkey();
        Address::p2wpkh(&pubkey, self.bitcoin.network).to_string()
    }

    // pub fn signer_priv_key(&self) -> SigningKey {
    //     // let hdpath = cosmrs::bip32::DerivationPath::from_str("m/44'/118'/0'/0/0").unwrap();
    //     let hdpath = cosmrs::bip32::DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
    //     let mnemonic = Mnemonic::parse(self.mnemonic.as_str()).expect("Invalid mnemonic");
    //     SigningKey::derive_from_path(mnemonic.to_seed(""), &hdpath).expect("failded to create signer key")
    // }

    // pub fn signer_cosmos_address(&self) -> AccountId {
    //     self.signer_priv_key().public_key().account_id(&self.side_chain.address_prefix).expect("failed to derive relayer address")
    // }

    // pub fn signer_bitcoin_address(&self) -> String {
    //     let pubkey = self.signer_bitcoin_pubkey();
    //     Address::p2wpkh(&pubkey, self.bitcoin.network).to_string()
    // }

    // pub fn signer_bitcoin_pubkey(&self) -> CompressedPublicKey {
    //     let pk_bytes = self.signer_priv_key().public_key().to_bytes();
    //     CompressedPublicKey::from_slice(pk_bytes.as_slice()).expect("failed to derive relayer address")
    // }
}

pub fn home_dir(app_home: &str) -> PathBuf {
    dirs::home_dir().map(|path| path.join(app_home)).unwrap()
}
