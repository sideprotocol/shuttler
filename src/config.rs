use bitcoincore_rpc::jsonrpc::base64;
use libp2p::identity::Keypair;
use serde::{Serialize, Deserialize};
use std::{f64::consts::E, fs, path::PathBuf};

const CONFIG_FILE: &str = "config.toml";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub message_server: String,
    pub signer: Signer,
    pub p2p: P2P,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Signer {
    pub party_id: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct P2P {
    pub local_key: String,
}

impl Config {
    pub fn from_file(app_home: &str) -> Result<Self, std::io::Error> {
        if !home_dir(app_home).join(CONFIG_FILE).exists() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Config file not found"));
        }
        let contents = fs::read_to_string(home_dir(app_home).join(CONFIG_FILE))?;
        let config: Config = toml::from_str(&contents).expect("Failed to parse config file");
        Ok(config)
    }

    pub fn default() -> Self {
        let keypair = Keypair::generate_ed25519();
        let txt = keypair.to_protobuf_encoding().expect("encoding failed");
        let encoded = base64::encode(txt);
        Self {
            message_server: "localhost:5321".to_string(),
            signer: Signer {
                party_id: 0,
            },
            p2p: P2P {
                local_key: encoded,
            },
        }
    }

    pub fn to_string(&self) -> String {
        toml::to_string(self).unwrap()
    }

    pub fn save(&self, app_home: &str) -> Result<(), std::io::Error> {
        let path = home_dir(app_home);
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        let contents = self.to_string();
        fs::write(path.join(CONFIG_FILE), contents)
    }
}

pub fn home_dir(app_home: &str) -> PathBuf {
    dirs::home_dir()
        .map(|path| path.join(app_home)).unwrap()
}