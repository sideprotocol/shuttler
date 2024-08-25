

use chrono::{Timelike, Utc};
use bitcoincore_rpc::{Auth, Client};
use frost_core::{keys::{PublicKeyPackage, KeyPackage}, Field};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tokio::{select, time::Instant};
use crate::{app::config::{self, Config}, helper::{bitcoin::get_group_address_by_tweak, cipher::random_bytes, messages::now}, tickers::relayer_tasks};
use crate::helper::encoding::from_base64;
use frost::Identifier; 
use frost_secp256k1_tr::{self as frost, Secp256K1Sha256};

use std::time::Duration;
use tracing::info;
use ed25519_compact:: SecretKey;

use super::config::Keypair;

#[derive(Debug)]
pub struct Relayer {
    config: Config,
    pub identity_key: SecretKey,
    identifier: Identifier,
    // pub priv_validator_key: PrivValidatorKey,
    pub bitcoin_client: Client,
}

impl Relayer {
    pub fn new(conf: Config) -> Self {

        // load private key from priv_validator_key_path
        let local_key = match conf.get_validator_key() {
            Some(validator_key) => {
                let b = from_base64(&validator_key.priv_key.value).expect("Decode private key failed");
                SecretKey::from_slice(b.as_slice()).expect("invalid secret key")
            },
            None => SecretKey::from_slice(random_bytes(SecretKey::BYTES).as_slice()).expect("invalid secret key")
        };

        let id = frost::Secp256K1ScalarField::deserialize(&local_key.public_key().as_slice().try_into().unwrap()).unwrap();
        let identifier = frost_core::Identifier::new(id).unwrap(); 

        info!("Threshold Signature Identifier: {:?}", identifier);

        let bitcoin_client = Client::new(
            &conf.bitcoin.rpc, 
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone()))
            .expect("Could not initial bitcoin RPC client");

        // let hdpath = cosmrs::bip32::DerivationPath::from_str("m/44'/118'/0'/0/0").unwrap();
        // let mnemonic = Mnemonic::parse(conf.mnemonic.as_str()).unwrap();

        // let relayer_key = SigningKey::derive_from_path(mnemonic.to_seed(""), &hdpath).unwrap();
        // let relayer_address =relayer_key.public_key().account_id(&conf.side_chain.address_prefix).expect("failed to derive relayer address");

        // info!("Relayer Address: {:?}", relayer_address.to_string());

        Self {
            identity_key: local_key,
            identifier,
            // priv_validator_key: validator_key,
            bitcoin_client,
            config: conf,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    // pub fn relayer_key(&self) -> &SigningKey {
    //     &self.relayer_key
    // }

    // pub fn relayer_address(&self) -> &AccountId {
    //     &self.relayer_address
    // }

    pub fn validator_address(&self) -> String {
        match &self.config().get_validator_key() {
            Some(key) => key.address.clone(),
            None => "".to_string()
        }
    }

    fn generate_tweak(&self, _pubkey: PublicKeyPackage<Secp256K1Sha256>, index: u16) -> Option<[u8;32]> {
        if index == 0 {
            None
        } else {
            Some([0;32])
        }
    }

    pub fn generate_vault_addresses(&self, pubkey: PublicKeyPackage<Secp256K1Sha256>, key: KeyPackage<Secp256K1Sha256>, address_num: u16) -> Vec<String> {

        let mut addrs = vec![];
        for i in 0..address_num {
            let tweak = self.generate_tweak(pubkey.clone(), i);
            let address_with_tweak = get_group_address_by_tweak(&pubkey.verifying_key(), tweak.clone(), self.config.bitcoin.network);

            addrs.push(address_with_tweak.to_string());
            config::save_keypair_to_db(address_with_tweak.to_string(), &Keypair{
                priv_key: key.clone(),
                pub_key: pubkey.clone(),
                tweak: tweak,
            });
        }
        self.config.save().expect("Failed to save generated keys");
        info!("Generated {:?} and vault addresses: {:?}", pubkey, addrs);
        addrs
    }

    pub fn get_complete_dkg_signature(&self, id: u64, vaults: &[String]) -> String {
        let mut sig_msg = id.to_be_bytes().to_vec();

        for v in vaults {
            sig_msg.extend(v.as_bytes())
        }

        sig_msg = hex::decode(sha256::digest(sig_msg)).unwrap();

        hex::encode(self.identity_key.sign(sig_msg, None))
    }
}

pub async fn run_relayer_daemon(conf: Config) {
    
    info!("Starting relayer daemon");

    let relayer = Relayer::new(conf);

    // this is to ensure that each node fetches tasks at the same time    
    let d = 6 as u64;
    let start = Instant::now() + (Duration::from_secs(d) - Duration::from_secs(now() % d));
    let mut interval_relayer = tokio::time::interval_at(start, Duration::from_secs(d));

    let seed = Utc::now().minute() as u64;
    let mut rng = ChaCha8Rng::seed_from_u64(seed );

    loop {
        select! {
            _ = interval_relayer.tick() => {
                relayer_tasks::start_relayer_tasks(&relayer, &mut rng).await;
            }
        }
    }
}
