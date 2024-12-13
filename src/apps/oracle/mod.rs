use std::{collections::BTreeMap, time::Duration};

use ed25519_compact::SecretKey;
use frost_adaptor_signature::{keys::dkg::round1::Package, Identifier};
use nonce::NonceGeneration;
use tokio::time::{Instant, Interval};

use crate::{config::{Config, VaultKeypair}, helper::{encoding::pubkey_to_identifier, store::DefaultStore}};

use super::{App, Context, SubscribeMessage};
pub mod nonce;

pub struct Oracle {    
    identifier: Identifier,
    enable: bool,
    config: Config,
    ticker: Interval,
    db_nonce: NonceStore,
    db_keypair: KeyStore,
    db_dkg_round1: Round1Store,
    db_dkg_round2: Round2Store,
}

type NonceStore = DefaultStore<String, NonceGeneration>;
type KeyStore = DefaultStore<String, VaultKeypair>;
type Round1Store = DefaultStore<String, BTreeMap<Identifier, Package>>;
type Round2Store = DefaultStore<String, BTreeMap<Identifier, Package>>;

impl Oracle {
    pub fn new(conf: Config, enable: bool) -> Self {
        let ticker = tokio::time::interval(Duration::from_secs(10));

        // load private key from priv_validator_key_path
        let priv_validator_key = conf.load_validator_key();

        let mut b = priv_validator_key
            .priv_key
            .ed25519_signing_key()
            .unwrap()
            .as_bytes()
            .to_vec();

        b.extend(priv_validator_key.pub_key.to_bytes());
        let local_key = SecretKey::new(b.as_slice().try_into().unwrap());

        let identifier = pubkey_to_identifier(local_key.public_key().as_slice());
        tracing::info!("Threshold Signature Identifier: {:?}", identifier);

        let db_nonce = NonceStore::new(conf.get_database_with_name("oracle-nonces"));
        let db_keypair = KeyStore::new(conf.get_database_with_name("oracle-keypair"));
        let db_dkg_round1 = Round1Store::new(conf.get_database_with_name("oracle-dkg-round1"));
        let db_dkg_round2 = Round2Store::new(conf.get_database_with_name("oracle-dkg-round2"));

        Self {
            identifier,
            config: conf,
            ticker,
            enable,
            db_nonce,
            db_keypair,
            db_dkg_round1,
            db_dkg_round2,
        }
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl App for Oracle {
    async fn on_tick(&self, _ctx: &mut Context) {
        // todo!()
    }

    fn on_message(&self, _ctx: &mut Context, _message: &SubscribeMessage) {
        // todo!()
    }

    fn enabled(&self) -> bool {
        self.enable
    }

    async fn tick(&mut self) -> Instant {
        self.ticker.tick().await
    }
}

