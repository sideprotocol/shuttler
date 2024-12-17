use ed25519_compact::SecretKey;
use frost_adaptor_signature::Identifier;
use libp2p::Swarm;
use tokio::time::Instant;

use crate::{config::{Config, VaultKeypair}, helper::store::DefaultStore, shuttler::ShuttlerBehaviour};

pub mod signer;
pub mod relayer;
pub mod oracle;

pub type SubscribeMessage = libp2p::gossipsub::Message;

pub trait App {
    fn enabled(&self) -> bool;
    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage);
    fn tick(&mut self) -> impl std::future::Future<Output = Instant> + Send;
    fn on_tick(&self, ctx: &mut Context) -> impl std::future::Future<Output = ()> + Send;
}

pub struct Context {
    pub swarm: Swarm<ShuttlerBehaviour>,
    pub identifier: Identifier,
    pub node_key: SecretKey,
    pub validator_hex_address: String,
    pub conf: Config,
    pub keystore: DefaultStore<String, VaultKeypair>
}

impl Context {
    pub fn new(swarm: Swarm<ShuttlerBehaviour>, identifier: Identifier, node_key: SecretKey, conf: Config, validator_hex_address:String) -> Self {
        Self { 
            swarm, 
            identifier, 
            node_key, 
            validator_hex_address, 
            keystore: DefaultStore::new(conf.get_database_with_name("keypairs")),
            conf, 
        }
    }
//     pub fn validator_address(&self) -> String {
//         self.config().load_validator_key().address.to_string()
//     }
}