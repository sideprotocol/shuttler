use ed25519_compact::SecretKey;
use frost_adaptor_signature::Identifier;
use libp2p::{gossipsub::IdentTopic, Swarm};
use serde::de::Error;
use tokio::time::Instant;

use crate::{config::{Config, VaultKeypair}, helper::store::DefaultStore, protocols::sign::SignTask, shuttler::ShuttlerBehaviour};

pub mod signer;
pub mod relayer;
pub mod oracle;

pub type SubscribeMessage = libp2p::gossipsub::Message;

pub trait App {
    fn enabled(&mut self) -> bool;
    fn subscribe(&self, ctx: &mut Context);
    fn on_message(&mut self, ctx: &mut Context, message: &SubscribeMessage);
    fn tick(&mut self) -> impl std::future::Future<Output = Instant> + Send;
    fn on_tick(&mut self, ctx: &mut Context) -> impl std::future::Future<Output = ()> + Send;
}

pub struct Context {
    pub swarm: Swarm<ShuttlerBehaviour>,
    pub identifier: Identifier,
    pub node_key: SecretKey,
    pub validator_hex_address: String,
    pub conf: Config,
    pub keystore: DefaultStore<String, VaultKeypair>,
    pub signing_store: DefaultStore<String, SignTask>
}

pub trait TopicAppHandle {
    fn topic() -> IdentTopic;
    fn message<M: for<'a> serde::Deserialize<'a>>(message: &SubscribeMessage) -> Result<M, serde_json::Error> {
        if message.topic == Self::topic().hash() {
            serde_json::from_slice::<M>(&message.data)
        } else {
            Err(serde_json::Error::unknown_field(message.topic.as_str(), &[]))
        }
    }
}

impl Context {
    pub fn new(swarm: Swarm<ShuttlerBehaviour>, identifier: Identifier, node_key: SecretKey, conf: Config, validator_hex_address:String) -> Self {
        Self { 
            swarm, 
            identifier, 
            node_key, 
            validator_hex_address, 
            keystore: DefaultStore::new(conf.get_database_with_name("keypairs")),
            signing_store: DefaultStore::new(conf.get_database_with_name("tasks")),
            conf, 
        }
    }
//     pub fn validator_address(&self) -> String {
//         self.config().load_validator_key().address.to_string()
//     }
}