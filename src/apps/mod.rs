use std::collections::BTreeMap;

use ed25519_compact::SecretKey;
use frost_adaptor_signature::{round1, round2, Identifier};
use libp2p::{gossipsub::IdentTopic, Swarm};
use serde::{de::Error, Deserialize, Serialize};
use tokio::time::Instant;

use crate::{config::{Config, VaultKeypair}, helper::{now, store::DefaultStore}, shuttler::ShuttlerBehaviour};

pub mod signer;
pub mod relayer;
pub mod dlc;

pub type SubscribeMessage = libp2p::gossipsub::Message;

pub trait App {
    fn enabled(&mut self) -> bool;
    fn subscribe(&self, ctx: &mut Context);
    fn on_message(&mut self, ctx: &mut Context, message: &SubscribeMessage);
    fn tick(&mut self) -> impl std::future::Future<Output = Instant> + Send;
    fn on_tick(&mut self, ctx: &mut Context) -> impl std::future::Future<Output = ()> + Send;
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    DkgRound1,
    DkgRound2,
    DkgComplete,
    SignRound1,
    SignRound2,
    SignComplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignMode {
    Sign,
    SignWithTweak,
    SignWithGroupcommitment,
    SignWithAdaptorPoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub key: String, 
    pub message: Vec<u8>,
    pub signature: Option<frost_adaptor_signature::Signature>,
    pub adaptor_signature: Option<frost_adaptor_signature::AdaptorSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub status: Status,
    pub time: u64,
    pub participants: Vec<Identifier>,
    pub threshold: u16,

    pub sign_mode: SignMode,
    pub sign_adaptor_point: String,
    pub sign_group_commitment: String,
    pub sign_inputs: Vec<Input>,
    pub submitted: bool,
}

impl Task {
    pub fn new_dkg(id: String, participants: Vec<Identifier>, threshold: u16, sign_mode: SignMode) -> Self {
        Self {
            id,
            status: Status::DkgRound1,
            time: now(),
            participants,
            threshold,
            sign_mode,
            sign_adaptor_point: "".to_string(),
            sign_group_commitment: "".to_string(),
            sign_inputs: vec![],
            submitted: false,
        }
    }
}
type Index = usize;
type CommitmentStore = DefaultStore<String, BTreeMap<Index,BTreeMap<Identifier,round1::SigningCommitments>>>;
type SignatureShareStore = DefaultStore<String, BTreeMap<Index,BTreeMap<Identifier,round2::SignatureShare>>>;
type SignerNonceStore = DefaultStore<String, BTreeMap<Index, round1::SigningNonces>>;

pub struct Context {
    pub swarm: Swarm<ShuttlerBehaviour>,
    pub identifier: Identifier,
    pub node_key: SecretKey,
    pub validator_hex_address: String,
    pub conf: Config,
    pub keystore: DefaultStore<String, VaultKeypair>,
    pub task_store: DefaultStore<String, Task>,
    pub nonce_store: SignerNonceStore,
    pub commitment_store: CommitmentStore,
    pub signature_store: SignatureShareStore,
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
            task_store: DefaultStore::new(conf.get_database_with_name("tasks")),
            nonce_store: SignerNonceStore::new(conf.get_database_with_name("nonces")),
            commitment_store: CommitmentStore::new(conf.get_database_with_name("commitments")),
            signature_store: SignatureShareStore::new(conf.get_database_with_name("signature_shares")),
            conf, 
        }
    }

    // pub fn get_dkg_inner_task(&self, task_id: &String) -> Option<DKGInput> {
    //     if let Some(t) =  self.task_store.get(task_id) {
    //         match t.payload {
    //             TaskPayload::DKG(d) => return Some(d),
    //             _ => return None,
    //         };
    //     }
    //     None
    // }

    // pub fn get_signing_inner_task(&self, task_id: &String) -> Option<SignTask> {
    //     if let Some(t) =  self.task_store.get(task_id) {
    //         match t.payload {
    //             TaskPayload::DKG(d) => return Some(d),
    //             _ => return None,
    //         };
    //     }
    //     None
    // }

//     pub fn validator_address(&self) -> String {
//         self.config().load_validator_key().address.to_string()
//     }
}

pub trait DKGHander {
    fn on_completed(ctx: &mut Context, task: &mut Task, priv_key: frost_adaptor_signature::keys::KeyPackage, pub_key: frost_adaptor_signature::keys::PublicKeyPackage);
}

pub trait SigningHandler {
    fn on_completed(ctx: &mut Context, task: &mut Task);
}