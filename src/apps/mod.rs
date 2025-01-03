use std::collections::BTreeMap;

use cosmrs::Any;
use ed25519_compact::SecretKey;
use frost_adaptor_signature::{round1, round2, AdaptorSignature, Identifier, Signature};
use libp2p::{gossipsub::IdentTopic, Swarm};
use serde::{de::Error, Deserialize, Serialize};
use tokio::{sync::mpsc::Sender, time::Instant};

use crate::{config::{Config, VaultKeypair}, helper::{now, store::DefaultStore}, shuttler::ShuttlerBehaviour};

pub mod bridge;
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
    SignWithGroupcommitment(String),
    SignWithAdaptorPoint(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrostSignature {
    Standard(Signature),
    Adaptor(AdaptorSignature)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub key: String,
    pub participants: Vec<Identifier>,
    pub index: usize,
    pub mode: SignMode,
    pub message: Vec<u8>,
    pub signature: Option<FrostSignature>,
}

impl Input {
    pub fn new(sign_key: String) -> Self {
        Self {
            index: 0,
            participants: vec![],
            key: sign_key,
            mode: SignMode::Sign,
            message: vec![],
            signature: None,
        }
    }

    pub fn new_with_message(sign_key: String, message: Vec<u8>) -> Self {
        Self {
            index: 0,
            participants: vec![],
            key: sign_key,
            mode: SignMode::Sign,
            message,
            signature: None,
        }
    } 
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DkgInput {
    pub participants: Vec<Identifier>,
    pub threshold: u16,
    pub tweaks: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub status: Status,
    pub time: u64,
    pub dkg_input: DkgInput,
    pub sign_inputs: BTreeMap<usize, Input>,
    pub psbt: String, // store psbt for later use
    pub submitted: bool,
}

impl Task {
    pub fn new_dkg(id: String, participants: Vec<Identifier>, threshold: u16) -> Self {
        Self {
            id,
            status: Status::DkgRound1,
            time: now(),
            dkg_input: DkgInput {participants, threshold, tweaks: vec![] },
            sign_inputs: BTreeMap::new(),
            psbt: "".to_owned(),
            submitted: false,
        }
    }

    pub fn new_signing(id: String, psbt: String, sign_inputs: BTreeMap<usize, Input> ) -> Self {
        Self {
            id,
            status: Status::SignRound1,
            time: now(),
            dkg_input: DkgInput::default(),
            psbt,
            sign_inputs,
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
    pub tx_sender: Sender<Any>,
    pub identifier: Identifier,
    pub node_key: SecretKey,
    pub id_base64: String,
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
    pub fn new(swarm: Swarm<ShuttlerBehaviour>, tx_sender: Sender<Any>,identifier: Identifier, node_key: SecretKey, conf: Config, id_base64:String) -> Self {
        Self { 
            swarm, 
            tx_sender,
            identifier, 
            node_key, 
            id_base64, 
            keystore: DefaultStore::new(conf.get_database_with_name("keypairs")),
            task_store: DefaultStore::new(conf.get_database_with_name("tasks")),
            nonce_store: SignerNonceStore::new(conf.get_database_with_name("nonces")),
            commitment_store: CommitmentStore::new(conf.get_database_with_name("commitments")),
            signature_store: SignatureShareStore::new(conf.get_database_with_name("signature_shares")),
            conf, 
        }
    }
}

pub trait DKGHander {
    fn on_completed(ctx: &mut Context, task: &mut Task, priv_key: frost_adaptor_signature::keys::KeyPackage, pub_key: frost_adaptor_signature::keys::PublicKeyPackage);
}

pub trait SigningHandler {
    fn on_completed(ctx: &mut Context, task: &mut Task);
}