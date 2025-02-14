use bitcoincore_rpc::{Auth, Client as BitcoinClient};
use cosmrs::Any;
use ed25519_compact::SecretKey;
use frost_adaptor_signature::{round1, round2, AdaptorSignature, Identifier, Signature};
use libp2p::{gossipsub::IdentTopic, Swarm};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use std::sync::mpsc::Sender;
use tendermint::abci::{Event, EventAttribute};

use crate::{
    apps::ShuttlerBehaviour,
    config::{Config, VaultKeypair},
    helper::{
        encoding::to_base64,
        now,
        store::{DefaultStore, MemStore, Store},
    }, providers::PriceStore,
};

pub type SubscribeMessage = libp2p::gossipsub::Message;

pub trait App {
    fn subscribe_topics(&self) -> Vec<IdentTopic>;
    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()>;
    fn on_event(&self, ctx: &mut Context, event: &Vec<Event>);
    // fn on_tick(&self, ctx: &mut Context);
    // fn tick(&self) -> Duration;
}

pub mod event {
    use crate::helper::encoding::to_base64;
    use tendermint::abci::{Event, EventAttribute};

    pub fn has_event_value(events: &Vec<Event>, value: &str) -> bool {
        events.iter().any(|e| has_attribute_value(&e.attributes, value))
    }

    pub fn get_event_value(events: &Vec<Event>, kind: &str, key: &str) -> Option<String> {
        events.iter().find(|e| e.kind == kind).map(|e| get_attribute_value(&e.attributes, key))?
    }

    pub fn has_attribute_value(attr: &Vec<EventAttribute>, value: &str) -> bool {
        attr.iter()
            .find(|ea| match ea {
                EventAttribute::V037(event_attribute) => &event_attribute.value == value,
                EventAttribute::V034(_) => false,
            })
            .is_some()
    }

    pub fn get_attribute_value(attr: &Vec<EventAttribute>, key: &str) -> Option<String> {
        attr.iter()
            .find(|ea| match ea {
                EventAttribute::V037(event_attribute) => &event_attribute.key == key,
                EventAttribute::V034(_) => false,
            })
            .map(|a| match a {
                EventAttribute::V037(event_attribute) => event_attribute.value.to_string(),
                EventAttribute::V034(event_attribute) => to_base64(&event_attribute.value),
            })
    }
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
    Adaptor(AdaptorSignature),
}

impl FrostSignature {
    pub fn inner(&self) -> &Signature {
        match self {
            FrostSignature::Standard(signature) => signature,
            FrostSignature::Adaptor(adaptor_signature) => &adaptor_signature.0,
        }
    }
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

    pub fn new_with_message(
        sign_key: String,
        message: Vec<u8>,
        participants: Vec<Identifier>,
    ) -> Self {
        Self::new_with_message_mode(sign_key, message, participants, SignMode::SignWithTweak)
    }

    pub fn new_with_message_mode(
        sign_key: String,
        message: Vec<u8>,
        participants: Vec<Identifier>,
        mode: SignMode,
    ) -> Self {
        Self {
            index: 0,
            participants,
            key: sign_key,
            mode,
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
            dkg_input: DkgInput {
                participants,
                threshold,
                tweaks: vec![],
            },
            sign_inputs: BTreeMap::new(),
            psbt: "".to_owned(),
            submitted: false,
        }
    }

    pub fn new_signing(
        id: String,
        psbt: impl Into<String>,
        sign_inputs: BTreeMap<usize, Input>,
    ) -> Self {
        Self {
            id,
            status: Status::SignRound1,
            time: now(),
            dkg_input: DkgInput::default(),
            psbt: psbt.into(),
            sign_inputs,
            submitted: false,
        }
    }
}
type Index = usize;
type CommitmentStore =
    DefaultStore<String, BTreeMap<Index, BTreeMap<Identifier, round1::SigningCommitments>>>;
type SignatureShareStore =
    DefaultStore<String, BTreeMap<Index, BTreeMap<Identifier, round2::SignatureShare>>>;
type SignerNonceStore = DefaultStore<String, BTreeMap<Index, round1::SigningNonces>>;

pub type Round1Store =
    MemStore<String, BTreeMap<Identifier, frost_adaptor_signature::keys::dkg::round1::Package>>;
pub type Round2Store = MemStore<String, BTreeMap<Identifier, Vec<u8>>>;

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
    pub price_store: Arc<PriceStore>,
    pub bitcoin_client: BitcoinClient,

    pub db_round1: Round1Store,
    pub db_round2: Round2Store,
}

impl Context {
    pub fn new(
        swarm: Swarm<ShuttlerBehaviour>,
        tx_sender: Sender<Any>,
        identifier: Identifier,
        node_key: SecretKey,
        conf: Config,
    ) -> Self {
        let id_base64 = to_base64(&identifier.serialize());
        let auth = if !conf.bitcoin.user.is_empty() {
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone())
        } else {
            Auth::None
        };

        let bitcoin_client = BitcoinClient::new(&conf.bitcoin.rpc, auth)
            .expect("Could not initial bitcoin RPC client");

        Self {
            bitcoin_client,
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
            price_store: Arc::new(PriceStore::new(conf.get_database_with_name("prices"))),
            conf,

            db_round1: Round1Store::new(),
            db_round2: Round2Store::new(),
        }
    }
}
