use dkg::{prepare_response_for_task, received_dkg_response, DKGResponse, DKGTask};
use serde::{Deserialize, Serialize};

use bitcoin::{TapNodeHash, XOnlyPublicKey};
use bitcoincore_rpc::{Auth, Client};
use cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use frost_adaptor_signature::Identifier;
use frost_adaptor_signature::keys::dkg::round1::Package;
use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};
use frost_adaptor_signature::round1::{SigningCommitments, SigningNonces};
use frost_adaptor_signature::round2::SignatureShare;

use libp2p::identity::Keypair;

use libp2p::PeerId;
use sign::{received_sign_message, SignMesage, SignTask};
use tick::tasks_executor;
use tokio::time::Instant;

use crate::config::{self, Config, TASK_INTERVAL};
use crate::helper::bitcoin::get_group_address_by_tweak;
use crate::helper::encoding::{identifier_to_peer_id, pubkey_to_identifier};
use crate::helper::gossip::{publish_message, SubscribeTopic};
use crate::helper::mem_store;

use std::collections::BTreeMap;
use std::sync::Mutex;
use tracing::{error, info};
use usize as Index;

use ed25519_compact::SecretKey;

use lazy_static::lazy_static;

use super::{Context, SubscribeMessage};

lazy_static! {
    static ref BASE_ACCOUNT: Mutex<Option<BaseAccount>> = Mutex::new(None);
}

mod dkg;
mod sign;
mod tick;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Round {
    Round1,
    Round2,
    Aggregate,
    Closed,
}

#[derive(Debug)]
pub struct Signer {
    enabled: bool,
    config: Config,
    /// Identity key of the signer
    /// This is the private key of sidechain validator that is used to sign messages
    pub identity_key: SecretKey,
    /// Identifier of the signer
    /// Identifier is derived from the public key of the identity key
    /// used to identify the signer in the threshold signature scheme
    identifier: Identifier,
    pub bitcoin_client: Client,
    db_sign_variables: sled::Db,
    db_sign: sled::Db,
    db_dkg: sled::Db,
    db_dkg_variables: sled::Db,
    db_keypair: sled::Db,
    ticker: tokio::time::Interval,
}

impl Signer {
    pub fn new(conf: Config, enabled: bool) -> Self {
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
        info!("Threshold Signature Identifier: {:?}", identifier);

        let bitcoin_client = Client::new(
            &conf.bitcoin.rpc,
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone()),
        )
        .expect("Could not initial bitcoin RPC client");

        let db_sign = sled::open(conf.get_database_with_name("sign-task"))
            .expect("Counld not create database!");
        let db_sign_variables = sled::open(conf.get_database_with_name("sign-task-variables"))
            .expect("Counld not create database!");
        let db_dkg_variables = sled::open(conf.get_database_with_name("dkg-variables"))
            .expect("Counld not create database!");
        let db_dkg = sled::open(conf.get_database_with_name("dkg-task"))
            .expect("Counld not create database!");
        let db_keypair = sled::open(conf.get_database_with_name("keypairs"))
            .expect("Counld not create database!");

        let ticker = tokio::time::interval(TASK_INTERVAL);

        Self {
            enabled,
            ticker,
            identity_key: local_key,
            identifier,
            bitcoin_client,
            config: conf,
            db_dkg,
            db_dkg_variables,
            db_sign,
            db_sign_variables,
            db_keypair,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    pub fn peer_id(&self) -> PeerId {
        identifier_to_peer_id(&self.identifier)
    }

    pub fn p2p_keypair(&self) -> Keypair {
        let raw = &self.identity_key.to_vec()[0..32].to_vec();
        Keypair::ed25519_from_bytes(raw.clone()).unwrap()
    }

    pub fn validator_address(&self) -> String {
        self.config().load_validator_key().address.to_string()
    }

    pub async fn get_relayer_account(&self) -> BaseAccount {
        let cache = BASE_ACCOUNT.lock().unwrap().clone().map(|account| account);
        match cache {
            Some(account) => {
                let mut new_account = account.clone();
                new_account.sequence += 1;
                BASE_ACCOUNT.lock().unwrap().replace(new_account.clone());
                return new_account;
            }
            None => {
                let mut client = AuthQueryClient::connect(self.config.side_chain.grpc.clone())
                    .await
                    .unwrap();
                let request = QueryAccountRequest {
                    address: self.config().relayer_bitcoin_address(),
                };

                match client.account(request).await {
                    Ok(response) => {
                        let base_account: BaseAccount =
                            response.into_inner().account.unwrap().to_msg().unwrap();
                        BASE_ACCOUNT.lock().unwrap().replace(base_account.clone());
                        base_account
                    }
                    Err(_) => {
                        panic!("===============================================\n Relayer account don't exist on side chain \n===============================================");
                    }
                }
            }
        }
    }

    fn generate_tweak(&self, pubkey: PublicKeyPackage, index: u16) -> Option<TapNodeHash> {
        let key_bytes = match pubkey.verifying_key().serialize() {
            Ok(b) => b,
            Err(_) => return None,
        };
        let x_only_pubkey = XOnlyPublicKey::from_slice(&key_bytes[1..]).unwrap();

        let mut script = bitcoin::ScriptBuf::new();
        script.push_slice(x_only_pubkey.serialize());
        script.push_opcode(bitcoin::opcodes::all::OP_CHECKSIG);
        script.push_slice((index as u8).to_be_bytes());

        Some(TapNodeHash::from_script(
            script.as_script(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
    }

    pub fn generate_vault_addresses(
        &self,
        pubkey: PublicKeyPackage,
        key: KeyPackage,
        address_num: u16,
    ) -> Vec<String> {
        let mut addrs = vec![];
        for i in 0..address_num {
            let tweak = self.generate_tweak(pubkey.clone(), i);
            let address_with_tweak = get_group_address_by_tweak(
                &pubkey.verifying_key(),
                tweak.clone(),
                self.config.bitcoin.network,
            );

            addrs.push(address_with_tweak.to_string());
            self.save_keypair_to_db(
                address_with_tweak.to_string(),
                &config::VaultKeypair {
                    priv_key: key.clone(),
                    pub_key: pubkey.clone(),
                    tweak: tweak,
                },
            );
        }

        // self.config.save().expect("Failed to save generated keys");
        info!("Generated vault addresses: {:?}", addrs);
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

    fn save_dkg_package<T: Serialize>(&self, key: String, package: &BTreeMap<Identifier, T>) {
        let value = serde_json::to_vec(package).unwrap();
        if let Err(e) = self.db_dkg_variables.insert(key.as_bytes(), value) {
            error!("unable to save dkg variable: {e}");
        };
    }

    pub fn save_dkg_round1_package(&self, task_id: &str, package: &BTreeMap<Identifier, Package>) {
        self.save_dkg_package(format!("{}-round1", task_id), package);
    }

    pub fn save_dkg_round2_package(
        &self,
        task_id: &str,
        package: &BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>,
    ) {
        self.save_dkg_package(format!("{}-round2", task_id), package);
    }

    pub fn get_dkg_round1_package(&self, task_id: &str) -> Option<BTreeMap<Identifier, Package>> {
        match self
            .db_dkg_variables
            .get(format!("{}-round1", task_id).as_bytes())
        {
            Ok(Some(v)) => Some(serde_json::from_slice(&v).unwrap()),
            _ => None,
        }
    }
    pub fn get_dkg_round2_package(
        &self,
        task_id: &str,
    ) -> Option<BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>> {
        match self
            .db_dkg_variables
            .get(format!("{}-round2", task_id).as_bytes())
        {
            Ok(Some(v)) => Some(serde_json::from_slice(&v).unwrap()),
            _ => None,
        }
    }
    pub fn get_dkg_task(&self, task_id: &str) -> Option<DKGTask> {
        match self.db_dkg.get(task_id) {
            Ok(Some(v)) => Some(serde_json::from_slice(&v).unwrap()),
            _ => None,
        }
    }

    pub fn save_dkg_task(&self, task: &DKGTask) {
        let value = serde_json::to_vec(&task).unwrap();
        self.db_dkg
            .insert(task.id.as_str(), value)
            .expect("Failed to save task to database");
    }

    pub fn list_dkg_tasks(&self) -> Vec<DKGTask> {
        self.db_dkg
            .iter()
            .map(|r| {
                let (_k, v) = r.unwrap();
                serde_json::from_slice(&v).unwrap()
            })
            .collect()
    }

    pub fn remove_dkg_task(&self, task_id: &str) {
        self.db_dkg.remove(task_id).expect("Unable to remove task");
        let _ = self.db_dkg_variables.remove(format!("{}-round1", task_id));
        let _ = self.db_dkg_variables.remove(format!("{}-round2", task_id));
    }

    pub fn has_task_preceeded(&self, task_id: &str) -> bool {
        self.db_dkg.contains_key(task_id).map_or(false, |v| v)
    }

    // sign

    fn save_signing_package<K: Serialize, T: Serialize>(
        &self,
        key: &[u8],
        package: &BTreeMap<K, T>,
    ) {
        let value = serde_json::to_vec(package).unwrap();
        if let Err(e) = self.db_sign_variables.insert(key, value) {
            error!("unable to save dkg variable: {e}");
        };
    }
    pub fn save_signing_local_variable(
        &self,
        task_id: &str,
        package: &BTreeMap<usize, SigningNonces>,
    ) {
        self.save_signing_package(task_id.as_bytes(), package);
    }
    pub fn save_signing_commitments<T: Serialize>(
        &self,
        task_id: &str,
        package: &BTreeMap<Index, T>,
    ) {
        self.save_signing_package(format!("{}-commitments", task_id).as_bytes(), package);
    }
    pub fn save_signing_signature_shares<T: Serialize>(
        &self,
        task_id: &str,
        package: &BTreeMap<Index, T>,
    ) {
        self.save_signing_package(format!("{}-sig-shares", task_id).as_bytes(), package);
    }
    pub fn get_signing_local_variable(&self, task_id: &str) -> BTreeMap<usize, SigningNonces> {
        match self.db_sign_variables.get(task_id.as_bytes()) {
            Ok(Some(v)) => serde_json::from_slice(&v).unwrap(),
            _ => BTreeMap::new(),
        }
    }
    pub fn get_signing_commitments(
        &self,
        task_id: &str,
    ) -> BTreeMap<Index, BTreeMap<Identifier, SigningCommitments>> {
        match self
            .db_sign_variables
            .get(format!("{}-commitments", task_id).as_bytes())
        {
            Ok(Some(v)) => serde_json::from_slice(&v).unwrap(),
            _ => BTreeMap::new(),
        }
    }
    pub fn get_signing_signature_shares(
        &self,
        task_id: &str,
    ) -> BTreeMap<Index, BTreeMap<Identifier, SignatureShare>> {
        match self
            .db_sign_variables
            .get(format!("{}-sig-shares", task_id).as_bytes())
        {
            Ok(Some(v)) => serde_json::from_slice(&v).unwrap(),
            _ => BTreeMap::new(),
        }
    }
    pub fn get_signing_task(&self, task_id: &str) -> Option<SignTask> {
        match self.db_sign.get(task_id.as_bytes()) {
            Ok(Some(v)) => Some(serde_json::from_slice(&v).unwrap()),
            _ => None,
        }
    }

    pub fn save_signing_task(&self, task: &SignTask) {
        let value = serde_json::to_vec(&task).unwrap();
        self.db_sign
            .insert(task.id.as_bytes(), value)
            .expect("Failed to save task to database");
    }

    pub fn list_signing_tasks(&self) -> Vec<SignTask> {
        self.db_sign
            .iter()
            .map(|r| {
                let (_k, v) = r.unwrap();
                serde_json::from_slice(&v).unwrap()
            })
            .collect()
    }

    pub fn remove_signing_task(&self, task_id: &str) {
        self.db_sign.remove(task_id).expect("Unable to remove task");
        self.remove_signing_task_variables(task_id);
        mem_store::remove_task_participants(task_id);
    }

    pub fn remove_signing_task_variables(&self, task_id: &str) {
        if let Err(e) = self.db_sign_variables.remove(task_id.as_bytes()) {
            error!("remove signing task error: {e}");
        }
        if let Err(e) = self
            .db_sign_variables
            .remove(format!("{}-commitments", task_id).as_bytes())
        {
            error!("remove commitments {e}");
        }
        if let Err(e) = self
            .db_sign_variables
            .remove(format!("{}-sig-shares", task_id).as_bytes())
        {
            error!("remove signature shares {e}");
        };
    }

    pub fn is_signing_task_exists(&self, task_id: &str) -> bool {
        self.db_sign
            .contains_key(task_id.as_bytes())
            .map_or(false, |v| v)
    }

    pub fn list_keypairs(&self) -> Vec<(String, config::VaultKeypair)> {
        self.db_keypair
            .iter()
            .map(|v| {
                let (k, value) = v.unwrap();
                (
                    String::from_utf8(k.to_vec()).unwrap(),
                    serde_json::from_slice(&value).unwrap(),
                )
            })
            .collect::<Vec<_>>()
    }

    pub fn get_keypair_from_db(&self, address: &str) -> Option<config::VaultKeypair> {
        match self.db_keypair.get(address) {
            Ok(Some(value)) => Some(serde_json::from_slice(&value).unwrap()),
            _ => {
                error!("Not found keypair for address: {}", address);
                None
            }
        }
    }

    pub fn save_keypair_to_db(&self, address: String, keypair: &config::VaultKeypair) {
        let value = serde_json::to_vec(keypair).unwrap();
        let _ = self.db_keypair.insert(address, value);
    }

    pub fn reset_db(&self) {
        self.db_dkg.clear().expect("failed to clean db");
        self.db_dkg_variables.clear().expect("failed to clean db");
        self.db_sign.clear().expect("failed to clean db");
        self.db_sign_variables.clear().expect("failed to clean db");
    }
}

impl super::App for Signer {
    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) {
        // debug!("Received {:?}", message);
        if message.topic == SubscribeTopic::DKG.topic().hash() {
            if let Ok(response) = serde_json::from_slice::<DKGResponse>(&message.data) {
                received_dkg_response(response, self);                   
            }
        } else if message.topic == SubscribeTopic::SIGNING.topic().hash() {
            // debug!("Gossip Received {:?}", msg);
            if let Ok(msg) = serde_json::from_slice::<SignMesage>(&message.data) {
                received_sign_message(ctx, self, msg);
            }
        }
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    async fn tick(&mut self) -> Instant {
        self.ticker.tick().await
    }

    async fn on_tick(&self, ctx: &mut Context) {
        tasks_executor(ctx, self).await
    }
}

pub fn broadcast_dkg_packages(ctx: &mut Context, signer: &Signer, task_id: &str) {
    let response = prepare_response_for_task(signer, task_id);
    // debug!("Broadcasting: {:?}", response.);
    let message = serde_json::to_vec(&response).expect("Failed to serialize DKG package");
    publish_message(ctx, SubscribeTopic::DKG, message);
}

pub fn broadcast_signing_packages(ctx: &mut Context, signer: &Signer, message: &mut SignMesage) {
    let raw = serde_json::to_vec(&message.package).unwrap();
    let signaure = signer.identity_key.sign(raw, None).to_vec();
    message.signature = signaure;

    // tracing::debug!("Broadcasting: {:?}", message);
    let message = serde_json::to_vec(&message).expect("Failed to serialize Sign package");
    publish_message(ctx, SubscribeTopic::SIGNING, message);
}