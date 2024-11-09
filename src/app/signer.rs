
use bitcoincore_rpc::{Auth, Client};
use cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use frost_core::Field;
use frost_secp256k1_tr::keys::dkg::round1::Package;
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr as frost;
use frost::Identifier;
use futures::StreamExt;

use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;

use libp2p::swarm::dial_opts::PeerCondition;
use libp2p::swarm::{dial_opts::DialOpts, SwarmEvent};
use libp2p::{ gossipsub, identify, mdns, noise, tcp, yamux, Multiaddr, PeerId, Swarm};
use serde::Serialize;

use crate::app::config::{self, TASK_ROUND_WINDOW};
use crate::app::config::Config;
use crate::helper::bitcoin::get_group_address_by_tweak;
use crate::helper::cipher::random_bytes;
use crate::helper::encoding::from_base64;
use crate::helper::gossip::{subscribe_gossip_topics, HeartBeatMessage, SubscribeTopic};
use crate::helper::mem_store;
use crate::protocols::sign::{received_sign_message, SignMesage, SignTask};
use crate::tickers::tss::time_free_tasks_executor;
use crate::protocols::dkg::{received_dkg_response, DKGResponse, DKGTask};
use crate::protocols::{TSSBehaviour, TSSBehaviourEvent};

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::str::FromStr;
use std::sync::Mutex;
use std::io;
use std::time::Duration;
use tokio::select;
use usize as Index;
use tracing::{debug, error, info, warn};

use ed25519_compact::SecretKey;

use lazy_static::lazy_static;

lazy_static! {
    static ref BASE_ACCOUNT: Mutex<Option<BaseAccount>> = {
        Mutex::new(None)
    };
}

#[derive(Debug)]
pub struct Signer {
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
}

impl Signer {
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

        let db_sign = sled::open(conf.get_database_with_name("sign-task")).expect("Counld not create database!");
        let db_sign_variables = sled::open(conf.get_database_with_name("sign-task-variables")).expect("Counld not create database!");
        let db_dkg_variables = sled::open(conf.get_database_with_name("dkg-variables")).expect("Counld not create database!");
        let db_dkg = sled::open(conf.get_database_with_name("dkg-task")).expect("Counld not create database!");
        let db_keypair = sled::open(conf.get_database_with_name("keypairs")).expect("Counld not create database!");

        Self {
            identity_key: local_key,
            identifier,
            bitcoin_client,
            config: conf,
            db_dkg,
            db_dkg_variables,
            db_sign,
            db_sign_variables,
            db_keypair
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    pub fn validator_address(&self) -> String {
        match &self.config().get_validator_key() {
            Some(key) => key.address.clone(),
            None => "".to_string()
        }
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
                let mut client = AuthQueryClient::connect(self.config.side_chain.grpc.clone()).await.unwrap();
                let request = QueryAccountRequest {
                    address: self.config().relayer_bitcoin_address(),
                };
        
                match client.account(request).await {
                    Ok(response) => {
        
                        let base_account: BaseAccount = response.into_inner().account.unwrap().to_msg().unwrap();
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

    fn generate_tweak(&self, _pubkey: PublicKeyPackage, index: u16) -> Option<[u8;32]> {
        Some([index as u8;32])
    }

    pub fn generate_vault_addresses(&self, pubkey: PublicKeyPackage, key: KeyPackage, address_num: u16) -> Vec<String> {

        let mut addrs = vec![];
        for i in 0..address_num {
            let tweak = self.generate_tweak(pubkey.clone(), i);
            let address_with_tweak = get_group_address_by_tweak(&pubkey.verifying_key(), tweak.clone(), self.config.bitcoin.network);

            addrs.push(address_with_tweak.to_string());
            self.save_keypair_to_db(address_with_tweak.to_string(), &config::VaultKeypair{
                priv_key: key.clone(),
                pub_key: pubkey.clone(),
                tweak: tweak,
            });
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

    pub fn save_dkg_round2_package(&self, task_id: &str, package: &BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>) {
        self.save_dkg_package(format!("{}-round2", task_id), package);
    }

    pub fn get_dkg_round1_package(&self, task_id: &str) -> Option<BTreeMap<Identifier, Package>> {
        match self.db_dkg_variables.get(format!("{}-round1", task_id).as_bytes()) {
            Ok(Some(v)) => {
                Some(serde_json::from_slice(&v).unwrap())
            },
            _ => None
        }
    }
    pub fn get_dkg_round2_package(&self, task_id: &str) -> Option<BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>>{
        match self.db_dkg_variables.get(format!("{}-round2", task_id).as_bytes()) {
            Ok(Some(v)) => {
                Some(serde_json::from_slice(&v).unwrap())
            },
            _ => None
        }
    }
    pub fn get_dkg_task(&self, task_id: &str) -> Option<DKGTask>{
        match self.db_dkg.get( task_id) {
            Ok(Some(v)) => {
                Some(serde_json::from_slice(&v).unwrap())
            },
            _ => None
        }
    }

    pub fn save_dkg_task(&self, task: &DKGTask) {    
        let value =  serde_json::to_vec(&task).unwrap();
        self.db_dkg.insert(task.id.as_str(), value).expect("Failed to save task to database");
    }

    pub fn list_dkg_tasks(&self) -> Vec<DKGTask>{
        self.db_dkg.iter().map(|r| { 
            let (_k, v) = r.unwrap();
            serde_json::from_slice(&v).unwrap()
        }).collect()
    }

    pub fn remove_dkg_task(&self, task_id: &str) {
        self.db_dkg.remove(task_id).expect("Unable to remove task");
        let _ = self.db_dkg_variables.remove(format!("{}-round1", task_id));
        let _ = self.db_dkg_variables.remove(format!("{}-round2", task_id));
    }

    pub fn has_task_preceeded(&self, task_id: &str) -> bool {
        self.db_dkg.contains_key(task_id).map_or(false, |v|v)
    }

    // sign

    fn save_signing_package<K: Serialize, T: Serialize>(&self, key: &[u8], package: &BTreeMap<K, T>) {
        let value = serde_json::to_vec(package).unwrap();
        if let Err(e) = self.db_sign_variables.insert(key, value) {
            error!("unable to save dkg variable: {e}");
        };
    }
    pub fn save_signing_local_variable(&self, task_id: &str, package: &BTreeMap<usize, SigningNonces>) {
        self.save_signing_package(task_id.as_bytes(), package);
    }
    pub fn save_signing_commitments<T: Serialize>(&self, task_id: &str, package: &BTreeMap<Index, T>) {
        self.save_signing_package(format!("{}-commitments", task_id).as_bytes(), package);
    }
    pub fn save_signing_signature_shares<T: Serialize>(&self, task_id: &str, package: &BTreeMap<Index, T>) {
        self.save_signing_package(format!("{}-sig-shares", task_id).as_bytes(), package);
    }
    pub fn get_signing_local_variable(&self, task_id: &str) -> BTreeMap<usize, SigningNonces> {
        match self.db_sign_variables.get( task_id.as_bytes()) {
            Ok(Some(v)) => {
                serde_json::from_slice(&v).unwrap()
            },
            _ => BTreeMap::new()
        }
    }
    pub fn get_signing_commitments(&self, task_id: &str) -> BTreeMap<Index, BTreeMap<Identifier, SigningCommitments>> {
        match self.db_sign_variables.get( format!("{}-commitments", task_id).as_bytes()) {
            Ok(Some(v)) => {
                serde_json::from_slice(&v).unwrap()
            },
            _ => BTreeMap::new()
        }
    }
    pub fn get_signing_signature_shares(&self, task_id: &str) -> BTreeMap<Index, BTreeMap<Identifier, SignatureShare>> {
        match self.db_sign_variables.get( format!("{}-sig-shares", task_id).as_bytes()) {
            Ok(Some(v)) => {
                serde_json::from_slice(&v).unwrap()
            },
            _ => BTreeMap::new()
        }
    }
    pub fn get_signing_task(&self, task_id: &str) -> Option<SignTask>{
        match self.db_sign.get( task_id.as_bytes()) {
            Ok(Some(v)) => {
                Some(serde_json::from_slice(&v).unwrap())
            },
            _ => None
        }
    }

    pub fn save_signing_task(&self, task: &SignTask) {    
        let value =  serde_json::to_vec(&task).unwrap();
        self.db_sign.insert(task.id.as_bytes(), value).expect("Failed to save task to database");
    }

    pub fn list_signing_tasks(&self) -> Vec<SignTask>{
        self.db_sign.iter().map(|r| { 
            let (_k, v) = r.unwrap();
            serde_json::from_slice(&v).unwrap()
        }).collect()
    }

    pub fn remove_signing_task(&self, task_id: &str) {
        self.db_sign.remove(task_id).expect("Unable to remove task");
        self.remove_signing_task_variables(task_id);
    }

    pub fn remove_signing_task_variables(&self, task_id: &str) {
        if let Err(e) = self.db_sign_variables.remove( task_id.as_bytes()) {
            error!("remove signing task error: {e}");
        }
        if let Err(e) = self.db_sign_variables.remove(format!("{}-commitments", task_id).as_bytes()) {
            error!("remove commitments {e}");
        }
        if let Err(e) = self.db_sign_variables.remove(format!("{}-sig-shares", task_id).as_bytes()) {
            error!("remove signature shares {e}");
        };
    }

    pub fn is_signing_task_exists(&self, task_id: &str) -> bool {
        self.db_sign.contains_key(task_id.as_bytes()).map_or(false, |v|v)
    }

    pub fn list_keypairs(&self) -> Vec<(String, config::VaultKeypair)> {
        self.db_keypair.iter().map(|v| {
            let (k, value) = v.unwrap();
            (String::from_utf8(k.to_vec()).unwrap(), serde_json::from_slice(&value).unwrap())
        }).collect::<Vec<_>>()
    }

    pub fn get_keypair_from_db(&self, address: &str) -> Option<config::VaultKeypair> {
        match self.db_keypair.get(address) {
            Ok(Some(value)) => {
                Some(serde_json::from_slice(&value).unwrap())
            },
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


pub async fn run_signer_daemon(conf: Config, seed: bool) {

    info!("Starting TSS Signer Daemon");

    // load config
    conf.load_validator_key();
    let signer = Signer::new(conf.clone());

    for (i, (addr, vkp) ) in signer.list_keypairs().iter().enumerate() {
        debug!("Vault {i}. {addr}");
        // maintain a permission white list for heartbeat
        vkp.pub_key.verifying_shares().keys().for_each(|identifier| {
            mem_store::update_alive_table(HeartBeatMessage { identifier: identifier.clone(), last_seen: 0 });
        });
    }

    let libp2p_keypair = Keypair::from_protobuf_encoding(from_base64(&conf.p2p_keypair).unwrap().as_slice()).unwrap();
    let mut swarm: libp2p::Swarm<TSSBehaviour> = libp2p::SwarmBuilder::with_existing_identity(libp2p_keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("Network setup failed")
        .with_quic()
        .with_behaviour(|key| {

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            // To content-address message, we can take the hash of message and use it as an ID.
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
                .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
                .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                .max_transmit_size(1000000)
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // build a gossipsub network behaviour
            let gossip = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let identify = identify::Behaviour::new(
                identify::Config::new("/shuttler/id/1.0.0".to_string(), key.public().clone())
                        .with_push_listen_addr_updates(true)
            );
            let kad = libp2p::kad::Behaviour::new(key.public().to_peer_id(), MemoryStore::new(key.public().to_peer_id()));
            
            Ok(TSSBehaviour { mdns, gossip, identify, kad})
        })
        .expect("swarm behaviour config failed")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60000)))

        .build();

    // start libp2p swarm
    // Listen on all interfaces and whatever port the OS assigns
    // swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", 5157).parse().expect("address parser error")).expect("failed to listen on all interfaces");
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", conf.port).parse().expect("Address parse error")).expect("failed to listen on all interfaces");

    if seed || conf.bootstrap_nodes.len() == 0 {
        swarm.behaviour_mut().kad.set_mode(Some(libp2p::kad::Mode::Server));
    }

    dail_bootstrap_nodes(&mut swarm, &conf);
    subscribe_gossip_topics(&mut swarm);

    let mut interval_free = tokio::time::interval(TASK_ROUND_WINDOW);
    // let start = Instant::now() + (TASK_ROUND_WINDOW - tokio::time::Duration::from_secs(now() % TASK_ROUND_WINDOW.as_secs()));
    // let mut interval_aligned = tokio::time::interval_at(start, TASK_ROUND_WINDOW);
    // let mut alive_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

    loop {
        select! {
            swarm_event = swarm.select_next_some() => match swarm_event {
                SwarmEvent::Behaviour(evt) => {
                    event_handler(evt, &mut swarm, &signer).await;
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on {address}/p2p/{}", swarm.local_peer_id());
                },
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, ..} => {
                    swarm.behaviour_mut().gossip.add_explicit_peer(&peer_id);
                    let connected = swarm.connected_peers().map(|p| p.clone()).collect::<Vec<_>>();
                    if connected.len() > 0 {
                        swarm.behaviour_mut().identify.push(connected);
                    }
                    let addr = endpoint.get_remote_address();
                    info!("Connected to {:?}/p2p/{peer_id}, ", addr);                  
                },
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    info!("Disconnected {peer_id}: {:?}", cause);
                },
                _ => {
                    // debug!("Swarm event: {:?}", swarm_event);
                },
            },
            _ = interval_free.tick() => {
                time_free_tasks_executor(&mut swarm, &signer).await;
            }
            // _ = interval_aligned.tick() => {
            //     time_aligned_tasks_executor(&mut swarm, &signer).await;
            // }

        }
    }
}

fn dail_bootstrap_nodes(swarm: &mut Swarm<TSSBehaviour>, conf: &Config) {
    for addr_text in conf.bootstrap_nodes.iter() {
        let address = Multiaddr::from_str(addr_text).expect("invalid bootstrap node address");
        let peer = PeerId::from_str(addr_text.split("/").last().unwrap()).expect("invalid peer id");
        swarm.behaviour_mut().kad.add_address(&peer, address);
        info!("Load bootstrap node: {:?}", addr_text);
    }
    if conf.bootstrap_nodes.len() > 0 {
        match swarm.behaviour_mut().kad.bootstrap() {
            Ok(_) => {
                info!("KAD bootstrap successful");
            }
            Err(e) => {
                warn!("Failed to start KAD bootstrap: {:?}", e);
            }
        }
    }
}

// handle sub events from the swarm
async fn event_handler(event: TSSBehaviourEvent, swarm: &mut Swarm<TSSBehaviour>, signer: &Signer) {
    match event {
        TSSBehaviourEvent::Gossip(gossipsub::Event::Message {message, .. }) => {
            // debug!("Received {:?}", message);
            if message.topic == SubscribeTopic::DKG.topic().hash() {
                if let Ok(response) = serde_json::from_slice::<DKGResponse>(&message.data) {
                    received_dkg_response(response, signer);                   
                }
            } else if message.topic == SubscribeTopic::SIGNING.topic().hash() {
                // debug!("Gossip Received {:?}", msg);
                if let Ok(msg) = serde_json::from_slice::<SignMesage>(&message.data) {
                    received_sign_message(swarm, signer, msg);
                }
            } else if message.topic == SubscribeTopic::ALIVE.topic().hash() {
                if let Ok(alive) = serde_json::from_slice::<HeartBeatMessage>(&message.data) {
                    mem_store::update_alive_table( alive );
                }
            }
        }
        TSSBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
            swarm.behaviour_mut().gossip.add_explicit_peer(&peer_id);
            // info!(" @@(Received) Discovered new peer: {peer_id} with info: {connection_id} {:?}", info);
            info.listen_addrs.iter().for_each(|addr| {
                if !addr.to_string().starts_with("/ip4/127.0.0.1") {
                    tracing::debug!("Discovered: {addr}/p2p/{peer_id}");
                    swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                }
            });
        }
        TSSBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
            for (peer_id, multiaddr) in list {
                swarm.behaviour_mut().gossip.add_explicit_peer(&peer_id);
                if swarm.is_connected(&peer_id) {
                    return;
                }
                swarm.add_peer_address(peer_id, multiaddr);
                // let opt = DialOpts::peer_id(peer_id)
                //     .addresses(vec![multiaddr.clone()])
                //     .condition(PeerCondition::DisconnectedAndNotDialing)
                //     .build();
                // if swarm.dial(opt).is_ok() {
                //     info!("Dailing {multiaddr}");
                // };  
            }
        }
        TSSBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
            for (peer_id, _multiaddr) in list {
                info!("mDNS peer has expired: {peer_id}");
            }
        }
        _ => {}
    }
}

