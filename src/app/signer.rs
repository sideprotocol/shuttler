
use bitcoincore_rpc::{Auth, Client};
use cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmos_sdk_proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use frost_core::Field;
use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1_tr::{self as frost};
use frost::Identifier;
use futures::StreamExt;

use libp2p::identity::Keypair;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::dial_opts::PeerCondition;
use libp2p::swarm::{dial_opts::DialOpts, SwarmEvent};
use libp2p::{ gossipsub, mdns, noise, tcp, yamux, Multiaddr, StreamProtocol, Swarm};

use crate::app::config;
use crate::app::config::Config;
use crate::helper::bitcoin::get_group_address_by_tweak;
use crate::helper::cipher::random_bytes;
use crate::helper::encoding::from_base64;
use crate::protocols::sign::{tss_event_handler, SignRequest, SignResponse};
use crate::tickers::tss::tss_tasks_fetcher;
use crate::protocols::dkg::{dkg_event_handler, DKGRequest, DKGResponse};
use crate::protocols::{TSSBehaviour, TSSBehaviourEvent};

use std::hash::{DefaultHasher, Hash, Hasher};
use std::str::FromStr;
use std::sync::Mutex;
use std::{io, iter};
use std::time::Duration;
use tokio::select;

use tracing::{debug, info, error};

use ed25519_compact:: SecretKey;

use lazy_static::lazy_static;

lazy_static! {
    static ref BASE_ACCOUNT: Mutex<Option<BaseAccount>> = {
        Mutex::new(None)
    };
}

#[derive(Debug)]
pub struct Signer {
    config: Config,
    pub identity_key: SecretKey,
    identifier: Identifier,
    pub bitcoin_client: Client,
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
                    address: self.config().signer_cosmos_address().to_string(),
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
        if index == 0 {
            None
        } else {
            Some([0;32])
        }
    }

    pub fn generate_vault_addresses(&self, pubkey: PublicKeyPackage, key: KeyPackage, address_num: u16) -> Vec<String> {

        let mut addrs = vec![];
        for i in 0..address_num {
            let tweak = self.generate_tweak(pubkey.clone(), i);
            let address_with_tweak = get_group_address_by_tweak(&pubkey.verifying_key(), tweak.clone(), self.config.bitcoin.network);

            addrs.push(address_with_tweak.to_string());
            let re = config::save_keypair_to_db(address_with_tweak.to_string(), &config::Keypair{
                priv_key: key.clone(),
                pub_key: pubkey.clone(),
                tweak: tweak,
            });
            if re.is_err() {
                error!("Failed to save generated keys to database: {:?}",   re.err());
            }
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


pub async fn run_signer_daemon(conf: Config) {

    info!("Starting TSS Signer Daemon");

    // load config
    conf.load_validator_key();
    let signer = Signer::new(conf.clone());

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
            let cfg = request_response::Config::default();

            let dkg = request_response::cbor::Behaviour::<DKGRequest, DKGResponse>::new(
                iter::once((StreamProtocol::new("/dkg/1"), ProtocolSupport::Full)), cfg.clone()
            );
            let signer = request_response::cbor::Behaviour::<SignRequest, SignResponse>::new(
                iter::once((StreamProtocol::new("/tss/1"), ProtocolSupport::Full)), cfg
            );

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
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // build a gossipsub network behaviour
            let gossip = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;
            
            Ok(TSSBehaviour { mdns, dkg , gossip, signer})
        })
        .expect("swarm behaviour config failed")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60000)))

        .build();

    // start libp2p swarm
    // subscribes to topics
    // subscribes(swarm.behaviour_mut());
    // Listen on all interfaces and whatever port the OS assigns
    // swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().expect("address parser error")).expect("failed to listen on all interfaces");
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", conf.port).parse().expect("Address parse error")).expect("failed to listen on all interfaces");

    dail_bootstrap_nodes(&mut swarm, &conf);

    let mut interval = tokio::time::interval(Duration::from_secs(6));

    loop {
        select! {
            swarm_event = swarm.select_next_some() => match swarm_event {
                SwarmEvent::Behaviour(evt) => {
                    event_handler(evt, &mut swarm, &signer).await;
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Local node is listening on {address}");
                },
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    info!("Connected to {peer_id}, request");                  
                },
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    info!("Connection {peer_id} closed.{:?}", cause);
                },
                _ => {
                    // debug!("Swarm event: {:?}", swarm_event);
                },
            },

            _ = interval.tick() => {
                debug!("Fetching TSS tasks");
                tss_tasks_fetcher(&mut swarm, &signer).await;
            }

        }
    }
}

fn dail_bootstrap_nodes(swarm: &mut Swarm<TSSBehaviour>, conf: &Config) {
    for addr_text in conf.bootstrap_nodes.iter() {
        let add = Multiaddr::from_str(addr_text).expect("invalid bootstrap node address");

        let opt = DialOpts::unknown_peer_id()
            .address(add)
            .build();
        match swarm.dial(opt) {
            Ok(_) => {
                info!("Dialed {addr_text}");
            }
            Err(e) => {
                error!("Failed to dial {addr_text}: {e}");
            }
        };
    }
}

// handle sub events from the swarm
async fn event_handler(event: TSSBehaviourEvent, swarm: &mut Swarm<TSSBehaviour>, shuttler: &Signer) {
    match event {
        TSSBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
            for (peer_id, multiaddr) in list {
                info!("mDNS discovered a new peer: {peer_id}");

                swarm.behaviour_mut().gossip.add_explicit_peer(&peer_id);
                if swarm.is_connected(&peer_id) {
                    continue;
                }
                let opt = DialOpts::peer_id(peer_id)
                    .addresses(vec![multiaddr])
                    .condition(PeerCondition::DisconnectedAndNotDialing)
                    .build();
                match swarm.dial(opt) {
                    Ok(_) => {
                        info!("Dialed {peer_id}");
                    }
                    Err(e) => {
                        error!("Failed to dial {peer_id}: {e}");
                    }
                };                
            }
        }
        TSSBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
            for (peer_id, _multiaddr) in list {
                info!("mDNS discover peer has expired: {peer_id}");
            }
        }
        TSSBehaviourEvent::Dkg(request_response::Event::Message { peer, message }) => {
            // debug!("Received DKG response from {peer}: {:?}", &message);
            dkg_event_handler( shuttler, swarm.behaviour_mut(), &peer, message);
        }
        TSSBehaviourEvent::Dkg(request_response::Event::InboundFailure { peer, request_id, error}) => {
            debug!("Inbound Failure {peer}: {request_id} - {error}");
        }
        TSSBehaviourEvent::Dkg(request_response::Event::OutboundFailure { peer, request_id, error}) => {
            debug!("Outbound Failure {peer}: {request_id} - {error}");
        }
        TSSBehaviourEvent::Signer(request_response::Event::Message { peer, message }) => {
            debug!("Received Signer response from {peer}: {:?}", &message);
            tss_event_handler( swarm.behaviour_mut(), &peer, message);
        }
        _ => {}
    }
}