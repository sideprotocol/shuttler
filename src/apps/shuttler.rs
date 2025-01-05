use std::{
    collections::BTreeMap, hash::{DefaultHasher, Hash, Hasher}, io, str::FromStr, time::Duration
};

use cosmrs::Any;
use ed25519_compact::{PublicKey, SecretKey, Signature};
use futures::stream::{self, FuturesUnordered, StreamExt};
use libp2p::{
    gossipsub, identify, identity::Keypair, kad::{self, store::MemoryStore}, mdns, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux, Multiaddr, PeerId, Swarm
};
use tokio::{select, spawn, time::interval};
use tracing::{debug, info, warn, error};

use crate::{
    apps::{
        App, Context, SubscribeMessage, Task
    },
    config::{candidate::Candidate, Config},
    helper::{
        client_side::send_cosmos_transaction, encoding::pubkey_to_identifier, gossip::{sending_heart_beat, subscribe_gossip_topics, HeartBeatMessage, SubscribeTopic}, mem_store
    },
};
use tokio_stream::wrappers::IntervalStream;

pub struct Shuttler<'a> {
    pub apps: Vec<&'a dyn App>,
    seed: bool,
    candidates: Candidate,
}

#[derive(NetworkBehaviour)]
pub struct ShuttlerBehaviour {
    pub kad: kad::Behaviour<MemoryStore>,
    pub identify: identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub gossip: gossipsub::Behaviour,
}

fn initial_swarm(keybyte: impl AsMut<[u8]>) -> Swarm<ShuttlerBehaviour> {
    libp2p::SwarmBuilder::with_existing_identity(Keypair::ed25519_from_bytes(keybyte).unwrap())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("Network setup failed")
        .with_quic()
        .with_behaviour(|key| {
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                key.public().to_peer_id(),
            )?;

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
                identify::Config::new(
                    "/shuttler/id/1.0.0".to_string(),
                    key.public().clone(),
                )
                .with_push_listen_addr_updates(true),
            );
            let kad = libp2p::kad::Behaviour::new(
                key.public().to_peer_id(),
                MemoryStore::new(key.public().to_peer_id()),
            );

            Ok(ShuttlerBehaviour {
                mdns,
                gossip,
                identify,
                kad,
            })
        }) 
        .expect("swarm behaviour config failed")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60000)))
        .build()
}

impl<'a> Shuttler<'a> {
    pub fn new(
        home: &str,
        seed: bool,
    ) -> Self {
        let conf = Config::from_file(home).unwrap();

        Self {
            candidates: Candidate::new(conf.side_chain.grpc.clone(), &conf.bootstrap_nodes),
            seed,
            apps: vec![],
        }
    }

    pub fn registry(&mut self, app: &'a impl App) {
        self.apps.push(app);
    }

    pub fn get_app(&self, index: usize ) -> Option<&&dyn App> {
        self.apps.get(index)
    }

    pub async fn start(&mut self, conf: &Config) {
        // load private key from priv_validator_key_path
        let priv_validator_key = conf.load_validator_key();

        let mut b = priv_validator_key
            .priv_key
            .ed25519_signing_key()
            .unwrap()
            .as_bytes()
            .to_vec();
        b.extend(priv_validator_key.pub_key.to_bytes());
        let node_key = SecretKey::new(b.as_slice().try_into().unwrap());
        let identifier = pubkey_to_identifier(node_key.public_key().as_slice());
        info!("Threshold Signature Identifier: {:?}", identifier);

        let raw = node_key.to_vec()[0..32].to_vec();

        let mut swarm = initial_swarm(raw);

        // start libp2p swarm
        // Listen on all interfaces and whatever port the OS assigns
        // swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", 5157).parse().expect("address parser error")).expect("failed to listen on all interfaces");
        swarm
            .listen_on(
                format!("/ip4/0.0.0.0/tcp/{}", conf.port)
                    .parse()
                    .expect("Address parse error"),
            )
            .expect("failed to listen on all interfaces");

        if self.seed || conf.bootstrap_nodes.len() == 0 {
            swarm
                .behaviour_mut()
                .kad
                .set_mode(Some(libp2p::kad::Mode::Server));
        }

        dail_bootstrap_nodes(&mut swarm, &conf);
        subscribe_gossip_topics(&mut swarm, &self);

        let (tx_sender, tx_receiver) = std::sync::mpsc::channel::<Any>();
        let conf2 = conf.clone();
        spawn(async move {
            while let Ok(message) = tx_receiver.recv() {
                println!("Received: {:?}", message);
                match send_cosmos_transaction(&conf2, message).await {
                    Ok(resp) => {
                        if let Some(inner) = resp.into_inner().tx_response {
                            debug!("Submited {}, {}, {}", inner.txhash, inner.code, inner.raw_log)
                        };
                    },
                    Err(e) => error!("Submit error: {:?}", e),
                };
            }
        });

        let mut context = Context::new(swarm, tx_sender, identifier, node_key, conf.clone());
        let mut heart_beat = tokio::time::interval(Duration::from_secs(mem_store::HEART_BEAT_WINDOW));


        let mut all = stream::select_all(self.apps.iter().enumerate().map(|(index, app)| {
            IntervalStream::new(interval(app.tick())).map(move |_| index)
        }));

        loop {
            select! {
                Some(index) = all.next() => {
                    if let Some(app) = self.get_app(index) {
                        app.on_tick(&mut context);
                    };
                }
                _ = heart_beat.tick() => {
                    sending_heart_beat(&mut context).await;
                }
                swarm_event = context.swarm.select_next_some() => match swarm_event {
                    SwarmEvent::Behaviour(ShuttlerBehaviourEvent::Gossip(gossipsub::Event::Message { message, .. })) => {
                        update_heartbeat(&context, &message);
                        for app in &self.apps {
                            dispatch_messages(app, &mut context, &message);
                        }
                    }
                    SwarmEvent::Behaviour(ShuttlerBehaviourEvent::Identify(identify::Event::Received {
                        peer_id, info, ..
                    })) => {
                        context.swarm.behaviour_mut().gossip.add_explicit_peer(&peer_id);
                        // info!(" @@(Received) Discovered new peer: {peer_id} with info: {connection_id} {:?}", info);
                        info.listen_addrs.iter().for_each(|addr| {
                            if !addr.to_string().starts_with("/ip4/127.0.0.1") {
                                tracing::debug!("Discovered: {addr}/p2p/{peer_id}");
                                context.swarm
                                    .behaviour_mut()
                                    .kad
                                    .add_address(&peer_id, addr.clone());
                            }
                        });
                    }
                    SwarmEvent::Behaviour(ShuttlerBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            context.swarm.behaviour_mut().gossip.add_explicit_peer(&peer_id);
                            context.swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr);
                        }
                    }
                    SwarmEvent::Behaviour(ShuttlerBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            info!("mDNS peer has expired: {peer_id}");
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on {address}/p2p/{}", context.swarm.local_peer_id());
                    },
                    SwarmEvent::ConnectionEstablished { peer_id, ..} => {
                        if self.is_white_listed_peer(&peer_id).await {
                            context.swarm.behaviour_mut().gossip.add_explicit_peer(&peer_id);
                        } else {
                            let _ = context.swarm.disconnect_peer_id(peer_id);
                        }
                        info!("Connected peers {:?}", context.swarm.connected_peers().collect::<Vec<_>>());
                    },
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        info!("Disconnected {peer_id}: {:?}", cause);
                    },
                    _ => {
                        // debug!("Swarm event: {:?}", swarm_event);
                    },
                },
            }
        }
    }

    pub async fn is_white_listed_peer(&mut self, peer_id: &PeerId) -> bool {
        
        self.candidates.sync_from_validators().await;
        // Allow anyone if no candidate is specified.
        if self.candidates.peers().len() == 0 {
            return true;
        }
        // Candidates are active validators and bootstrap nodes
        self.candidates.peers().contains(peer_id)
    }

    // Defines who is allowed to participate in the p2p network.
    // pub async fn sync_candidates_from_validators(&mut self) {
    //     self.candidates.sync_from_validators().await;
    // }

}

fn dispatch_messages(app: &&dyn App, context: &mut Context,  message: &SubscribeMessage) {
    if let Err(e) = app.on_message(context, message) {
        error!("Dispatch message error: {:?}", e);
    }
}

fn update_heartbeat(ctx: &Context, message: &SubscribeMessage) {
    if message.topic == SubscribeTopic::HEARTBEAT.topic().hash() {
        if let Ok(alive) = serde_json::from_slice::<HeartBeatMessage>(&message.data) {
            // Ensure the message is not forged.
            match PublicKey::from_slice(&alive.payload.identifier.serialize()) {
                Ok(public_key) => {
                    let sig = Signature::from_slice(&alive.signature).unwrap();
                    let bytes = serde_json::to_vec(&alive.payload).unwrap();
                    if public_key.verify(bytes, &sig).is_err() {
                        debug!("Reject, untrusted package from {:?}", alive.payload.identifier);
                        return;
                    }
                }
                Err(_) => return
            }
            mem_store::update_alive_table(&ctx.identifier, alive );
        }
    }
}

fn dail_bootstrap_nodes(swarm: &mut Swarm<ShuttlerBehaviour>, conf: &Config) {
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

