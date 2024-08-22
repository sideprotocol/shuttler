
use chrono::{Timelike, Utc};
use futures::StreamExt;

use libp2p::identity::Keypair;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::dial_opts::PeerCondition;
use libp2p::swarm::{dial_opts::DialOpts, SwarmEvent};
use libp2p::{ mdns, gossipsub, noise, tcp, yamux, StreamProtocol, Swarm};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tokio::io::AsyncReadExt as _;
use tokio::time::Instant;

use crate::app::{config::Config, shuttler::Shuttler};
use crate::helper::messages::now;
use crate::tickers::{relayer_tasks::start_loop_tasks, tss_tasks::tasks_fetcher};
use crate::protocols::dkg::{dkg_event_handler, DKGRequest, DKGResponse};
use crate::protocols::{TSSBehaviour, TSSBehaviourEvent};

use std::iter;
use std::time::Duration;
use tokio::select;

use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, error};

use super::Cli;

pub async fn execute(cli: &Cli) {

    // Generate a random peer ID
    let kb = Keypair::generate_ed25519();
    let local_peer_id = kb.public().to_peer_id();

    info!("Local peer id: {:?}", local_peer_id);

    let mut swarm: libp2p::Swarm<TSSBehaviour> = libp2p::SwarmBuilder::with_new_identity()
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

            let protocols = iter::once((StreamProtocol::new("/dkg/1"), ProtocolSupport::Full));
            let cfg = request_response::Config::default();

            let dkg = request_response::cbor::Behaviour::<DKGRequest, DKGResponse>::new(protocols.clone(), cfg.clone());

            let gossip: gossipsub::Behaviour = gossipsub::Behaviour::new(gossipsub::Config::default()).expect("msgsub setup failed");
            
            Ok(TSSBehaviour { mdns, dkg , gossip})
        })
        .expect("swarm behaviour config failed")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))

        .build();

    // start libp2p swarm
    // subscribes to topics
    // subscribes(swarm.behaviour_mut());
    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().expect("address parser error")).expect("failed to listen on all interfaces");
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().expect("Address parse error")).expect("failed to listen on all interfaces");

    // swarm.connected_peers().
    let conf = Config::from_file(&cli.home).unwrap();
    let mut shuttler = Shuttler::new(conf.clone());

    // this is to ensure that each node fetches tasks at the same time    
    let d = 6 as u64;
    let start = Instant::now() + (Duration::from_secs(d) - Duration::from_secs(now() % d));
    let mut interval = tokio::time::interval_at(start, Duration::from_secs(d));


    let seed = Utc::now().minute() as u64;
    let mut rng = ChaCha8Rng::seed_from_u64(seed );

    tokio::spawn(start_loop_tasks(conf.clone()));

    loop {
        select! {
            swarm_event = swarm.select_next_some() => match swarm_event {
                SwarmEvent::Behaviour(evt) => {
                    event_handler(evt, &mut swarm, &mut shuttler).await;
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
                // let peers = swarm.connected_peers().collect::<Vec<_>>();
                tasks_fetcher(cli, &mut swarm, &mut shuttler, &mut rng).await;
            },

        }
    }
}



// handle sub events from the swarm
async fn event_handler(event: TSSBehaviourEvent, swarm: &mut Swarm<TSSBehaviour>, shuttler: &mut Shuttler) {
    match event {
        TSSBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
            for (peer_id, multiaddr) in list {
                info!("mDNS discovered a new peer: {peer_id}");

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
        TSSBehaviourEvent::Dkg(request_response::Event::Message { peer, message }) => {;
            // debug!("Received DKG response from {peer}: {:?}", &message);
            dkg_event_handler( shuttler, swarm.behaviour_mut(), &peer, message);
        }
        TSSBehaviourEvent::Dkg(request_response::Event::InboundFailure { peer, request_id, error}) => {
            debug!("Inbound Failure {peer}: {request_id} - {error}");
        }
        TSSBehaviourEvent::Dkg(request_response::Event::OutboundFailure { peer, request_id, error}) => {
            debug!("Outbound Failure {peer}: {request_id} - {error}");
            // let opt = DialOpts::peer_id(peer)
            // .condition(PeerCondition::DisconnectedAndNotDialing)
            // .build();
            // match swarm.dial(opt) {
            //     Ok(_) => {
            //         info!("Dialed {peer}");
            //     }
            //     Err(e) => {
            //         error!("Failed to dial {peer}: {e}");
            //     }
            // };
            
        }
        _ => {}
    }
}

pub async fn command_handler(steam: &mut TcpStream, shuttler: &mut Shuttler) {

    debug!("Accepted connection from: {:?}", steam.peer_addr().unwrap());
    let mut buf = [0; 1024];
    let result = steam.read(&mut buf).await;

    match result {
        Ok(0) => {
            // Connection closed
            error!("Connection closed");
            return;
        }
        Ok(n) => {
            // Print the received message
            let message = String::from_utf8_lossy(&buf[..n]);
            let task = serde_json::from_str::<crate::helper::messages::Task>(&message).unwrap();

        }
        Err(e) => {
            error!("Failed to read from socket: {}", e);
        }
    }
}

