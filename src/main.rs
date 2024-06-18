
use bitcoin::{ Address, PublicKey, secp256k1::{Message, Secp256k1}};

use frost_core::serde::{Serialize, Deserialize};
use futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, mdns, noise, tcp, yamux};
use rand::thread_rng;
use serde_json::to_string;
use std::{collections::BTreeMap, ops::Mul};
use std::{env, vec};
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::{io, io::AsyncBufReadExt, select};

use frost_secp256k1 as frost;

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RoundMessage<T> {
    party_id: frost::Identifier,
    packet: T,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round2Message {
    sender_party_id: frost::Identifier,
    receiver_party_id: frost::Identifier,
    packet: frost::keys::dkg::round2::Package,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignMessage<T> {
    party_id: frost::Identifier,
    message: String,
    packet: T,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // let _ = tracing_subscriber::fmt()
    //     .with_env_filter(EnvFilter::from_default_env())
    //     .try_init();
    let args: Vec<String> = env::args().collect();
    dbg!(&args);

    let local_party_id: u16 = args[1].clone().parse()?;
    println!("party_id: {}", local_party_id );

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            // To content-address message, we can take the hash of message and use it as an ID.
            let message_id_fn = |message: &gossipsub::Message| {
                // let mut s = DefaultHasher::new();
                // message.data.hash(&mut s);
                // gossipsub::MessageId::from(s.finish().to_string())
                // hash_msg(String::from_utf8(message.data)?.to_string())
                gossipsub::MessageId::from(String::from_utf8_lossy(&message.data).to_string())
            };

            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
                .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
                .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // build a gossipsub network behaviour
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
            Ok(MyBehaviour { gossipsub, mdns })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new("test-net");
    let topic1 = gossipsub::IdentTopic::new("round1");
    let topic2 = gossipsub::IdentTopic::new("round2");
    let topic3 = gossipsub::IdentTopic::new("sign");
    let topic4 = gossipsub::IdentTopic::new("sign_round1");
    let topic5 = gossipsub::IdentTopic::new("sign_round2");
    // subscribes to our topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&topic1)?;
    swarm.behaviour_mut().gossipsub.subscribe(&topic2)?;
    swarm.behaviour_mut().gossipsub.subscribe(&topic3)?;
    swarm.behaviour_mut().gossipsub.subscribe(&topic4)?;
    swarm.behaviour_mut().gossipsub.subscribe(&topic5)?;

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    println!("Enter messages via STDIN and they will be sent to connected peers using Gossipsub");


    let max_signers = 3;
    let min_signers = 2;
    let mut rng = thread_rng();

    let participant_identifier: frost::Identifier = local_party_id.try_into().expect("should be nonzero");
    let (round1_secret_package, round1_package) =
        frost::keys::dkg::part1(participant_identifier.clone(), max_signers, min_signers, &mut rng)?;
    println!(
        "round1_secret_package: {:?}, {:?}",
        &round1_secret_package, &round1_package
    );
    // let mut text_round1_secret_package: frost::keys::dkg::round1::SecretPackage<Secp256K1Sha256> = frost_secp256k1::keys::dkg::round1::SecretPackage::new(null, null);
    let mut received_round1_packages = BTreeMap::new();
    let mut received_round2_packages = BTreeMap::new();

    let mut round2_secret_package_store: Vec<frost::keys::dkg::round2::SecretPackage> = vec![];

    let mut local_key: Vec<frost::keys::KeyPackage> = vec![]; 
    let mut public_key_package: Vec<frost::keys::PublicKeyPackage> = vec![];
    
    // signing variables
    let mut nonces_store = BTreeMap::new();
    let mut commitment_store = BTreeMap::new();
    let mut sign_package_store = BTreeMap::new();
    let mut sign_shares_store = BTreeMap::new();

    let text_bytes = [181, 121, 244, 3, 218, 122, 170, 51, 38, 102, 122, 153, 179, 167, 118, 242, 174, 45, 157, 135, 155, 177, 158, 39, 134, 66, 84, 1, 56, 169, 227, 164];

    // Kick it off
    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                let to_topic = if line.starts_with("sign") {
                    topic3.clone()
                } else {
                    topic.clone()
                };
                if let Err(e) = swarm
                    .behaviour_mut().gossipsub
                    .publish(to_topic, line.as_bytes()) {
                    println!("Publish error: {e:?}");
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discovered a new peer: {peer_id}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: _peer_id,
                    message_id: _id,
                    message,
                })) => {
                    if local_party_id > 1000u16 {
                        continue;
                    }
                    let msg = String::from_utf8_lossy(&message.data);

                    
                    if &message.topic.to_string() == "sign" {
                        println!("message topic: {}", message.topic.to_string());
                        let (nonces, commitments) = frost::round1::commit(
                            local_key[0].signing_share(),
                            &mut rng,
                        );
                        nonces_store.insert(hash_msg(msg.to_string().clone()), nonces);

                        let sign_message = SignMessage {
                            party_id: participant_identifier,
                            packet:commitments, 
                            message: hash_msg(msg.to_string()),
                        };

                        // sha256::Hash::hash(msg.as_bytes()).clone();
   
                        commitment_store.insert(sign_message.party_id, sign_message.packet);

                        swarm.behaviour_mut().gossipsub
                        .publish(gossipsub::IdentTopic::new("sign_round1"), serde_json::to_string(&sign_message)?.as_bytes())?;
                    }
                    
                    if &message.topic.to_string() == "sign_round1" {
                        println!("message topic: {}", message.topic.to_string());
                        let sign_message: SignMessage<frost::round1::SigningCommitments> = serde_json::from_slice(&message.data)?;
   
                        commitment_store.insert(sign_message.party_id, sign_message.packet);
                        println!("commitment_store: {:?}", commitment_store.len());

                        if commitment_store.len() >= max_signers as usize {
                            // let signing_package = frost::SigningPackage::new(commitment_store.clone(), sign_message.message.clone().as_bytes());
                            // let raw = hex::decode(sign_message.message.clone()).unwrap();
                            let signing_package = frost::SigningPackage::new(commitment_store.clone(), &text_bytes);

                            println!("sign_message: {:?}", sign_message);
                            sign_package_store.insert(sign_message.message.to_string().clone(), signing_package.clone());
                            
                            let nonces = nonces_store.get(&sign_message.message.to_string()).unwrap();
                            let signature_shares = frost::round2::sign(
                                &signing_package,
                                &nonces,
                                &local_key[0],
                            )?;
                            println!("signature_shares: {:?}", signature_shares);

                            let sign_message = SignMessage {
                                party_id: participant_identifier,
                                packet:signature_shares, 
                                message: sign_message.message.clone(),
                            };
                            sign_shares_store.insert(sign_message.party_id, sign_message.packet.clone());

                            swarm.behaviour_mut().gossipsub
                                .publish(gossipsub::IdentTopic::new("sign_round2"), serde_json::to_string(&sign_message)?.as_bytes())?;
                        }

                        // println!("proof: {:?}", proof);
                    }
                    if &message.topic.to_string() == "sign_round2" {
                        let sign_message: SignMessage<frost::round2::SignatureShare> = serde_json::from_slice(&message.data)?;
                        println!("sign_message: {:?}", &sign_message);

                        sign_shares_store
                            .insert(sign_message.party_id, sign_message.packet.clone());
                        println!("sign_shares_store: {:?}", sign_shares_store.len());

                        if sign_shares_store.len() == max_signers as usize {
                            println!("=============================");
                            let signing_package = sign_package_store.get(&sign_message.message.to_string()).unwrap();
                            // println!("signing_package: {:?}", signing_package);
                            match frost::aggregate(signing_package, &sign_shares_store, &public_key_package[0]) {
                                Ok(signature) => {
                                    // println!("public key: {:?}", pub)
                                    println!("signature: {:?}", signature.serialize());
                                    
                                    let is_signature_valid = &public_key_package[0]
                                        .verifying_key()
                                        .verify(&text_bytes, &signature)
                                        .is_ok();
                                    println!("is_signature_valid: {:?}", is_signature_valid);

                                    // let text = public_key_package[0]
                                    //     .verifying_key().serialize();
                                    // XOnlyPublicKey::from_slice(&text).unwrap();

                                    let text = &public_key_package[0]
                                        .verifying_key().serialize();
                                    println!("verify key: {:?}, {}", &text, &text.len());
                                    match PublicKey::from_slice(&text[..]) {
                                        Ok(pk) => {
                                            println!("pk: {:?}", pk);

                                            println!("messege: {:?}", &text_bytes);

                                            let secp = Secp256k1::verification_only();
                                            let msg = Message::from_hashed_data::<bitcoin::hashes::sha256::Hash>(&text_bytes);
                                            let sig = bitcoin::ecdsa::Signature::from_slice(&signature.serialize()[..]).unwrap();
                                            match pk.verify(&secp, &msg, &sig) {
                                                Ok(_) => println!("Signature is valid!"),
                                                Err(e) => println!("Error: {:?}", e),
                                            };
                                        }
                                        Err(e) => {
                                            println!("Error: {:?}", e);
                                        }
                                    };
                                }
                                Err(e) => {
                                    println!("Error: {:?}", e);
                                }
                            
                            };
                        }
                        
                    }

                    // DKG 
                    if msg.starts_with("generate") {

                        let round1_message = RoundMessage {
                            party_id: participant_identifier,
                            packet: &round1_package,
                        }; 

                        swarm.behaviour_mut().gossipsub
                            .publish(gossipsub::IdentTopic::new("round1"), serde_json::to_string(&round1_message)?.as_bytes())?;
                    }
                    if &message.topic.to_string() == "round1" {
                        let round1_package: RoundMessage<frost::keys::dkg::round1::Package> = serde_json::from_slice(&message.data)?;
                        println!("round1_package: {:?}", round1_package);
                        received_round1_packages
                            .insert(round1_package.party_id, round1_package.packet);

                        if received_round1_packages.len() == max_signers as usize - 1 {
                            let (round2_secret_package, round2_packages) =
                            frost::keys::dkg::part2(round1_secret_package.clone(), &received_round1_packages)?;

                            println!("**********\n");
                            println!(
                                "round2_secret_package: {:?}, {:?}",
                                &round2_secret_package, &round2_packages
                            );
                            round2_secret_package_store.push(round2_secret_package);

                            for (receiver_identifier, round2_package) in round2_packages {
                                let round2_message = Round2Message {
                                    sender_party_id: participant_identifier.clone(),
                                    receiver_party_id: receiver_identifier.clone(),
                                    packet: round2_package.clone(),
                                }; 

                                swarm.behaviour_mut().gossipsub
                                    .publish(gossipsub::IdentTopic::new("round2"), serde_json::to_string(&round2_message)?.as_bytes())?;
                            }
                        }

                    }
                    if &message.topic.to_string() == "round2" {
                        
                        println!("message topic: {}", message.topic.to_string());
                        let round2_package: Round2Message = serde_json::from_slice(&message.data)?;
                        println!("round2_package: {:?}", String::from_utf8_lossy(&message.data));

                        if round2_package.receiver_party_id != participant_identifier {
                            continue;
                        }
                        received_round2_packages
                            .insert(round2_package.sender_party_id, round2_package.packet);

                        if received_round2_packages.len() == max_signers as usize - 1 {
                            let round2_secret_package = round2_secret_package_store.pop().unwrap();
                            let (key, pubkey) =
                            frost::keys::dkg::part3(&round2_secret_package, &received_round1_packages, &received_round2_packages)?;
                            println!("**********");
                            println!(
                                "round3_secret_package: {:?},\n\n {:?}",
                                &key, &pubkey
                            );
                            local_key.push(key);
                            public_key_package.push(pubkey.clone());


                            let text = &pubkey
                                .verifying_key().serialize();
                            println!("text: {:?}, {}", &text, &text.len());
                            match PublicKey::from_slice(&text[..]) {
                                Ok(pk) => {
                                    println!("pk: {:?}", pk);
                                    
                                    let address = Address::p2shwpkh(&pk, bitcoin::Network::Regtest);
                                    println!("address: {:?}", address);
                                }
                                Err(e) => {
                                    println!("Error: {:?}", e);
                                }
                            };
                            // let pk = Secp256K1Sha256::PublicKey::from_slice(&text).unwrap();

                            // Address::p2tr(&xonly, bitcoin::Network::Regtest).unwrap();
                            
                        }
                    }
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                _ => {}
            }
        }
    }
}

// fn message_handler(party_id: u16, message: &gossipsub::Message) -> Result<(), Box<dyn Error>> {
//     println!("Received: {:?}, {:?}", &message.topic.as_str(), String::from_utf8_lossy(&message.data));
//     if String::from_utf8_lossy(&message.data).starts_with("generate") {

//         let max_signers = 3;
//         let min_signers = 2;

//         let mut rng = thread_rng();

//         let participant_identifier = party_id.try_into().expect("should be nonzero");
//         let (round1_secret_package, round1_package) =
//             frost::keys::dkg::part1(participant_identifier, max_signers, min_signers, &mut rng)?;
//         println!(
//             "round1_secret_package: {:?}, {:?}",
//             round1_secret_package, &round1_package.serialize()?
//         );
//     }
//     if &message.topic.to_string() == "round1" {
//         let round1_package = frost::keys::dkg::Round1Package::deserialize(&message.data)?;
//         swarm
//             .behaviour_mut().gossipsub
//             .publish(gossipsub::IdentTopic::new("round1"), round1_package.serialize())?;
//             println!("Publish error: {e:?}");
//         println!("round1_package: {:?}", round1_package);
//     } else if &message.topic.to_string() == "round2" {
//         let round2_package = frost::keys::dkg::Round2Package::deserialize(&message.data)?;
//         println!("round2_package: {:?}", round2_package);
//     }
//     return Ok(());
// }

fn hash_msg(message: String) -> String {
    // let mut hasher = Sha256::new();
    // hasher.update(message.as_bytes());
    // hasher.result_str().to_string()

    sha256::digest(message.as_bytes()).to_string()
    // sha256::Hash::from_str::<sha256::Hash>(&message).to_string()
    // Hasher::hash::<sha256::Hash, _>(&message.as_bytes()).to_string()
   //  Message::from_hashed_data::<sha256::Hash>(message.as_bytes()).to_string()
   // let hasher = sha256::Hash::hash<sha256::Hash>(message.as_bytes());
}
