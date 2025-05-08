
use cosmrs::Any;
use libp2p::gossipsub::IdentTopic;
use tracing::{error, info};
use bitcoin::{Network, TapNodeHash, XOnlyPublicKey};
use bitcoincore_rpc::{Auth, Client};
use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};

use side_proto::side::btcbridge::{MsgCompleteDkg, MsgSubmitSignatures};

use crate::apps::{App, Context, Input, SignMode, Status, SubscribeMessage, Task };
use crate::config::{Config, VaultKeypair, APP_NAME_BRIDGE};
use crate::helper::bitcoin::get_group_address_by_tweak;
use crate::helper::encoding::{from_base64, hash, pubkey_to_identifier};

use crate::helper::mem_store;
use crate::helper::store::Store;
use crate::protocols::dkg::{DKGAdaptor, DKG};
use crate::protocols::sign::{SignAdaptor, StandardSigner};

use super::SideEvent;

// #[derive(Debug)]
pub struct BridgeApp {
    pub bitcoin_client: Client,
    pub keygen: DKG<KeygenHander>,
    pub signer: StandardSigner<SignatureHandler>,
}

impl BridgeApp {
    pub fn new(conf: Config) -> Self {
        let bitcoin_client = Client::new(
            &conf.bitcoin.rpc,
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone()),
        )
        .expect("Could not initial bitcoin RPC client");

        Self {
            bitcoin_client,
            keygen: DKG::new("bridge_dkg", KeygenHander{}),
            signer: StandardSigner::new("bridge_signing", SignatureHandler{}),
        }
    }  
}

impl App for BridgeApp {
    fn name(&self) -> String {
        APP_NAME_BRIDGE.to_string()
    }
    fn on_message(&self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()> {
        // debug!("Received {:?}", message);
        self.keygen.on_message(ctx, message)?;
        self.signer.on_message(ctx, message)
    }
    
    fn subscribe_topics(&self) -> Vec<IdentTopic> {
        vec![self.keygen.topic(), self.signer.topic()]
    }
    fn on_event(&self, ctx: &mut Context, event: &SideEvent) {
        self.keygen.on_event(ctx, event);
        self.signer.on_event(ctx, event);
    }
    fn execute(&self, ctx: &mut Context, tasks: Vec<Task>) -> anyhow::Result<()> {
        self.signer.execute(ctx, &tasks);
        Ok(())
    }
}

pub struct KeygenHander{}
impl DKGAdaptor for KeygenHander {
    fn new_task(&self, _ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("initiate_dkg_bridge.id") {
                    // println!("Events: {:?}", events);
                    let mut tasks = vec![];
                    for (((id, ps), tks ), t)in events.get("initiate_dkg_bridge.id")?.iter()
                        .zip(events.get("initiate_dkg_bridge.participants")?)
                        .zip(events.get("initiate_dkg_bridge.batch_size")?)
                        .zip(events.get("initiate_dkg_bridge.threshold")?) {
                        
                            let mut participants = vec![];
                            for p in ps.split(",") {
                                if let Ok(identifier) = from_base64(p) {
                                    participants.push(pubkey_to_identifier(&identifier));
                                }
                            };
                            if let Ok(size) = tks.parse::<i32>() {
                                let tweaks = (0..size).collect();
                                if let Ok(threshold) = t.parse() {
                                    if threshold as usize * 3 >= participants.len() * 2  {
                                        tasks.push(Task::new_dkg_with_tweak(format!("create-vault-{}", id), participants, threshold,  tweaks));
                                    }
                                }

                            };
                        };
                    return Some(tasks);
                }
            },
            _ => {},
        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task, keys: Vec<(frost_adaptor_signature::keys::KeyPackage,frost_adaptor_signature::keys::PublicKeyPackage)>) {
        let (priv_key, pub_key) = keys.into_iter().next().unwrap();
        let vaults = generate_vault_addresses(ctx, pub_key.clone(), priv_key.clone(), &task.dkg_input.tweaks, ctx.conf.bitcoin.network);
        let id: u64 = task.id.replace("create-vault-", "").parse().unwrap();
        let mut sig_msg = id.to_be_bytes().to_vec();

        for v in &vaults {
            sig_msg.extend(v.as_bytes())
        }

        let message = hex::decode(hash(&sig_msg)).unwrap();
        let signature = hex::encode(ctx.node_key.sign(message, None));
        let cosm_msg = MsgCompleteDkg {
            id,
            sender: ctx.conf.relayer_bitcoin_address(),
            vaults,
            consensus_pubkey: ctx.id_base64.clone(),
            signature,
        };
        let any = Any::from_msg(&cosm_msg).unwrap();
        if let Err(e) = ctx.tx_sender.send(any) {
            error!("{:?}", e)
        }
    }
}

fn generate_tweak(pubkey: PublicKeyPackage, index: &i32) -> Option<TapNodeHash> {
    let key_bytes = match pubkey.verifying_key().serialize() {
        Ok(b) => b,
        Err(_) => return None,
    };
    let x_only_pubkey = XOnlyPublicKey::from_slice(&key_bytes[1..]).unwrap();

    let mut script = bitcoin::ScriptBuf::new();
    script.push_slice(x_only_pubkey.serialize());
    script.push_opcode(bitcoin::opcodes::all::OP_CHECKSIG);
    script.push_slice(index.to_be_bytes() );

    Some(TapNodeHash::from_script(
        script.as_script(),
        bitcoin::taproot::LeafVersion::TapScript,
    ))
}

pub fn generate_vault_addresses(
    ctx: &mut Context,
    pub_key: PublicKeyPackage,
    priv_key: KeyPackage,
    tweaks: &Vec<i32>,
    network: Network,
) -> Vec<String> {
    let mut addrs = vec![];
    for t in tweaks {
        let tweak = generate_tweak(pub_key.clone(), t);
        let address_with_tweak = get_group_address_by_tweak( &pub_key.verifying_key(), tweak.clone(), network );

        ctx.keystore.save(&address_with_tweak.to_string(), &VaultKeypair { priv_key: priv_key.clone(), pub_key: pub_key.clone(), tweak });

        addrs.push(address_with_tweak.to_string());
    }

    info!("Generated vault addresses: {:?}", addrs);
    addrs
}

pub struct SignatureHandler{}
impl SignAdaptor for SignatureHandler {
    fn new_task(&self, ctx: &mut Context, event: &SideEvent) -> Option<Vec<Task>> {
        match event {
            SideEvent::BlockEvent(events) => {
                if events.contains_key("initiate_signing_bridge.id") {
                    println!("Bridge Signing Event: {:?}", events);
                    let mut tasks = vec![];
                    for ((id, s), h) in events.get("initiate_signing_bridge.id")?.iter()
                        .zip(events.get("initiate_signing_bridge.signers")?)
                        .zip(events.get("initiate_signing_bridge.sig_hashes")?) {
    
                            let mut inputs = vec![];
                            s.split(",").zip(h.split(",")).for_each(|(signer, sig_hash)| {
                                let participants = mem_store::count_task_participants(ctx, &signer.to_string());
                                if participants.len() > 0 {
                                    let input = Input::new_with_message_mode(signer.to_string(), from_base64(sig_hash).unwrap(), participants, SignMode::SignWithTweak);
                                    inputs.push(input);
                                }
                            });
                            tasks.push( Task::new_signing(id.to_string(), "", inputs));
                        };
                    return Some(tasks);
                }
            },
            _ => {},
        }
        None
    }
    fn on_complete(&self, ctx: &mut Context, task: &mut Task) -> anyhow::Result<()> {
        println!("Signing completed: {:?}, {:?}", ctx.identifier, task.id);
        if task.submitted {
            return anyhow::Ok(());
        }

        let signatures = task.sign_inputs.iter()
            .map(|input| hex::encode(&input.signature.as_ref().unwrap().inner().serialize().unwrap()))
            .collect::<Vec<_>>();
        // submit signed psbt to side chain
        let msg = MsgSubmitSignatures {
            sender: ctx.conf.relayer_bitcoin_address(),
            txid: task.id.to_string(),
            signatures: signatures,
        };

        let any = Any::from_msg(&msg)?;
        ctx.tx_sender.send(any)?;

        task.submitted = true;
        // task.memo = to_base64(&psbt_bytes);
        task.status = Status::SignComplete;
        ctx.task_store.save(&task.id, &task);

        anyhow::Ok(())
    }
}
