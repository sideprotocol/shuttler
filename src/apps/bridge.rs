use std::collections::BTreeMap;

use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache};
use cosmrs::Any;
use libp2p::gossipsub::IdentTopic;
use tracing::{error, info};
use bitcoin::{Address, Network, Psbt, TapNodeHash, TapSighashType, Witness, XOnlyPublicKey};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};

use side_proto::side::btcbridge::{MsgCompleteDkg, MsgSubmitSignatures};

use crate::apps::{App, Context, Status, SubscribeMessage, Task };
use crate::config::{Config, VaultKeypair, APP_NAME_BRIDGE};
use crate::helper::bitcoin::get_group_address_by_tweak;
use crate::helper::encoding::{from_base64, pubkey_to_identifier, to_base64};
use crate::helper::mem_store;
use crate::helper::store::Store;
use crate::mock::extact_value;
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
                if events.contains_key("create_bridge_vault.id") {
                    // println!("Events: {:?}", events);
                    let mut tasks = vec![];
                    for (((id, ps), tweaks ), t)in events.get("create_bridge_vault.id")?.iter()
                        .zip(events.get("create_bridge_vault.participants")?)
                        .zip(events.get("create_bridge_vault.tweaks")?)
                        .zip(events.get("create_bridge_vault.threshold")?) {
                        
                            let mut participants = vec![];
                            for p in ps.split(",") {
                                if let Ok(identifier) = from_base64(p) {
                                    participants.push(pubkey_to_identifier(&identifier));
                                }
                            };
                            if let Ok(threshold) = t.parse() {
                                if threshold as usize * 3 >= participants.len() * 2  {
                                    tasks.push(Task::new_dkg_with_tweak(format!("create-vault-{}", id), participants, threshold, tweaks.split(",").map(|t| t.parse::<i32>().unwrap()).collect()));
                                }
                            }
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

        let signature = hex::encode(ctx.node_key.sign(&sig_msg, None));
        let cosm_msg = MsgCompleteDkg {
            id,
            sender: ctx.conf.relayer_bitcoin_address(),
            vaults,
            consensus_address: ctx.id_base64.clone(),
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
            SideEvent::TxEvent(events) => {


                println!("SignAdaptor: {:?}", events);

                let mut tasks = vec![];
                events.iter().filter(|e| e.kind == "bridge_transaction").for_each(|e| {

                    println!("evt: {:?}", e);
                    let id = extact_value(&e.attributes, "txid");
                    if id.is_none() {
                        return
                    }
                    let psbt_raw = extact_value(&e.attributes, "psbt");
                    if psbt_raw.is_none() {
                        return
                    }

                    let psbt_text = psbt_raw.unwrap();
                    println!("received psbt: {} ", psbt_text);

                    if let Ok(psbt_bytes ) = from_base64(&psbt_text) {
                        if let Ok(psbt) = Psbt::deserialize(psbt_bytes.as_slice()) {

                            let mut inputs = vec![];    
                            let preouts = psbt.inputs.iter()
                                .map(|input| input.witness_utxo.clone().unwrap())
                                .collect::<Vec<_>>();

                            psbt.inputs.iter().enumerate().for_each(|(index, input)| {
                                let script = input.witness_utxo.clone().unwrap().script_pubkey;
                                let address = Address::from_script(&script, ctx.conf.bitcoin.network).unwrap();
                        
                                // get the message to sign
                                let hash_ty = input
                                    .sighash_type
                                    .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
                                    .unwrap_or(bitcoin::TapSighashType::Default);
                                let hash = match SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
                                    index,
                                    &Prevouts::All(&preouts),
                                    hash_ty,
                                ) {
                                    Ok(hash) => hash,
                                    Err(e) => {
                                        error!("failed to compute sighash: {}", e);
                                        return;
                                    }
                                };
                                
                                inputs.insert(index, super::Input::new_with_message_mode(
                                    address.to_string(), 
                                    hash.to_raw_hash().to_byte_array().to_vec(), 
                                    mem_store::count_task_participants(ctx, &address.to_string()),
                                    crate::apps::SignMode::SignWithTweak,
                                ));
                            });
                            if inputs.len() > 0 {
                                tasks.push(Task::new_signing(id.unwrap(), psbt_text, inputs));
                            }
                        };
                    }

                });

                if tasks.len() > 0 {
                    return Some(tasks);
                }
                // if events.events[0].kind("create_bridge_vault.id") {
                //     // println!("Events: {:?}", events);
                //     let mut tasks = vec![];
                //     for ((id, ps), t) in events.get("create_bridge_vault.id")?.iter()
                //         .zip(events.get("create_bridge_vault.participants")?)
                //         .zip(events.get("create_bridge_vault.threshold")?) {
                        
                //             let mut participants = vec![];
                //             for p in ps.split(",") {
                //                 if let Ok(identifier) = from_base64(p) {
                //                     participants.push(pubkey_to_identifier(&identifier));
                //                 }
                //             };
                //             if let Ok(threshold) = t.parse() {
                //                 if threshold as usize * 3 >= participants.len() * 2  {
                //                     tasks.push(Task::new_dkg(format!("create-vault-{}", id), participants, threshold));
                //                 }
                //             }
                //         };
                //     return Some(tasks);
                // }
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

        // // check if I am a sender to submit the txs
        // let address = match task.sign_inputs.get(&0) {
        //     Some(i) => i.key.clone(),
        //     None => return,
        // };

        // let vk = match ctx.task_store.get(&address) {
        //     Some(k) => k,
        //     None => return,
        // };

        // let participants = vk.pub_key.verifying_shares();

        // let sender_index = participants.iter().position(|(id, _)| {id == signer.identifier()}).unwrap_or(0);
        
        // let current = now();
        // let d = TASK_INTERVAL.as_secs();
        // let x = (current - (current % d) - task.start_time) % d + current / d;
        // if x as usize % participants.len() != sender_index {
        //     continue;
        // }

        // submit the transaction if I am the sender.

        let mut psbt_bytes = from_base64(&task.memo)?;
        let mut psbt = Psbt::deserialize(psbt_bytes.as_slice())?;

        for (index, input) in task.sign_inputs.iter().enumerate() {

            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&input.signature.as_ref().unwrap().inner().serialize()?)?;

            psbt.inputs[index].tap_key_sig = Option::Some(bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            });

            let witness = Witness::p2tr_key_spend(&psbt.inputs[index].tap_key_sig.unwrap());
            psbt.inputs[index].final_script_witness = Some(witness);
            psbt.inputs[index].partial_sigs = BTreeMap::new();
            psbt.inputs[index].sighash_type = None;
        };

        let signed_tx = psbt.clone().extract_tx()?;
        // let txid = signed_tx.compute_txid().to_string();

        if let Err(e) = ctx.bitcoin_client.send_raw_transaction(&signed_tx) {
            error!("{:?}", e)
        };

        psbt_bytes = psbt.serialize();

        // submit signed psbt to side chain
        let msg = MsgSubmitSignatures {
            sender: ctx.conf.relayer_bitcoin_address(),
            txid: signed_tx.compute_txid().to_string(),
            psbt: to_base64(&psbt_bytes),
        };

        let any = Any::from_msg(&msg)?;
        ctx.tx_sender.send(any)?;

        task.submitted = true;
        task.memo = to_base64(&psbt_bytes);
        task.status = Status::SignComplete;
        ctx.task_store.save(&task.id, &task);

        anyhow::Ok(())
    }
}
