use std::sync::Mutex;

use cosmrs::Any;
use libp2p::gossipsub::IdentTopic;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use tracing::{error, info};
use bitcoin::{Network, TapNodeHash, XOnlyPublicKey};
use bitcoincore_rpc::{Auth, Client};
use cosmos_sdk_proto::cosmos::auth::v1beta1::BaseAccount;
use frost_adaptor_signature::keys::{KeyPackage, PublicKeyPackage};

use side_proto::side::btcbridge::MsgCompleteDkg;
use tick::tasks_executor;

use crate::config::{Config, VaultKeypair, TASK_INTERVAL};
use crate::helper::bitcoin::get_group_address_by_tweak;
use crate::helper::store::Store;
use crate::protocols::dkg::DKG;
use crate::protocols::sign::StandardSigner;

use lazy_static::lazy_static;

use super::{Context, SubscribeMessage, Task};

lazy_static! {
    static ref BASE_ACCOUNT: Mutex<Option<BaseAccount>> = Mutex::new(None);
}

// mod dkg;
// mod sign;
mod tick;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Round {
    Round1,
    Round2,
    Aggregate,
    Closed,
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

// #[derive(Debug)]
pub struct BridgeSigner {
    enabled: bool,
    pub bitcoin_client: Client,
    keygen: DKG,
    signer: StandardSigner,
    ticker: tokio::time::Interval,
}

impl BridgeSigner {
    pub fn new(conf: Config, enabled: bool) -> Self {
        let bitcoin_client = Client::new(
            &conf.bitcoin.rpc,
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone()),
        )
        .expect("Could not initial bitcoin RPC client");

        let ticker = tokio::time::interval(TASK_INTERVAL);

        Self {
            enabled,
            ticker,
            bitcoin_client,
            keygen: DKG::new("bridge_dkg", Box::new(|ctx: &mut Context, task: &mut Task, priv_key: &frost_adaptor_signature::keys::KeyPackage, pub_key: &frost_adaptor_signature::keys::PublicKeyPackage| {

                let vaults = generate_vault_addresses(ctx, pub_key.clone(), priv_key.clone(), &task.dkg_input.tweaks, ctx.conf.bitcoin.network);
        
                let id: u64 = task.id.replace("dkg-", "").parse().unwrap();
        
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
            })),
            signer: StandardSigner::new("bridge_signing", Box::new(aa))

        }
    }  

}

fn aa(ctx: &mut Context, task: &mut Task) {
    println!("Signing completed: {:?}, {:?}", ctx.identifier, task.id);
}

impl super::App for BridgeSigner {
    fn on_message(&mut self, ctx: &mut Context, message: &SubscribeMessage) -> anyhow::Result<()> {
        // debug!("Received {:?}", message);
        self.keygen.on_message(ctx, message)
    }

    fn enabled(&mut self) -> bool {
        self.enabled
    }

    async fn tick(&mut self) -> Instant {
        self.ticker.tick().await
    }

    async fn on_tick(&mut self, ctx: &mut Context) {
        tasks_executor(ctx, self).await
    }
    
    fn subscribe_topics(&self) -> Vec<IdentTopic> {
        vec![self.keygen.topic(), self.signer.topic()]
    }
}
