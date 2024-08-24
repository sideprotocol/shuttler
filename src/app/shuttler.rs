
use std:: sync::Mutex;

use bitcoincore_rpc::{Auth, Client};
use cosmos_sdk_proto::cosmos::auth::v1beta1::{query_client::QueryClient as AuthQueryClient, QueryAccountRequest, BaseAccount};
use frost_core::{keys::{PublicKeyPackage, KeyPackage}, Field};
use crate::{app::config::{ AnyKey, Config, PrivValidatorKey}, helper::{bitcoin::get_group_address_by_tweak, cipher::random_bytes}};
use crate::helper::encoding::from_base64;
use frost::Identifier; 
use frost_secp256k1_tr::{self as frost, Secp256K1Sha256};

use tracing::info;
use ed25519_compact:: SecretKey;

use lazy_static::lazy_static;

use super::config::Keypair;

lazy_static! {
    static ref BASE_ACCOUNT: Mutex<Option<BaseAccount>> = {
        Mutex::new(None)
    };
}

pub struct Shuttler {
    config: Config,
    pub identity_key: SecretKey,
    identifier: Identifier,
    pub priv_validator_key: PrivValidatorKey,
    pub bitcoin_client: Client,
}

impl Shuttler {
    pub fn new(conf: Config) -> Self {

        // load private key from priv_validator_key_path

        let validator_key = match conf.load_validator_key() {
            Ok(key) => {
                info!("You are running node in validator mode");
                key
            },
            Err(_) => {
                info!("You are running node in relayer mode");
                // return a empty key
                PrivValidatorKey {
                    address: "".to_string(),
                    priv_key: AnyKey {
                        value: "".to_string(),
                        r#type: "".to_string(),
                    },
                    pub_key: AnyKey {
                        value: "".to_string(),
                        r#type: "".to_string(),
                    },
                }
            }
        };

        let local_key = if validator_key.priv_key.value.len() > 0 {
            let b = from_base64(&validator_key.priv_key.value).expect("Decode private key failed");
            SecretKey::from_slice(b.as_slice()).expect("invalid secret key")
        } else {
            SecretKey::from_slice(random_bytes(SecretKey::BYTES).as_slice()).expect("invalid secret key")
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
            priv_validator_key: validator_key,
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
        self.priv_validator_key.address.clone()
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

    fn generate_tweak(&self, _pubkey: PublicKeyPackage<Secp256K1Sha256>, index: u16) -> Option<[u8;32]> {
        if index == 0 {
            None
        } else {
            Some([0;32])
        }
    }

    pub fn generate_vault_addresses(&mut self, pubkey: PublicKeyPackage<Secp256K1Sha256>, key: KeyPackage<Secp256K1Sha256>, address_num: u16) -> Vec<String> {

        let mut addrs = vec![];
        for i in 0..address_num {
            let tweak = self.generate_tweak(pubkey.clone(), i);
            let address_with_tweak = get_group_address_by_tweak(&pubkey.verifying_key(), tweak.clone(), self.config.bitcoin.network);

            addrs.push(address_with_tweak.to_string());
            self.config.keypairs.insert(address_with_tweak.to_string(), Keypair{
                priv_key: key.clone(),
                pub_key: pubkey.clone(),
                tweak: tweak,
            });
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
