use std::{fs::{self, File}, path::PathBuf, thread, time::Duration};

use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::Validator;
use cosmos_sdk_proto::cosmos::auth::v1beta1::query_server::QueryServer as AuthServer;
use cosmos_sdk_proto::cosmos::tx::v1beta1::service_server::ServiceServer as TxServer;
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_server::ServiceServer as BlockServer;
use cosmrs::Any;
use tempfile::TempDir;
use tendermint::{account::Id, PrivateKey};
use tendermint_config::PrivValidatorKey;
use tonic::transport::Server;
use std::process::Command;

use crate::{config, helper::encoding::to_base64, mock::{websocket, MockBlockService, MockEnv, MockQuery, MockTxService}};

pub async fn execute(bin: &'static str, n: u32, tx: u32, delay: u32, module: String) {
    // parameters
    //let n: u32 = 3;
    let executor = bin;
    let network = bitcoin::Network::Bitcoin;
    let port = 5150;

    let testdir = TempDir::new().expect("Unable to create test directory!");
    println!("Create test home: {:?}", testdir);

    // prepare 
    let home = String::from(testdir.path().to_str().unwrap());    
    let mut participants: Vec<PrivValidatorKey> = vec![];
    for i in 1..=n {

        let rng = rand::thread_rng();
        let sk = ed25519_consensus::SigningKey::new(rng);
        let priv_key = PrivateKey::from_ed25519_consensus(sk);
        println!("{i}.{}", priv_key.public_key().to_hex().to_ascii_lowercase());
        
        let priv_validator_key = PrivValidatorKey {
            address: Id::from(priv_key.public_key()),
            pub_key: priv_key.public_key(),
            priv_key,
        };

        participants.push(priv_validator_key);
    }

    let mock_env = MockEnv::new(home.clone(), module.clone(), participants.iter().map(|p| to_base64(&p.pub_key.to_bytes())).collect::<Vec<_>>());
    tokio::spawn(async move{
        websocket::start(mock_env).await;
    });

    thread::sleep(Duration::from_secs(2));

    // start tss node for each validator
    participants.iter().enumerate().for_each(|(i, v)| {
        let mut home_i = PathBuf::new();
        home_i.push(testdir.path());
        home_i.push(format!("home{}", i));
        
        fs::create_dir_all(home_i.clone()).expect("initial home i");
        let mut conf = config::Config::default(home_i.to_str().unwrap(), port+(i as u32) , network);
        if i == 1 {
            conf.enable_rpc = true;
        }
        conf.save().unwrap();

        let text= serde_json::to_string_pretty(&v).unwrap();
        fs::write(home_i.join("priv_validator_key.json"), text).unwrap();

        let module2 = module.clone();
        thread::spawn(move || {
            let log = File::create(home_i.join("log.txt")).expect("failed to open log");
            std::thread::sleep(Duration::from_secs(delay as u64));
            Command::new(executor)
                .arg("--home")
                .arg(home_i.to_str().unwrap())
                .arg("start")
                .arg(format!("--{}", &module2))
                .stdout(log)
                .spawn()
                .expect("failed to start echo");
        });
    });

    let addr = "[::1]:9090".parse().expect("msg");
    let s = MockQuery::new(home.clone());
        
    Server::builder()
        // .add_service(OracleQueryServer::new(s.clone()))
        // .add_service(BridgeQueryServer::new(s.clone()))
        .add_service(AuthServer::new(s))
        .add_service(TxServer::new(MockTxService{home: home.clone(), tx}))
        .add_service(BlockServer::new(MockBlockService::new(participants.iter().map(|p| { Validator{
            pub_key: Some(Any {
                type_url: "tendermint/PubKeyEd25519".to_string(),
                value: p.priv_key.public_key().to_bytes(),
            }),
            address: Id::from(p.priv_key.public_key()).to_string(),
            voting_power: 1,
            proposer_priority: 1,
        }}).collect())))

        .serve(addr)
        .await.unwrap();

    println!("Quited");
}

