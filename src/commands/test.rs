use std::{fs::{self, File}, path::PathBuf};

use cosmos_sdk_proto::side::btcbridge::query_server::QueryServer;
use cosmos_sdk_proto::cosmos::auth::v1beta1::query_server::QueryServer as AuthServer;
use cosmos_sdk_proto::cosmos::tx::v1beta1::service_server::ServiceServer as TxServer;
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_server::ServiceServer as BlockServer;
use tempfile::TempDir;
use tendermint::{account::Id, PrivateKey};
use tendermint_config::PrivValidatorKey;
use tonic::transport::Server;
use std::process::Command;

use crate::{app::config, mock::{MockBlockService, MockQuery, MockTxService, DKG, DKG_FILE_NAME}};

pub async fn execute(bin: &'static str, n: u32) {
    // parameters
    //let n: u32 = 3;
    let executor = bin;
    let network = bitcoin::Network::Bitcoin;
    let port = 5150;

    let testdir = TempDir::new().expect("Unable to create test directory!");
    println!("Create test home: {:?}", testdir);

    // prepare 
    let home = String::from(testdir.path().to_str().unwrap());    
    let mut participants = vec![];
    
    for i in 1..=n {
        let mut home_i = PathBuf::new();
        home_i.push(testdir.path());
        home_i.push(format!("home{}", i));
        
        fs::create_dir_all(home_i.clone()).expect("initial home i");

        config::update_app_home(home_i.to_str().unwrap());
        config::Config::default(port+i, network).save().unwrap();

        let rng = rand::thread_rng();
        let sk = ed25519_consensus::SigningKey::new(rng);
        let priv_key = PrivateKey::from_ed25519_consensus(sk);
        println!("{i}.{}", priv_key.public_key().to_hex().to_ascii_lowercase());

        let priv_validator_key = PrivValidatorKey {
            address: Id::from(priv_key.public_key()),
            pub_key: priv_key.public_key(),
            priv_key,
        };

        participants.push(priv_validator_key.address.to_string());

        let text= serde_json::to_string_pretty(&priv_validator_key).unwrap();
        fs::write(home_i.join("priv_validator_key.json"), text).unwrap();

        let log = File::create(home_i.join("log.txt")).expect("failed to open log");

        Command::new(executor)
            .arg("--home")
            .arg(home_i.to_str().unwrap())
            .arg("start")
            .arg("--signer")
            .stdout(log)
            .spawn()
            .expect("failed to start echo");

        // child.wait().expect("failed to finish echo");
    }

    let dkg = DKG{
        id: 1,
        threshold: (participants.len() * 2/3 ) as u32,
        participants,
    };
    let contents = serde_json::to_string(&dkg).unwrap();
    let mut path = PathBuf::new();
    path.push(testdir.path());
    path.push("mock");
    let _ = fs::create_dir_all(&path);
    path.push(DKG_FILE_NAME);
    fs::write(path, contents).unwrap();

    let addr = "[::1]:9090".parse().expect("msg");
    let s = MockQuery::new(home.clone());
        
    Server::builder()
        // .max_concurrent_streams(Some(65535))
        // .concurrency_limit_per_connection(300)
        // .layer(ConnectionLi)
        // .add_service(Service::new(greeter))
        .add_service(QueryServer::new(s.clone()))
        .add_service(AuthServer::new(s))
        .add_service(TxServer::new(MockTxService{home: home.clone()}))
        .add_service(BlockServer::new(MockBlockService{}))
        .serve(addr)
        .await.unwrap();

    // println!("Press any key to abort!");
    // let mut buffer = String::new();
    // io::stdin().read_line(&mut buffer).expect("");

    println!("Quited");
}