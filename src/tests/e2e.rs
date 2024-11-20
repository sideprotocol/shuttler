use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::fs;

use cosmos_sdk_proto::side::btcbridge::query_client::QueryClient as BtcQueryClient;
use cosmos_sdk_proto::side::btcbridge::query_server::QueryServer;
use cosmos_sdk_proto::side::btcbridge::{QuerySigningRequestsRequest, SigningStatus};
use futures::future::join_all;
use tendermint::account::Id;
use tendermint:: PrivateKey;
use tempfile::TempDir;
use tendermint_config::PrivValidatorKey;
use tonic::transport::Server;
use crate::app::config;
use crate::mock::{DKG_FILE_NAME, MockQuery, DKG};


#[tokio::test]
async fn test_mock_service() {
    let addr = "[::1]:9090".parse().expect("msg");
    // let greeter = ;
    let tempdir = TempDir::new().unwrap();
    let s = MockQuery::new(String::from(tempdir.path().to_str().unwrap()));
    
    Server::builder()
        // .add_service(Service::new(greeter))
        .add_service(QueryServer::new(s))
        .serve(addr)
        .await.unwrap();

    // Ok(())
}

#[tokio::test]
async fn test_grpc_client() {
    let host = "http://localhost:9090";
    let mut client = match BtcQueryClient::connect(host.to_owned()).await {
        Ok(client) => client,
        Err(e) => {
            println!("error: {}", e);
            return;
        }
    };
    if let Ok(requests_response) = client
        .query_signing_requests(QuerySigningRequestsRequest {
            status: SigningStatus::Pending as i32,
            pagination: None
        })
        .await {
            let rs = requests_response.into_inner();
            println!("response: {:?}", rs)
        }
    println!("done.")
}

#[tokio::test]
async fn test_cluster() {
    
    // parameters
    let n: u32 = 3;
    let executor = "/Users/developer/workspace/tssigner/target/debug/shuttler";
    let network = bitcoin::Network::Bitcoin;
    let port = 5150;

    let testdir = TempDir::new().expect("Unable to create test directory!");
    println!("Create test home: {:?}", testdir);

    // prepare 
    let mut handles = vec![];
    let home = String::from(testdir.path().to_str().unwrap());
    // Start mock gRPC server
    let handle = tokio::spawn(async move {
        let addr = "[::1]:9090".parse().expect("msg");
        let s = MockQuery::new(home);
        
        Server::builder()
            // .add_service(Service::new(greeter))
            .add_service(QueryServer::new(s))
            .serve(addr)
            .await.unwrap();
    });
    handles.push(handle);

    
    let mut participants = vec![];
    
    for i in 1..=n {
        let mut home_i = PathBuf::new();
        home_i.push(testdir.path());
        home_i.push(format!("home{}", i));
        
        fs::create_dir_all(home_i.clone()).expect("initial home i");

        config::Config::default(home_i.to_str().unwrap(), port+i, network).save().unwrap();

        let rng = rand::thread_rng();
        let sk = ed25519_consensus::SigningKey::new(rng);
        let priv_key = PrivateKey::from_ed25519_consensus(sk);
        let priv_validator_key = PrivValidatorKey {
            address: Id::from(priv_key.public_key()),
            pub_key: priv_key.public_key(),
            priv_key,
        };

        participants.push(priv_validator_key.address.to_string());

        let text= serde_json::to_string_pretty(&priv_validator_key).unwrap();
        
        println!("key: {}", text);
        fs::write(home_i.join("priv_validator_key.json"), text).unwrap();

        let x = fs::read_dir(home_i.clone()).unwrap();
        x.for_each(|f| {
            match f {
                Ok(d) => {
                    println!("file: {:?}", d);
                },
                Err(e) => {
                    println!("error: {}", e);
                }
            }
        });

        let handler = tokio::spawn( async move {
            
            let log = File::create(home_i.join("log.txt")).expect("failed to open log");

            let mut child = Command::new(executor)
                .arg("--home")
                .arg(home_i.to_str().unwrap())
                .arg("start")
                .arg("--signer")
                .stdout(log)
                .spawn()
                .expect("failed to start echo");

            child.wait().expect("failed to finish echo");
        });

        handles.push(handler);
    }

    let dkg = DKG{
        id: 1,
        threshold: (participants.len() * 2/3 ) as u32,
        participants,
    };
    let contents = serde_json::to_string(&dkg).unwrap();
    let mut path = PathBuf::new();
    path.push(testdir.path());
    path.push(DKG_FILE_NAME);
    fs::write(path, contents).unwrap();

    join_all(handles).await;

    // println!("Press any key to abort!");
    // let mut buffer = String::new();
    // io::stdin().read_line(&mut buffer).expect("");

    println!("Quited");

}