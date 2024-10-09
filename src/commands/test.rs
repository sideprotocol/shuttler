use std::{fs, path::PathBuf};

use futures::future::join_all;
use tempfile::TempDir;
use tendermint::{account::Id, PrivateKey};
use tendermint_config::PrivValidatorKey;

use crate::{app::config, commands::start};

pub async fn execute() {
    let testdir = TempDir::new().expect("Unable to create test directory!");

    println!("Create test home: {:?}", testdir);

    // parameters
    let n: u32 = 3;
    let network = bitcoin::Network::Bitcoin;
    let port = 5150;

    // prepare 
    let mut handles = vec![];
    for i in 1..n {
        let mut home_i = PathBuf::new();
        home_i.push(testdir.path());
        home_i.push(format!("home{}", i));
        
        fs::create_dir_all(home_i.clone()).expect("initial home i");

        config::update_app_home(home_i.to_str().unwrap());
        config::Config::default(port+i, network).save().unwrap();

        let rng = rand::thread_rng();
        let sk = ed25519_consensus::SigningKey::new(rng);
        let priv_key = PrivateKey::from_ed25519_consensus(sk);
        let priv_validator_key = PrivValidatorKey {
            address: Id::from(priv_key.public_key()),
            pub_key: priv_key.public_key(),
            priv_key,
        };

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
            start::execute(home_i.to_str().unwrap(), false, true).await;
        });

        handles.push(handler);
    }

    join_all(handles).await;

    // println!("Press any key to abort!");
    // let mut buffer = String::new();
    // io::stdin().read_line(&mut buffer).expect("");

    println!("Quited");
}