use async_std::{stream::StreamExt, task::block_on};
use bitcoin::absolute::Height;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoincore_zmq::subscribe_async;

//#[tokio::test]
// async fn test_zmq_async() {
//     info!("starting");
//     let mut stream = subscribe_async(&["tcp://149.28.156.79:38332"]).unwrap();

//     info!("started ");

//     loop {
//         select! {
//             zmq_msg = stream.next() => match zmq_msg {
//                 Some(block) => {
//                     info!("block: {:?}", block)
//                 },
//                 None => {
//                     info!("none is returned")
//                 }
//             },
//         }
//     }
// }

#[test]
fn test_zmq() {
    println!("start test zmq");
    let mut stream = subscribe_async(&["tcp://149.28.156.79:38332"]).unwrap();
    println!("started");

    // This is a small example to demonstrate subscribe_single_async, it is okay here to use
    // block_on, but not in production environments as this defeats the purpose of async.
    block_on(async {
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(msg) => println!("Received message: {msg}"),
                Err(err) => println!("Error receiving message: {err}"),
            }
        }
    });
}

#[test]
fn test_bitcoin_client() {
    let auth = Auth::UserPass("side".to_string(), "12345678".to_string());
    let client = Client::new("http://signet:38332", auth).expect("Cound not connect to bitcoin rpc");
    let height = client.get_block_count().expect("msg");
    assert_eq!(height > 0, true);

    let hash = client.get_best_block_hash().expect("failed to get hash");

    let block = client.get_block(&hash).expect("error");

    println!("version: {:?}", block.header.version.to_consensus());
    println!("nonce: {:?}", block.header.bits.to_consensus());
    println!("block: {:?}", block.header);
}

