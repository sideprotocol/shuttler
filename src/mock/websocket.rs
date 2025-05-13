use std::{collections::BTreeMap, str::FromStr, time::Duration};

use futures::{SinkExt, StreamExt};
use serde::Serialize;
use tendermint::{abci::response::FinalizeBlock, account::Id, block::{header::Version, Header, Height, Id as BlockId}, evidence::List, AppHash, Block, Hash, Time};
use tendermint_rpc::event::v0_38::{SerEvent, SerEventData};
use tokio::{net::{TcpListener, TcpStream}, select};

use crate::{apps::SideEvent, mock::generate_event_queue};

use super::{EventQueue, MockEnv};

pub async fn start(mock_env: MockEnv) {
    let addr = "0.0.0.0:26657";
    let listener = TcpListener::bind(&addr).await.expect("Can't listen");
    tracing::info!("Listening on: {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        let peer = stream.peer_addr().expect("connected streams should have a peer address");
        tracing::info!("Peer address: {}", peer);
        let env2 = mock_env.clone();
        tokio::spawn(accept_connection(env2,  stream));
    }  
}

async fn accept_connection(mock_env: MockEnv, stream: TcpStream ) {
    let addr = stream.peer_addr().expect("connected streams should have a peer address");
    tracing::info!("Peer address: {}", addr);

    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");

    tracing::info!("New WebSocket connection: {}", addr);

    let (mut write, mut read) = ws_stream.split();
    // let msg = r#"{"jsonrpc":"2.0","id":0,"result":{}}"#;
    // match write.send(tokio_tungstenite::tungstenite::Message::Text(msg.into())).await {
    //     Ok(_) =>  tracing::info!("block"),
    //     Err(e) => tracing::error!("emit event error {}", e),
    // };
    // We should not forward messages other than text or binary.
    let mut ticker = tokio::time::interval(Duration::from_secs(6));
    let mut last = None; 
    let queue = generate_event_queue(&mock_env.module);

    loop {
        select! {
            Some(Ok(x)) = read.next() => {
                println!("recv: {:?}", x)
            }
            _ = ticker.tick() => {

                let header = mock_block(last);
                let block = Block::new(header.clone(), vec![vec![]], List::new(vec![]), None);
          
                let event = SerEvent { 
                    query: "tm.event='NewBlock'".to_owned(), 
                    data: SerEventData::NewBlock { 
                        block: Some(Box::new(block)), 
                        block_id: BlockId::from_str("26C0A41F3243C6BCD7AD2DFF8A8D83A71D29D307B5326C227F734A1A512FE47D").unwrap(), 
                        result_finalize_block: Some(FinalizeBlock { 
                            events: create_tx_event(&queue, &header.height, &mock_env), 
                            tx_results: vec![], 
                            validator_updates: vec![], 
                            consensus_param_updates: None, 
                            app_hash: AppHash::from_str("BEA45FCF7F0218B201D2C261C0968AF145882B7FBEF5B6BC23561183A00C7C6C").unwrap(),
                        }), 
                    },
                    events: Some(create_block_event(&queue, &header.height, &mock_env)), 
                };
                let value = JSONRPC::new(event);

                let mut block_text = serde_json::to_string(&value).unwrap();
                block_text = block_text.replace("NewBlock", "tendermint/event/NewBlock");
                tracing::info!("block: {:?}", block_text);
                let re = write.send(tokio_tungstenite::tungstenite::Message::Text(block_text.into())).await;
                assert!(re.is_ok(), "send block response ");

                last = Some(header);
                
            }
        }
    };

}

fn create_block_event(queue: &EventQueue, height: &Height, env: &MockEnv) -> BTreeMap<String, Vec<String>> {
    if let Some(f) = queue.get(&height.value()) {
        if let SideEvent::BlockEvent(evt) = f(env.clone(), height.clone()) {
            return evt;
        };
    }
    BTreeMap::new()
}

fn create_tx_event(queue: &EventQueue, height: &Height, env: &MockEnv) -> Vec<tendermint::abci::Event> {
    if let Some(f) = queue.get(&height.value()) {
        if let SideEvent::TxEvent(evt) = f(env.clone(), height.clone()) {
            return evt;
        };
    }
    vec![]
}

fn mock_block(last: Option<Header>) -> Header {
    let height = if let Some(l) = last { l.height.increment() } else { Height::default() };
    Header{ 
        version: Version { block: 1, app: 1 }, 
        chain_id: "devnet-1".parse().unwrap(), 
        height, 
        time: Time::now(), 
        last_block_id: None, 
        last_commit_hash: None, data_hash: None, 
        validators_hash: Hash::from_str("C6FCA431C16D5EA9CCC5BCC9743CF7351962656D16180D5692EB14F0E8599C6D").unwrap(), 
        next_validators_hash: Hash::from_str("C6FCA431C16D5EA9CCC5BCC9743CF7351962656D16180D5692EB14F0E8599C6D").unwrap(), 
        consensus_hash: Hash::from_str("C6FCA431C16D5EA9CCC5BCC9743CF7351962656D16180D5692EB14F0E8599C6D").unwrap(), 
        app_hash: AppHash::from_hex_upper("2D034E6BC29B00A09BE33D2D4E6FAE5DF72E78E9EF6E67D4C46DE4C8160218A5").unwrap(), 
        last_results_hash: None, 
        evidence_hash: None, 
        proposer_address: Id::from_str("C68DD64D2D5B79232D6882875811B17E4D6F516E").unwrap()
    }

}

#[derive(Serialize)]
struct JSONRPC {
    jsonrpc: String,
    id: u64,
    result: SerEvent,
}

impl JSONRPC {
    pub fn new(result: SerEvent) -> Self {
        Self { jsonrpc: "2.0".to_owned(), id: 0, result }
    }
}
