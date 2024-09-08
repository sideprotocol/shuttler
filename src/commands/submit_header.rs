
use crate::{app::{config::Config, relayer::Relayer}, tickers::relayer};

pub async fn execute(home: &str, height: u64) {

    if height < 1 {
        println!("Invalid block height");
        return;
    }
    
    let conf = Config::from_file(home).unwrap();
    let relayer = Relayer::new(conf);
    match relayer::fetch_block_header_by_height(&relayer, height).await {
        Ok(header) => {
            match relayer::send_block_headers(&relayer, &vec![header]).await {
                Ok(_) => {
                    println!("Block header submitted successfully");
                }
                Err(e) => {
                    println!("Error submitting block header: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Error submitting block header: {:?}", e);
        }
    }

}