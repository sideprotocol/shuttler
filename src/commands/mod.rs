use clap::{Parser, Subcommand};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::config;
use log::{info, error};


#[derive(Parser)]
#[command(name = "tssigner", version = "0.1.0", author = "Side Labs")]
#[command(about = "A threshold vault signer of Side Bitcoin Bridge", long_about = None)]
pub struct Cli {
    #[clap(long, default_value = ".tssigner")]
    pub home: String,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Init {
        #[clap(long, default_value = "5121")]
        port: u16,    
    },
    /// Remove an item
    DKG,
    Sign {
        pbst: String,
    },
    /// Start a libp2p node
    Start,
}

pub mod init;
pub mod dkg;
pub mod sign;
pub mod start;

pub async fn publish(conf: &config::Config, task: crate::messages::Task) {
    match TcpStream::connect(conf.command_server.clone()).await {
        Ok(mut stream) => {
            let message = serde_json::to_string(&task).unwrap();
            if let Err(e) = stream.write_all(message.as_bytes()).await {
                error!("Failed to send message: {}", e);
                return;
            }
            info!("Sent: {}", message);
        }
        Err(e) => {
            error!("Failed to connect: {}", e);
        }
    }
}
