use clap::{Parser, Subcommand};


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
    Init,
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
