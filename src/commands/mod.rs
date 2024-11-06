use bitcoin::Network;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "shuttler", version = "0.2.4", author = "Side Labs")]
#[command(about = "A threshold vault signer of Side Bitcoin Bridge", long_about = None)]
pub struct Cli {
    #[clap(long, default_value = ".tssigner")]
    pub home: String,
    #[clap(long, default_value = "false")]
    pub mock: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Init {
        #[clap(long, default_value = "5158")]
        port: u32,
        #[clap(long, default_value = "bitcoin")]
        network: Network    
    },
    /// Remove an item
    // DKG {
    //     #[clap(long, default_value = "2")]
    //     min_signers: u16,
    //     #[clap(long, default_value = "3")]
    //     max_signers: u16,
    // },
    // Sign {
    //     pbst: String,
    // },
    /// Start a libp2p node
    Start {
        #[clap(long, default_value = "false")]
        relayer: bool,
        #[clap(long, default_value = "false")]
        signer: bool,
    },
    #[command(about = "Submit a bitcoin header to the sidechain")]
    SubmitHeader {
        #[clap(long, default_value = "0")]
        height: u64,
    },
    #[command(about = "Submit a bitcoin transaction to the sidechain")]
    SubmitTx {
        #[clap(long, default_value = "")]
        hash: String,
    },
    Address,
    Reset,
    #[command(about = "Print TSS variables for debug")]
    Debug {
        txid: String,
    },
    Id,
    Test {
        #[clap(long, default_value = "shuttler")]
        bin: String,
        #[clap(long, default_value = "3")]
        n: u32,
    },
}

pub mod init;
pub mod start;
pub mod address;
pub mod reset;
pub mod submit_header;
pub mod submit_tx;
pub mod debug;
pub mod id;
pub mod test;
