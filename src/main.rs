use clap::Parser;
use tssigner::commands::{dkg, init, sign, start, Cli, Commands};
use env_logger;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    env_logger::init();
    match &cli.command {
        Commands::Init { port } => {
            init::execute(&cli, port.to_owned());
        }
        Commands::DKG => {
            dkg::execute(&cli).await;
        }
        Commands::Sign { pbst } => {
            sign::execute(&cli, pbst.to_owned()).await;
        }
        Commands::Start => {
            start::execute(&cli).await;
        }
    }
}

