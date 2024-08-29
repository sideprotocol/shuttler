use clap::Parser;
use shuttler::commands::{address, init, reset, start, Cli, Commands};

#[tokio::main]
async fn main() {
    // Initialize tracing with customization
    let cli = Cli::parse();
    match &cli.command {
        Commands::Init { port, network } => {
            init::execute(&cli, port.to_owned(), network.to_owned());
        }
        Commands::Start {relayer, signer} => {
            start::execute(&cli.home, *relayer, *signer).await;
        }
        Commands::Address => {
            address::execute(&cli);
        }
        Commands::Reset => {
            reset::execute(&cli);
        }
    }
}

