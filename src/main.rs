use clap::Parser;
use shuttler::commands::{address, init, reset, start, Cli, Commands};
use tracing_subscriber::{FmtSubscriber, EnvFilter};

#[tokio::main]
async fn main() {
    // Initialize tracing with customization
    
    let filter = EnvFilter::new("info").add_directive("shuttler=debug".parse().unwrap());
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter) // Enable log filtering through environment variable
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

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

