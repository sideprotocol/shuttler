use clap::Parser;
use tssigner::commands::{dkg, init, sign, start, Cli, Commands};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init => {
            init::execute(&cli);
        }
        Commands::DKG => {
            dkg::execute(&cli).await;
        }
        Commands::Sign { pbst } => {
            sign::execute(&cli, pbst.to_owned());
        }
        Commands::Start => {
            start::execute(&cli).await;
        }
    }
}
