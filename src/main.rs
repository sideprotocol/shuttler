use clap::Parser;
use shuttler::commands::{
    address, debug, id, init, reset, start, test,
    submit_header, submit_tx, Cli, Commands};

#[tokio::main(flavor = "multi_thread", worker_threads=4)]
async fn main() {
    // Initialize tracing with customization
    let cli = Cli::parse();
    match &cli.command {
        Commands::Init { port, network } => {
            init::execute(&cli, port.to_owned(), network.to_owned());
        }
        Commands::Start {relayer, signer, seed} => {
            start::execute(&cli.home, *relayer, *signer, *seed).await;
        }
        Commands::Address => {
            address::execute(&cli);
        }
        Commands::Reset => {
            reset::execute(&cli);
        }
        Commands::SubmitHeader { height } => {
            submit_header::execute(&cli.home, *height).await;
        }
        Commands::SubmitTx { hash} => {
            submit_tx::execute(&cli.home, hash).await;
        }
        Commands::Debug { txid } => {
            debug::execute(&cli, txid);
        }
        Commands::Id => {
            id::execute(&cli.home);
        }
        Commands::Test {bin, n, tx, delay} => {
            test::execute(bin.clone().leak(), *n, *tx, *delay).await;
        }
    }
}
