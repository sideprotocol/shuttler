use tokio::{io::AsyncWriteExt, net::TcpStream};

use super::Cli;

pub async fn execute(cli: &Cli) {
    // Add your logic here
    let conf = crate::config::Config::from_file(&cli.home).unwrap();
    match TcpStream::connect(conf.message_server).await {
        Ok(mut stream) => {
            for i in 0..10 {
                let message = format!("Message {}", i);
                if let Err(e) = stream.write_all(message.as_bytes()).await {
                    println!("Failed to send message: {}", e);
                    return;
                }
                stream.flush().await.unwrap();
                println!("Sent: {}", message);
                // time::sleep(Duration::from_secs(1)).await;
            }
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
}