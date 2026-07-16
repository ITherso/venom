use clap::{Parser, Subcommand};
use venom_scanner::Scanner;
use venom_api;
use venom_proxy::ProxyServer;

#[derive(Parser)]
#[command(name = "venom")]
#[command(about = "VENOM - Enterprise Pentesting Platform", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the scanning engine
    Scan { target: String },
    /// Start the API server
    Api {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
    /// Start the proxy server
    Proxy {
        #[arg(long, default_value = "127.0.0.1:8081")]
        addr: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan { target }) => {
            let scanner = Scanner::new(target);
            let _results = scanner.scan().await?;
            println!("Scan complete");
        }
        Some(Commands::Api { addr }) => {
            venom_api::start_api(&addr).await?;
        }
        Some(Commands::Proxy { addr }) => {
            let parts: Vec<&str> = addr.split(':').collect();
            if parts.len() == 2 {
                let proxy = ProxyServer::new(parts[0].to_string(), parts[1].parse()?);
                proxy.start().await?;
            }
        }
        None => {
            println!("VENOM v1.0.0 - Enterprise Pentesting Platform");
            println!("Use --help for more information");
        }
    }

    Ok(())
}
