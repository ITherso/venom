use venom::{proxy::MitmProxy, scanner::Scanner, repeater::Repeater, database};
use clap::{Parser, Subcommand};
use std::path::Path;

#[derive(Parser)]
#[command(name = "VENOM")]
#[command(about = "Rust Web Pentesting Framework")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Proxy {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value = "8080")]
        port: u16,
    },
    Scanner {
        #[arg(value_name = "URL")]
        target: String,
        #[arg(long)]
        aggressive: bool,
    },
    Repeater {
        #[arg(value_name = "URL")]
        url: String,
        #[arg(long, default_value = "GET")]
        method: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Proxy { host, port } => {
            println!("🔴 VENOM - MITM Proxy Starting");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            let db_path = dirs::home_dir()
                .map(|p| p.join(".venom/history.db"))
                .unwrap_or_else(|| ".venom/history.db".into());

            if let Some(parent) = db_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            match database::init_pool(db_path.to_str().unwrap_or("history.db")).await {
                Ok(pool) => {
                    match MitmProxy::new(&host, port, pool).await {
                        Ok(proxy) => {
                            println!("[+] Database initialized at {:?}", db_path);
                            println!("[+] Proxy listening on {}:{}", host, port);
                            if let Err(e) = proxy.start().await {
                                eprintln!("[!] Proxy error: {}", e);
                            }
                        }
                        Err(e) => eprintln!("[!] Failed to create proxy: {}", e),
                    }
                }
                Err(e) => eprintln!("[!] Database error: {}", e),
            }
        }

        Commands::Scanner { target, aggressive } => {
            println!("🔴 VENOM - Scanner Starting");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("[*] Target: {}", target);
            println!("[*] Aggressive: {}", aggressive);
            println!();

            let scanner = Scanner::new(target, aggressive);
            match scanner.scan().await {
                Ok(vulns) => {
                    if vulns.is_empty() {
                        println!("[+] No vulnerabilities found");
                    } else {
                        println!("[+] Found {} vulnerabilities:\n", vulns.len());
                        for v in vulns {
                            println!("  [{}] {} - {}", v.severity, v.vuln_type, v.url);
                            println!("      Payload: {}", v.payload);
                            println!("      Status: {}\n", v.response_code);
                        }
                    }
                }
                Err(e) => eprintln!("[!] Scan error: {}", e),
            }
        }

        Commands::Repeater { url, method } => {
            println!("🔴 VENOM - Repeater");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("[*] URL: {}", url);
            println!("[*] Method: {}", method);

            let repeater = Repeater::new();
            match repeater.send(&url, &method, None).await {
                Ok(resp) => println!("[+] Response:\n{}", resp),
                Err(e) => eprintln!("[!] Error: {}", e),
            }
        }
    }
}
