use venom::{proxy::MitmServer, scanner::Scanner, repeater::Repeater, database};
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

            let venom_dir = std::path::PathBuf::from(".venom");
            let db_path = venom_dir.join("history.db");
            let _ = std::fs::create_dir_all(&venom_dir);

            match database::init_pool(db_path.to_str().unwrap_or("history.db")).await {
                Ok(pool) => {
                    match MitmServer::new(&host, port, &venom_dir, pool).await {
                        Ok(server) => {
                            println!("[+] Database: {:?}", db_path);
                            println!("[+] CA Dir: {:?}", venom_dir);
                            println!("[+] Proxy listening on {}:{}", host, port);
                            if let Err(e) = server.start().await {
                                eprintln!("[!] Server error: {}", e);
                            }
                        }
                        Err(e) => eprintln!("[!] Failed to create server: {}", e),
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
                            println!("      Param: {}", v.parameter);
                            println!("      Payload: {}", v.payload);
                            println!("      Evidence: {}\n", v.evidence);
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
