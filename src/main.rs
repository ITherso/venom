use venom::{proxy::MitmServer, scanner::Scanner, repeater::Repeater, database, api::ApiServer, loadtest::{LoadTestRunner, profiles::{LoadProfile, LoadTestConfig}}};
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
    Api {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value = "3000")]
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
    LoadTest {
        #[arg(value_name = "URL")]
        target: String,
        #[arg(long, default_value = "baseline")]
        profile: String,
        #[arg(long)]
        generate_scripts: bool,
        #[arg(long)]
        output_dir: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    // Install Rustls crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

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

        Commands::Api { host, port } => {
            println!("🔴 VENOM - API Server");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("[+] API listening on http://{}:{}", host, port);
            println!("[+] Task Management: POST /api/tasks");
            println!("[+] WebSocket: ws://{}:{}/ws", host, port);
            println!("[+] Dashboard: http://{}:{}/dashboard", host, port);

            let api_server = ApiServer::new(&host, port);
            if let Err(e) = api_server.start().await {
                eprintln!("[!] API error: {}", e);
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

        Commands::LoadTest { target, profile, generate_scripts, output_dir } => {
            println!("🔥 VENOM - Load Testing Suite");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("[*] Target: {}", target);
            println!("[*] Profile: {}", profile);
            println!();

            // Parse profile
            let load_profile = match profile.as_str() {
                "baseline" => LoadProfile::Baseline,
                "standard" => LoadProfile::Standard,
                "high" => LoadProfile::High,
                "stress" => LoadProfile::Stress,
                "spike" => LoadProfile::Spike,
                _ => {
                    eprintln!("[!] Unknown profile: {}. Use: baseline, standard, high, stress, spike", profile);
                    return;
                }
            };

            let config = load_profile.config(&target);
            println!("[+] Configuration:");
            println!("    Concurrent Users: {}", config.concurrent_users);
            println!("    Requests/sec: {}", config.requests_per_second);
            println!("    Duration: {}s", config.duration_seconds);
            println!();

            if generate_scripts {
                let out_dir = output_dir.unwrap_or_else(|| ".venom/loadtest".to_string());
                let _ = std::fs::create_dir_all(&out_dir);

                println!("[*] Generating load test scripts...");

                // Generate Apache Bench script
                let ab_path = format!("{}/bench-{}.sh", out_dir, profile);
                match LoadTestRunner::generate_ab_script(&config, &ab_path).await {
                    Ok(_) => println!("[+] Apache Bench script: {}", ab_path),
                    Err(e) => eprintln!("[!] Error generating AB script: {}", e),
                }

                // Generate wrk Lua script
                let wrk_path = format!("{}/bench-{}.lua", out_dir, profile);
                match LoadTestRunner::generate_wrk_script_file(&config, &wrk_path).await {
                    Ok(_) => println!("[+] wrk Lua script: {}", wrk_path),
                    Err(e) => eprintln!("[!] Error generating wrk script: {}", e),
                }

                // Generate combined benchmark script
                let combined_path = format!("{}/benchmark-{}.sh", out_dir, profile);
                match LoadTestRunner::generate_benchmark_script(&config, &combined_path).await {
                    Ok(_) => println!("[+] Combined benchmark script: {}", combined_path),
                    Err(e) => eprintln!("[!] Error generating benchmark script: {}", e),
                }

                // Generate docker-compose for monitoring
                let docker_path = format!("{}/docker-compose.yml", out_dir);
                match LoadTestRunner::generate_docker_compose(&docker_path).await {
                    Ok(_) => println!("[+] Docker Compose: {}", docker_path),
                    Err(e) => eprintln!("[!] Error generating docker-compose: {}", e),
                }

                // Generate Prometheus config
                let prom_path = format!("{}/prometheus.yml", out_dir);
                match LoadTestRunner::generate_prometheus_config(&prom_path).await {
                    Ok(_) => println!("[+] Prometheus config: {}", prom_path),
                    Err(e) => eprintln!("[!] Error generating prometheus config: {}", e),
                }

                println!();
                println!("[+] Load test scripts generated!");
                println!("[*] Usage:");
                println!("    bash {}", combined_path);
                println!("    or");
                println!("    bash {}", ab_path);
            } else {
                println!("[*] Apache Bench command:");
                println!("    {}", LoadTestRunner::generate_ab_command(&config));
                println!();
                println!("[*] wrk command:");
                println!("    wrk -t {} -c {} -d {}s {}",
                    config.concurrent_users / 4.max(1),
                    config.concurrent_users,
                    config.duration_seconds,
                    config.target_url
                );
            }
        }
    }
}
