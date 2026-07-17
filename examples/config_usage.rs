//! Example: Using VENOM Configuration with Builder Pattern
//!
//! This example demonstrates:
//! - ConfigBuilder pattern for fluent configuration
//! - Configuration validation
//! - Environment variable overrides
//! - Exporting to TOML/JSON

use venom_core::{Config, ScanIntensity, ConfigError};

fn main() -> Result<(), ConfigError> {
    println!("=== VENOM Configuration Examples ===\n");

    // Example 1: Basic configuration with builder
    println!("📋 Example 1: Basic Configuration");
    let config = Config::builder("http://localhost:8080")
        .timeout(300)
        .threads(4)
        .build()?;

    println!("Target: {}", config.target);
    println!("Timeout: {}s", config.timeout_secs);
    println!("Threads: {}\n", config.num_threads);

    // Example 2: Aggressive scanning configuration
    println!("📋 Example 2: Aggressive Scanning");
    let config = Config::builder("https://api.example.com")
        .intensity(ScanIntensity::Aggressive)
        .timeout(600)
        .threads(16)
        .rate_limit(100)
        .aggressive(true)
        .max_payload_size(65536)
        .build()?;

    println!("Target: {}", config.target);
    println!("Intensity: {}", config.intensity.as_str());
    println!("Threads: {}", config.num_threads);
    println!("Rate Limit: {} RPS", config.rate_limit_rps);
    println!("Aggressive: {}\n", config.aggressive);

    // Example 3: Stealth scanning (slow, evasive)
    println!("📋 Example 3: Stealth Scanning");
    let config = Config::builder("https://defended-app.example.com")
        .intensity(ScanIntensity::Stealth)
        .timeout(3600)
        .threads(1)
        .rate_limit(2)
        .verify_ssl(false)
        .option("waf_evasion", "true")
        .option("encoding", "random")
        .build()?;

    println!("Target: {}", config.target);
    println!("Intensity: {}", config.intensity.as_str());
    println!("Threads: {}", config.num_threads);
    println!("SSL Verify: {}", config.verify_ssl);
    println!("Custom Options: {:?}\n", config.options);

    // Example 4: Configuration with custom options
    println!("📋 Example 4: Configuration with Custom Options");
    let config = Config::builder("http://internal-app.corp:8080")
        .intensity(ScanIntensity::Normal)
        .threads(8)
        .option("proxy", "http://corp-proxy:3128")
        .option("auth_type", "ntlm")
        .option("auth_user", "corp\\admin")
        .option("skip_ssl_verification", "false")
        .build()?;

    println!("Target: {}", config.target);
    println!("Proxy: {}", config.options.get("proxy").unwrap_or(&"none".to_string()));
    println!("Auth: {}", config.options.get("auth_type").unwrap_or(&"none".to_string()));
    println!();

    // Example 5: Export configuration to TOML
    println!("📋 Example 5: Export to TOML");
    let config = Config::builder("https://target.com")
        .timeout(300)
        .threads(4)
        .build()?;

    let toml = config.to_toml()?;
    println!("TOML Output:\n{}\n", toml);

    // Example 6: Export configuration to JSON
    println!("📋 Example 6: Export to JSON");
    let json = config.to_json()?;
    println!("JSON Output:\n{}\n", json);

    // Example 7: Configuration validation
    println!("📋 Example 7: Configuration Validation");
    let result = Config::builder("http://target.com")
        .timeout(0)  // This will fail validation
        .build();

    match result {
        Ok(_) => println!("Configuration is valid"),
        Err(e) => println!("Validation error: {}", e),
    }

    println!();
    println!("✅ All examples completed!");

    Ok(())
}
