//! Example: VENOM Error Handling with Rich Context
//!
//! Demonstrates:
//! - Creating typed errors with context
//! - Error classification (transient vs critical)
//! - Proper error propagation
//! - Logging and error reporting

use venom_core::{Error, Result};

fn main() -> Result<()> {
    println!("=== VENOM Error Handling Examples ===\n");

    // Example 1: Creating typed errors
    println!("📋 Example 1: Typed Errors");
    demo_typed_errors()?;
    println!();

    // Example 2: Error classification
    println!("📋 Example 2: Error Classification");
    demo_error_classification();
    println!();

    // Example 3: Error propagation
    println!("📋 Example 3: Error Propagation");
    demo_error_propagation()?;
    println!();

    // Example 4: Error handling strategy
    println!("📋 Example 4: Error Handling Strategy");
    demo_error_strategy();
    println!();

    println!("✅ All examples completed!");
    Ok(())
}

/// Demonstrates creating different typed errors
fn demo_typed_errors() -> Result<()> {
    // Configuration error
    let err = Error::config("Invalid scan intensity: 'ultra'");
    println!("Config Error: {}", err);
    println!("  Kind: {}\n", err.kind());

    // Scanner error
    let err = Error::scanner("Phase 5 timed out after 300s");
    println!("Scanner Error: {}", err);
    println!("  Kind: {}\n", err.kind());

    // Network error
    let err = Error::network("Connection refused: 127.0.0.1:8080");
    println!("Network Error: {}", err);
    println!("  Kind: {}\n", err.kind());

    // Plugin error
    let err = Error::plugin("Failed to load plugin: xss_scanner.so");
    println!("Plugin Error: {}", err);
    println!("  Kind: {}\n", err.kind());

    // Custom error with context
    let err = Error::custom("SCAN_PHASE_3", "XSS detection failed for parameter 'id'");
    println!("Custom Error: {}", err);
    println!("  Kind: {}\n", err.kind());

    Ok(())
}

/// Demonstrates error classification
fn demo_error_classification() {
    let errors = vec![
        Error::network("timeout"),
        Error::rate_limit("429 Too Many Requests"),
        Error::config("invalid target"),
        Error::tls("certificate expired"),
        Error::database("connection pool exhausted"),
    ];

    for err in errors {
        let is_transient = err.is_transient();
        let is_critical = err.is_critical();

        println!(
            "Error: {:15} | Transient: {:5} | Critical: {:5}",
            err.kind(),
            is_transient,
            is_critical
        );

        if is_transient {
            println!("  → Can retry this error");
        }
        if is_critical {
            println!("  → Should stop scanning");
        }
    }
    println!();
}

/// Demonstrates error propagation with ? operator
fn demo_error_propagation() -> Result<()> {
    println!("Simulating scanning pipeline...");

    // This would normally be called in sequence
    scan_target("http://invalid")?;

    println!("Scan completed!");
    Ok(())
}

fn scan_target(target: &str) -> Result<()> {
    // Validate target
    if target.is_empty() {
        return Err(Error::target("Target URL cannot be empty"));
    }

    if !target.starts_with("http://") && !target.starts_with("https://") {
        return Err(Error::target("Target must be a valid HTTP(S) URL"));
    }

    println!("Target validated: {}", target);

    // Simulate phase execution
    execute_phase()?;

    Ok(())
}

fn execute_phase() -> Result<()> {
    println!("Executing phase...");

    // Simulate different error conditions
    let should_fail = true;

    if should_fail {
        return Err(Error::scanner(
            "Phase timed out - target may be rate limiting",
        ));
    }

    println!("Phase completed!");
    Ok(())
}

/// Demonstrates handling errors by category
fn demo_error_strategy() {
    let errors = vec![
        Error::network("Connection timeout"),
        Error::config("Invalid configuration"),
        Error::scanner("Vulnerability detection failed"),
        Error::rate_limit("Too many requests"),
        Error::threading("Worker thread panicked"),
    ];

    for err in errors {
        handle_error(&err);
        println!();
    }
}

/// Error handling strategy based on error type
fn handle_error(err: &Error) {
    println!("Handling error: {}", err);
    println!("  Kind: {}", err.kind());

    match err.kind() {
        "NETWORK" => {
            println!("  → Strategy: Retry with exponential backoff");
            println!("  → Retry delay: 1s, 2s, 4s, 8s");
        }
        "CONFIG" => {
            println!("  → Strategy: Log error and stop scanning");
            println!("  → Action: User must fix configuration");
        }
        "SCANNER" => {
            println!("  → Strategy: Log error and skip current phase");
            println!("  → Action: Continue with next phase if possible");
        }
        "RATE_LIMIT" => {
            println!("  → Strategy: Retry with longer delay");
            println!("  → Retry delay: 60s (honor Retry-After header)");
        }
        "THREADING" => {
            println!("  → Strategy: Spawn replacement worker");
            println!("  → Action: Resume from last checkpoint");
        }
        _ => {
            println!("  → Strategy: Log and investigate");
            println!("  → Action: May require manual intervention");
        }
    }
}
