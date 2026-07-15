use crate::Result;
use super::profiles::LoadTestConfig;
use std::path::Path;
use tokio::fs;

pub struct LoadTestRunner;

impl LoadTestRunner {
    /// Generate Apache Bench command
    pub fn generate_ab_command(config: &LoadTestConfig) -> String {
        let mut cmd = format!(
            "ab -n {} -c {} -t {} ",
            config.requests_per_second * config.duration_seconds,
            config.concurrent_users,
            config.duration_seconds
        );

        // Add timeout
        cmd.push_str(&format!("-s {} ", config.timeout_seconds));

        // Add method if not GET
        if config.method != "GET" {
            cmd.push_str(&format!("-p {} ", config.method));
        }

        // Add headers
        for (key, value) in &config.headers {
            cmd.push_str(&format!("-H '{}:{}' ", key, value));
        }

        // Add body if POST/PUT
        if let Some(body) = &config.body {
            // Save body to temp file for ab
            cmd.push_str(&format!("-d '{}' ", body));
        }

        cmd.push_str(&config.target_url);
        cmd
    }

    /// Generate wrk Lua script for advanced load testing
    pub fn generate_wrk_script(config: &LoadTestConfig) -> String {
        let headers_lua = if config.headers.is_empty() {
            String::new()
        } else {
            let mut headers = String::from("request = function()\n  local req = wrk.format(nil, path)\n");
            for (key, value) in &config.headers {
                headers.push_str(&format!("  req.headers['{}'] = '{}'\n", key, value));
            }
            headers.push_str("  return req\nend\n");
            headers
        };

        let body_section = if let Some(body) = &config.body {
            format!(
                "wrk.body = [==[{}]==]\nwrk.method = '{}'\n",
                body, config.method
            )
        } else {
            String::new()
        };

        format!(
            r#"-- VENOM Load Test Script
-- Generated for: {}
-- Duration: {}s, Concurrent: {}, Target RPS: {}

wrk.host = "{}"
wrk.path = "/"
wrk.threads = {}
wrk.connections = {}
{}{}

response = function(status, headers, body)
  if status ~= 200 then
    io.stderr:write("Error: " .. status .. "\n")
  end
end

done = function(summary, latency, requests)
  print("=== VENOM Load Test Results ===")
  print(string.format("Requests: %d", summary.requests))
  print(string.format("Duration: %.2fs", summary.duration / 1e6))
  print(string.format("Errors: %d", summary.errors.connect + summary.errors.read + summary.errors.write + summary.errors.status + summary.errors.timeout))
  print(string.format("Latency (avg): %.2fms", latency.mean / 1000))
  print(string.format("Latency (p50): %.2fms", latency.percentile(50) / 1000))
  print(string.format("Latency (p95): %.2fms", latency.percentile(95) / 1000))
  print(string.format("Latency (p99): %.2fms", latency.percentile(99) / 1000))
  print(string.format("Throughput: %.2f req/s", summary.requests / (summary.duration / 1e6)))
end
"#,
            config.target_url,
            config.duration_seconds,
            config.concurrent_users,
            config.requests_per_second,
            config.target_url,
            config.concurrent_users / 4.max(1),
            config.concurrent_users,
            headers_lua,
            body_section
        )
    }

    /// Generate bash script that runs both ab and wrk
    pub async fn generate_benchmark_script(config: &LoadTestConfig, output_path: &str) -> Result<()> {
        let ab_cmd = Self::generate_ab_command(config);
        let wrk_script = Self::generate_wrk_script(config);

        let script = format!(
            r#"#!/bin/bash
# VENOM Load Test Script
# Target: {}
# Concurrent: {}, RPS: {}, Duration: {}s

set -e

echo "🔥 VENOM Load Testing Suite"
echo "════════════════════════════════════"
echo "Target: {}"
echo "Profile: {} concurrent users, {} req/s"
echo "Duration: {}s"
echo ""

# Create temporary wrk script
WRK_SCRIPT=$(mktemp)
cat > "$WRK_SCRIPT" << 'WRK_EOF'
{}
WRK_EOF

# Test 1: Apache Bench
echo "📊 Test 1: Apache Bench"
echo "─────────────────────"
echo "Command: {}"
echo ""

if command -v ab &> /dev/null; then
    {}
    echo ""
else
    echo "⚠️  Apache Bench (ab) not found. Install: apt-get install apache2-utils"
    echo ""
fi

# Test 2: wrk Load Tester
echo "📊 Test 2: wrk Lua Benchmarking"
echo "───────────────────────────────"
echo "Command: wrk -t {} -c {} -d {}s --script $WRK_SCRIPT {}"
echo ""

if command -v wrk &> /dev/null; then
    wrk -t {} -c {} -d {}s --script "$WRK_SCRIPT" {} || true
    echo ""
else
    echo "⚠️  wrk not found. Install from: https://github.com/wg/wrk"
    echo ""
fi

# Cleanup
rm -f "$WRK_SCRIPT"

echo "✅ Load testing complete!"
echo "════════════════════════════════════"
"#,
            config.target_url,
            config.concurrent_users,
            config.requests_per_second,
            config.duration_seconds,
            config.target_url,
            config.concurrent_users,
            config.requests_per_second,
            config.duration_seconds,
            wrk_script,
            ab_cmd,
            ab_cmd,
            config.concurrent_users / 4.max(1),
            config.concurrent_users,
            config.duration_seconds,
            config.target_url,
            config.concurrent_users / 4.max(1),
            config.concurrent_users,
            config.duration_seconds,
            config.target_url
        );

        fs::write(output_path, script).await?;

        // Make executable
        #[cfg(unix)]
        {
            use std::fs as std_fs;
            use std::os::unix::fs::PermissionsExt;
            let perms = std_fs::Permissions::from_mode(0o755);
            std_fs::set_permissions(output_path, perms)?;
        }

        Ok(())
    }

    /// Generate Apache Bench script
    pub async fn generate_ab_script(config: &LoadTestConfig, output_path: &str) -> Result<()> {
        let cmd = Self::generate_ab_command(config);

        let script = format!(
            r#"#!/bin/bash
# VENOM Apache Bench Script
# Generated for: {}

echo "🔥 Apache Bench Load Test"
echo "Target: {}"
echo "Concurrency: {}"
echo "Duration: {}s"
echo ""

if ! command -v ab &> /dev/null; then
    echo "❌ Apache Bench not found!"
    echo "Install: sudo apt-get install apache2-utils"
    exit 1
fi

# Run Apache Bench
{}

echo ""
echo "✅ Benchmark complete!"
"#,
            config.target_url,
            config.target_url,
            config.concurrent_users,
            config.duration_seconds,
            cmd
        );

        fs::write(output_path, script).await?;

        // Make executable
        #[cfg(unix)]
        {
            use std::fs as std_fs;
            use std::os::unix::fs::PermissionsExt;
            let perms = std_fs::Permissions::from_mode(0o755);
            std_fs::set_permissions(output_path, perms)?;
        }

        Ok(())
    }

    /// Generate wrk Lua script
    pub async fn generate_wrk_script_file(config: &LoadTestConfig, output_path: &str) -> Result<()> {
        let script = Self::generate_wrk_script(config);
        fs::write(output_path, script).await?;
        Ok(())
    }

    /// Generate docker-compose for load testing infrastructure
    pub async fn generate_docker_compose(output_path: &str) -> Result<()> {
        let compose = r#"version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-storage:/var/lib/grafana
    depends_on:
      - prometheus

  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

volumes:
  grafana-storage:
  redis-data:
"#;

        fs::write(output_path, compose).await?;
        Ok(())
    }

    /// Generate Prometheus config
    pub async fn generate_prometheus_config(output_path: &str) -> Result<()> {
        let config = r#"global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'venom-proxy'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:6379']
"#;

        fs::write(output_path, config).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loadtest::profiles::LoadProfile;

    #[test]
    fn test_ab_command_generation() {
        let config = LoadProfile::Baseline.config("http://localhost:8080");
        let cmd = LoadTestRunner::generate_ab_command(&config);

        assert!(cmd.contains("http://localhost:8080"));
        assert!(cmd.contains("-n 6000")); // 100 * 60
        assert!(cmd.contains("-c 10"));  // concurrent
        assert!(cmd.contains("-t 60"));  // timeout
    }

    #[test]
    fn test_wrk_script_generation() {
        let config = LoadProfile::Standard.config("http://target.com");
        let script = LoadTestRunner::generate_wrk_script(&config);

        assert!(script.contains("target.com"));
        assert!(script.contains("POST") || script.contains("GET"));
        assert!(script.contains("VENOM Load Test Script"));
    }

    #[test]
    fn test_custom_config_with_headers() {
        use crate::loadtest::profiles::LoadTestConfig;

        let config = LoadTestConfig::new("http://api.test")
            .with_header("Authorization", "Bearer token123")
            .with_header("Content-Type", "application/json")
            .with_method("POST")
            .with_body(r#"{"key":"value"}"#);

        let cmd = LoadTestRunner::generate_ab_command(&config);
        assert!(cmd.contains("Authorization:Bearer token123"));
        assert!(cmd.contains("http://api.test"));
    }
}
