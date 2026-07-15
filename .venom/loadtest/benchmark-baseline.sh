#!/bin/bash
# VENOM Load Test Script
# Target: http://httpbin.org/get
# Concurrent: 10, RPS: 100, Duration: 60s

set -e

echo "🔥 VENOM Load Testing Suite"
echo "════════════════════════════════════"
echo "Target: http://httpbin.org/get"
echo "Profile: 10 concurrent users, 100 req/s"
echo "Duration: 60s"
echo ""

# Create temporary wrk script
WRK_SCRIPT=$(mktemp)
cat > "$WRK_SCRIPT" << 'WRK_EOF'
-- VENOM Load Test Script
-- Generated for: http://httpbin.org/get
-- Duration: 60s, Concurrent: 10, Target RPS: 100

wrk.host = "http://httpbin.org/get"
wrk.path = "/"
wrk.threads = 2
wrk.connections = 10


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

WRK_EOF

# Test 1: Apache Bench
echo "📊 Test 1: Apache Bench"
echo "─────────────────────"
echo "Command: ab -n 6000 -c 10 -t 60 -s 30 http://httpbin.org/get"
echo ""

if command -v ab &> /dev/null; then
    ab -n 6000 -c 10 -t 60 -s 30 http://httpbin.org/get
    echo ""
else
    echo "⚠️  Apache Bench (ab) not found. Install: apt-get install apache2-utils"
    echo ""
fi

# Test 2: wrk Load Tester
echo "📊 Test 2: wrk Lua Benchmarking"
echo "───────────────────────────────"
echo "Command: wrk -t 2 -c 10 -d 60s --script $WRK_SCRIPT http://httpbin.org/get"
echo ""

if command -v wrk &> /dev/null; then
    wrk -t 2 -c 10 -d 60s --script "$WRK_SCRIPT" http://httpbin.org/get || true
    echo ""
else
    echo "⚠️  wrk not found. Install from: https://github.com/wg/wrk"
    echo ""
fi

# Cleanup
rm -f "$WRK_SCRIPT"

echo "✅ Load testing complete!"
echo "════════════════════════════════════"
