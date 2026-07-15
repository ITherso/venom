#!/bin/bash
# VENOM Apache Bench Script
# Generated for: http://httpbin.org/get

echo "🔥 Apache Bench Load Test"
echo "Target: http://httpbin.org/get"
echo "Concurrency: 10"
echo "Duration: 60s"
echo ""

if ! command -v ab &> /dev/null; then
    echo "❌ Apache Bench not found!"
    echo "Install: sudo apt-get install apache2-utils"
    exit 1
fi

# Run Apache Bench
ab -n 6000 -c 10 -t 60 -s 30 http://httpbin.org/get

echo ""
echo "✅ Benchmark complete!"
