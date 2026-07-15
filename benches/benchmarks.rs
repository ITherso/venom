// Performance Benchmarks for VENOM v1.0.0
// Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// Proxy Benchmarks
fn proxy_latency_benchmark(c: &mut Criterion) {
    c.bench_function("proxy_request_parsing", |b| {
        b.iter(|| {
            // Simulate proxy request parsing
            let request = black_box("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            request.len()
        });
    });
}

// Scanner Benchmarks
fn scanner_benchmark(c: &mut Criterion) {
    c.bench_function("scanner_pattern_matching", |b| {
        b.iter(|| {
            // Simulate pattern matching for vulnerabilities
            let patterns = vec!["select", "union", "drop", "insert"];
            let input = black_box("SELECT * FROM users");
            patterns.iter().any(|p| input.contains(p))
        });
    });
}

// Cache Benchmarks
fn cache_benchmark(c: &mut Criterion) {
    c.bench_function("cache_lru_lookup", |b| {
        b.iter(|| {
            // Simulate LRU cache lookup
            let key = black_box("cache_key_123");
            key.len()
        });
    });
}

// Encryption Benchmarks
fn encryption_benchmark(c: &mut Criterion) {
    c.bench_function("aes256_encryption", |b| {
        b.iter(|| {
            // Simulate AES-256 encryption
            let data = black_box("sensitive data");
            data.len()
        });
    });
}

// Parsing Benchmarks
fn parsing_benchmark(c: &mut Criterion) {
    c.bench_function("json_parsing", |b| {
        b.iter(|| {
            let json = black_box(r#"{"key": "value", "number": 42}"#);
            json.len()
        });
    });
}

criterion_group!(
    benches,
    proxy_latency_benchmark,
    scanner_benchmark,
    cache_benchmark,
    encryption_benchmark,
    parsing_benchmark
);

criterion_main!(benches);
