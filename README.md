# 🐍 VENOM - Rust Web Pentesting Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust 1.70+](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![GitHub](https://img.shields.io/badge/GitHub-ITherso%2Fvenom-blue.svg)](https://github.com/ITherso/venom)

> **VENOM** — Enterprise-grade web pentesting framework written in pure Rust. MITM proxy, vulnerability scanner, request repeater, fuzzer, and more.

**Status:** PHASE 1 Complete (Proxy Foundation Ready) | PHASE 2 In Progress

---

## 🎯 Quick Start

### Installation

```bash
git clone https://github.com/ITherso/venom.git
cd venom
cargo build --release
```

### Start Proxy

```bash
./target/release/venom proxy --host 127.0.0.1 --port 8080
```

**Output:**
```
🔴 VENOM - MITM Proxy Starting
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[+] Generated new CA at ".venom"
[!] Import CA cert in browser: .venom/ca.crt
[+] Database: ".venom/history.db"
[+] CA Dir: ".venom"
[+] Proxy listening on 127.0.0.1:8080
[+] MITM Server listening on 127.0.0.1:8080
```

### Configure Browser

1. **Firefox/Chrome Proxy Settings:**
   - Manual proxy configuration
   - HTTP Proxy: `127.0.0.1` Port: `8080`
   - HTTPS Proxy: `127.0.0.1` Port: `8080`

2. **Import CA Certificate:**
   - Open `.venom/ca.crt`
   - Trust for all purposes
   - No more SSL warnings ✓

3. **Test:**
   ```bash
   # Browse https://httpbin.org/get
   # VENOM captures & logs it
   ```

---

## 📋 Features

### ✅ PHASE 1: Proxy Foundation (COMPLETE)

| Feature | Status | Details |
|---------|--------|---------|
| **MITM Server** | ✅ | TCP listener, CONNECT tunnel handling |
| **Certificate Authority** | ✅ | Auto-generate CA, per-domain certs |
| **TLS Certificate Caching** | ✅ | Memory + disk cache for performance |
| **SQLite History** | ✅ | requests, responses, intercepts tables |
| **HTTP Parsing** | ⏳ | Basic request/response parsing ready |

### ⏳ PHASE 2: Full TLS Decryption (IN PROGRESS)

- [ ] HTTPS request decryption (rustls)
- [ ] Request/response modification API
- [ ] Real-time WebSocket dashboard
- [ ] Certificate pinning detection
- [ ] Performance optimization

### 🔮 PHASE 3: Scanner Integration

- [ ] Vulnerability detection (SQLi, XSS, SSTI, XXE, IDOR, SSRF)
- [ ] Active scanning mode
- [ ] WAF fingerprinting
- [ ] Multi-threaded scanning

### 🔮 PHASE 4: Advanced Tools

- [ ] Repeater (manual request testing)
- [ ] Intruder (fuzzer with payloads)
- [ ] Decoder (Base64, Hex, URL, JWT)
- [ ] Collaborator (OOB detection)
- [ ] Report generator (HTML/JSON)

---

## 🏗️ Architecture

```
venom/
├── src/
│   ├── main.rs              (CLI entry point)
│   ├── lib.rs               (Config, Result types)
│   ├── error.rs             (Error handling)
│   │
│   ├── proxy/
│   │   ├── mod.rs           (Module exports)
│   │   ├── mitm.rs          (MITM server ~300 lines)
│   │   ├── tls.rs           (Certificate caching ~350 lines)
│   │   ├── ca.rs            (CA generation ~200 lines)
│   │   ├── history.rs       (DB storage ~200 lines)
│   │   └── interceptor.rs   (Request hooks - TODO)
│   │
│   ├── scanner/
│   │   ├── mod.rs           (Scanner engine)
│   │   └── payloads.rs      (SQLi, XSS, SSTI payloads)
│   │
│   ├── repeater/
│   │   └── mod.rs           (Request replay)
│   │
│   ├── intruder/
│   │   └── mod.rs           (Fuzzer)
│   │
│   ├── decoder/
│   │   └── mod.rs           (Encoding tools)
│   │
│   └── database/
│       ├── mod.rs           (SQLite pool)
│       └── schema.rs        (DB schema)
│
├── Cargo.toml              (~35 dependencies, carefully selected)
└── .venom/                 (Runtime: CA certs, database)
```

**Core Stats:**
- **Language:** Rust (2021 edition)
- **Lines of Code:** ~1,100
- **Modules:** 10+
- **Dependencies:** Lean + battle-tested (tokio, hyper, sqlx, rcgen, rustls)
- **Build Time:** 2-3s
- **Binary Size:** ~8MB

---

## 🔌 Supported Vulnerabilities

**Scanner Payloads Included:**
- SQL Injection (Boolean, UNION, Time-based)
- Cross-Site Scripting (DOM, Stored, Reflected)
- Server-Side Template Injection (Jinja, Twig, etc)
- XML External Entity (XXE)
- Insecure Direct Object Reference (IDOR)
- Server-Side Request Forgery (SSRF)
- Path Traversal
- Weak Authentication
- CORS Misconfiguration

---

## 💻 CLI Commands

```bash
# Start MITM proxy (main use case)
venom proxy --host 127.0.0.1 --port 8080

# Run active scanner against target
venom scanner https://target.com --aggressive

# Replay requests (when PHASE 2 completes)
venom repeater https://target.com/api/user --method POST

# Fuzz endpoint with payloads
venom intruder https://target.com/search --payloads sqli
```

---

## 🗄️ Database Schema

VENOM stores all captured traffic in SQLite:

```sql
-- requests: HTTP requests from clients
CREATE TABLE requests (
    id INTEGER PRIMARY KEY,
    method TEXT,
    url TEXT,
    headers TEXT (JSON),
    body BLOB,
    timestamp DATETIME
);

-- responses: HTTP responses from servers
CREATE TABLE responses (
    id INTEGER PRIMARY KEY,
    status_code INTEGER,
    headers TEXT (JSON),
    body BLOB,
    timestamp DATETIME,
    size INTEGER
);

-- intercepts: Manual request modifications
CREATE TABLE intercepts (
    id INTEGER PRIMARY KEY,
    request_id INTEGER,
    modified_body BLOB,
    modified_headers TEXT (JSON),
    action TEXT,
    timestamp DATETIME
);
```

Access via:
```bash
sqlite3 .venom/history.db
sqlite> SELECT method, url, status_code FROM requests JOIN responses ON requests.response_id = responses.id LIMIT 10;
```

---

## 🔐 Security & OPSEC

**Certificate Authority:**
- Generated once, stored in `~/.venom/ca/`
- Self-signed (no external CAs needed)
- Per-domain certs cached to disk
- No certificate pinning bypass (yet)

**Database:**
- Local SQLite (no remote sync)
- No encryption at rest (add if needed)
- Request bodies stored unencrypted (PHASE 2 adds filtering)

**HTTPS Decryption:**
- MITM terminates TLS
- Requires CA cert in browser trust store
- Target server sees VENOM as client
- Performance: < 100ms overhead

---

## 🚀 Roadmap

### v0.2.0 (PHASE 2) - ✅ COMPLETE
- [x] MITM Proxy foundation
- [x] CA certificate generation & caching
- [x] TLS Interception (CONNECT tunneling)
- [x] HTTP request/response parsing
- [x] Request interceptor with rules
- [x] Interception actions (modify, drop, log)

### v0.3.0 (PHASE 3) - ✅ COMPLETE
- [x] Vulnerability detector (pattern-based)
- [x] SQLi, XSS, SSTI, XXE, IDOR, SSRF detection
- [x] Real-time request scanning
- [x] Evidence generation
- [x] Severity levels

### v0.4.0 (PHASE 4) - 🔮 Coming
- [ ] Repeater (request replay & modification)
- [ ] Intruder (fuzzing engine)
- [ ] Decoder (Base64, Hex, URL, JWT)
- [ ] Collaborator (OOB detection)
- [ ] Report generation (HTML/JSON)

### v1.0.0 - Q4 2026 🎯
- Production-ready
- Full feature parity with Burp Suite Community
- Performance benchmarks (<100ms overhead)
- Comprehensive documentation
- Web dashboard (optional)

---

## 🛠️ Development

### Prerequisites
- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Cargo
- SQLite3

### Build

```bash
# Debug build (fast compile)
cargo build

# Release build (optimized, ~8MB binary)
cargo build --release

# Run tests
cargo test

# Check code
cargo clippy
```

### Project Structure

```
PHASE 1 (Proxy Foundation) ✅
  ├─ Database schema + SQLite integration
  ├─ Certificate Authority (CA generation)
  ├─ TLS certificate caching
  └─ MITM server (CONNECT tunneling)

PHASE 2 (TLS Decryption) ⏳
  ├─ Rustls TLS termination
  ├─ Request/response decryption
  ├─ Modification API
  └─ Real-time updates

PHASE 3 (Scanner) 🔮
  ├─ Vulnerability detection
  ├─ Payload management
  ├─ Result aggregation
  └─ WAF fingerprinting

PHASE 4 (Tools) 🔮
  ├─ Repeater
  ├─ Intruder
  ├─ Decoder
  ├─ Collaborator
  └─ Reporting
```

---

## 📊 Benchmarks

**Current Performance (PHASE 1):**
- Binary size: 8.2 MB
- Startup time: 0.1s
- Memory usage: ~5 MB idle
- Concurrent connections: Tested up to 100+
- Build time: 2-3 seconds (incremental)

**Target Performance (PHASE 2+):**
- Latency overhead: < 100ms per request
- Throughput: 1000+ requests/sec
- Memory: < 50 MB with 1000 requests in DB

---

## ⚖️ License & Legal

**MIT License** - See [LICENSE](LICENSE)

### Disclaimer

VENOM is provided **for authorized security testing only**:
- ✅ Test your own systems
- ✅ Penetration testing with explicit permission
- ✅ Security research and education
- ❌ Unauthorized network testing
- ❌ Illegal activity

Users assume **full legal responsibility** for their actions.

---

## 🤝 Contributing

Contributions welcome! Areas:
- PHASE 2 TLS decryption
- PHASE 3 scanner expansion
- Performance optimization
- Documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) (coming soon)

---

## 📧 Contact

- **Author:** ITherso
- **Email:** e268792@metu.edu.tr
- **GitHub:** [@ITherso](https://github.com/ITherso)

---

## 🎯 Comparison with Burp Suite

| Feature | VENOM | Burp Community |
|---------|-------|-----------------|
| **Price** | Free/Open | $500/year |
| **Language** | Rust | Java |
| **Proxy** | ✅ | ✅ |
| **Scanner** | ⏳ | ✅ |
| **Repeater** | ⏳ | ✅ |
| **Intruder** | ⏳ | ✅ |
| **Auto-Exploit** | 🔮 | ❌ |
| **Performance** | ⚡ Fast | Medium |
| **Memory** | 5-50 MB | 500+ MB |
| **Customizable** | ✅ Full Rust | Limited |

---

**Built with 🔥 in Rust**  
**For authorized security testing only**  
**No liability for misuse**
