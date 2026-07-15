# VENOM Architecture Documentation

## System Overview

```
┌─────────────────────────────────────────────────┐
│           Browser / Client                       │
└──────────────────┬──────────────────────────────┘
                   │ HTTPS
                   ▼
┌─────────────────────────────────────────────────┐
│         VENOM MITM Proxy (8080)                 │
├─────────────────────────────────────────────────┤
│  TLS Interception │ HTTP Parser │ Interceptor  │
│  Certificate Gen  │ Scanner     │ Rules Engine │
│  Cache Manager    │ Zero-Day DB │ Modifiers    │
└──────────────────┬──────────────────────────────┘
                   │
        ┌──────────┼──────────┬──────────┐
        ▼          ▼          ▼          ▼
      ┌──────────────────────────────────────────┐
      │      Target Servers (HTTPS/HTTP)        │
      └──────────────────────────────────────────┘
```

---

## Module Architecture

### Tier 1: Core Proxy (Phases 1-2)
- **proxy/**: MITM server, TLS interception, HTTP parsing
- **tls/**: Certificate authority, cert generation, caching
- **history/**: SQLite database, traffic logging

### Tier 2: Security Testing (Phases 3-5)
- **scanner/**: Vulnerability detection (6 types)
- **zeroday_db/**: Zero-day exploit database, daily updates
- **repeater/**: Request replay, response comparison
- **intruder/**: Fuzzing, payload generation, conditional execution
- **decoder/**: 8 encoding/decoding codecs

### Tier 3: Post-Exploitation (Phase 7)
- **postexploit/**: Webshells, RCE, persistence, lateral movement
- **c2/**: Command & Control framework, agent management

### Tier 4: Enterprise (Phases 8-16)
- **collaboration/**: Teams, sharing, permissions
- **enterprise/**: Audit logging, RBAC, backup, disaster recovery
- **security/**: Encryption, secrets, validation, threat detection
- **compliance/**: GDPR, HIPAA, SOC2, reporting
- **performance/**: Benchmarking, profiling, optimization, caching
- **cli/**: 40+ commands, multi-format output
- **web/**: React/TypeScript dashboard

### Tier 5: Infrastructure
- **database/**: SQLite queries, schema
- **api/**: REST endpoints, WebSocket, handlers
- **monitoring/**: Prometheus metrics, Grafana
- **cache/**: Redis + local fallback

---

## Data Flow

### Request Interception Flow
```
Browser HTTPS Request
       ↓
[MITM Proxy] - Intercept CONNECT
       ↓
[TLS Handshake] - Generate cert for domain
       ↓
[HTTP Parser] - Decrypt & parse request
       ↓
[Scanner] - Check for vulnerabilities
       ↓
[Interceptor Rules] - Apply modifications if needed
       ↓
[Database] - Log to SQLite
       ↓
[Forward to Target] - Send to real server
       ↓
[Response Handler] - Parse response
       ↓
[Security Audit] - Log access
       ↓
[TLS Re-encrypt] - Send to browser
```

### Vulnerability Detection Flow
```
HTTP Request/Response
       ↓
[Anomaly Scorer] - Score suspicious patterns
       ↓
[Pattern Detector] - Detect 6 vulnerability types
       ↓
[Evidence Generator] - Collect proof
       ↓
[Severity Calculator] - CVSS scoring
       ↓
[Database] - Store finding
       ↓
[Report Generator] - Add to report
```

---

## Security Model

### Certificate Authority
```
~/.venom/
├── ca.crt          (Self-signed CA certificate)
├── ca.key          (Private key - protect this!)
└── cache/
    ├── domain1.com.crt
    ├── domain1.com.key
    └── ...
```

### Encryption Strategy
- **Transit:** TLS 1.3 for client/server, AES-256-GCM for data at rest
- **Secrets:** Encrypted with Argon2 key derivation
- **API Keys:** SHA-256 hashed, never stored plaintext
- **Database:** SQLite with per-field encryption option

### RBAC Model
```
User → Role → Permissions
         ↓
    [5 role types]
    - Owner (full access)
    - Admin (team management)
    - Member (scan execution)
    - Analyst (read-only findings)
    - Viewer (view-only)
```

---

## Performance Characteristics

### Memory Usage
- **Idle:** ~15 MB
- **100 concurrent:** ~25 MB
- **1000 concurrent:** ~150 MB

### Latency
- **Proxy overhead:** <50ms
- **Scanner execution:** 100-500ms per request
- **Report generation:** 1-5s depending on findings

### Throughput
- **Requests/second:** 1,000+
- **Concurrent connections:** 100+
- **Database queries/second:** 10,000+

### Optimization Techniques
1. **Connection Pooling:** Reuse TLS connections
2. **Certificate Caching:** In-memory cache + disk fallback
3. **Request Batching:** Batch writes to database
4. **Async/Await:** Non-blocking I/O throughout
5. **Parallel Scanning:** Multi-threaded vulnerability detection

---

## Compliance Architecture

### GDPR
```
Data Processing
    ↓
[Consent Management]
    ↓
[Retention Policies] (automatic deletion)
    ↓
[Right to Erasure] (user deletion tool)
    ↓
[Audit Trail] (all access logged)
```

### HIPAA
```
PHI Records
    ↓
[Encryption] (AES-256-GCM)
    ↓
[Access Control] (RBAC)
    ↓
[Audit Logging] (all access)
    ↓
[Breach Reporting]
```

### SOC2
```
Security Policies
    ↓
[Control Assessment] (Type I/II)
    ↓
[Evidence Collection]
    ↓
[Automated Compliance Report]
    ↓
[Remediation Tracking]
```

---

## Deployment Architecture

### Single Machine
```
VENOM Server (8080)
├── Proxy
├── Scanner
├── Database (SQLite)
└── API (3000)
```

### Kubernetes
```
├── venom-deployment (3+ replicas)
├── venom-database (PostgreSQL)
├── venom-redis (caching)
├── venom-elasticsearch (logging)
└── venom-ingress (TLS termination)
```

### High Availability
```
Load Balancer
    ↓
┌───┬───┬───┐
▼   ▼   ▼
[Proxy 1]
[Proxy 2]
[Proxy 3]
    ↓
Shared Database (RDS)
Shared Cache (ElastiCache)
```

---

## Extensibility

### Custom Vulnerability Detectors
```rust
pub struct CustomDetector {
    pattern: String,
    severity: SeverityLevel,
}

impl VulnerabilityDetector for CustomDetector {
    fn detect(&self, request: &Request, response: &Response) -> Option<Finding> {
        // Your detection logic
    }
}
```

### Custom Payload Generators
```rust
pub struct CustomPayload {
    name: String,
    payloads: Vec<String>,
}

impl PayloadGenerator for CustomPayload {
    fn generate(&self) -> Vec<String> {
        self.payloads.clone()
    }
}
```

### Custom Compliance Frameworks
```rust
pub struct CustomFramework {
    name: String,
    requirements: Vec<Requirement>,
}

impl ComplianceFramework for CustomFramework {
    fn audit(&self) -> ComplianceReport {
        // Your audit logic
    }
}
```

---

## Technology Stack

**Backend:**
- Language: Rust 1.70+
- Async Runtime: Tokio
- HTTP: Hyper + Axum
- Database: SQLite + SQL-X
- Crypto: Rustls + Ring
- Serialization: Serde + JSON

**Frontend:**
- Framework: React 18
- Language: TypeScript
- Styling: CSS3
- Build: Vite/webpack
- State: React Hooks

**Deployment:**
- Container: Docker
- Orchestration: Kubernetes
- Infrastructure: Terraform
- CI/CD: GitHub Actions
- Monitoring: Prometheus + Grafana

---

## Thread Safety Model

All shared state uses:
- `Arc<RwLock<T>>` for read-heavy data
- `Arc<Mutex<T>>` for write-heavy data
- `Arc<AtomicU64>` for atomic counters
- `DashMap` for concurrent maps

Example:
```rust
let database = Arc::new(RwLock::new(Database::new()));
let db_clone = Arc::clone(&database);

tokio::spawn(async move {
    let mut db = db_clone.write().await;
    db.insert(key, value);
});
```

---

## Logging & Observability

### Structured Logging
```json
{
  "timestamp": "2026-07-15T10:30:00Z",
  "level": "INFO",
  "module": "scanner",
  "message": "SQL injection detected",
  "finding_id": "finding_001",
  "severity": "High"
}
```

### Metrics Collection
- Request latency (P50/P95/P99)
- Vulnerability detection rate
- Cache hit ratio
- Database query time
- Memory usage trends

### Health Checks
```
GET /api/health
{
  "status": "healthy",
  "database": "ok",
  "cache": "ok",
  "api": "ok"
}
```

---

**For implementation details:** See individual module documentation in `/docs/modules/`
