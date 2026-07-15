# VENOM v1.0.0 Documentation Index

Welcome to the complete VENOM documentation. Start here to find what you need.

---

## 📖 For Everyone

### Getting Started (New Users)
- **[Getting Started Guide](GETTING_STARTED.md)** - Installation, first scan, troubleshooting
- **[Quick Demo](GETTING_STARTED.md#quick-start-5-minutes)** - Set up and running in 5 minutes
- **[Use Cases](GETTING_STARTED.md#common-use-cases)** - Security assessment, compliance, load testing

### Using VENOM
- **[API Documentation](API.md)** - REST API endpoints, examples, authentication
- **[CLI Reference](CLI.md)** - 40+ commands organized by category
- **[Dashboard Guide](DASHBOARD.md)** - Web interface walkthrough

---

## 🏗️ For Developers

### Understanding the System
- **[Architecture Overview](ARCHITECTURE.md)** - System design, data flow, security model
- **[Module Guide](MODULES.md)** - Each module explained with examples
- **[Technology Stack](ARCHITECTURE.md#technology-stack)** - Languages, frameworks, tools

### Development
- **[Contributing Guide](CONTRIBUTING.md)** - Code style, PR process, development setup
- **[Module Development](EXTENDING.md)** - How to create custom detectors, payloads, frameworks
- **[Testing Guide](TESTING.md)** - Writing and running tests
- **[Performance Tips](ARCHITECTURE.md#performance-characteristics)** - Optimization techniques

### Building & Deployment
- **[Building from Source](GETTING_STARTED.md#option-1-build-from-source)**
- **[Docker Deployment](DEPLOYMENT.md#docker)**
- **[Kubernetes Setup](DEPLOYMENT.md#kubernetes)**
- **[Terraform Infrastructure](DEPLOYMENT.md#infrastructure-as-code)**

---

## 🔐 For Security

### Security Overview
- **[Security Architecture](ARCHITECTURE.md#security-model)** - Certificate CA, encryption, RBAC
- **[API Authentication](API.md#authentication)** - API keys, bearer tokens
- **[Access Control](ARCHITECTURE.md#rbac-model)** - Role-based permissions

### Compliance
- **[GDPR Compliance](COMPLIANCE.md#gdpr)** - Data processing, consent, retention
- **[HIPAA Compliance](COMPLIANCE.md#hipaa)** - PHI protection, access logs, breach reporting
- **[SOC2 Compliance](COMPLIANCE.md#soc2)** - Control assessment, policies

---

## 📋 For Operators

### Running VENOM
- **[Getting Started](GETTING_STARTED.md)** - Installation and first setup
- **[Deployment Guide](DEPLOYMENT.md)** - Production deployment options
- **[Monitoring](MONITORING.md)** - Prometheus metrics, Grafana dashboards
- **[Backup & Recovery](DISASTER_RECOVERY.md)** - Backup strategies, recovery procedures

### Team Management
- **[Team Collaboration](COLLABORATION.md)** - Creating teams, sharing scans, permissions
- **[User Management](USER_MANAGEMENT.md)** - Creating users, assigning roles

---

## 📚 Reference Documentation

### APIs & Protocols
- **[REST API](API.md)** - Complete endpoint reference
- **[WebSocket Events](API.md#webhook-events)** - Real-time event streaming
- **[Error Codes](API.md#error-codes)** - Error responses and meanings

### Configuration
- **[Environment Variables](CONFIG.md)**
- **[Database Schema](DATABASE.md)**
- **[Logging Configuration](LOGGING.md)**

### Tools & Features
- **[Proxy Features](PROXY.md)** - MITM, interception, TLS
- **[Scanner](SCANNER.md)** - Vulnerability detection, payload generation
- **[Repeater](REPEATER.md)** - Request replay, response comparison
- **[Intruder](INTRUDER.md)** - Fuzzing, macros, conditional payloads
- **[Decoder](DECODER.md)** - 8 encoding/decoding codecs
- **[C2 Framework](C2.md)** - Command & Control, agent management
- **[Post-Exploitation](POSTEXPLOIT.md)** - Webshells, persistence, lateral movement
- **[CLI](CLI.md)** - 40+ commands reference

---

## 🎯 By Task

### I want to...

#### Start a security assessment
1. Read: [Getting Started](GETTING_STARTED.md)
2. Read: [Scanner Guide](SCANNER.md)
3. Read: [API Examples](API.md#examples)

#### Deploy VENOM to production
1. Read: [Deployment Guide](DEPLOYMENT.md)
2. Read: [Security Architecture](ARCHITECTURE.md#security-model)
3. Read: [Monitoring Setup](MONITORING.md)

#### Contribute to VENOM
1. Read: [Contributing Guide](CONTRIBUTING.md)
2. Read: [Architecture](ARCHITECTURE.md)
3. Read: [Module Development](EXTENDING.md)

#### Achieve compliance certification
1. Read: [GDPR Compliance](COMPLIANCE.md#gdpr)
2. Read: [HIPAA Compliance](COMPLIANCE.md#hipaa)
3. Read: [SOC2 Compliance](COMPLIANCE.md#soc2)

#### Integrate VENOM with other tools
1. Read: [REST API](API.md)
2. Read: [WebSocket Events](API.md#webhook-events)
3. Read: [API Examples](API.md#examples)

#### Troubleshoot issues
1. Read: [Troubleshooting](GETTING_STARTED.md#troubleshooting)
2. Read: [Monitoring](MONITORING.md)
3. File: [Issue on GitHub](https://github.com/ITherso/venom/issues)

---

## 📦 Module Documentation

Individual module guides (in `/docs/modules/`):

- **proxy.md** - MITM server, TLS interception, certificate handling
- **scanner.md** - Vulnerability detection, pattern matching, evidence generation
- **repeater.md** - Request replay, response comparison, macro system
- **intruder.md** - Fuzzing, payload generation, conditional execution
- **decoder.md** - Encoding/decoding, codec reference
- **postexploit.md** - Post-exploitation, persistence, evasion
- **c2.md** - Command & Control, agent management, task queuing
- **api.md** - REST API, endpoint documentation
- **web.md** - React dashboard, component overview
- **cli.md** - Command-line interface, command reference
- **security.md** - Encryption, secrets, validation, threat detection
- **compliance.md** - GDPR, HIPAA, SOC2 frameworks
- **performance.md** - Benchmarking, profiling, optimization

---

## 🔗 External Links

- **GitHub:** https://github.com/ITherso/venom
- **Issues:** https://github.com/ITherso/venom/issues
- **Discussions:** https://github.com/ITherso/venom/discussions
- **Website:** https://venom.dev
- **Discord:** https://discord.gg/venom

---

## 📝 Documentation Versions

- **v1.0.0** (current) - Complete enterprise platform
- **v0.5.0** - Core pentesting features
- **v0.1.0** - Initial release

---

## 📄 License

All documentation is licensed under the same MIT license as VENOM.

---

## 📞 Getting Help

- **Quick question?** Check the [FAQ](FAQ.md)
- **Found a bug?** Open an [issue](https://github.com/ITherso/venom/issues)
- **Want to discuss?** Start a [discussion](https://github.com/ITherso/venom/discussions)
- **Security concern?** Email security@venom.dev

---

**Start with [Getting Started](GETTING_STARTED.md) if you're new to VENOM! 🐍**
