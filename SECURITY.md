# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in VENOM, please email **security@venom.local** instead of using the issue tracker.

**DO NOT** publicly disclose security vulnerabilities before they are fixed.

Include:
- Type of vulnerability
- Location in code (file, line)
- Proof of concept
- Suggested fix (if available)

We will respond within 48 hours.

## Security Considerations

### Certificate Management

VENOM generates self-signed certificates for MITM proxy operations:
- CA certificates are stored in `.venom/ca.key` (never commit to git)
- Per-domain certificates are cached in `.venom/certs/`
- Private keys are generated at runtime and NOT stored in the repository

### Secrets Management

- Private keys, API keys, and credentials MUST NOT be committed
- Use environment variables or `.env` files (add to .gitignore)
- Example: `export VENOM_API_KEY=your_key_here`

### Compliance

VENOM is designed for authorized security testing only:
- Obtain written permission before scanning targets
- Comply with GDPR, CFAA, and local laws
- Respect rate limits and infrastructure constraints

## Production Deployment

**Current Status: NOT PRODUCTION READY**

Before deploying to production, ensure:

- [ ] Security audit completed (3rd party review)
- [ ] Penetration testing against VENOM itself
- [ ] Dependency vulnerability scan (cargo audit)
- [ ] All tests passing (573+ test suite)
- [ ] Benchmark results documented
- [ ] Memory profiling completed
- [ ] Fuzz testing results analyzed
- [ ] Load testing completed
- [ ] Incident response plan established

## Known Limitations

- **Stability**: Beta-level (active development)
- **Performance**: Not yet benchmarked at scale
- **Security**: Pending formal security audit
- **Production**: Experimental features should not be used in production

## Version Support

| Version | Status | Support Until |
|---------|--------|---------------|
| 1.0.0   | Alpha  | TBD           |
| 2.0.0   | Planned| TBD           |

---

**Last Updated:** 2026-07-17
**Maintainer:** ITherso
