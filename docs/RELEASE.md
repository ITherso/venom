# VENOM Release Management

Complete release management guide for VENOM v1.0.0 and beyond.

## Versioning Strategy

VENOM follows **Semantic Versioning 2.0.0** (MAJOR.MINOR.PATCH):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible new functionality
- **PATCH**: Backwards-compatible bug fixes

### Version Format

```
v1.0.0[-alpha|beta|rc.N]
```

**Examples:**
- `v1.0.0` - Production release
- `v1.0.1` - Patch release (bug fixes)
- `v1.1.0` - Minor release (new features)
- `v2.0.0` - Major release (breaking changes)
- `v1.1.0-alpha.1` - Alpha pre-release
- `v1.1.0-beta.2` - Beta pre-release
- `v1.1.0-rc.1` - Release candidate

## Release Cycle

### Timeline

**Standard Release (8-12 weeks):**
- Week 1: Planning & feature freeze
- Weeks 2-10: Development & testing
- Week 11: Release candidate
- Week 12: Production release

**Patch Release (1-2 weeks):**
- Development on main branch
- Critical fixes only
- Released as needed

**LTS Release (Every 2 years):**
- v2.0.0 (2025-07)
- v3.0.0 (2027-07)
- v4.0.0 (2029-07)

### Support Windows

**Standard Releases:**
- Supported for 6 months
- Then receives security fixes for 6 additional months
- Total: 12 months

**LTS Releases:**
- Supported for 3 years
- Security fixes for full 3-year period
- Bug fixes for first 18 months

**End of Life Dates:**

| Version | Release | End of Support | End of Life |
|---------|---------|----------------|-------------|
| v1.0.x  | 2026-07 | 2027-01        | 2027-07     |
| v1.1.x  | 2026-09 | 2027-03        | 2027-09     |
| v2.0.x  | 2027-07 | 2030-07        | 2030-07 (LTS) |
| v2.1.x  | 2027-09 | 2028-03        | 2028-09     |

## Release Process

### 1. Pre-Release Checklist

```bash
# Update version numbers
cargo search venom  # Verify not on crates.io yet
grep "1.0.0" Cargo.toml

# Run full test suite
cargo test --all

# Security scan
cargo audit
cargo clippy -- -D warnings

# Format check
cargo fmt --check

# Generate SBOM
syft packages . -o json > sbom.json
```

### 2. Release Notes Generation

**Format:**

```markdown
# VENOM v1.1.0 - Feature Release
**Release Date:** 2026-09-15

## What's New

### Features
- ✨ Shell completion (bash, zsh, fish, PowerShell)
- ✨ Configuration profiles
- 🔧 Improved error messages

### Bug Fixes
- 🐛 Fixed proxy memory leak (#123)
- 🐛 Fixed scanner timeout issue (#124)

### Security
- 🔒 Upgraded OpenSSL (CVE-2024-xxxx)
- 🔒 Fixed XSS in dashboard (#125)

### Performance
- ⚡ 30% faster proxy initialization
- ⚡ Improved cache hit rate (70% → 85%)

### Breaking Changes
None

### Deprecations
- ⚠️ `--old-flag` is deprecated, use `--new-flag` instead (removal: v2.0.0)

## Migration Guide

### Upgrading from v1.0.x

No breaking changes. Simply upgrade:

```bash
brew upgrade venom
# or
cargo install venom
```

## Contributors

Thanks to all contributors:
- @user1 (#123)
- @user2 (#124)

## Downloads

- [GitHub Releases](https://github.com/ITherso/venom/releases)
- [Docker Hub](https://hub.docker.com/r/itherso/venom)
- [Crates.io](https://crates.io/crates/venom)
```

### 3. Changelog Management

**Automated Changelog:**

```bash
# Using conventional commits
git log v1.0.0..HEAD --oneline --grep="feat\|fix\|perf" > CHANGELOG.txt
```

**Format:**

```markdown
## [1.1.0] - 2026-09-15

### Added
- Shell completion support
- Configuration profiles

### Changed
- Improved error messages

### Fixed
- Memory leak in proxy
- Scanner timeout

### Security
- Upgraded OpenSSL dependency
- Fixed XSS vulnerability

### Deprecated
- `--old-flag` (use `--new-flag`)

### Removed
- Legacy Python support

[1.1.0]: https://github.com/ITherso/venom/releases/tag/v1.1.0
```

### 4. Tag & Release

```bash
# Create annotated tag
git tag -a v1.1.0 -m "Release v1.1.0"

# Push to GitHub
git push origin v1.1.0

# GitHub Actions will automatically:
# - Build multi-platform binaries
# - Create release with artifacts
# - Publish to crates.io
# - Publish Docker images
# - Update Homebrew formula
```

### 5. Post-Release

```bash
# Verify release on all platforms
curl -I https://github.com/ITherso/venom/releases/tag/v1.1.0
curl https://crates.io/api/v1/crates/venom | jq '.crate.max_version'
docker pull ghcr.io/itherso/venom:1.1.0
```

## Deprecation Policy

### 12-Month Warning

When features or APIs are deprecated:

1. **Announcement** (Month 1)
   - Deprecation notice in release notes
   - Warning in documentation
   - Log warning at runtime

2. **Migration Guide** (Month 1+)
   - Upgrade instructions
   - Code examples
   - Timeline for removal

3. **Removal** (Month 13+)
   - Remove in next major version
   - Bold warning in migration guide

**Example Deprecation Timeline:**

```
v1.1.0 (Sep 2026) - Deprecate --old-flag
    ↓
v1.5.0 (May 2027) - Last minor release supporting --old-flag
    ↓
v2.0.0 (Jul 2027) - Remove --old-flag (breaking change)
```

## Breaking Changes

### Major Version Requirements

Breaking changes trigger a major version bump:

- API endpoint changes
- CLI flag removal
- Database schema changes
- Configuration format changes
- Dependency removal

### Migration Guides

Each major version includes migration guide:

**v2.0.0 Migration Guide Example:**

```markdown
## Breaking Changes

### 1. API Endpoint Changes

**Before:**
```bash
GET /api/v1/scan/{id}
```

**After:**
```bash
GET /api/v2/scan/{id}
```

### 2. Configuration Format

**Before:**
```yaml
proxy:
  port: 8080
  tls: true
```

**After:**
```yaml
proxy:
  port: 8080
  tls:
    enabled: true
    certificate_path: /path/to/cert
```

### 3. Removal of Deprecated Features

- Removed `--legacy-mode` flag
- Removed Python integration
- Removed support for Elasticsearch 6.x
```

## LTS Release Management

### v2.0.0 LTS (July 2027 - July 2030)

**3-Year Support Commitment:**

| Phase | Duration | Support |
|-------|----------|---------|
| Active | 18 months | Bug fixes + Security updates |
| Maintenance | 18 months | Security updates only |
| EOL | After 36 months | No support |

**Patch Release Schedule:**

```
v2.0.0 (2027-07) - Initial LTS
v2.0.1 (2027-08) - Security fixes
v2.0.2 (2027-09) - Bug fixes
...
v2.0.50+ (2030-06) - Final security patches
```

## Quality Standards

### Before Release

- ✅ All tests passing (100% pass rate)
- ✅ Code coverage > 80%
- ✅ No security vulnerabilities (cargo audit)
- ✅ No clippy warnings
- ✅ Code formatted (rustfmt)
- ✅ Documentation updated
- ✅ SBOM generated
- ✅ Performance benchmarks acceptable
- ✅ Compatibility verified (3+ platforms)

### Release Artifact Checklist

- ✅ GitHub release with artifacts
- ✅ Signed binaries (GPG)
- ✅ SHA256 checksums
- ✅ Release notes
- ✅ Docker images (latest, version, slim)
- ✅ Crates.io package
- ✅ Homebrew formula
- ✅ Helm chart
- ✅ Documentation published

## Performance Baseline

Each release includes performance metrics:

```json
{
  "version": "1.1.0",
  "date": "2026-09-15",
  "benchmarks": {
    "proxy_latency_ms": 45.2,
    "scanner_throughput_rps": 105.5,
    "memory_usage_mb": 87.3,
    "api_response_p95_ms": 98.4
  },
  "comparison": {
    "vs_previous": "5% faster proxy, 10% better cache"
  }
}
```

## Incident Response

### Critical Security Issues

**SLA: Patch within 24 hours**

```
Report → Assess → Patch → Test → Release → Notify
```

### Major Bugs

**SLA: Fix in next patch release (1 week)**

### Minor Issues

**Included in next scheduled release**

## References

- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [Conventional Commits](https://www.conventionalcommits.org/)
