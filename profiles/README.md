# VENOM Scanning Profiles

Pre-configured scanning strategies for different scenarios and threat models.

## Available Profiles

### 🟢 Enterprise (enterprise.toml)
**Recommended for:** Compliance-focused security assessments, audit trails

- **Intensity:** Light
- **Workers:** 4
- **Rate Limit:** 10 RPS
- **Timeout:** 300s
- **Plugins:** SQLi, XSS, LFI
- **Features:** Compliance tracking, detailed reporting, audit logging
- **Use Case:** GDPR/HIPAA/SOC2 compliance assessments

**Example:**
```bash
venom scan --profile enterprise --target http://app.example.com
```

---

### ☁️ Cloud (cloud.toml)
**Recommended for:** Cloud infrastructure assessment (AWS/GCP/Azure)

- **Intensity:** Aggressive
- **Workers:** 16
- **Rate Limit:** 50 RPS
- **Timeout:** 600s
- **Plugins:** SQLi, XSS, SSRF, LFI, XXE
- **Features:** Cloud provider detection, metadata endpoint scanning
- **Use Case:** AWS/GCP/Azure security testing

**Example:**
```bash
venom scan --profile cloud --target https://api.example.com
```

---

### ⚡ Aggressive (aggressive.toml)
**Recommended for:** Full vulnerability assessment, all-in testing

- **Intensity:** Aggressive
- **Workers:** 32
- **Rate Limit:** 100 RPS
- **Timeout:** 180s
- **Plugins:** All (6 plugins)
- **Features:** ML engine, post-exploitation, exploit chains
- **Use Case:** Comprehensive penetration testing

**Example:**
```bash
venom scan --profile aggressive --target http://app.example.com
```

---

### 🥷 Stealth (stealth.toml)
**Recommended for:** Authorized testing against defended targets, WAF evasion

- **Intensity:** Stealth
- **Workers:** 1
- **Rate Limit:** 2 RPS
- **Timeout:** 3600s
- **Plugins:** SQLi, XSS (carefully)
- **Features:** WAF detection/evasion, request randomization, encoding
- **Use Case:** Sneaky scanning against defended targets

**Example:**
```bash
venom scan --profile stealth --target http://app.example.com
```

---

## Custom Profiles

Create your own profile by copying a built-in profile:

```bash
cp profiles/enterprise.toml profiles/custom.toml
# Edit custom.toml
venom scan --profile custom --target http://target.com
```

---

## Profile Structure

Each profile contains:

```toml
[scan]
name = "profile_name"
intensity = "light|normal|aggressive|stealth"
concurrent_workers = 8
rate_limit_rps = 20

[plugins]
enabled = ["plugin_id_1", "plugin_id_2"]

[lua_scripts]
enabled = ["script_id_1"]

[compliance]
frameworks = ["gdpr", "hipaa"]

[options]
custom_option = "value"
```

---

## Selecting a Profile

### By Use Case:

| Scenario | Profile | Reason |
|----------|---------|--------|
| Compliance audit | enterprise | Low noise, detailed reporting |
| Cloud assessment | cloud | Cloud-specific checks enabled |
| Full pentest | aggressive | All features, max coverage |
| Stealth testing | stealth | WAF evasion, slow rate |
| Custom needs | custom.toml | Build your own |

---

## Profile Recommendations

- **Starting out?** → Use `enterprise` (safe, auditable)
- **Cloud testing?** → Use `cloud` (AWS/GCP/Azure optimized)
- **Full assessment?** → Use `aggressive` (comprehensive)
- **Against WAF?** → Use `stealth` (evasion enabled)
- **Something else?** → Create `custom.toml` (extend built-in)

---

## Advanced: Merging Profiles

Combine two profiles (overlay one on another):

```bash
venom scan \
  --profile enterprise \
  --merge-profile aggressive \
  --target http://target.com
```

This takes enterprise's baseline but adds aggressive's plugins/scripts.

---

**Last Updated:** 2026-07-17  
**Version:** 0.9.0  
**Status:** Experimental
