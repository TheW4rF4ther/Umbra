# Blackbox Umbra — Quick Reference Card

## Command Syntax

```bash
umbra -t <TARGET> -c <CLIENT> [OPTIONS]
```

or

```bash
sudo python3 ~/tools/bbr/bbr.py -t <TARGET> -c <CLIENT> [OPTIONS]
```

---

## Common Scenarios

### 1. Single Host — Full Recon
```bash
sudo umbra -t 10.10.10.5 -c "Acme" --operator "Alexander Morrow"
```
✓ All phases (recon → enum → ad → vulns)  
✓ ~5-15 min depending on services

### 2. Network Range — Fast Mode
```bash
sudo umbra -t 192.168.1.0/24 -c "Internal" --fast
```
✓ Host discovery + top-1000 port scan  
✓ ~30-45 min per subnet

### 3. Recon Only (Silent Footprint)
```bash
sudo umbra -t 10.0.0.0/24 -c "Client" --phases recon
```
✓ Host discovery + port scan only  
✓ No service enumeration

### 4. Debug Mode (Show All Commands)
```bash
sudo umbra -t 10.10.10.5 -c "Test" -v
```
✓ Prints every tool command  
✓ Logs full tool output

### 5. Custom Output Path & ROE
```bash
sudo umbra -t 10.10.10.5 -c "Target" \
  -o /mnt/results \
  --scope "10.10.10.0/24 excluding gateways"
```
✓ Saves to `/mnt/results/Target_*/`  
✓ Scope documented in report

---

## Arguments Quick Lookup

| Arg | Purpose | Example |
|-----|---------|---------|
| `-t, --target` | **REQUIRED** Target IP/subnet/hostname | `-t 10.10.10.0/24` |
| `-c, --client` | **REQUIRED** Client name | `-c "ACME Corp"` |
| `-o, --output` | Output directory | `-o ~/engagements` |
| `--operator` | Operator name for attribution | `--operator "John Doe"` |
| `--scope` | ROE/scope string for report | `--scope "10.10.10.0/22 only"` |
| `--phases` | Which phases to run | `--phases recon,enum,ad` |
| `--fast` | Fast mode (top-1000 ports) | `--fast` |
| `-v, --verbose` | Show all tool output | `-v` |
| `-h, --help` | Show help | `--help` |

---

## Phases Overview

| Phase | Purpose | Time | Triggered By |
|-------|---------|------|--------------|
| **recon** | Host discovery + port/OS scan | 2-10 min | Always (default) |
| **enum** | Service enumeration (SMB, HTTP, LDAP, etc.) | 2-5 min | Open ports detected |
| **ad** | Domain enumeration + roasting | 1-3 min | AD ports (88, 389, 3268) |
| **vulns** | nmap vuln scripts + searchsploit + netexec checks | 2-5 min | Open ports detected |

---

## Output Locations

```
~/engagements/<CLIENT>_<TIMESTAMP>/
├── engagement.json              # Metadata
├── findings.json                # Full structured findings
├── report.md                    # Formatted report
├── recon/                       # Nmap outputs
├── enum/                        # Service enum results
├── ad/                          # AD findings + hashes
└── vulns/                       # Vulnerability data
```

---

## Key Files to Review

1. **report.md** — Executive summary + per-host findings (START HERE)
2. **findings.json** — Raw structured data for further processing
3. **vulns/*.txt** — Individual vulnerability findings by tool
4. **ad/*_hashes.txt** — Crackable hashes (if AS-REP/Kerberoast found)

---

## Severity Reference

| Level | Count | Action |
|-------|-------|--------|
| **CRITICAL** | ? | Address immediately before deployment |
| **HIGH** | ? | Remediate within 30 days |
| **MEDIUM** | ? | Standard patch cycle |
| **LOW** | ? | Monitor & include in roadmap |

---

## Common Findings

### CRITICAL
- MS17-010 (EternalBlue) — RCE on unpatched SMB
- CVE-2019-0708 (BlueKeep) — RCE on unpatched RDP
- CVE-2020-1472 (Zerologon) — DC compromise via NETLOGON
- Pre-auth AD accounts (AS-REP roastable)

### HIGH
- Kerberoastable SPNs → offline cracking
- SMB signing disabled → relay attacks
- Weak password policies → spray attacks
- Null SMB sessions → information disclosure

### MEDIUM
- Old service versions → known CVEs
- HTTP headers leaking tech stack
- Weak SSL/TLS configurations
- Missing security headers

---

## Example Workflow

```bash
# 1. Conduct engagement
sudo umbra -t 192.168.1.50 -c "Acme Finance" \
  --operator "Alexander Morrow" \
  --scope "Finance server only | No production DB direct scan"

# 2. Review output
cd ~/engagements/Acme_Finance_20260324_*/
cat report.md           # Read executive summary
jq '.hosts | keys' findings.json  # List discovered hosts

# 3. Extract hashes for offline cracking (if AD found)
cat ad/*_hashes.txt > hashes_to_crack.txt

# 4. Custom follow-up testing against specific findings
# (Manual testing for SQLi, XXE, etc.)

# 5. Archive results
tar czf acme_finance_pentest_20260324.tar.gz engagements/Acme_Finance*/
```

---

## Troubleshooting Quick Fixes

| Issue | Solution |
|-------|----------|
| `[tool not found: nikto]` | `sudo apt install nikto` |
| Authorization prompt doesn't accept input | Type `y` or `yes` and press Enter |
| Timeout during scan | Add `--fast` flag or run phases separately |
| Permission denied on output | `sudo chown $USER ~/engagements` |
| LDAP returns "auth required" | Normal if not domain-joined; other phases continue |

---

## System Requirements

- Kali Linux 2025+, Ubuntu 22.04+, or similar
- Python 3.8+
- Minimum: nmap, enum4linux, ldapsearch, rpcclient, smbclient
- Recommended: nikto, gobuster/feroxbuster, enum4linux-ng, netexec, searchsploit

---

**Blackbox Intelligence Group LLC**  
*The shadow sees all.*

---

Print this card. Laminate it. Keep it in your ops kit. 📋
