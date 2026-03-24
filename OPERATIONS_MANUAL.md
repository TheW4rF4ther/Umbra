# Blackbox Umbra Operations Manual

## 🕵️ The Shadow Sees All

**Blackbox Umbra** is an automated pentest reconnaissance and vulnerability discovery framework built for professional red teamers and penetration testing operators at Blackbox Intelligence Group LLC.

This manual covers operational procedures, tactical deployment, and engagement workflows.

---

## Table of Contents

1. [Installation & Setup](#installation--setup)
2. [Operational Phases](#operational-phases)
3. [Quick Start](#quick-start)
4. [Advanced Usage](#advanced-usage)
5. [Output & Reporting](#output--reporting)
6. [Troubleshooting](#troubleshooting)

---

## Installation & Setup

### Prerequisites

- Kali Linux 2025+, Ubuntu 22.04+, or equivalent pentest distro
- Python 3.8+
- Root/sudo access
- Nmap, enum4linux, ldapsearch, rpcclient, smbclient, searchsploit, netexec

### Quick Install

```bash
# Ensure directory structure exists
mkdir -p ~/tools/bbr/modules ~/tools/bbr/wordlists ~/engagements

# Navigate to framework
cd ~/tools/bbr

# Verify all modules are present
python3 -m py_compile bbr.py modules/*.py

# Load alias (already in ~/.zshrc)
source ~/.zshrc

# Test
umbra --help
```

### Dependency Check

```bash
# Verify all pentest tools are installed
command -v nmap enum4linux ldapsearch rpcclient smbclient searchsploit netexec

# If missing, install:
sudo apt install -y nikto gobuster feroxbuster enum4linux-ng netexec
```

---

## Operational Phases

Umbra operates in **4 sequential phases**, each building on the previous:

### Phase 1: Reconnaissance (`recon`)
**Objective**: Map the target landscape.

- Host discovery (ping sweep for subnets; single host passthrough)
- TCP port scanning (full or top-1000 in fast mode)
- Service version detection + OS fingerprinting
- Hostname resolution

**Output**: `recon/ports_*.xml`, `recon/services_*.xml`, `recon/os_*.xml`

### Phase 2: Enumeration (`enum`)
**Objective**: Extract actionable intelligence from open services.

Service-specific dispatchers:
- **SMB (139, 445)**: netexec shares, rpcclient enum, smbclient null-session
- **HTTP/HTTPS (80, 443, 8080, 8443)**: curl headers, whatweb, nikto, gobuster/feroxbuster
- **LDAP (389, 636)**: base query, user/group enumeration, SPN discovery
- **RPC (135)**: rpcclient SID enum, domain user discovery
- **FTP (21)**: anonymous login test
- **MSSQL (1433)**: netexec banner + creds attempt
- **RDP (3389)**: netexec capabilities check
- **WinRM (5985, 5986)**: netexec execution probe

**Output**: `enum/smb_*.txt`, `enum/http_*.txt`, `enum/ldap_*.txt`, etc.

### Phase 3: Active Directory Analysis (`ad`)
**Objective**: Exploit domain environment for lateral movement vectors.

**Triggered automatically** if domain controller signatures detected (ports 88, 389, 3268).

- enum4linux-ng full domain enumeration
- LDAP user/group/SPN discovery
- AS-REP roasting (CVE-2018-20225 — pre-auth required check)
- Kerberoasting (service principal name Hash extraction)
- SMB signing status
- Password policy extraction

**Output**: `ad/enum4linux_*.txt`, `ad/ldap_*.txt`, `ad/*_hashes.txt`

### Phase 4: Vulnerability Identification (`vulns`)
**Objective**: Catalog exploitable security gaps.

- nmap NSE vuln scripts
- searchsploit ExploitDB matching on service versions
- netexec named checks: MS17-010 (EternalBlue), BlueKeep (CVE-2019-0708), Zerologon (CVE-2020-1472), PetitPotam

**Output**: `vulns/nmap_vuln_*.xml`, `vulns/searchsploit_*.json`, findings indexed by severity (CRITICAL → HIGH → MEDIUM → LOW)

---

## Quick Start

### Scenario 1: Single Host Deep Dive

```bash
# Target: 10.10.10.5 belonging to "ACME Corp"
# Full recon with all phases
sudo umbra -t 10.10.10.5 -c "ACME Corp" -o ~/engagements --operator "Alexander Morrow"
```

**What happens**:
1. Authorization gate appears — confirm written authorization
2. Creates: `~/engagements/ACME_Corp_20260324_143022/`
3. Runs recon → enum → ad → vulns sequentially
4. Outputs findings.json + report.md after ~5-15 minutes

### Scenario 2: Network Range Fast Mode

```bash
# Target: 192.168.1.0/24 (Class C network)
# Fast mode: top-1000 ports only, no full port scan
sudo umbra -t 192.168.1.0/24 -c "Internal Network" --fast
```

**What happens**:
1. Host discovery (ping sweep)
2. Top-1000 port scan per live host
3. Service + enum + AD + vulns on all discovered hosts
4. Reduces scan time from hours to 30-45 minutes

### Scenario 3: Specific Phase(s) Only

```bash
# Run only recon + enum (skip AD + vuln phases)
sudo umbra -t 10.0.0.0/24 -c "Client" --phases recon,enum

# Run only AD enumeration (assumes prior recon already done — may fail)
sudo umbra -t 10.10.10.5 -c "Domain Check" --phases ad
```

### Scenario 4: Verbose Output (Debugging)

```bash
# Show all tool commands and raw output
sudo umbra -t 10.10.10.5 -c "Debug Run" -v
```

Prints each nmap/netexec/searchsploit command invocation.

---

## Advanced Usage

### Custom Scope Definition

```bash
sudo umbra -t 10.10.10.5 \
  -c "Acme Dev Server" \
  --scope "10.10.10.0/24 excluding .1, .254 | SSH/RDP only | Database port 3306 in-scope" \
  --operator "Alexander Morrow"
```

The `--scope` string appears in the final report for ROE (Rules of Engagement) alignment.

### Output to Specific Directory

```bash
sudo umbra -t 192.168.1.100 -c "Workstation" -o /mnt/pentest/results
```

Outputs to: `/mnt/pentest/results/Workstation_<timestamp>/`

### Custom Operator Attribution

```bash
sudo umbra -t 10.0.0.5 -c "Target" --operator "John Doe, Lead Operator"
```

Appears in report and findings.json metadata.

### Combining Options

```bash
sudo umbra \
  -t 172.16.0.0/16 \
  -c "Enterprise Network" \
  --operator "Alexander Morrow" \
  --scope "172.16.0.0/22 only | No production DB scans" \
  --phases recon,enum,ad,vulns \
  --fast \
  -v \
  -o ~/engagements
```

---

## Output & Reporting

### Directory Structure

```
~/engagements/
└── ACME_Corp_20260324_143022/
    ├── engagement.json          # Engagement metadata
    ├── findings.json            # Complete findings dict
    ├── report.md                # Markdown report
    ├── recon/
    │   ├── discovery.xml        # Host sweep (ping scan)
    │   ├── ports_10.10.10.5.xml
    │   ├── services_10.10.10.5.xml
    │   └── os_10.10.10.5.xml
    ├── enum/
    │   ├── smb_*.txt
    │   ├── http_*.txt
    │   ├── ldap_*.txt
    │   └── [service]_*.txt
    ├── ad/
    │   ├── enum4linux_*.txt
    │   ├── ldap_*.txt
    │   ├── asrep_hashes.txt     (if AS-REP vulnerable accounts found)
    │   └── kerberoast_hashes.txt (if Kerberoastable accounts found)
    └── vulns/
        ├── nmap_vuln_*.xml
        ├── searchsploit_*.json
        └── *.txt                (netexec named checks)
```

### Reading the Report

**`report.md`** contains:

1. **Executive Summary**: Live hosts, open ports, findings count, severity breakdown
2. **Per-Host Sections**: OS, open ports, enum results, AD findings, vulnerability list by severity
3. **Recommendations**: Immediate actions, remediation timeline, hardening guidance

**`findings.json`** structure:

```json
{
  "engagement": {
    "client": "ACME Corp",
    "operator": "Alexander Morrow",
    "target": "10.10.10.5",
    "scope": "Single server only",
    "start_time": "2026-03-24T14:30:22",
    "end_time": "2026-03-24T14:45:18",
    "output_dir": "/home/herecy/engagements/ACME_Corp_20260324_143022"
  },
  "hosts": {
    "10.10.10.5": {
      "status": "up",
      "hostname": "dc01.acme.local",
      "os": "Windows Server 2019 (acc: 95%)",
      "ports": {
        "80": { "protocol": "tcp", "state": "open", "service": "http", "product": "IIS", "version": "10.0" },
        "445": { "protocol": "tcp", "state": "open", "service": "netbios-ssn", "product": "Windows", "version": "" }
      },
      "enum": { "smb": {}, "http": {}, "ldap": {} },
      "ad": {
        "domain": "acme.local",
        "users": ["Administrator", "Guest", "krbtgt", ...],
        "spns": ["HOST/dc01.acme.local", ...],
        "asrep_hashes": [...],
        "kerberoast_hashes": [...]
      },
      "vulns": [
        {
          "source": "searchsploit",
          "port": "445",
          "severity": "CRITICAL",
          "cves": ["CVE-2017-0144"],
          "title": "MS17-010 EternalBlue"
        }
      ]
    }
  }
}
```

---

## Troubleshooting

### Tool Not Found Errors

```bash
# If you see "[tool not found: nmap]"
sudo apt install -y nmap

# Install all recommended tools at once:
sudo apt install -y nikto gobuster feroxbuster enum4linux-ng netexec
```

### "Authorization not confirmed" Exit

This is **intentional** — Umbra requires explicit confirmation before proceeding.

```
I confirm I have written authorization for this target [y/N]: 
```

Type `y` and press Enter.

### Timeouts

If phases timeout (default 120-300s per tool):

- Run with `--fast` flag to skip full port scans
- Run single phases at a time: `--phases recon` then `--phases enum` separately
- Check target network connectivity: `ping <target>` first

### LDAP Null-Bind Fails

If LDAP shows `"auth required"`:

- AD enumeration still proceeds but returns less data
- Often expected for security-hardened environments
- AS-REP + Kerberoast may fail without valid credentials

### Missing Wordlists for HTTP Enumeration

`gobuster/feroxbuster` requires directory wordlists:

```bash
sudo apt install -y seclists
# Or manually: /usr/share/seclists/Discovery/Web-Content/
```

If no wordlist found, HTTP dirbust is marked `[no wordlist found]` in output.

### Permission Denied on Output Directory

Umbra creates `~/engagements/` by default. If using custom `-o` path:

```bash
# Ensure directory is writable
sudo mkdir -p /mnt/pentest/results
sudo chown $USER /mnt/pentest/results
sudo umbra -t 10.10.10.5 -c "Target" -o /mnt/pentest/results
```

---

## Best Practices

### Pre-Engagement Checklist

- [ ] Written authorization letter on file
- [ ] Defined scope in writing (includes exclusions)
- [ ] Emergency contact numbers for client
- [ ] Rules of Engagement (ROE) negotiated
- [ ] Legal/NDA signed
- [ ] VPN/network path confirmed working
- [ ] Operator credentials prepared

### Tactical Deployment

1. **Daytime vs. Off-Hours**: Run during business hours for better service discovery; off-hours for stealth
2. **Throttling**: High-speed scans may trigger IDS; use `-T3` equivalent (Umbra defaults to T4)
3. **Fragmentation**: For large networks, break into smaller ranges and run sequentially
4. **Attribution**: Always set `--operator` for audit trail

### Post-Engagement Workflow

1. Run Umbra with full phases
2. Collect findings.json + report.md
3. Cross-reference with manual testing (SQLi, XXE, etc. that automated tools miss)
4. Build remediation plan from CRITICAL/HIGH findings
5. Archive outputs with engagement metadata in secure location

---

## Support & Feedback

**Blackbox Intelligence Group LLC**  
OSCP-certified penetration testing  
*The shadow sees all.*

For issues or enhancements:
- Consult this manual
- Check tool versions with `command -v <tool>`
- Verify Python 3.8+ installed

---

**Last Updated**: March 24, 2026  
**Version**: Blackbox Umbra v1.0  
**Classification**: Internal Use — Authorized Operators Only
