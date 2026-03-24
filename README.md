```
 ██╗   ██╗███╗   ███╗██████╗ ██████╗  █████╗
 ██║   ██║████╗ ████║██╔══██╗██╔══██╗██╔══██╗
 ██║   ██║██╔████╔██║██████╔╝██████╔╝███████║
 ██║   ██║██║╚██╔╝██║██╔══██╗██╔══██╗██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║██████╔╝██║  ██║██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
   Blackbox Intelligence Group LLC
   Automated Pentest Reconnaissance & Vulnerability Discovery
```

# Blackbox Umbra

**Cutting-edge Penetration Testing & Vulnerability Discovery Framework**

![Version](https://img.shields.io/badge/version-1.0-orange.svg)
![License](https://img.shields.io/badge/license-Proprietary-red.svg)
![Status](https://img.shields.io/badge/status-Active-brightgreen.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)

---

## 🕵️ The Shadow Sees All

**Blackbox Umbra** is a professional-grade penetration testing automation platform designed for security professionals at Blackbox Intelligence Group LLC. It orchestrates comprehensive reconnaissance, service enumeration, Active Directory discovery, and vulnerability identification across target networks.

Built for **authorized penetration testing engagements only**. Umbra automates the labor-intensive discovery phases of a pentest, enabling operators to focus on manual exploitation, reporting, and strategic recommendations.

---

## � Brand Identity

**Color Palette:**
- Primary: `#B44A1A` (Dark Orange) — Power & Authority
- Secondary: `#07090C` (Deep Black) — Mystery & Stealth  
- Accent: `#FF5A66` (Red) — Threat Detection
- Neutral: `#A8B2C0` (Steel) — Professional

**Tagline:**  
*"The shadow sees all."*

---

## �🎯 Capabilities

### Phase 1: Reconnaissance
- Host discovery (ping sweep for subnets; pass-through for single hosts)
- Full TCP port scanning (or top-1000 in fast mode)
- Service/version identification (nmap -sV)
- OS fingerprinting & accuracy metrics

### Phase 2: Service Enumeration
**Automated dispatchers** for detected services:
- **SMB (139, 445)**: Shares, null-session access, user enumeration
- **HTTP/HTTPS (80, 443, 8080, etc.)**: Headers, technology fingerprint, directory enumeration, vuln scan
- **LDAP (389, 636)**: User/group/SPN discovery, domain extraction
- **RPC (135)**: User/domain enumeration via rpcclient
- **FTP, MSSQL, RDP, WinRM**: Service-specific checks & banners
- **SSH, SMTP**: Banner grabbing & auth method enumeration

### Phase 3: Active Directory Analysis
*Triggered automatically if domain controller signatures detected (ports 88, 389, 3268)*
- enum4linux-ng domain enumeration
- LDAP user/group hierarchy discovery
- SPN discovery for **Kerberoasting**
- AS-REP roasting detection (pre-auth not required accounts)
- SMB signing status
- Password policy extraction
- Credential cracking hash extraction (hashcat/John format)

### Phase 4: Vulnerability Identification
- **nmap NSE vuln scripts**: CVE-tagged service vulnerabilities
- **searchsploit integration**: ExploitDB offline database matching on service versions
- **netexec named checks**: EternalBlue (MS17-010), BlueKeep (CVE-2019-0708), Zerologon (CVE-2020-1472), PetitPotam
- Severity stratification: CRITICAL → HIGH → MEDIUM → LOW

---

## 📋 Quick Start

### Installation

```bash
# Clone / place framework
git clone https://github.com/blackboxintelgroup/umbra ~/tools/bbr
cd ~/tools/bbr

# Verify dependencies
pip install -r requirements.txt
sudo apt install -y nmap enum4linux ldapsearch rpcclient smbclient searchsploit netexec nikto gobuster feroxbuster enum4linux-ng

# Test
python3 bbr.py --help
```

### Basic Usage

```bash
# Full engagement recon
sudo python3 bbr.py -t 192.168.1.0/24 -c "Client Name" \
  --operator "Your Name" \
  --scope "Defined scope from ROE" \
  -o ~/engagements

# Fast mode (top-1000 ports only)
sudo python3 bbr.py -t 10.10.10.5 -c "Target" --fast

# Specific phases
sudo python3 bbr.py -t 10.0.0.0/24 -c "Network" --phases recon,enum,ad

# Verbose debugging
sudo python3 bbr.py -t 10.10.10.5 -c "Debug" -v
```

### Outputs

```
~/engagements/<CLIENT>_<TIMESTAMP>/
├── engagement.json          # Metadata
├── findings.json            # Structured findings
├── report.md                # Executive & detailed report
├── recon/                   # Nmap outputs (discovery, ports, services, OS)
├── enum/                    # Service enumeration results
├── ad/                      # Active Directory findings (users, SPNs, hashes)
└── vulns/                   # Vulnerability assessments (nmap, searchsploit, netexec)
```

---

## 🔧 Requirements

### System
- **OS**: Kali Linux 2025+, Ubuntu 22.04+, or equivalent pentest distro
- **Python**: 3.8+
- **RAM**: 512MB+ (1GB+ recommended for large scans)
- **Disk**: 1GB+ for wordlists and outputs

### Core Tools (Required)
```bash
nmap              # Port scanning and NSE scripts
enum4linux        # SMB and LDAP enumeration
ldapsearch        # LDAP queries
rpcclient         # RPC enumeration
smbclient         # SMB share access
searchsploit      # ExploitDB offline DB
netexec (nxc)     # Multi-protocol checking (replaces crackmapexec)
```

### Optional (Recommended)
```bash
nikto             # Web server vulnerability scanner
gobuster          # Directory enumeration
feroxbuster       # Fast directory enumeration
enum4linux-ng     # Improved enum4linux (better output)
impacket          # For AS-REP roasting & Kerberoasting
```

---

## 📖 Documentation

- **[OPERATIONS_MANUAL.md](OPERATIONS_MANUAL.md)** — Comprehensive tactical guide (phases, usage, workflows)
- **[QUICK_REF.md](QUICK_REF.md)** — Laminate-ready cheat sheet
- **[LICENSE](LICENSE)** — Proprietary restrictions & legal terms

---

## ⚖️ Legal & Authorization

### ⚠️ AUTHORIZED USE ONLY

**This tool performs active reconnaissance, port scanning, and vulnerability assessment.**

**YOU MUST HAVE WRITTEN AUTHORIZATION** from the legitimate asset owner before using Blackbox Umbra against any target.

**Unauthorized access is a federal crime** (Computer Fraud & Abuse Act — CFAA 18 U.S.C. § 1030).

### Pre-Engagement Checklist
- [ ] Written authorization letter from asset owner
- [ ] Defined scope (inclusions & exclusions)
- [ ] Rules of Engagement (ROE) negotiated & signed
- [ ] Emergency contact information collected
- [ ] NDA/confidentiality agreements executed
- [ ] Operator credentials prepared
- [ ] Network access confirmed working

---

## 🛡️ What Umbra Does NOT Do

- **SQLi, XXE, SSRF**: Manual web exploitation testing beyond basic HTTP headers
- **Wireless auditing**: Use Aircrack-ng or similar specialized tools
- **Physical security**: Social engineering or physical penetration
- **Credential testing**: Brute-force attacks or known-good credential attempts (except null-session checks)
- **Exploitation**: Umbra discovers vulnerabilities; it does NOT exploit them (intentionally)
- **Post-exploitation**: Lateral movement, persistence, exfiltration (out of scope)

---

## 🔐 License

**Proprietary.** No modifications, redistribution, or derivative works permitted. See [LICENSE](LICENSE) for full terms.

This software is **not open source**. It is provided as-is for authorized use only by Blackbox Intelligence Group LLC and authorized partners.

---

## 📊 Architecture

```
bbr.py (main entrypoint)
├── modules/
│   ├── recon.py         → Host discovery, port/service scanning, OS detection
│   ├── enum.py          → Service-specific enumeration (SMB, HTTP, LDAP, etc.)
│   ├── ad.py            → Domain enumeration, Kerberoasting, AS-REP roasting
│   ├── vulns.py         → nmap vuln check, searchsploit, netexec named checks
│   └── report.py        → Markdown report + JSON findings + summary tables
├── wordlists/           → Directory enumeration lists (optional, external)
└── engagements/         → Output directory for all engagement data
```

---

## 🚀 Example Workflow

```bash
# Step 1: Conduct engagement
sudo python3 ~/tools/bbr/bbr.py \
  -t 172.16.0.0/22 \
  -c "Enterprise Network" \
  --operator "Alexander Morrow" \
  --scope "Defined in ROE" \
  -o ~/engagements

# Step 2: Review findings
cd ~/engagements/Enterprise_Network_*/
cat report.md                    # Read executive summary
jq '.hosts | keys' findings.json # List discovered hosts

# Step 3: Extract hashes for offline cracking
cat ad/*_hashes.txt > hashes_to_crack.txt

# Step 4: Supplement with manual testing
# (SQLi, XXE, RCE testing that automated tools miss)

# Step 5: Compile final report & recommendations
# (Build remediation plan from findings)
```

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Tool not found | `sudo apt install <tool>` |
| Authorization prompt hangs | Ensure sudo session is active; type `y` + Enter |
| Timeout errors | Add `--fast` flag or run phases separately |
| Permission denied on output | `sudo chown $USER ~/engagements` |
| LDAP auth required | Normal for hardened environments; other phases continue |
| No wordlists for HTTP enum | `sudo apt install seclists` |

---

## 📧 Support & Contact

**Blackbox Intelligence Group LLC**  
OSCP-certified penetration testing  
Website: https://blackboxintelgroup.com

For issues or inquiries, contact authorized operators directly.

---

## 📝 Changelog

### v1.0 (March 24, 2026)
- Initial release
- 4-phase automation framework
- Integrated recon, enum, AD, vulns pipelines
- Rich console output + markdown reports
- JSON findings export for custom processing

---

## 🎖️ Credits

**Built by**: Blackbox Intelligence Group LLC  
**Lead Operator**: Alexander Morrow, OSCP  
**Veteran-Owned Business**

---

**The shadow sees all.** 🕵️

*Last Updated: March 24, 2026*  
*Classification: Internal Use — Authorized Operators Only*
