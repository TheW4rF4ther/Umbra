"""
BBR – Vulnerability Module
Identifies known CVEs and exploits via:
  • nmap --script vuln   – local NSE scripts
  • searchsploit         – Exploit-DB offline DB match on service/version strings
  • netexec checks       – BlueKeep (RDP), EternalBlue (SMB), ZeroLogon (LDAP)
"""

import subprocess
import shutil
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console

console = Console()

ORANGE = "bold #B44A1A"
STEEL  = "#A8B2C0"
RED    = "bold red"
YELLOW = "bold yellow"


def _tool(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list, label: str, out_file: Path, timeout: int = 120, verbose: bool = False) -> str:
    if verbose:
        console.print(f"    [dim]CMD: {' '.join(cmd)}[/dim]")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (result.stdout + ("\n" + result.stderr if result.stderr.strip() else "")).strip()
        if out_file:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(output)
        return output
    except subprocess.TimeoutExpired:
        msg = f"[timed out after {timeout}s]"
        if out_file:
            out_file.write_text(msg)
        return msg
    except FileNotFoundError:
        return f"[tool not found: {cmd[0]}]"


class VulnModule:
    def __init__(self, output_dir: str, verbose: bool = False):
        self.output_dir = Path(output_dir) / "vulns"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose    = verbose

    def run(self, host: str, port_data: Dict[str, Any]) -> List[Dict]:
        """Return sorted list of vuln findings for `host`."""
        open_ports = sorted(int(p) for p in port_data.keys() if str(p).isdigit())
        if not open_ports:
            return []

        console.print(f"\n  [{ORANGE}][VULNS][/{ORANGE}] {host}")

        vulns: List[Dict] = []

        # ── nmap vuln scripts ──────────────────────────────────────────────
        nmap_results = self._nmap_vuln(host, open_ports)
        vulns.extend(nmap_results)

        # ── searchsploit per service/version ──────────────────────────────
        if _tool("searchsploit"):
            ss_results = self._searchsploit(host, port_data)
            vulns.extend(ss_results)
        else:
            console.print(f"    [{STEEL}]searchsploit not found – skipping ExploitDB check[/{STEEL}]")

        # ── netexec named checks ───────────────────────────────────────────
        netexec_results = self._netexec_checks(host, open_ports)
        vulns.extend(netexec_results)

        # Summary
        crit = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
        high = sum(1 for v in vulns if v.get("severity") == "HIGH")
        if vulns:
            console.print(
                f"    [{ORANGE}]{len(vulns)} finding(s) — "
                f"[/{ORANGE}][{RED}]CRITICAL: {crit}[/{RED}]  "
                f"[{YELLOW}]HIGH: {high}[/{YELLOW}]"
            )
        else:
            console.print(f"    [{STEEL}]No confirmed vulnerabilities detected[/{STEEL}]")

        return vulns

    # ── nmap vuln scripts ─────────────────────────────────────────────────────

    def _nmap_vuln(self, host: str, open_ports: list) -> List[Dict]:
        port_str = ",".join(str(p) for p in open_ports)
        xml_out  = self.output_dir / f"nmap_vuln_{host}.xml"

        cmd = [
            "nmap", "--script", "vuln",
            "-T4", "--max-retries", "1",
            "-p", port_str,
            "-oX", str(xml_out),
            host,
        ]
        _run(cmd, f"nmap vuln {host}", xml_out.with_suffix(".txt"), timeout=300, verbose=self.verbose)

        vulns = []
        if not xml_out.exists():
            return vulns

        try:
            tree = ET.parse(xml_out)
            for port_el in tree.findall(".//port"):
                portid = port_el.get("portid", "?")
                for sc_el in port_el.findall("script"):
                    sc_id  = sc_el.get("id", "")
                    output = sc_el.get("output", "")

                    # Only record when script actually reports something actionable
                    if not output or "ERROR" in output or "couldn't be run" in output:
                        continue
                    if len(output.strip()) < 10:
                        continue

                    severity = self._guess_severity_nmap(sc_id, output)
                    cves = re.findall(r"CVE-\d{4}-\d{4,}", output)

                    vulns.append({
                        "source":   "nmap-vuln-script",
                        "port":     portid,
                        "script":   sc_id,
                        "title":    sc_id,
                        "detail":   output[:600],
                        "cves":     list(set(cves)),
                        "severity": severity,
                    })
                    console.print(f"    [{_severity_color(severity)}][{severity}][/{_severity_color(severity)}] port {portid} – {sc_id}")
        except ET.ParseError:
            pass

        return vulns

    @staticmethod
    def _guess_severity_nmap(script_id: str, output: str) -> str:
        critical = ["ms17-010", "eternalblue", "bluekeep", "zerologon", "ms08-067"]
        high     = ["smb-vuln", "rdp-vuln", "ms15", "ms14", "ms12", "ms10", "ms09"]
        sid = script_id.lower()
        for kw in critical:
            if kw in sid or kw in output.lower():
                return "CRITICAL"
        for kw in high:
            if kw in sid:
                return "HIGH"
        return "MEDIUM"

    # ── searchsploit ───────────────────────────────────────────────────────────

    def _searchsploit(self, host: str, port_data: Dict[str, Any]) -> List[Dict]:
        vulns = []
        seen_queries: set = set()

        for port, info in port_data.items():
            if not str(port).isdigit():
                continue
            product = info.get("product", "").strip()
            version = info.get("version", "").strip()

            if not product:
                continue
            query = f"{product} {version}".strip()
            if query in seen_queries or len(query) < 4:
                continue
            seen_queries.add(query)

            out_file = self.output_dir / f"searchsploit_{host}_{port}.json"
            raw = _run(
                ["searchsploit", "--json", query],
                f"searchsploit {query}",
                out_file,
                timeout=20,
                verbose=self.verbose,
            )

            try:
                data = json.loads(raw)
                for exp in data.get("RESULTS_EXPLOIT", []):
                    title = exp.get("Title", "")
                    eid   = exp.get("EDB-ID", "")
                    path  = exp.get("Path", "")
                    cves  = re.findall(r"CVE-\d{4}-\d{4,}", title)
                    severity = self._guess_severity_ss(title)

                    vuln = {
                        "source":   "searchsploit",
                        "port":     port,
                        "query":    query,
                        "title":    title,
                        "edb_id":   eid,
                        "path":     path,
                        "cves":     cves,
                        "severity": severity,
                    }
                    vulns.append(vuln)
                    console.print(
                        f"    [{_severity_color(severity)}][{severity}][/{_severity_color(severity)}]"
                        f" EDB-{eid}  port {port}  {title[:70]}"
                    )
            except (json.JSONDecodeError, KeyError):
                pass

        return vulns

    @staticmethod
    def _guess_severity_ss(title: str) -> str:
        t = title.lower()
        if any(kw in t for kw in ["remote code", "rce", "unauthenticated", "pre-auth"]):
            return "CRITICAL"
        if any(kw in t for kw in ["privilege escalation", "privesc", "remote"]):
            return "HIGH"
        if any(kw in t for kw in ["denial of service", "dos", "buffer overflow"]):
            return "MEDIUM"
        return "LOW"

    # ── netexec named checks ──────────────────────────────────────────────────

    def _netexec_checks(self, host: str, open_ports: list) -> List[Dict]:
        """Run named vulnerability checks via netexec modules."""
        vulns = []

        for nxc in ("netexec", "nxc"):
            if not _tool(nxc):
                continue

            # EternalBlue / MS17-010 (SMB)
            if any(p in open_ports for p in (139, 445)):
                raw = _run(
                    [nxc, "smb", host, "-M", "ms17-010"],
                    "netexec ms17-010",
                    self.output_dir / f"ms17010_{host}.txt",
                    timeout=20,
                    verbose=self.verbose,
                )
                if "VULNERABLE" in raw.upper():
                    vulns.append({
                        "source":   "netexec",
                        "title":    "MS17-010 EternalBlue (SMB)",
                        "port":     "445",
                        "cves":     ["CVE-2017-0144"],
                        "severity": "CRITICAL",
                        "detail":   raw[:300],
                    })
                    console.print(f"    [{_severity_color('CRITICAL')}][CRITICAL][/{_severity_color('CRITICAL')}] MS17-010 EternalBlue detected!")

            # BlueKeep (RDP)
            if 3389 in open_ports:
                raw = _run(
                    [nxc, "rdp", host, "-M", "bluekeep"],
                    "netexec bluekeep",
                    self.output_dir / f"bluekeep_{host}.txt",
                    timeout=20,
                    verbose=self.verbose,
                )
                if "VULNERABLE" in raw.upper():
                    vulns.append({
                        "source":   "netexec",
                        "title":    "BlueKeep RDP (CVE-2019-0708)",
                        "port":     "3389",
                        "cves":     ["CVE-2019-0708"],
                        "severity": "CRITICAL",
                        "detail":   raw[:300],
                    })

            # ZeroLogon (LDAP/RPC)
            if any(p in open_ports for p in (88, 389)):
                raw = _run(
                    [nxc, "smb", host, "-M", "zerologon"],
                    "netexec zerologon",
                    self.output_dir / f"zerologon_{host}.txt",
                    timeout=20,
                    verbose=self.verbose,
                )
                if "VULNERABLE" in raw.upper():
                    vulns.append({
                        "source":   "netexec",
                        "title":    "Zerologon (CVE-2020-1472)",
                        "port":     "445",
                        "cves":     ["CVE-2020-1472"],
                        "severity": "CRITICAL",
                        "detail":   raw[:300],
                    })

            # PetitPotam
            if any(p in open_ports for p in (139, 445)):
                raw = _run(
                    [nxc, "smb", host, "-M", "petitpotam"],
                    "netexec petitpotam",
                    self.output_dir / f"petitpotam_{host}.txt",
                    timeout=20,
                    verbose=self.verbose,
                )
                if "VULNERABLE" in raw.upper():
                    vulns.append({
                        "source":   "netexec",
                        "title":    "PetitPotam NTLM Coercion",
                        "port":     "445",
                        "cves":     ["CVE-2021-36942"],
                        "severity": "HIGH",
                        "detail":   raw[:300],
                    })

            break  # only run once with whichever tool is available

        return vulns


def _severity_color(sev: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH":     "bold #B44A1A",
        "MEDIUM":   "bold yellow",
        "LOW":      "dim",
        "INFO":     "cyan",
    }.get(sev, "white")
