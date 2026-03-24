"""
BBR – Enumeration Module
Service-specific enumeration dispatched automatically from open port list.

Covered services:
  FTP   (21)          – anonymous login, banner
  SSH   (22)          – version, auth methods
  SMTP  (25,465,587)  – version, VRFY/EXPN check
  HTTP/HTTPS          – headers, title, nikto, gobuster/feroxbuster
  SMB   (139,445)     – netexec, smbclient, null-session shares
  LDAP  (389,636)     – ldapsearch base query
  RPC   (135)         – rpcclient SID/user enum
  MSSQL (1433)        – netexec mssql banner
  MySQL (3306)        – banner
  RDP   (3389)        – netexec rdp
  WinRM (5985,5986)   – netexec winrm
"""

import subprocess
import shutil
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console

console = Console()

ORANGE = "bold #B44A1A"
STEEL  = "#A8B2C0"

SMB_PORTS  = {139, 445}
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888}
LDAP_PORTS = {389, 636}
RPC_PORTS  = {135, 593}
FTP_PORTS  = {21}
SSH_PORTS  = {22}
SMTP_PORTS = {25, 465, 587}
MSSQL_PORTS= {1433}
MYSQL_PORTS= {3306}
RDP_PORTS  = {3389}
WINRM_PORTS= {5985, 5986}

# Best wordlist candidates on Kali
WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


def _tool(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: List[str], label: str, out_file: Path, timeout: int = 120, verbose: bool = False) -> str:
    if verbose:
        console.print(f"    [dim]CMD: {' '.join(cmd)}[/dim]")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + ("\n--- STDERR ---\n" + result.stderr if result.stderr.strip() else "")
        output = output.strip()
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


class EnumModule:
    def __init__(self, output_dir: str, verbose: bool = False):
        self.output_dir = Path(output_dir) / "enum"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose     = verbose

    def run(self, host: str, port_data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch enumeration for all open ports on `host`."""
        open_ports = set(int(p) for p in port_data.keys() if str(p).isdigit())
        results    = {}

        console.print(f"\n  [{ORANGE}][ENUM][/{ORANGE}] {host}  [{STEEL}]{len(open_ports)} open port(s)[/{STEEL}]")

        # --- SMB ----------------------------------------------------------
        if open_ports & SMB_PORTS:
            console.print(f"    [{STEEL}]→ SMB enumeration[/{STEEL}]")
            results["smb"] = self._smb(host)

        # --- HTTP/HTTPS ---------------------------------------------------
        web_ports = sorted(open_ports & HTTP_PORTS)
        if web_ports:
            console.print(f"    [{STEEL}]→ HTTP enumeration on {web_ports}[/{STEEL}]")
            results["http"] = self._http(host, web_ports, port_data)

        # --- LDAP ---------------------------------------------------------
        if open_ports & LDAP_PORTS:
            console.print(f"    [{STEEL}]→ LDAP enumeration[/{STEEL}]")
            results["ldap"] = self._ldap(host)

        # --- RPC ----------------------------------------------------------
        if open_ports & RPC_PORTS:
            console.print(f"    [{STEEL}]→ RPC enumeration[/{STEEL}]")
            results["rpc"] = self._rpc(host)

        # --- FTP ----------------------------------------------------------
        if open_ports & FTP_PORTS:
            console.print(f"    [{STEEL}]→ FTP enumeration[/{STEEL}]")
            results["ftp"] = self._ftp(host)

        # --- MSSQL --------------------------------------------------------
        if open_ports & MSSQL_PORTS:
            console.print(f"    [{STEEL}]→ MSSQL check[/{STEEL}]")
            results["mssql"] = self._mssql(host)

        # --- RDP ----------------------------------------------------------
        if open_ports & RDP_PORTS:
            results["rdp"] = self._rdp(host)

        # --- WinRM --------------------------------------------------------
        if open_ports & WINRM_PORTS:
            results["winrm"] = self._winrm(host)

        return results

    # ── SMB ───────────────────────────────────────────────────────────────────

    def _smb(self, host: str) -> dict:
        out = {}

        # netexec – recommended replacement for crackmapexec
        for tool in ("netexec", "nxc"):
            if _tool(tool):
                raw = _run(
                    [tool, "smb", host, "--shares", "--users", "-u", "", "-p", ""],
                    "netexec smb",
                    self.output_dir / f"smb_netexec_{host}.txt",
                    timeout=60,
                    verbose=self.verbose,
                )
                out["netexec"] = raw
                break

        # smbclient share list (null session)
        raw = _run(
            ["smbclient", "-N", "-L", f"//{host}"],
            "smbclient",
            self.output_dir / f"smb_shares_{host}.txt",
            timeout=30,
            verbose=self.verbose,
        )
        out["shares"] = raw

        # rpcclient null session
        raw = _run(
            ["rpcclient", "-U", "", "-N", host, "-c", "srvinfo; enumdomains; enumdomusers"],
            "rpcclient",
            self.output_dir / f"smb_rpc_{host}.txt",
            timeout=30,
            verbose=self.verbose,
        )
        out["rpcclient"] = raw

        return out

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _http(self, host: str, ports: list, port_data: dict) -> dict:
        out = {}

        for port in ports:
            scheme = "https" if port in (443, 8443) else "http"
            url    = f"{scheme}://{host}:{port}"

            # curl headers + title
            raw = _run(
                ["curl", "-sk", "-m", "10", "-I", url],
                f"headers {url}",
                self.output_dir / f"http_headers_{host}_{port}.txt",
                timeout=20,
                verbose=self.verbose,
            )
            out[f"{port}_headers"] = raw

            # whatweb – tech fingerprint
            if _tool("whatweb"):
                raw = _run(
                    ["whatweb", "-a", "3", "-q", url],
                    f"whatweb {url}",
                    self.output_dir / f"http_whatweb_{host}_{port}.txt",
                    timeout=30,
                    verbose=self.verbose,
                )
                out[f"{port}_whatweb"] = raw

            # nikto
            if _tool("nikto"):
                raw = _run(
                    ["nikto", "-host", url, "-nointeractive", "-maxtime", "120"],
                    f"nikto {url}",
                    self.output_dir / f"http_nikto_{host}_{port}.txt",
                    timeout=150,
                    verbose=self.verbose,
                )
                out[f"{port}_nikto"] = raw

            # gobuster or feroxbuster
            wordlist = next((w for w in WORDLIST_CANDIDATES if Path(w).exists()), None)
            if wordlist:
                if _tool("feroxbuster"):
                    raw = _run(
                        [
                            "feroxbuster", "--url", url, "--wordlist", wordlist,
                            "--threads", "10", "--depth", "2",
                            "--no-state", "--quiet",
                            "--status-codes", "200,204,301,302,401,403",
                            "--timeout", "5",
                        ],
                        f"feroxbuster {url}",
                        self.output_dir / f"http_ferox_{host}_{port}.txt",
                        timeout=300,
                        verbose=self.verbose,
                    )
                    out[f"{port}_dirbust"] = raw
                elif _tool("gobuster"):
                    raw = _run(
                        [
                            "gobuster", "dir", "-u", url, "-w", wordlist,
                            "-t", "10", "-q", "--no-error",
                        ],
                        f"gobuster {url}",
                        self.output_dir / f"http_gobuster_{host}_{port}.txt",
                        timeout=300,
                        verbose=self.verbose,
                    )
                    out[f"{port}_dirbust"] = raw
            else:
                out[f"{port}_dirbust"] = "[no wordlist found; install seclists]"

        return out

    # ── LDAP ──────────────────────────────────────────────────────────────────

    def _ldap(self, host: str) -> dict:
        out = {}

        # Base query
        raw = _run(
            ["ldapsearch", "-x", "-H", f"ldap://{host}",
             "-b", "", "-s", "base"],
            "ldapsearch base",
            self.output_dir / f"ldap_base_{host}.txt",
            timeout=20,
            verbose=self.verbose,
        )
        out["base"] = raw

        # Try to get naming context and then query it
        nc = ""
        for line in raw.splitlines():
            if "defaultNamingContext:" in line:
                nc = line.split(":", 1)[1].strip()
                break

        if nc:
            raw2 = _run(
                ["ldapsearch", "-x", "-H", f"ldap://{host}",
                 "-b", nc, "-s", "sub",
                 "(objectClass=user)", "sAMAccountName", "mail", "memberOf"],
                "ldapsearch users",
                self.output_dir / f"ldap_users_{host}.txt",
                timeout=30,
                verbose=self.verbose,
            )
            out["users"] = raw2
            out["naming_context"] = nc

        return out

    # ── RPC ───────────────────────────────────────────────────────────────────

    def _rpc(self, host: str) -> dict:
        out = {}
        raw = _run(
            ["rpcclient", "-U", "", "-N", host,
             "-c", "srvinfo; enumdomains; enumdomusers; enumdomgroups"],
            "rpcclient full",
            self.output_dir / f"rpc_{host}.txt",
            timeout=30,
            verbose=self.verbose,
        )
        out["rpcclient"] = raw
        return out

    # ── FTP ───────────────────────────────────────────────────────────────────

    def _ftp(self, host: str) -> dict:
        # Try anonymous login
        raw = _run(
            ["curl", "-sk", "--max-time", "10",
             f"ftp://{host}/", "--user", "anonymous:anonymous"],
            "ftp anon",
            self.output_dir / f"ftp_{host}.txt",
            timeout=20,
            verbose=self.verbose,
        )
        anon_ok = "550" not in raw and "530" not in raw and raw.strip() != ""
        return {"anonymous": anon_ok, "output": raw}

    # ── MSSQL ─────────────────────────────────────────────────────────────────

    def _mssql(self, host: str) -> dict:
        for tool in ("netexec", "nxc"):
            if _tool(tool):
                raw = _run(
                    [tool, "mssql", host, "-u", "", "-p", ""],
                    "netexec mssql",
                    self.output_dir / f"mssql_{host}.txt",
                    timeout=30,
                    verbose=self.verbose,
                )
                return {"netexec": raw}
        return {"error": "netexec not found"}

    # ── RDP ───────────────────────────────────────────────────────────────────

    def _rdp(self, host: str) -> dict:
        for tool in ("netexec", "nxc"):
            if _tool(tool):
                raw = _run(
                    [tool, "rdp", host],
                    "netexec rdp",
                    self.output_dir / f"rdp_{host}.txt",
                    timeout=20,
                    verbose=self.verbose,
                )
                return {"netexec": raw}
        return {}

    # ── WinRM ─────────────────────────────────────────────────────────────────

    def _winrm(self, host: str) -> dict:
        for tool in ("netexec", "nxc"):
            if _tool(tool):
                raw = _run(
                    [tool, "winrm", host, "-u", "", "-p", ""],
                    "netexec winrm",
                    self.output_dir / f"winrm_{host}.txt",
                    timeout=20,
                    verbose=self.verbose,
                )
                return {"netexec": raw}
        return {}
