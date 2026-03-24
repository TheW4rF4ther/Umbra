"""
BBR – Recon Module
Handles all nmap-based reconnaissance phases:
  1. Host discovery (ping sweep for subnets)
  2. Full TCP port scan
  3. Service/version detection + default scripts
  4. OS detection (requires root)
"""

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

ORANGE = "bold #B44A1A"
STEEL  = "#A8B2C0"


class ReconModule:
    def __init__(self, target: str, output_dir: str, verbose: bool = False, fast: bool = False):
        self.target     = target
        self.output_dir = Path(output_dir) / "recon"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose    = verbose
        self.fast       = fast

    # ── Public entry ─────────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        """Run full recon chain. Returns dict keyed by IP."""
        hosts = {}

        # 1. Host discovery (skip for single host, only needed for ranges)
        live_targets = self._discover_hosts()

        # 2. Per-host: port scan → service scan
        for host in live_targets:
            console.print(f"  [{STEEL}]→ Scanning {host}[/{STEEL}]")
            ports    = self._port_scan(host)
            services = self._service_scan(host, ports) if ports else {}
            os_guess = self._os_detect(host)
            hostname = services.pop("_hostname", host)

            hosts[host] = {
                "status":    "up",
                "hostname":  hostname,
                "os":        os_guess,
                "ports":     services,
            }
            self._print_host_table(host, hostname, os_guess, services)

        return hosts

    # ── Phase 1: Host discovery ───────────────────────────────────────────────

    def _discover_hosts(self):
        """Ping sweep for subnets; return single host as-is."""
        # Single host – skip sweep
        if "/" not in self.target and self._valid_single_host():
            return [self.target]

        xml_out = self.output_dir / "discovery.xml"
        cmd = [
            "nmap", "-sn", "-T4",
            "--max-retries", "2",
            "-oX", str(xml_out),
            self.target,
        ]
        console.print(f"  [{STEEL}]Host discovery: {self.target}[/{STEEL}]")
        self._run(cmd, label="Host sweep")

        if not xml_out.exists():
            return [self.target]

        hosts = []
        tree = ET.parse(xml_out)
        for host_el in tree.getroot().findall("host"):
            state = host_el.find("status")
            if state is not None and state.get("state") == "up":
                addr_el = host_el.find("address[@addrtype='ipv4']")
                if addr_el is not None:
                    hosts.append(addr_el.get("addr"))

        console.print(f"  [{ORANGE}]{len(hosts)} live host(s) found[/{ORANGE}]")
        return hosts if hosts else [self.target]

    def _valid_single_host(self) -> bool:
        import re
        ip  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        hn  = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
        return bool(ip.match(self.target) or hn.match(self.target))

    # ── Phase 2: Port scan ────────────────────────────────────────────────────

    def _port_scan(self, host: str) -> list:
        """Return sorted list of open port numbers."""
        xml_out = self.output_dir / f"ports_{host.replace('/', '_')}.xml"

        if self.fast:
            port_args = ["--top-ports", "1000"]
        else:
            port_args = ["-p-"]

        cmd = [
            "nmap", "-T4", "--open",
            "--max-retries", "2",
            *port_args,
            "-oX", str(xml_out),
            host,
        ]
        label = f"Port scan ({host})"
        self._run(cmd, label=label)

        if not xml_out.exists():
            return []

        ports = []
        try:
            tree = ET.parse(xml_out)
            for port_el in tree.findall(".//port"):
                state = port_el.find("state")
                if state is not None and state.get("state") == "open":
                    ports.append(int(port_el.get("portid", 0)))
        except ET.ParseError:
            pass

        if self.verbose and ports:
            console.print(f"    [{STEEL}]Open ports: {', '.join(str(p) for p in sorted(ports))}[/{STEEL}]")
        return sorted(ports)

    # ── Phase 3: Service / version scan ──────────────────────────────────────

    def _service_scan(self, host: str, ports: list) -> dict:
        """Return dict: {port_str: {service, product, version, state, scripts}}"""
        if not ports:
            return {}

        port_str = ",".join(str(p) for p in ports)
        xml_out  = self.output_dir / f"services_{host.replace('/', '_')}.xml"

        cmd = [
            "nmap", "-sV", "-sC",
            "-T4", "--max-retries", "2",
            "-p", port_str,
            "-oX", str(xml_out),
            host,
        ]
        self._run(cmd, label=f"Service scan ({host})")

        return self._parse_service_xml(xml_out)

    def _parse_service_xml(self, xml_out: Path) -> dict:
        services = {}
        if not xml_out.exists():
            return services
        try:
            tree   = ET.parse(xml_out)
            root   = tree.getroot()

            # Hostname
            for hn_el in root.findall(".//hostname"):
                if hn_el.get("type") == "user":
                    services["_hostname"] = hn_el.get("name", "")

            for port_el in root.findall(".//port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid   = port_el.get("portid")
                proto    = port_el.get("protocol", "tcp")
                svc_el   = port_el.find("service")

                svc_info = {
                    "protocol": proto,
                    "state":    "open",
                    "service":  svc_el.get("name",    "") if svc_el is not None else "",
                    "product":  svc_el.get("product",  "") if svc_el is not None else "",
                    "version":  svc_el.get("version",  "") if svc_el is not None else "",
                    "extra":    svc_el.get("extrainfo","") if svc_el is not None else "",
                    "scripts":  {},
                }
                for sc_el in port_el.findall("script"):
                    svc_info["scripts"][sc_el.get("id", "")] = sc_el.get("output", "")[:500]

                services[portid] = svc_info
        except ET.ParseError:
            pass
        return services

    # ── Phase 4: OS detection ─────────────────────────────────────────────────

    def _os_detect(self, host: str) -> str:
        xml_out = self.output_dir / f"os_{host.replace('/', '_')}.xml"
        cmd = [
            "nmap", "-O", "--osscan-guess",
            "--max-retries", "1",
            "-oX", str(xml_out),
            host,
        ]
        self._run(cmd, label=f"OS detect ({host})")
        try:
            if xml_out.exists():
                tree = ET.parse(xml_out)
                matches = tree.findall(".//osmatch")
                if matches:
                    best = max(matches, key=lambda m: int(m.get("accuracy", "0")))
                    return f"{best.get('name','')} (acc: {best.get('accuracy','')}%)"
        except (ET.ParseError, ValueError):
            pass
        return "Unknown"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _run(self, cmd: list, label: str) -> str:
        if self.verbose:
            console.print(f"    [dim]CMD: {' '.join(cmd)}[/dim]")
        with Progress(
            SpinnerColumn(style=ORANGE),
            TextColumn(f"  [dim]{label}[/dim]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as prog:
            prog.add_task("", total=None)
            result = subprocess.run(
                cmd,
                capture_output=not self.verbose,
                text=True,
            )
        if self.verbose and result.stdout:
            console.print(result.stdout[:2000])
        return result.stdout or ""

    def _print_host_table(self, host, hostname, os_guess, services):
        from rich.table import Table
        from rich import box

        tbl = Table(
            title=f"[{ORANGE}]{host}[/{ORANGE}]  [{STEEL}]{hostname}[/{STEEL}]  [{STEEL}]{os_guess}[/{STEEL}]",
            box=box.SIMPLE_HEAD,
            show_lines=False,
        )
        tbl.add_column("Port",    style="bold white", width=8)
        tbl.add_column("Proto",   style=STEEL,        width=6)
        tbl.add_column("Service", style="bold cyan",  width=14)
        tbl.add_column("Version", style=STEEL)

        for port, info in sorted(services.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
            ver = f"{info.get('product','')} {info.get('version','')}".strip()
            tbl.add_row(str(port), info.get("protocol","tcp"), info.get("service",""), ver)

        console.print(tbl)
