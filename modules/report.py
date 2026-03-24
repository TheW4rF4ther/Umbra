"""
Blackbox Umbra – Report Module
Generates engagement reports in Markdown + tabular summaries.
Ingests the centralized findings dict and produces:
  • Markdown report with all findings organized by host
  • Rich table summary printed to console
  • JSON already saved by main entrypoint
"""

from pathlib import Path
from typing import Any, Dict, List
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
from rich import box

console = Console()

ORANGE = "bold #B44A1A"
STEEL  = "#A8B2C0"
RED    = "bold red"
YELLOW = "bold yellow"
GREEN  = "bold green"


class ReportModule:
    def __init__(self, findings: Dict[str, Any]):
        self.findings = findings
        self.engagement = findings.get("engagement", {})
        self.hosts = findings.get("hosts", {})

    def write_markdown(self, output_path: Path) -> Path:
        """Write comprehensive markdown report."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "# Blackbox Umbra Engagement Report",
            "",
            f"**Client:** {self.engagement.get('client', 'N/A')}",
            f"**Operator:** {self.engagement.get('operator', 'N/A')}",
            f"**Target(s):** {self.engagement.get('target', 'N/A')}",
            f"**Scope:** {self.engagement.get('scope', 'N/A')}",
            "",
            f"**Start:** {self.engagement.get('start_time', 'N/A')}",
            f"**End:** {self.engagement.get('end_time', 'N/A')}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
        ]

        # Quick stats
        total_hosts = len([h for h in self.hosts.values() if h.get("status") == "up"])
        total_ports = sum(len(h.get("ports", {})) for h in self.hosts.values())
        total_vulns = sum(len(h.get("vulns", [])) for h in self.hosts.values())
        ad_hosts = sum(1 for h in self.hosts.values() if h.get("ad"))
        critical_vulns = sum(
            1 for h in self.hosts.values()
            for v in h.get("vulns", [])
            if v.get("severity") == "CRITICAL"
        )
        high_vulns = sum(
            1 for h in self.hosts.values()
            for v in h.get("vulns", [])
            if v.get("severity") == "HIGH"
        )

        lines.extend([
            f"- **Live Hosts:** {total_hosts}",
            f"- **Open Ports:** {total_ports}",
            f"- **Total Findings:** {total_vulns}",
            f"  - CRITICAL: {critical_vulns}",
            f"  - HIGH: {high_vulns}",
            f"- **Domain Controllers:** {ad_hosts}",
            "",
            "---",
            "",
            "## Detailed Findings",
            "",
        ])

        # Per-host sections
        for host, data in sorted(self.hosts.items()):
            if data.get("status") != "up":
                continue

            lines.append(f"### {host}")
            lines.append("")
            lines.append(f"**Hostname:** {data.get('hostname', 'N/A')}")
            lines.append(f"**OS:** {data.get('os', 'Unknown')}")
            lines.append("")

            # Ports
            ports = data.get("ports", {})
            if ports:
                lines.append("#### Open Ports")
                lines.append("")
                for port, info in sorted(ports.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
                    svc = info.get("service", "?")
                    prod = info.get("product", "")
                    ver = info.get("version", "")
                    proto = info.get("protocol", "tcp")
                    ver_str = f"{prod} {ver}".strip()
                    lines.append(f"- **{port}/{proto}** – {svc}")
                    if ver_str:
                        lines.append(f"  - Version: {ver_str}")
                lines.append("")

            # Enumeration
            enum_data = data.get("enum", {})
            if enum_data:
                lines.append("#### Enumeration Results")
                lines.append("")
                for svc, results in enum_data.items():
                    if isinstance(results, dict):
                        lines.append(f"**{svc.upper()}:**")
                        for k, v in results.items():
                            if isinstance(v, str) and len(v) > 200:
                                lines.append(f"- {k}: [output truncated]")
                            elif isinstance(v, list):
                                for item in v[:10]:
                                    lines.append(f"  - {item}")
                                if len(v) > 10:
                                    lines.append(f"  ... and {len(v) - 10} more")
                            elif v:
                                lines.append(f"- {k}: {v}")
                lines.append("")

            # AD findings
            ad_data = data.get("ad", {})
            if ad_data:
                lines.append("#### Active Directory Findings")
                lines.append("")
                lines.append(f"**Domain:** {ad_data.get('domain', 'N/A')}")
                if ad_data.get("users"):
                    lines.append(f"**Users Found:** {len(ad_data['users'])}")
                    for u in ad_data["users"][:20]:
                        lines.append(f"- {u}")
                    if len(ad_data["users"]) > 20:
                        lines.append(f"- ... and {len(ad_data['users']) - 20} more")
                if ad_data.get("spns"):
                    lines.append(f"**SPNs (Kerberoastable):** {len(ad_data['spns'])}")
                    for spn in ad_data["spns"][:10]:
                        lines.append(f"- {spn}")
                if ad_data.get("asrep_hashes"):
                    lines.append(f"**AS-REP Hashes:** {len(ad_data['asrep_hashes'])}")
                if ad_data.get("kerberoast_hashes"):
                    lines.append(f"**Kerberoast Hashes:** {len(ad_data['kerberoast_hashes'])}")
                if ad_data.get("notes"):
                    lines.append("**Notes:**")
                    for note in ad_data["notes"]:
                        lines.append(f"- {note}")
                lines.append("")

            # Vulnerabilities
            vulns = data.get("vulns", [])
            if vulns:
                lines.append("#### Vulnerabilities")
                lines.append("")
                critical = [v for v in vulns if v.get("severity") == "CRITICAL"]
                high = [v for v in vulns if v.get("severity") == "HIGH"]
                medium = [v for v in vulns if v.get("severity") == "MEDIUM"]

                if critical:
                    lines.append("**CRITICAL**")
                    for v in critical:
                        lines.append(f"- {v.get('title', 'Unknown')} (port {v.get('port', '?')})")
                        if v.get("cves"):
                            lines.append(f"  - CVEs: {', '.join(v['cves'])}")

                if high:
                    lines.append("**HIGH**")
                    for v in high:
                        lines.append(f"- {v.get('title', 'Unknown')} (port {v.get('port', '?')})")
                        if v.get("cves"):
                            lines.append(f"  - CVEs: {', '.join(v['cves'])}")

                if medium:
                    lines.append("**MEDIUM**")
                    for v in medium[:10]:
                        lines.append(f"- {v.get('title', 'Unknown')}")
                    if len(medium) > 10:
                        lines.append(f"- ... and {len(medium) - 10} more")

                lines.append("")

            lines.append("---")
            lines.append("")

        # Recommendations
        lines.extend([
            "## Recommendations",
            "",
            "### Immediate Actions",
            "",
            f"- Address all CRITICAL findings before deployment (count: {critical_vulns})",
            f"- Remediate HIGH findings within 30 days (count: {high_vulns})",
            "- Apply vendor patches for all identified CVEs",
            "",
            "### General Hardening",
            "",
            "- Implement network segmentation and zero-trust controls",
            "- Enable MFA on all administrative accounts",
            "- Disable SMB signing enforcement across the domain (if applicable)",
            "- Implement EDR and continuous vulnerability management",
            "",
            "---",
            "",
            "**Report Generated:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "",
            "*Blackbox Intelligence Group LLC*",
        ])

        report_text = "\n".join(lines)
        output_path.write_text(report_text)
        return output_path

    def print_summary(self) -> None:
        """Print a rich table summary to console."""
        table = Table(
            title=f"[{ORANGE}]Blackbox Umbra Engagement Summary[/{ORANGE}]",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("Host", style=ORANGE, width=18)
        table.add_column("OS", style=STEEL, width=20)
        table.add_column("Ports", style="cyan", width=12)
        table.add_column("AD", style=YELLOW, width=6)
        table.add_column("CRITICAL", style=RED, width=10)
        table.add_column("HIGH", style=YELLOW, width=10)
        table.add_column("MEDIUM", style="dim yellow", width=10)

        for host, data in sorted(self.hosts.items()):
            if data.get("status") != "up":
                continue

            os_info = (data.get("os", "Unknown"))[:20]
            port_count = len(data.get("ports", {}))
            is_dc = "✓" if data.get("ad") else ""

            crit = sum(1 for v in data.get("vulns", []) if v.get("severity") == "CRITICAL")
            high = sum(1 for v in data.get("vulns", []) if v.get("severity") == "HIGH")
            medium = sum(1 for v in data.get("vulns", []) if v.get("severity") == "MEDIUM")

            table.add_row(
                host,
                os_info,
                str(port_count),
                is_dc,
                str(crit) if crit else "–",
                str(high) if high else "–",
                str(medium) if medium else "–",
            )

        console.print(table)
