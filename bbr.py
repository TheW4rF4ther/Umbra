#!/usr/bin/env python3
"""
Blackbox Umbra
Blackbox Intelligence Group LLC
OSCP-aligned pentest methodology automation.

Usage:
  sudo python3 bbr.py -t 192.168.1.0/24 -c "Acme Corp" -o ~/engagements
  sudo python3 bbr.py -t 10.0.0.5 -c "Client XYZ" --phases recon,enum,ad,graph,acl,bh,chains,vulns

AUTHORIZED USE ONLY. Run only against systems you have written permission to test.
"""

import argparse
import datetime
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box

from modules.recon import ReconModule
from modules.enum import EnumModule
from modules.ad import ADModule
from modules.graph import run_graph_analysis
from modules.acl import run_acl_analysis
from modules.bloodhound import run_bloodhound_analysis
from modules.visualization import run_chain_visualization
from modules.vulns import VulnModule
from modules.report import ReportModule

console = Console()

# ── Brand colors ────────────────────────────────────────────────────────────
ORANGE   = "bold #B44A1A"
RED      = "bold #C0392B"
STEEL    = "#A8B2C0"
DIM      = "dim white"
GOOD     = "bold green"
WARN     = "bold yellow"
BAD      = "bold red"

UMBRA_BANNER = r"""
 ██╗   ██╗███╗   ███╗██████╗ ██████╗  █████╗
 ██║   ██║████╗ ████║██╔══██║██╔══██║██╔══██║
 ██║   ██║██╔████╔██║██████╔╝██████╔╝███████║
 ██║   ██║██║╚██╔╝██║██╔══██║██╔══██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║██████╔╝██║  ██║██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
   Blackbox Intelligence Group LLC
   Pentest Automation & Discovery
"""


def print_banner() -> None:
    console.print(Panel.fit(
        Text(UMBRA_BANNER, style=ORANGE, justify="center"),
        border_style="#B44A1A",
        subtitle="[dim]AUTHORIZED USE ONLY[/dim]",
    ))


def authorization_gate(target: str, client: str) -> bool:
    """Hard stop: operator must explicitly confirm written authorization."""
    console.print()
    console.print(Panel(
        f"""[bold white]TARGET :[/bold white] [yellow]{target}[/yellow]
[bold white]CLIENT :[/bold white] [yellow]{client}[/yellow]

[bold red]WARNING — READ BEFORE PROCEEDING[/bold red]

This tool performs active reconnaissance and vulnerability scanning.
Use ONLY against systems you have [bold underline]written authorization[/bold underline] to test.

By continuing you confirm:
  [bold green]✔[/bold green] You hold signed written authorization from the asset owner
  [bold green]✔[/bold green] This engagement has a defined scope and rules of engagement
  [bold green]✔[/bold green] You understand unauthorized access is a federal crime (CFAA)
  [bold green]✔[/bold green] Emergency contacts are established with the client""",
        title="[bold red]⚠  AUTHORIZATION REQUIRED[/bold red]",
        border_style="red",
    ))
    console.print()
    confirmed = Confirm.ask(
        "[bold yellow]I confirm I have written authorization for this target[/bold yellow]",
        default=False,
    )
    if not confirmed:
        console.print("[red]Authorization not confirmed. Aborting.[/red]")
        sys.exit(0)
    return True


def setup_engagement(args) -> dict:
    """Build the engagement metadata dict used across all modules."""
    now = datetime.datetime.now()
    slug = f"{args.client.replace(' ', '_')}_{now.strftime('%Y%m%d_%H%M%S')}"
    out_dir = Path(args.output) / slug
    out_dir.mkdir(parents=True, exist_ok=True)

    engagement = {
        "client":    args.client,
        "operator":  args.operator,
        "target":    args.target,
        "scope":     args.scope or args.target,
        "start_time": now.isoformat(),
        "end_time":   None,
        "output_dir": str(out_dir),
        "phases":    args.phases.split(",") if args.phases else ["recon","enum","ad","graph","acl","bh","chains","vulns"],
    }

    # Save metadata immediately so engagement is on record
    meta_path = out_dir / "engagement.json"
    meta_path.write_text(json.dumps(engagement, indent=2))
    console.print(f"[{STEEL}]Engagement directory: {out_dir}[/{STEEL}]")
    return engagement


def run_phases(engagement: dict, args) -> dict:
    """Orchestrate each phase, passing findings forward."""
    phases   = engagement["phases"]
    findings = {"engagement": engagement, "hosts": {}}
    out_dir  = engagement["output_dir"]

    # ── Phase 1: Reconnaissance ──────────────────────────────────────────
    if "recon" in phases:
        console.rule(f"[{ORANGE}]Phase 1 · Reconnaissance[/{ORANGE}]")
        recon = ReconModule(
            target=engagement["target"],
            output_dir=out_dir,
            verbose=args.verbose,
            fast=args.fast,
        )
        hosts = recon.run()
        for h, data in hosts.items():
            findings["hosts"].setdefault(h, {}).update(data)
        console.print(f"[{GOOD}]✔ Recon complete — {len(hosts)} host(s) identified[/{GOOD}]")

    # ── Phase 2: Enumeration ─────────────────────────────────────────────
    if "enum" in phases and findings["hosts"]:
        console.rule(f"[{ORANGE}]Phase 2 · Service Enumeration[/{ORANGE}]")
        enum_mod = EnumModule(output_dir=out_dir, verbose=args.verbose)
        for host, data in findings["hosts"].items():
            if data.get("status") != "up":
                continue
            console.print(f"  [{STEEL}]→ Enumerating {host}[/{STEEL}]")
            result = enum_mod.run(host, data.get("ports", {}))
            findings["hosts"][host].setdefault("enum", {}).update(result)
        console.print(f"[{GOOD}]✔ Enumeration complete[/{GOOD}]")

    # ── Phase 3: Active Directory ────────────────────────────────────────
    ad_findings = {}
    if "ad" in phases and findings["hosts"]:
        console.rule(f"[{ORANGE}]Phase 3 · Active Directory Analysis[/{ORANGE}]")
        ad_mod = ADModule(output_dir=out_dir, verbose=args.verbose)
        for host, data in findings["hosts"].items():
            if data.get("status") != "up":
                continue
            ports = data.get("ports", {})
            if ad_mod.is_domain_controller(ports):
                console.print(f"  [{WARN}]★ Domain Controller detected: {host}[/{WARN}]")
                result = ad_mod.run(host, ports, data.get("enum", {}))
                findings["hosts"][host].setdefault("ad", {}).update(result)
                ad_findings = result  # Capture AD findings for graph/acl analysis
            else:
                console.print(f"  [{STEEL}]  {host}: no AD signatures[/{STEEL}]")
        console.print(f"[{GOOD}]✔ AD analysis complete[/{GOOD}]")
    
    # ── Phase 3.5: Graph Analysis (Neo4j attack paths) ────────────────────
    if "graph" in phases and ad_findings:
        console.rule(f"[{ORANGE}]Phase 3.5 · Attack Path Analysis[/{ORANGE}]")
        console.print(f"  [{STEEL}]→ Analyzing AD relationships with Neo4j[/{STEEL}]")
        graph_result = run_graph_analysis(ad_findings, out_dir)
        findings.setdefault("graph_analysis", {}).update(graph_result)
        if graph_result.get("status") == "success":
            console.print(f"[{GOOD}]✔ Found {len(graph_result.get('attack_paths', []))} attack paths to Domain Admin[/{GOOD}]")
        else:
            console.print(f"[{WARN}]⚠ Graph analysis: {graph_result.get('status')}[/{WARN}]")
    
    # ── Phase 3.6: ACL Abuse Analysis ────────────────────────────────────
    if "acl" in phases and ad_findings:
        console.rule(f"[{ORANGE}]Phase 3.6 · ACL Abuse Detection[/{ORANGE}]")
        console.print(f"  [{STEEL}]→ Scanning for dangerous permissions[/{STEEL}]")
        acl_result = run_acl_analysis(ad_findings)
        findings.setdefault("acl_analysis", {}).update(acl_result)
        if acl_result.get("status") == "success":
            crit_count = acl_result.get('summary', {}).get('critical_vector_count', 0)
            console.print(f"[{GOOD}]✔ Identified {crit_count} critical ACL abuse vectors[/{GOOD}]")
        else:
            console.print(f"[{WARN}]⚠ ACL analysis: {acl_result.get('status')}[/{WARN}]")
    
    # ── Phase 3.7: BloodHound Integration ────────────────────────────────
    if "bh" in phases and ad_findings:
        console.rule(f"[{ORANGE}]Phase 3.7 · BloodHound-CE Analysis[/{ORANGE}]")
        console.print(f"  [{STEEL}]→ Querying BloodHound attack paths[/{STEEL}]")
        bh_result = run_bloodhound_analysis(out_dir)
        findings.setdefault("bloodhound_analysis", {}).update(bh_result)
        if bh_result.get("status") == "success":
            critical = bh_result.get('analysis', {}).get('statistics', {})
            console.print(f"[{GOOD}]✔ BloodHound analysis: {critical.get('unconstrained_delegation_count', 0)} "
                         f"unconstrained delegations, {critical.get('kerberoastable_count', 0)} kerberoastable accounts[/{GOOD}]")
        else:
            console.print(f"[{WARN}]⚠ BloodHound: {bh_result.get('status')}[/{WARN}]")
    
    # ── Phase 3.8: Attack Chain Visualization ────────────────────────────
    graph_findings = findings.get("graph_analysis", {})
    if "chains" in phases and graph_findings.get("attack_paths"):
        console.rule(f"[{ORANGE}]Phase 3.8 · Attack Chain Visualization[/{ORANGE}]")
        console.print(f"  [{STEEL}]→ Generating attack chain diagrams[/{STEEL}]")
        viz_result = run_chain_visualization(graph_findings, 
                                            findings.get("bloodhound_analysis", {}),
                                            out_dir)
        findings.setdefault("attack_chains", {}).update(viz_result)
        if viz_result.get("status") == "success":
            chain_count = len(viz_result.get('chains', []))
            console.print(f"[{GOOD}]✔ Generated {chain_count} attack chain visualizations[/{GOOD}]")
        else:
            console.print(f"[{WARN}]⚠ Visualization: {viz_result.get('status')}[/{WARN}]")

    # ── Phase 4: Vulnerability Identification ────────────────────────────
    if "vulns" in phases and findings["hosts"]:
        console.rule(f"[{ORANGE}]Phase 4 · Vulnerability Identification[/{ORANGE}]")
        vuln_mod = VulnModule(output_dir=out_dir, verbose=args.verbose)
        for host, data in findings["hosts"].items():
            if data.get("status") != "up":
                continue
            console.print(f"  [{STEEL}]→ Scanning {host}[/{STEEL}]")
            result = vuln_mod.run(host, data.get("ports", {}))
            findings["hosts"][host].setdefault("vulns", []).extend(result)
        console.print(f"[{GOOD}]✔ Vulnerability scan complete[/{GOOD}]")

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="umbra",
        description="Blackbox Umbra – Pentest Automation Platform | Blackbox Intelligence Group LLC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  Example: sudo umbra -t 10.10.10.0/24 -c 'Acme Corp'\n"
               "  Example: sudo umbra -t 10.10.10.5 -c 'Acme' --phases recon,enum,ad",
    )
    parser.add_argument("-t", "--target",   required=True,
                        help="Target IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("-c", "--client",   required=True,
                        help="Client name (used in output path and report)")
    parser.add_argument("-o", "--output",   default=str(Path.home()/"engagements"),
                        help="Base output directory (default: ~/engagements)")
    parser.add_argument("--operator",       default=os.getenv("USER", "operator"),
                        help="Operator name for report attribution")
    parser.add_argument("--scope",          default=None,
                        help="Written scope string for report (defaults to target)")
    parser.add_argument("--phases",         default="recon,enum,ad,graph,acl,bh,chains,vulns",
                        help="Comma-separated phases: recon,enum,ad,graph,acl,bh,chains,vulns")
    parser.add_argument("--fast",           action="store_true",
                        help="Fast mode: top-1000 ports only, skip full port scan")
    parser.add_argument("-v", "--verbose",  action="store_true",
                        help="Show raw tool output")
    args = parser.parse_args()

    print_banner()

    # Authorization gate — mandatory
    authorization_gate(args.target, args.client)

    # Engagement setup
    engagement = setup_engagement(args)

    # Run all phases
    findings = run_phases(engagement, args)

    # Finalize engagement record
    engagement["end_time"] = datetime.datetime.now().isoformat()
    findings["engagement"] = engagement

    # Save full findings JSON
    out = Path(engagement["output_dir"])
    (out / "findings.json").write_text(json.dumps(findings, indent=2, default=str))

    # Generate report
    console.rule(f"[{ORANGE}]Generating Engagement Report[/{ORANGE}]")
    report = ReportModule(findings)
    report_path = report.write_markdown(out / "report.md")
    report.print_summary()

    console.print()
    console.print(Panel(
        f"[bold white]Report :[/bold white] {report_path}\n"
        f"[bold white]Raw JSON:[/bold white] {out/'findings.json'}\n"
        f"[bold white]Duration:[/bold white] "
        f"{engagement['start_time']} → {engagement['end_time']}",
        title=f"[{GOOD}]✔  Engagement Complete[/{GOOD}]",
        border_style="#B44A1A",
    ))


if __name__ == "__main__":
    main()
