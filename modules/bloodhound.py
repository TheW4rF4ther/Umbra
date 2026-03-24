#!/usr/bin/env python3
"""
BloodHound Community Edition Integration Module for Blackbox Umbra
Ingest SharpHound collections and queried pre-computed attack paths from BloodHound-CE
"""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:
    from neo4j import GraphDatabase, basic_auth
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

logger = logging.getLogger(__name__)


class BloodHoundCEClient:
    """
    Interface to BloodHound Community Edition Neo4j backend.
    Queries pre-computed attack paths, high-value targets, and privilege escalation chains.
    """

    # Critical attack path queries optimized for pentest reporting
    QUERIES = {
        'shortest_paths_to_high_value': """
            MATCH p=shortestPath((n:User)-[*..5]->(m:Group {highvalue: true}))
            WHERE NOT n.name =~ '.*\\$'
            RETURN n.name AS source, collect(m.name) AS targets, length(p) AS path_length
            ORDER BY path_length ASC
            LIMIT 50
        """,
        'unconstrained_delegation': """
            MATCH (c:Computer {unconstraineddelegation: true})
            RETURN c.name AS computer, c.description AS description
        """,
        'constrained_delegation': """
            MATCH (u:User {allowedtodelegate: true})
            RETURN u.name AS user, u.allowedtodelegateto AS allowed_services
            LIMIT 25
        """,
        'as_rep_roastable': """
            MATCH (u:User {dontreqpreauth: true})
            RETURN u.name AS user, u.description AS description
            LIMIT 25
        """,
        'kerberoastable': """
            MATCH (u:User)-[r:MemberOf*1..]->(g:Group)
            WHERE u.hasspn = true AND u.name !~ '.*\\$'
            RETURN u.name AS user, u.serviceprincipalnames AS spns,
                   collect(g.name) AS groups
            LIMIT 50
        """,
        'acl_abuse': """
            MATCH p=(n)-[r:AddMember|AllExtendedRights|GenericAll|GenericWrite|
                        WriteOwner|WriteDacl|Owns|WriteProperty|ReadLAPSPassword|
                        ReadGMSAPassword]->(m)
            RETURN n.name AS source, type(r) AS privilege, m.name AS target,
                   labels(n)[0] AS source_type, labels(m)[0] AS target_type
            LIMIT 100
        """,
        'domain_admins': """
            MATCH (u:User)-[r:MemberOf*1..]->(g:Group {name: /.*DOMAIN ADMINS.*/})
            RETURN u.name AS user, collect(distinct g.name) AS admin_groups,
                   u.description AS description
        """,
        'password_spraying_targets': """
            MATCH (u:User {passwordnotchanged: true})
            RETURN u.name AS user, u.lastlogontimestamp AS last_logon
            ORDER BY last_logon DESC
            LIMIT 50
        """,
    }

    def __init__(self, uri: str = "bolt://localhost:7687", username: str = "neo4j", password: str = "umbra"):
        """
        Connect to BloodHound-CE Neo4j backend.
        
        Args:
            uri: Neo4j bolt URI
            username: Neo4j username
            password: Neo4j password
        """
        self.uri = uri
        self.username = username
        self.password = password
        self.driver = None
        self.connected = False
        
        if not NEO4J_AVAILABLE:
            logger.warning("Neo4j driver not installed. BloodHound integration disabled.")
            return
        
        self._connect()
    
    def _connect(self) -> bool:
        """Establish BloodHound-CE Neo4j connection."""
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=basic_auth(self.username, self.password),
                encrypted=False
            )
            with self.driver.session() as session:
                session.run("RETURN 1")
            self.connected = True
            logger.info(f"✅ Connected to BloodHound-CE at {self.uri}")
            return True
        except Exception as e:
            logger.warning(f"⚠️  Could not connect to BloodHound-CE: {e}")
            self.connected = False
            return False
    
    def import_sharphound_json(self, sharphound_json_path: str) -> Dict:
        """
        Import SharpHound JSON collection files into BloodHound-CE.
        
        Args:
            sharphound_json_path: Path to SharpHound .json output file
        
        Returns:
            Dict with import statistics
        """
        if not self.connected:
            return {"status": "failed", "reason": "neo4j_unavailable"}
        
        try:
            with open(sharphound_json_path, 'r') as f:
                data = json.load(f)
            
            stats = {"imported": 0, "errors": []}
            
            with self.driver.session() as session:
                # Import users
                for user in data.get('users', []):
                    try:
                        session.run(
                            """MERGE (u:User {name: $name})
                               SET u.highvalue = $highvalue,
                                   u.hasspn = $hasspn,
                                   u.dontreqpreauth = $dontreqpreauth,
                                   u.description = $description""",
                            {
                                "name": user.get('name'),
                                "highvalue": user.get('highvalue', False),
                                "hasspn": user.get('hasspn', False),
                                "dontreqpreauth": user.get('dontreqpreauth', False),
                                "description": user.get('description', '')
                            }
                        )
                        stats["imported"] += 1
                    except Exception as e:
                        stats["errors"].append(f"User {user.get('name')}: {str(e)}")
                
                # Import computers
                for comp in data.get('computers', []):
                    try:
                        session.run(
                            """MERGE (c:Computer {name: $name})
                               SET c.unconstraineddelegation = $uncon_deleg,
                                   c.allowedtodelegate = $allowed_deleg,
                                   c.description = $description""",
                            {
                                "name": comp.get('name'),
                                "uncon_deleg": comp.get('unconstraineddelegation', False),
                                "allowed_deleg": comp.get('allowedtodelegate', False),
                                "description": comp.get('description', '')
                            }
                        )
                        stats["imported"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Computer {comp.get('name')}: {str(e)}")
            
            logger.info(f"Imported {stats['imported']} SharpHound objects")
            return {"status": "success", **stats}
        
        except Exception as e:
            logger.error(f"SharpHound import failed: {e}")
            return {"status": "failed", "error": str(e)}
    
    def query_attack_paths(self, query_type: str) -> List[Dict]:
        """
        Execute pre-defined attack path queries against BloodHound-CE.
        
        Args:
            query_type: Query type (e.g., 'shortest_paths_to_high_value', 'unconstrained_delegation')
        
        Returns:
            List of results from query
        """
        if not self.connected:
            return []
        
        if query_type not in self.QUERIES:
            logger.error(f"Unknown query type: {query_type}")
            return []
        
        query = self.QUERIES[query_type]
        results = []
        
        try:
            with self.driver.session() as session:
                result = session.run(query)
                for record in result:
                    results.append(dict(record))
            
            logger.info(f"Query '{query_type}' returned {len(results)} results")
            return results
        
        except Exception as e:
            logger.error(f"Query '{query_type}' failed: {e}")
            return []
    
    def query_all_attack_paths(self) -> Dict:
        """
        Execute all attack path queries and aggregate results.
        
        Returns:
            Dict mapping query types to results
        """
        all_results = {}
        
        for query_type in self.QUERIES.keys():
            all_results[query_type] = self.query_attack_paths(query_type)
        
        return all_results
    
    def export_findings(self, output_file: str, findings: Dict) -> bool:
        """
        Export BloodHound findings to JSON report.
        
        Args:
            output_file: Path to output JSON file
            findings: Dict of findings to export
        
        Returns:
            True if successful
        """
        try:
            export = {
                "export_date": datetime.now().isoformat(),
                "source": "BloodHound-CE",
                "findings": findings
            }
            
            with open(output_file, 'w') as f:
                json.dump(export, f, indent=2, default=str)
            
            logger.info(f"Exported BloodHound findings to {output_file}")
            return True
        
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False
    
    def close(self):
        """Close BloodHound-CE connection."""
        if self.driver:
            self.driver.close()
            logger.info("Closed BloodHound-CE connection")


class BloodHoundAnalyzer:
    """
    High-level analyzer for BloodHound findings.
    Translates BloodHound output into actionable pentest recommendations.
    """
    
    SEVERITY_MAP = {
        'unconstrained_delegation': 'CRITICAL',
        'constrained_delegation': 'HIGH',
        'as_rep_roastable': 'HIGH',
        'kerberoastable': 'HIGH',
        'acl_abuse': 'HIGH',
        'domain_admins': 'CRITICAL',
        'password_spraying': 'MEDIUM',
    }
    
    def __init__(self, client: BloodHoundCEClient):
        self.client = client
        self.findings = []
    
    def analyze(self) -> Dict:
        """
        Perform comprehensive BloodHound analysis.
        
        Returns:
            Dict with analysis results and recommendations
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "attack_paths": {},
            "critical_findings": [],
            "recommendations": [],
            "statistics": {}
        }
        
        if not self.client.connected:
            return results
        
        try:
            # Query all attack paths
            all_findings = self.client.query_all_attack_paths()
            results["attack_paths"] = all_findings
            
            # Extract critical findings
            if all_findings.get('unconstrained_delegation'):
                for item in all_findings['unconstrained_delegation']:
                    results["critical_findings"].append({
                        "type": "Unconstrained Delegation",
                        "target": item.get('computer'),
                        "severity": "CRITICAL",
                        "exploitation": "Capture TGT via PrinterBug/PetitPotam, use Rubeus to extract tickets",
                        "tool": "Rubeus.ps1, Get-Printer"
                    })
            
            if all_findings.get('domain_admins'):
                for item in all_findings['domain_admins']:
                    results["critical_findings"].append({
                        "type": "Domain Admin",
                        "target": item.get('user'),
                        "severity": "CRITICAL",
                        "exploitation": "High-value target for compromise",
                        "groups": item.get('admin_groups')
                    })
            
            # Generate targeted recommendations
            results["recommendations"] = self._generate_recommendations(all_findings)
            
            # Statistics
            results["statistics"] = {
                "unconstrained_delegation_count": len(all_findings.get('unconstrained_delegation', [])),
                "kerberoastable_count": len(all_findings.get('kerberoastable', [])),
                "as_rep_roastable_count": len(all_findings.get('as_rep_roastable', [])),
                "acl_abuse_vectors": len(all_findings.get('acl_abuse', [])),
            }
            
            logger.info(f"✅ BloodHound analysis complete")
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            results["error"] = str(e)
        
        return results
    
    def _generate_recommendations(self, findings: Dict) -> List[str]:
        """Generate tactical recommendations based on findings."""
        recs = []
        
        if findings.get('unconstrained_delegation'):
            recs.append("🎯 IMMEDIATE: Exploit unconstrained delegation via PrinterBug + Rubeus to obtain admin tickets")
        
        if findings.get('kerberoastable'):
            recs.append("🎯 MEDIUM: Perform Kerberoasting on SPNs in privileged groups - crack service account passwords offline")
        
        if findings.get('as_rep_roastable'):
            recs.append("🎯 MEDIUM: AS-REP roasting on users with DONT_REQUIRE_PREAUTH - crack without valid credentials")
        
        if findings.get('acl_abuse'):
            recs.append("🎯 HIGH: Dangerous ACL permissions detected - perform ACL-based privilege escalation")
        
        if findings.get('constrained_delegation'):
            recs.append("🎯 HIGH: Constrained delegation with S4U2Proxy - could enable service impersonation")
        
        return recs


def run_bloodhound_analysis(engagement_output: str, sharphound_path: Optional[str] = None) -> Dict:
    """
    Main entry point for BloodHound-CE analysis phase.
    
    Args:
        engagement_output: Output directory for findings
        sharphound_path: Optional path to SharpHound JSON collection
    
    Returns:
        Dict containing BloodHound analysis results
    """
    results = {
        "phase": "bloodhound",
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "analysis": None,
        "notes": []
    }
    
    if not NEO4J_AVAILABLE:
        results["notes"].append("⚠️  Neo4j driver not installed. BloodHound integration unavailable.")
        results["status"] = "skipped"
        return results
    
    try:
        # Initialize BloodHound client
        client = BloodHoundCEClient()
        
        if not client.connected:
            results["notes"].append("⚠️  Could not connect to BloodHound-CE. Ensure BloodHound is running on localhost:7687")
            results["status"] = "warning"
            return results
        
        # Import SharpHound collection if provided
        if sharphound_path and Path(sharphound_path).exists():
            import_stats = client.import_sharphound_json(sharphound_path)
            results["notes"].append(f"Imported SharpHound: {import_stats.get('imported')} objects")
        
        # Perform analysis
        analyzer = BloodHoundAnalyzer(client)
        analysis = analyzer.analyze()
        results["analysis"] = analysis
        
        # Export findings
        export_path = f"{engagement_output}/bloodhound_findings.json"
        if client.export_findings(export_path, analysis):
            results["notes"].append(f"BloodHound findings exported to {export_path}")
        
        results["status"] = "success"
        client.close()
        
    except Exception as e:
        logger.error(f"BloodHound analysis failed: {e}")
        results["status"] = "error"
        results["notes"].append(f"Error: {str(e)}")
    
    return results
