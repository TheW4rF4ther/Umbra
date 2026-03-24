#!/usr/bin/env python3
"""
Neo4j Graph Analysis Module for Blackbox Umbra
Builds attack graphs from AD relationships and identifies shortest paths to Domain Admin
"""

import json
import logging
from typing import Dict, List, Tuple, Set, Optional
from datetime import datetime

try:
    from neo4j import GraphDatabase, basic_auth
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

logger = logging.getLogger(__name__)


class UmbraGraphAnalyzer:
    """
    Neo4j-backed graph analyzer for AD attack paths and privilege escalation chains.
    Ingests host/AD data and computes shortest paths to critical targets.
    """

    def __init__(self, uri: str = "bolt://localhost:7687", username: str = "neo4j", password: str = "umbra"):
        """
        Initialize Neo4j connection.
        
        Args:
            uri: Neo4j connection URI (default: local bolt)
            username: Neo4j username
            password: Neo4j password
        """
        self.uri = uri
        self.username = username
        self.password = password
        self.driver = None
        self.session = None
        self.connected = False
        
        if not NEO4J_AVAILABLE:
            logger.warning("Neo4j Python driver not installed. Graph analysis disabled.")
            return
        
        self._connect()
    
    def _connect(self):
        """Establish Neo4j connection."""
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=basic_auth(self.username, self.password),
                encrypted=False
            )
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            self.connected = True
            logger.info(f"✅ Connected to Neo4j at {self.uri}")
        except Exception as e:
            logger.warning(f"⚠️  Could not connect to Neo4j: {e}")
            self.connected = False
    
    def ingest_ad_data(self, ad_data: Dict) -> Dict:
        """
        Ingest Active Directory data (users, groups, computers, ACLs) into Neo4j.
        
        Args:
            ad_data: Dictionary containing enum/ad module output
                {
                    'domain': str,
                    'users': [{'name': str, 'spn': bool, 'asrep_roastable': bool, ...}],
                    'groups': [{'name': str, 'members': [str]}],
                    'computers': [{'name': str, 'os': str, ...}],
                    'acls': [{'source': str, 'target': str, 'privilege': str}]
                }
        
        Returns:
            Dict with node/relationship creation statistics
        """
        if not self.connected:
            logger.warning("Neo4j not connected. Skipping graph ingestion.")
            return {"status": "skipped", "reason": "neo4j_unavailable"}
        
        stats = {"nodes_created": 0, "relationships_created": 0, "errors": []}
        
        try:
            domain = ad_data.get('domain', 'WORKGROUP')
            
            with self.driver.session() as session:
                # Clear existing data (optional - for demo)
                session.run("MATCH (n) DETACH DELETE n")
                logger.info("Cleared Neo4j database for fresh ingestion")
                
                # Create Domain node
                session.run(
                    "CREATE (d:Domain {name: $domain})",
                    {"domain": domain}
                )
                stats["nodes_created"] += 1
                
                # Ingest Users
                for user in ad_data.get('users', []):
                    props = {
                        'name': user.get('name', 'UNKNOWN'),
                        'domain': domain,
                        'spn': user.get('spn', False),
                        'asrep_roastable': user.get('asrep_roastable', False),
                        'kerberoastable': user.get('kerberoastable', False),
                        'admin': 'admin' in user.get('name', '').lower(),
                    }
                    session.run(
                        """CREATE (u:User {name: $name, domain: $domain, 
                           spn: $spn, asrep_roastable: $asrep_roastable,
                           kerberoastable: $kerberoastable, admin: $admin})
                           WITH u MATCH (d:Domain {name: $domain})
                           CREATE (u)-[:MEMBER_OF]->(d)""",
                        props
                    )
                    stats["nodes_created"] += 1
                    stats["relationships_created"] += 1
                
                # Ingest Groups
                for group in ad_data.get('groups', []):
                    group_name = group.get('name', 'UNKNOWN')
                    is_admin_group = any(x in group_name.lower() for x in ['admin', 'da', 'domain admin'])
                    
                    session.run(
                        """CREATE (g:Group {name: $name, domain: $domain, admin_group: $admin_group})
                           WITH g MATCH (d:Domain {name: $domain})
                           CREATE (g)-[:MEMBER_OF]->(d)""",
                        {"name": group_name, "domain": domain, "admin_group": is_admin_group}
                    )
                    stats["nodes_created"] += 1
                    stats["relationships_created"] += 1
                    
                    # Create group membership relationships
                    for member in group.get('members', []):
                        try:
                            session.run(
                                """MATCH (m:User {name: $member, domain: $domain})
                                   MATCH (g:Group {name: $group, domain: $domain})
                                   CREATE (m)-[:MEMBER_OF]->(g)""",
                                {"member": member, "group": group_name, "domain": domain}
                            )
                            stats["relationships_created"] += 1
                        except Exception as e:
                            stats["errors"].append(f"Group membership {member}→{group_name}: {str(e)}")
                
                # Ingest Computers
                for comp in ad_data.get('computers', []):
                    session.run(
                        """CREATE (c:Computer {name: $name, domain: $domain, os: $os})
                           WITH c MATCH (d:Domain {name: $domain})
                           CREATE (c)-[:MEMBER_OF]->(d)""",
                        {"name": comp.get('name', 'UNKNOWN'), "domain": domain, "os": comp.get('os', 'UNKNOWN')}
                    )
                    stats["nodes_created"] += 1
                    stats["relationships_created"] += 1
                
                # Ingest ACLs (dangerous permissions)
                for acl in ad_data.get('acls', []):
                    acl_type = acl.get('privilege', 'GENERIC')
                    source = acl.get('source', 'UNKNOWN')
                    target = acl.get('target', 'UNKNOWN')
                    
                    # Map to attack edges
                    edge_map = {
                        'GenericAll': 'CAN_EXPLOIT_GENERIC_ALL',
                        'WriteProperty': 'CAN_EXPLOIT_WRITE_PROPERTY',
                        'WriteDacl': 'CAN_EXPLOIT_WRITE_DACL',
                        'WriteOwner': 'CAN_EXPLOIT_WRITE_OWNER',
                        'Owns': 'CAN_EXPLOIT_OWNS',
                        'AllExtendedRights': 'CAN_EXPLOIT_ALL_EXTENDED',
                    }
                    edge_type = edge_map.get(acl_type, 'CAN_EXPLOIT')
                    
                    try:
                        session.run(
                            f"""MATCH (s) WHERE (s.name = $source OR s.name CONTAINS $source)
                               MATCH (t) WHERE (t.name = $target OR t.name CONTAINS $target)
                               CREATE (s)-[:{edge_type} {{privilege: $priv}}]->(t)""",
                            {"source": source, "target": target, "priv": acl_type}
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"ACL {source}→{target}: {str(e)}")
            
            logger.info(f"✅ Ingested AD data: {stats['nodes_created']} nodes, {stats['relationships_created']} relationships")
            return stats
        
        except Exception as e:
            logger.error(f"Error during graph ingestion: {e}")
            stats["errors"].append(str(e))
            return stats
    
    def find_shortest_path_to_da(self, domain: str) -> List[Dict]:
        """
        Find shortest paths to Domain Admin for all non-admin users.
        Uses Neo4j shortest path algorithm to identify compromise chains.
        
        Args:
            domain: Active Directory domain name
        
        Returns:
            List of attack paths, each containing node chain and attack methods
        """
        if not self.connected:
            return []
        
        attack_paths = []
        
        try:
            with self.driver.session() as session:
                # Find all users that are NOT admin
                users = session.run(
                    "MATCH (u:User {domain: $domain, admin: false}) RETURN u.name AS name",
                    {"domain": domain}
                ).records()
                
                # Find Domain Admin group
                da_result = session.run(
                    "MATCH (g:Group {domain: $domain, admin_group: true}) RETURN g.name AS name LIMIT 1",
                    {"domain": domain}
                ).single()
                
                if not da_result:
                    logger.warning(f"No Domain Admin group found for {domain}")
                    return attack_paths
                
                da_group = da_result["name"]
                
                # For each user, find shortest exploitation path to DA group
                for user_record in users:
                    user_name = user_record["name"]
                    
                    # Find shortest path using any relationship type
                    path_result = session.run(
                        """MATCH (u:User {name: $user, domain: $domain})
                           MATCH (g:Group {name: $da_group, domain: $domain})
                           MATCH p = shortestPath((u)-[*..5]->(g))
                           RETURN p, length(p) AS path_length""",
                        {"user": user_name, "domain": domain, "da_group": da_group}
                    ).single()
                    
                    if path_result:
                        path = path_result["p"]
                        path_length = path_result["path_length"]
                        
                        # Extract nodes and relationships from path
                        nodes = []
                        edges = []
                        for i, entity in enumerate(path):
                            if i % 2 == 0:  # Nodes
                                nodes.append({"name": entity.get("name"), "type": list(entity.labels)[0]})
                            else:  # Relationships
                                edges.append({"type": entity.type, "privilege": entity.get("privilege")})
                        
                        attack_paths.append({
                            "source_user": user_name,
                            "target": da_group,
                            "path_length": path_length,
                            "nodes": nodes,
                            "attack_chain": edges,
                            "severity": "CRITICAL" if path_length <= 3 else ("HIGH" if path_length <= 4 else "MEDIUM")
                        })
                
                # Also find high-privilege users with direct DA group membership
                high_priv_result = session.run(
                    """MATCH (u:User {domain: $domain})-[:MEMBER_OF]->(g:Group {admin_group: true, domain: $domain})
                       RETURN u.name AS user, g.name AS group""",
                    {"domain": domain}
                ).records()
                
                for record in high_priv_result:
                    attack_paths.append({
                        "source_user": record["user"],
                        "target": record["group"],
                        "path_length": 1,
                        "nodes": [{"name": record["user"], "type": "User"}, {"name": record["group"], "type": "Group"}],
                        "attack_chain": [{"type": "MEMBER_OF"}],
                        "severity": "CRITICAL",
                        "note": "Direct Domain Admin group membership"
                    })
            
            logger.info(f"Found {len(attack_paths)} attack paths to Domain Admin")
            return attack_paths
        
        except Exception as e:
            logger.error(f"Error finding paths to DA: {e}")
            return []
    
    def identify_attack_primitives(self, domain: str) -> Dict:
        """
        Identify high-value attack primitives (users/groups that unlock further attack surface).
        Returns nodes with the highest centrality and exploitation potential.
        
        Args:
            domain: Active Directory domain name
        
        Returns:
            Dict mapping attack primitives with their exposure level
        """
        if not self.connected:
            return {}
        
        primitives = {
            "critical_users": [],
            "critical_groups": [],
            "lateral_movement_vectors": [],
            "privilege_escalation_chains": []
        }
        
        try:
            with self.driver.session() as session:
                # Find high-value users (kerberoastable SPN, AS-REP roastable, etc.)
                high_value_users = session.run(
                    """MATCH (u:User {domain: $domain})
                       WHERE u.spn = true OR u.asrep_roastable = true OR u.kerberoastable = true
                       RETURN u.name AS name, u.spn AS spn, u.asrep_roastable AS asrep, 
                              u.kerberoastable AS kerberoast""",
                    {"domain": domain}
                ).records()
                
                for record in high_value_users:
                    primitives["critical_users"].append({
                        "name": record["name"],
                        "roastable": record["spn"] or record["asrep"] or record["kerberoast"],
                        "exposure": "HIGH"
                    })
                
                # Find groups with excessive permissions
                privileged_groups = session.run(
                    """MATCH (g:Group {domain: $domain, admin_group: true})
                       MATCH (g)<-[:MEMBER_OF]-(members)
                       RETURN g.name AS group_name, count(members) AS member_count""",
                    {"domain": domain}
                ).records()
                
                for record in privileged_groups:
                    primitives["critical_groups"].append({
                        "name": record["group_name"],
                        "member_count": record["member_count"],
                        "exposure": "CRITICAL"
                    })
                
                # Find ACL abuse vectors (any CAN_EXPLOIT* relationships)
                acl_vectors = session.run(
                    """MATCH (s)-[r]->(t)
                       WHERE type(r) STARTS WITH 'CAN_EXPLOIT'
                       RETURN s.name AS source, type(r) AS privilege_type, t.name AS target,
                              labels(s)[0] AS source_type, labels(t)[0] AS target_type""",
                    {}
                ).records()
                
                for record in acl_vectors:
                    primitives["lateral_movement_vectors"].append({
                        "from": record["source"],
                        "from_type": record["source_type"],
                        "to": record["target"],
                        "to_type": record["target_type"],
                        "privilege": record["privilege_type"],
                        "exposure": "HIGH"
                    })
            
            logger.info(f"Identified {len(primitives['critical_users'])} critical users, "
                       f"{len(primitives['critical_groups'])} critical groups")
            return primitives
        
        except Exception as e:
            logger.error(f"Error identifying attack primitives: {e}")
            return primitives
    
    def export_graph_json(self, output_file: str) -> bool:
        """
        Export entire Neo4j graph to JSON for visualization/reporting.
        
        Args:
            output_file: Path to output JSON file
        
        Returns:
            True if successful, False otherwise
        """
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                # Export all nodes and relationships
                nodes = []
                relationships = []
                
                node_result = session.run("MATCH (n) RETURN id(n) AS id, labels(n) AS labels, properties(n) AS props")
                for record in node_result:
                    nodes.append({
                        "id": record["id"],
                        "labels": record["labels"],
                        "properties": record["props"]
                    })
                
                rel_result = session.run(
                    """MATCH (s)-[r]->(t) RETURN id(s) AS source, id(t) AS target, 
                       type(r) AS type, properties(r) AS props"""
                )
                for record in rel_result:
                    relationships.append({
                        "source": record["source"],
                        "target": record["target"],
                        "type": record["type"],
                        "properties": record["props"]
                    })
                
                graph_export = {
                    "export_date": datetime.now().isoformat(),
                    "nodes": nodes,
                    "relationships": relationships
                }
                
                with open(output_file, 'w') as f:
                    json.dump(graph_export, f, indent=2, default=str)
                
                logger.info(f"Exported graph: {len(nodes)} nodes, {len(relationships)} relationships to {output_file}")
                return True
        
        except Exception as e:
            logger.error(f"Error exporting graph: {e}")
            return False
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            logger.info("Closed Neo4j connection")


def run_graph_analysis(ad_data: Dict, engagement_output: str) -> Dict:
    """
    Main entry point for graph analysis phase.
    
    Args:
        ad_data: AD enumeration data from ad.py module
        engagement_output: Output directory for findings
    
    Returns:
        Dict containing graph analysis results
    """
    results = {
        "phase": "graph",
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "graph_available": False,
        "attack_paths": [],
        "attack_primitives": {},
        "notes": []
    }
    
    if not NEO4J_AVAILABLE:
        results["notes"].append("⚠️  Neo4j driver not installed (pip install neo4j). Graph analysis skipped.")
        results["status"] = "skipped"
        return results
    
    try:
        # Initialize graph analyzer
        analyzer = UmbraGraphAnalyzer()
        
        if not analyzer.connected:
            results["notes"].append("⚠️  Could not connect to Neo4j. Ensure Neo4j is running (docker run -d -p 7687:7687 neo4j)")
            results["status"] = "warning"
            return results
        
        # Ingest AD data
        ingest_stats = analyzer.ingest_ad_data(ad_data)
        results["notes"].append(f"Ingested {ingest_stats['nodes_created']} nodes, "
                               f"{ingest_stats['relationships_created']} relationships")
        
        # Find attack paths to Domain Admin
        domain = ad_data.get('domain', 'WORKGROUP')
        attack_paths = analyzer.find_shortest_path_to_da(domain)
        results["attack_paths"] = attack_paths
        
        # Identify attack primitives
        primitives = analyzer.identify_attack_primitives(domain)
        results["attack_primitives"] = primitives
        
        # Export graph
        export_path = f"{engagement_output}/graph_export.json"
        if analyzer.export_graph_json(export_path):
            results["graph_available"] = True
            results["notes"].append(f"Graph exported to {export_path}")
        
        analyzer.close()
        results["status"] = "success"
        logger.info("✅ Graph analysis phase completed successfully")
    
    except Exception as e:
        logger.error(f"Graph analysis failed: {e}")
        results["status"] = "error"
        results["notes"].append(f"Error: {str(e)}")
    
    return results
