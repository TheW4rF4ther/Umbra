#!/usr/bin/env python3
"""
Persistence Mechanisms Detection Module for Blackbox Umbra
Identifies post-compromise persistence techniques installed on target systems
"""

import json
import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class PersistenceMechanism(Enum):
    """Types of Windows persistence mechanisms."""
    RUN_KEY = "Registry Run Key"
    STARTUP_FOLDER = "Startup Folder"
    SCHEDULED_TASK = "Scheduled Task"
    WMI_SUBSCRIPTION = "WMI Event Subscription"
    SERVICE = "Windows Service"
    COM_HIJACKING = "COM Object Hijacking"
    LOGON_SCRIPT = "Logon Script"
    GPLOGON_SCRIPT = "Group Policy Logon Script"
    LSA_AUTH_PACKAGE = "LSA Authentication Package"
    BROWSER_EXTENSION = "Browser Extension"
    SHIM = "Application Shim (AppCompat)"
    PRINT_MONITOR = "Print Monitor"
    WINSOCK_PROVIDER = "Winsock Provider"
    EXPLORER_ADDON = "Explorer Add-on"


class PersistenceArtifact:
    """Represents a detected persistence mechanism."""
    
    def __init__(self, mechanism: PersistenceMechanism, location: str, 
                 artifact_name: str, created_date: str = "UNKNOWN",
                 severity: str = "HIGH", suspicious: bool = False):
        self.mechanism = mechanism
        self.location = location
        self.artifact_name = artifact_name
        self.created_date = created_date
        self.severity = severity
        self.suspicious = suspicious
        self.cleanup_commands = []
        self.detection_methods = []
    
    def to_dict(self) -> Dict:
        return {
            "mechanism": self.mechanism.value,
            "location": self.location,
            "artifact_name": self.artifact_name,
            "created_date": self.created_date,
            "severity": self.severity,
            "suspicious": self.suspicious,
            "cleanup": self.cleanup_commands,
            "detection": self.detection_methods
        }


class PersistenceAnalyzer:
    """
    Analyzes systems for installed persistence mechanisms.
    Detects post-compromise survival techniques (WMI, scheduled tasks, registry, etc.)
    """
    
    REGISTRY_PERSISTENCE_LOCATIONS = {
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': {
            'critical': True,
            'description': 'User-level auto-start programs',
            'cleanup': 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v ARTIFACT /f'
        },
        'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': {
            'critical': True,
            'description': 'System-level auto-start programs (admin required)',
            'cleanup': 'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v ARTIFACT /f'
        },
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce': {
            'critical': False,
            'description': 'One-time user-level startup',
            'cleanup': 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v ARTIFACT /f'
        },
        'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices': {
            'critical': True,
            'description': 'Service startup (deprecated but still used)',
            'cleanup': 'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" /v ARTIFACT /f'
        },
    }
    
    WMI_PERSISTENCE = {
        'EventFilter': {
            'description': 'WMI Event Filter (trigger condition)',
            'query': 'Get-WmiObject -Class __EventFilter -Namespace "root\\subscription" -Filter "name!=\'\'"|Remove-WmiObject -Confirm:$false'
        },
        'EventConsumer': {
            'description': 'WMI Event Consumer (action to perform)',
            'query': 'Get-WmiObject -Class __EventConsumer -Namespace "root\\subscription" -Filter "name!=\'\'"|Remove-WmiObject -Confirm:$false'
        },
        'FilterToConsumer': {
            'description': 'WMI Filter-to-Consumer Binding',
            'query': 'Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\\subscription" -Filter "filter!=\'\'"|Remove-WmiObject -Confirm:$false'
        }
    }
    
    def __init__(self):
        self.artifacts: List[PersistenceArtifact] = []
        self.admin_artifacts: List[PersistenceArtifact] = []
        self.user_artifacts: List[PersistenceArtifact] = []
    
    def analyze_registry_persistence(self, registry_data: Dict) -> List[PersistenceArtifact]:
        """
        Analyze registry for persistence mechanisms.
        
        Args:
            registry_data: Registry dump from enum.py
        
        Returns:
            List of detected persistence artifacts
        """
        artifacts = []
        
        for location, location_info in self.REGISTRY_PERSISTENCE_LOCATIONS.items():
            reg_keys = registry_data.get(location, {})
            
            for key_name, key_value in reg_keys.items():
                # Detect suspicious entries
                is_suspicious = self._is_suspicious_entry(key_name, key_value)
                
                artifact = PersistenceArtifact(
                    mechanism=PersistenceMechanism.RUN_KEY,
                    location=location,
                    artifact_name=key_name,
                    created_date="UNKNOWN",
                    severity="CRITICAL" if location_info['critical'] else "HIGH",
                    suspicious=is_suspicious
                )
                
                artifact.detection_methods = [
                    f"Get-ItemProperty '{location}' | Select-Object {key_name}",
                    f"reg query \"{location}\" /v {key_name}"
                ]
                
                artifact.cleanup_commands = [
                    location_info['cleanup'].replace('ARTIFACT', key_name)
                ]
                
                artifacts.append(artifact)
        
        logger.info(f"Analyzed registry: found {len(artifacts)} potential Run entries")
        return artifacts
    
    def analyze_scheduled_tasks(self, task_data: Dict) -> List[PersistenceArtifact]:
        """
        Analyze scheduled tasks for persistence.
        
        Args:
            task_data: Scheduled tasks dump from enum.py
        
        Returns:
            List of detected persistence artifacts
        """
        artifacts = []
        
        suspicious_patterns = [
            'powershell', 'cmd', 'cscript', 'wscript', 'rundll32', 'regsvcs',
            'regasm', 'instantiator', 'mshta', 'certutil'
        ]
        
        for task_name, task_info in task_data.items():
            task_action = task_info.get('action', '').lower()
            
            # Detect suspicious task actions
            is_suspicious = any(pattern in task_action for pattern in suspicious_patterns)
            
            if is_suspicious or task_info.get('enabled', False):
                artifact = PersistenceArtifact(
                    mechanism=PersistenceMechanism.SCHEDULED_TASK,
                    location=f"Task Scheduler: {task_name}",
                    artifact_name=task_name,
                    created_date=task_info.get('created', 'UNKNOWN'),
                    severity="CRITICAL" if is_suspicious else "HIGH",
                    suspicious=is_suspicious
                )
                
                artifact.detection_methods = [
                    f"Get-ScheduledTask -TaskName {task_name} | Format-List",
                    f"schtasks /query /tn {task_name} /v"
                ]
                
                artifact.cleanup_commands = [
                    f"Unregister-ScheduledTask -TaskName {task_name} -Confirm:$false",
                    f"schtasks /delete /tn {task_name} /f"
                ]
                
                artifacts.append(artifact)
        
        logger.info(f"Analyzed scheduled tasks: found {len(artifacts)} suspicious tasks")
        return artifacts
    
    def analyze_startup_folders(self, startup_data: Dict) -> List[PersistenceArtifact]:
        """
        Analyze startup folders for persistence.
        
        Args:
            startup_data: Startup folder contents
        
        Returns:
            List of detected persistence artifacts
        """
        artifacts = []
        
        startup_paths = [
            'C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
            'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        ]
        
        for file_info in startup_data.get('files', []):
            file_name = file_info.get('name')
            file_path = file_info.get('path')
            
            artifact = PersistenceArtifact(
                mechanism=PersistenceMechanism.STARTUP_FOLDER,
                location=file_path,
                artifact_name=file_name,
                created_date=file_info.get('created', 'UNKNOWN'),
                severity="HIGH",
                suspicious=True
            )
            
            artifact.cleanup_commands = [f"del \"{file_path}\\{file_name}\""]
            artifacts.append(artifact)
        
        logger.info(f"Analyzed startup folders: found {len(artifacts)} files")
        return artifacts
    
    def analyze_services(self, service_data: Dict) -> List[PersistenceArtifact]:
        """
        Analyze Windows services for suspicious installations.
        
        Args:
            service_data: Windows services list
        
        Returns:
            List of detected persistence artifacts
        """
        artifacts = []
        
        suspicious_service_names = [
            'update', 'security', 'driver', 'helper', 'agent', 'service',
            'task', 'monitor', 'system', 'windows'  # Generic names often used by malware
        ]
        
        for svc_name, svc_info in service_data.items():
            # Detect suspicious services
            is_suspicious = (
                any(pattern in svc_name.lower() for pattern in suspicious_service_names) or
                svc_info.get('start_type') == 'Auto' or
                svc_info.get('binary_path', '').count('\\\\') > 2  # Unusual path depth
            )
            
            if is_suspicious:
                artifact = PersistenceArtifact(
                    mechanism=PersistenceMechanism.SERVICE,
                    location=f"HKLM\\System\\CurrentControlSet\\Services\\{svc_name}",
                    artifact_name=svc_name,
                    created_date="UNKNOWN",
                    severity="CRITICAL",
                    suspicious=True
                )
                
                artifact.detection_methods = [
                    f"Get-Service {svc_name}",
                    f"sc query {svc_name}"
                ]
                
                artifact.cleanup_commands = [
                    f"sc delete {svc_name}",
                    f"Remove-Service -Name {svc_name} -Confirm:$false"
                ]
                
                artifacts.append(artifact)
        
        logger.info(f"Analyzed services: found {len(artifacts)} suspicious services")
        return artifacts
    
    def analyze_wmi_subscriptions(self, wmi_data: Dict) -> List[PersistenceArtifact]:
        """
        Analyze WMI Event Subscriptions for persistence.
        
        Args:
            wmi_data: WMI subscription data
        
        Returns:
            List of detected persistence artifacts
        """
        artifacts = []
        
        # Check for event filters
        event_filters = wmi_data.get('event_filters', [])
        for filter_name in event_filters:
            artifact = PersistenceArtifact(
                mechanism=PersistenceMechanism.WMI_SUBSCRIPTION,
                location="WMI: root\\subscription",
                artifact_name=f"EventFilter: {filter_name}",
                severity="CRITICAL",
                suspicious=True
            )
            
            artifact.detection_methods = [
                f"Get-WmiObject -Class __EventFilter -Namespace 'root\\subscription' -Filter \"name='{filter_name}'\""
            ]
            
            artifact.cleanup_commands = [
                self.WMI_PERSISTENCE['EventFilter']['query']
            ]
            
            artifacts.append(artifact)
        
        logger.info(f"Analyzed WMI: found {len(artifacts)} WMI subscriptions")
        return artifacts
    
    def _is_suspicious_entry(self, key_name: str, key_value: str) -> bool:
        """Detect suspicious registry entries."""
        suspicious_patterns = [
            'powershell', 'cmd', 'rundll32', 'regsvcs', 'mshta', 'certutil',
            'bitsadmin', 'wscript', 'cscript', 'schtasks', 'taskkill'
        ]
        
        combined_str = (key_name + key_value).lower()
        return any(pattern in combined_str for pattern in suspicious_patterns)
    
    def generate_persistence_report(self, host: str, all_artifacts: List[PersistenceArtifact]) -> Dict:
        """
        Generate comprehensive persistence analysis report.
        
        Args:
            host: Target hostname
            all_artifacts: All detected artifacts
        
        Returns:
            Dict with report data
        """
        report = {
            "host": host,
            "timestamp": datetime.now().isoformat(),
            "total_artifacts": len(all_artifacts),
            "critical_artifacts": len([a for a in all_artifacts if a.severity == "CRITICAL"]),
            "high_artifacts": len([a for a in all_artifacts if a.severity == "HIGH"]),
            "artifacts": [a.to_dict() for a in all_artifacts],
            "cleanup_guide": self._generate_cleanup_guide(all_artifacts),
            "recommendations": [
                "Implement application whitelisting to block unauthorized executables",
                "Monitor registry and scheduled task changes in real-time",
                "Disable unnecessary services and enforce least-privilege",
                "Regular WMI auditing and log monitoring",
                "Use Windows Defender for exploitation detection"
            ]
        }
        
        return report
    
    def _generate_cleanup_guide(self, artifacts: List[PersistenceArtifact]) -> List[Dict]:
        """Generate step-by-step cleanup instructions."""
        guide = []
        
        # Group by mechanism type
        by_type = {}
        for artifact in artifacts:
            mech = artifact.mechanism
            if mech not in by_type:
                by_type[mech] = []
            by_type[mech].append(artifact)
        
        for mech_type, group in by_type.items():
            guide.append({
                "mechanism": mech_type.value,
                "count": len(group),
                "cleanup_commands": [cmd for a in group for cmd in a.cleanup_commands]
            })
        
        return guide


def run_persistence_analysis(hosts: Dict) -> Dict:
    """
    Main entry point for persistence mechanisms detection phase.
    
    Args:
        hosts: Host discovery data with enumeration findings
    
    Returns:
        Dict containing persistence analysis results
    """
    results = {
        "phase": "persistence",
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "hosts_analyzed": 0,
        "total_artifacts": 0,
        "critical_artifacts": 0,
        "reports": [],
        "notes": []
    }
    
    try:
        analyzer = PersistenceAnalyzer()
        
        for host_ip, host_data in hosts.items():
            if host_data.get('status') != 'up':
                continue
            
            results["hosts_analyzed"] += 1
            enum_data = host_data.get('enum', {})
            all_artifacts = []
            
            # Analyze each persistence vector
            if enum_data.get('registry'):
                artifacts = analyzer.analyze_registry_persistence(enum_data['registry'])
                all_artifacts.extend(artifacts)
            
            if enum_data.get('scheduled_tasks'):
                artifacts = analyzer.analyze_scheduled_tasks(enum_data['scheduled_tasks'])
                all_artifacts.extend(artifacts)
            
            if enum_data.get('startup_folder'):
                artifacts = analyzer.analyze_startup_folders(enum_data['startup_folder'])
                all_artifacts.extend(artifacts)
            
            if enum_data.get('services'):
                artifacts = analyzer.analyze_services(enum_data['services'])
                all_artifacts.extend(artifacts)
            
            if enum_data.get('wmi_subscriptions'):
                artifacts = analyzer.analyze_wmi_subscriptions(enum_data['wmi_subscriptions'])
                all_artifacts.extend(artifacts)
            
            # Generate report
            report = analyzer.generate_persistence_report(host_ip, all_artifacts)
            results["reports"].append(report)
            
            results["total_artifacts"] += len(all_artifacts)
            results["critical_artifacts"] += len([a for a in all_artifacts if a.severity == "CRITICAL"])
        
        results["notes"].append(
            f"Analyzed {results['hosts_analyzed']} hosts, "
            f"found {results['total_artifacts']} persistence artifacts "
            f"({results['critical_artifacts']} critical)"
        )
        
        if results["total_artifacts"] > 0:
            results["status"] = "success"
        else:
            results["status"] = "warning"
            results["notes"].append("No persistence mechanisms detected")
    
    except Exception as e:
        logger.error(f"Persistence analysis failed: {e}")
        results["status"] = "error"
        results["notes"].append(f"Error: {str(e)}")
    
    return results
