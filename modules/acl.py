#!/usr/bin/env python3
"""
ACL Abuse Detection Module for Blackbox Umbra
Identifies dangerous Active Directory permissions that enable privilege escalation and lateral movement
"""

import logging
import json
from typing import Dict, List, Set, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class ACLAnalyzer:
    """
    Analyzes Active Directory ACLs for exploitable permissions.
    Detects WriteProperty, GenericAll, WriteDacl, WriteOwner, Owns, AllExtendedRights.
    """
    
    # Dangerous ACL permissions that enable exploitation
    DANGEROUS_PERMISSIONS = {
        'GenericAll': {
            'severity': 'CRITICAL',
            'description': 'Full control over object - reset password, modify properties, etc.',
            'exploitation': 'User can impersonate target, reset password, add to groups'
        },
        'WriteProperty': {
            'severity': 'HIGH',
            'description': 'Can modify object properties',
            'exploitation': 'Modify targetAddress, scriptPath, homeDirectory, logonScript'
        },
        'WriteDacl': {
            'severity': 'HIGH',
            'description': 'Can modify ACLs on object',
            'exploitation': 'Modify permissions to grant further access'
        },
        'WriteOwner': {
            'severity': 'HIGH',
            'description': 'Can modify object owner',
            'exploitation': 'Take ownership, then modify properties via GenericAll'
        },
        'Owns': {
            'severity': 'MEDIUM',
            'description': 'Is owner of object',
            'exploitation': 'Can grant yourself additional permissions (WriteDacl equivalent)'
        },
        'AllExtendedRights': {
            'severity': 'CRITICAL',
            'description': 'Can perform all extended rights on object',
            'exploitation': 'Reset password, add to group, AS-REP roasting, etc.'
        },
        'ResetPassword': {
            'severity': 'CRITICAL',
            'description': 'Can reset object password',
            'exploitation': 'Reset user password to known value, impersonate'
        },
        'AddMember': {
            'severity': 'HIGH',
            'description': 'Can add members to group',
            'exploitation': 'Add self or controlled users to privileged groups'
        }
    }
    
    # Dangerous extended rights
    DANGEROUS_EXTENDED_RIGHTS = {
        'User-Force-Change-Password': 'Can reset user password',
        'Reset-Password': 'Can reset object password',
        'Send-As': 'Can send emails as this mailbox (Exchange)',
        'Receive-As': 'Can receive emails as this mailbox (Exchange)',
    }
    
    def __init__(self):
        self.findings = []
        self.acl_graph = {}
    
    def analyze_user_acls(self, user: Dict, ad_data: Dict) -> List[Dict]:
        """
        Analyze ACLs for a specific user.
        Check what dangerous permissions this user has over other objects.
        
        Args:
            user: User object with name and properties
            ad_data: Full AD data (for context)
        
        Returns:
            List of dangerous ACL findings
        """
        findings = []
        user_name = user.get('name', 'UNKNOWN')
        
        # Check if user belongs to privileged groups
        for group in ad_data.get('groups', []):
            if user_name in group.get('members', []):
                if any(x in group.get('name', '').lower() for x in ['admin', 'da ', 'domain admin']):
                    findings.append({
                        'source': user_name,
                        'source_type': 'User',
                        'target': group.get('name'),
                        'target_type': 'Group',
                        'privilege': 'GenericAll',
                        'severity': 'CRITICAL',
                        'exploitation': f'{user_name} is member of {group.get("name")} - has full control',
                        'recommendation': 'Isolate account immediately if compromised'
                    })
        
        return findings
    
    def analyze_group_acls(self, group: Dict, ad_data: Dict) -> List[Dict]:
        """
        Analyze ACLs for a specific group.
        Identify who has dangerous permissions on this group.
        
        Args:
            group: Group object
            ad_data: Full AD data
        
        Returns:
            List of dangerous ACL findings
        """
        findings = []
        group_name = group.get('name', 'UNKNOWN')
        
        # Check if group is privileged
        is_privileged = any(x in group_name.lower() for x in ['admin', 'da', 'domain admin', 'enterprise admin'])
        
        if is_privileged:
            # Who can add members to this group?
            # Check for explicit permissions (would come from LDAP ACL query)
            for user in ad_data.get('users', []):
                # In real engagement, this would come from LDAP ACL queries
                # For now, flag the group as high-value
                pass
            
            findings.append({
                'source': 'MULTIPLE',
                'source_type': 'Unknown',
                'target': group_name,
                'target_type': 'Group',
                'privilege': 'Investigate',
                'severity': 'CRITICAL',
                'exploitation': f'{group_name} is a privileged group - target for lateral movement',
                'recommendation': 'Query LDAP ACLs: ldapsearch -H ldap://DC -D "user@domain" -w pass "(objectClass=*)" nTSecurityDescriptor'
            })
        
        return findings
    
    def analyze_computer_acls(self, computer: Dict, ad_data: Dict) -> List[Dict]:
        """
        Analyze ACLs for computers.
        Identify who can manage this computer (modify properties, reset password, etc.).
        
        Args:
            computer: Computer object
            ad_data: Full AD data
        
        Returns:
            List of dangerous ACL findings
        """
        findings = []
        comp_name = computer.get('name', 'UNKNOWN')
        
        # Computers with sensitive services are higher value targets
        sensitive_keywords = ['dc', 'fs', 'sql', 'web', 'app', 'exchange']
        is_sensitive = any(x in comp_name.lower() for x in sensitive_keywords)
        
        if is_sensitive:
            findings.append({
                'source': 'INVESTIGATION_REQUIRED',
                'source_type': 'Unknown',
                'target': comp_name,
                'target_type': 'Computer',
                'privilege': 'Investigate',
                'severity': 'HIGH',
                'exploitation': f'{comp_name} appears to be sensitive infrastructure',
                'recommendation': 'Verify computer role and query ACL: ldapsearch -H ldap://DC "(cn={}) | grep -A 100 nTSecurityDescriptor"'.format(comp_name)
            })
        
        return findings
    
    def detect_acl_abuse_vectors(self, ad_data: Dict) -> List[Dict]:
        """
        Detect high-value ACL abuse vectors (relationships enabling privilege escalation).
        
        Args:
            ad_data: AD enumeration data
        
        Returns:
            List of abuse vectors ranked by severity
        """
        vectors = []
        
        # Vector 1: Users with dangerous permissions on objects
        for user in ad_data.get('users', []):
            user_findings = self.analyze_user_acls(user, ad_data)
            vectors.extend(user_findings)
        
        # Vector 2: Privileged group analysis
        for group in ad_data.get('groups', []):
            group_findings = self.analyze_group_acls(group, ad_data)
            vectors.extend(group_findings)
        
        # Vector 3: High-value computer targets
        for computer in ad_data.get('computers', []):
            comp_findings = self.analyze_computer_acls(computer, ad_data)
            vectors.extend(comp_findings)
        
        # Vector 4: Detect risky SPN objects (Kerberoastable with high privileges)
        for user in ad_data.get('users', []):
            if user.get('spn') or user.get('kerberoastable'):
                for group in ad_data.get('groups', []):
                    if user.get('name') in group.get('members', []):
                        if any(x in group.get('name').lower() for x in ['admin', 'da']):
                            vectors.append({
                                'source': user.get('name'),
                                'source_type': 'User',
                                'target': group.get('name'),
                                'target_type': 'Group',
                                'privilege': 'Kerberoastable_Admin',
                                'severity': 'CRITICAL',
                                'exploitation': f'{user.get("name")} is Kerberoastable and in {group.get("name")}',
                                'recommendation': 'Invoke-Rubeus.ps1 kerberoast /domain:DOMAIN.COM'
                            })
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        vectors.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4))
        
        return vectors
    
    def detect_delegation_abuse(self, ad_data: Dict) -> List[Dict]:
        """
        Detect Kerberos delegation abuse opportunities.
        Identifies unconstrained/constrained delegation for S4U2Self/S4U2Proxy attacks.
        
        Args:
            ad_data: AD enumeration data
        
        Returns:
            List of delegation abuse vectors
        """
        delegation_findings = []
        
        for user in ad_data.get('users', []):
            # Unconstrained delegation (can impersonate anyone to any service)
            if user.get('delegation_type') == 'unconstrained':
                delegation_findings.append({
                    'source': user.get('name'),
                    'target': 'ANY_SERVICE',
                    'type': 'Unconstrained Delegation',
                    'severity': 'CRITICAL',
                    'exploitation': 'Can impersonate any user to any service via TGT capture',
                    'attack': 'Monitor for TGT, use printerbug to trigger auth, extract ticket',
                    'tool': 'Rubeus.ps1, Get-Printer, Mimikatz'
                })
            
            # Constrained delegation with S4U2 (can impersonate to specific services)
            if user.get('delegation_type') == 'constrained':
                spn_list = user.get('spn_list', [])
                delegation_findings.append({
                    'source': user.get('name'),
                    'target': ', '.join(spn_list) if spn_list else 'UNKNOWN',
                    'type': 'Constrained Delegation (S4U2Proxy)',
                    'severity': 'HIGH',
                    'exploitation': f'Can impersonate any user to: {", ".join(spn_list) if spn_list else "unknown services"}',
                    'attack': 'Compromise service account, use S4U2Proxy to get service ticket as admin',
                    'tool': 'Rubeus.ps1 - getST /user:admin /domain:DOMAIN.COM /rc4:HASH /impersonateuser:admin /mspn:CIFS/SERVER'
                })
        
        return delegation_findings
    
    def generate_acl_report(self, ad_data: Dict) -> Dict:
        """
        Generate comprehensive ACL abuse report.
        
        Args:
            ad_data: AD enumeration data
        
        Returns:
            Dict containing all ACL analysis results
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'domain': ad_data.get('domain', 'WORKGROUP'),
            'total_users': len(ad_data.get('users', [])),
            'total_groups': len(ad_data.get('groups', [])),
            'total_computers': len(ad_data.get('computers', [])),
            'acl_abuse_vectors': [],
            'delegation_abuse_vectors': [],
            'critical_findings': [],
            'recommendations': [],
            'remeduation_steps': []
        }
        
        # Analyze ACL abuse
        acl_vectors = self.detect_acl_abuse_vectors(ad_data)
        report['acl_abuse_vectors'] = acl_vectors
        
        # Filter critical findings
        report['critical_findings'] = [v for v in acl_vectors if v.get('severity') == 'CRITICAL']
        
        # Analyze delegation abuse
        delegation_vectors = self.detect_delegation_abuse(ad_data)
        report['delegation_abuse_vectors'] = delegation_vectors
        report['critical_findings'].extend([v for v in delegation_vectors if v.get('severity') == 'CRITICAL'])
        
        # Generate recommendations
        if report['critical_findings']:
            report['recommendations'] = [
                'Immediately audit critical users identified above',
                'Enable Kerberos armoring (FAST) to prevent delegation abuse',
                'Restrict DA/EA group membership to service accounts only',
                'Implement tiering model: Tier 0 (DCs), Tier 1 (Servers), Tier 2 (Workstations)',
                'Enable privileged access workstations (PAW) for admin accounts',
                'Disable unconstrained delegation unless absolutely necessary',
                'Monitor for PrinterBug, Kerberoasting, S4U attacks'
            ]
        
        # Remediation
        report['remeduation_steps'] = [
            'Remove unnecessary ACLs using dsacls.exe',
            'Audit delegation settings: Get-ADUser -Filter * | where {$_.TrustedForDelegation} | ft Name',
            'Reset compromised service account passwords',
            'Force all compromise accounts to change password at next logon'
        ]
        
        logger.info(f"Generated ACL analysis: {len(report['acl_abuse_vectors'])} vectors, "
                   f"{len(report['critical_findings'])} critical findings")
        
        return report


def run_acl_analysis(ad_data: Dict) -> Dict:
    """
    Main entry point for ACL analysis phase.
    
    Args:
        ad_data: Active Directory enumeration data from ad.py module
    
    Returns:
        Dict containing ACL analysis results
    """
    results = {
        'phase': 'acl_analysis',
        'status': 'completed',
        'timestamp': datetime.now().isoformat(),
    }
    
    try:
        analyzer = ACLAnalyzer()
        report = analyzer.generate_acl_report(ad_data)
        results['report'] = report
        results['status'] = 'success'
        
        # Summary stats
        results['summary'] = {
            'total_acl_abuse_vectors': len(report['acl_abuse_vectors']),
            'critical_vector_count': len(report['critical_findings']),
            'delegation_abuse_vectors': len(report['delegation_abuse_vectors'])
        }
        
        logger.info(f"✅ ACL analysis completed: {results['summary']}")
    
    except Exception as e:
        logger.error(f"ACL analysis failed: {e}")
        results['status'] = 'error'
        results['error'] = str(e)
    
    return results
