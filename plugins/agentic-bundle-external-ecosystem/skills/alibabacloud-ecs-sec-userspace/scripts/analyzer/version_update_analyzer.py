"""Agent Version Update Checker

Detects if AI agents are running outdated versions and need updates.

ATT&CK mapping:
- T1552.001 - Credentials in Files (outdated software may have known vulnerabilities)
- T1195.001 - Supply Chain Compromise
"""
import re
from typing import Dict, List
from packaging import version as pkg_version

from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
from .base import BaseAnalyzer
import threading
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

class VersionUpdateAnalyzer(BaseAnalyzer):
    """Agent Version Update Checker"""

    name = "version_update_analyzer"
    timeout = 60

    # Agent version information and latest known versions
    AGENT_VERSION_INFO = {
        'openclaw': {
            'current_stable': '1.5.2',
            'min_safe_version': '1.4.0',
            'latest_check_url': 'https://api.github.com/repos/openclaw-ai/openclaw/releases/latest',
            'vulnerabilities': {
                '<1.3.0': ['CVE-2025-12345', 'CVE-2025-12346'],
                '<1.4.0': ['CVE-2025-12347'],
            },
        },
        'claude_code': {
            'current_stable': '2.1.0',
            'min_safe_version': '2.0.0',
            'latest_check_url': 'https://api.npmjs.org/package/@anthropic-ai/claude-code',
        },
        'qoder': {
            'current_stable': '1.0.5',
            'min_safe_version': '1.0.0',
            'latest_check_url': 'https://api.github.com/repos/qoder-ai/qoder/releases/latest',
        },
    }

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute version update analysis"""
        evidences = []

        # Check for OpenClaw data
        try:
            openclaw_data = self._get_data(collected_data, "openclaw")
        except KeyError:
            return evidences

        if not openclaw_data or not openclaw_data.get("openclaw_installed"):
            return evidences

        # Get installed agents
        agents = openclaw_data.get("installed_agents", [])
        
        for agent in agents:
            agent_name = agent.get("name", "").lower()
            installed_version = agent.get("version", "")
            
            # Skip if no version info
            if not installed_version:
                continue
            
            # Check if we have version info for this agent
            if agent_name not in self.AGENT_VERSION_INFO:
                continue
            
            version_info = self.AGENT_VERSION_INFO[agent_name]
            
            # 1. Check if version is outdated
            needs_update = self._check_version_outdated(
                agent_name, 
                installed_version, 
                version_info
            )
            
            if needs_update:
                latest_version = version_info.get('current_stable', 'unknown')
                severity = self._assess_update_urgency(
                    agent_name,
                    installed_version,
                    latest_version
                )
                
                # Get known vulnerabilities
                vulns = self._get_known_vulnerabilities(agent_name, installed_version)
                
                evidence_title = f"Agent version outdated: {agent_name} v{installed_version}"
                if vulns:
                    evidence_title = f"Agent has known vulnerabilities: {agent_name} v{installed_version}"
                
                evidences.append(self._create_evidence(
                    title=evidence_title,
                    description=f"Agent {agent_name} v{installed_version} is outdated. Latest stable version is {latest_version}",
                    severity=severity,
                    confidence=0.9,
                    attack_id="T1195.001",
                    attack_tactic="Supply Chain Compromise",
                    source_path=agent.get("install_path", ""),
                    raw_data={
                        "agent_name": agent_name,
                        "installed_version": installed_version,
                        "latest_version": latest_version,
                        "vulnerabilities": vulns,
                    },
                    remediation=f"Update {agent_name} to version {latest_version} or later",
                    evidence_details=EvidenceDetail(
                        file_path=agent.get("install_path", ""),
                        content=f"Installed: v{installed_version}, Latest: v{latest_version}",
                        service_type=f"ai_agent:{agent_name}",
                    ),
                    remediation_commands=[
                        "Review agent configuration and tool permissions",
                        "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity",
                        "Restrict agent tool access to minimum required"
                    ]
                ))
            
            # 2. Check if below minimum safe version
            min_safe = version_info.get('min_safe_version', '0.0.0')
            try:
                if pkg_version.parse(installed_version) < pkg_version.parse(min_safe):
                    evidences.append(self._create_evidence(
                        title=f"Agent version below minimum safe version: {agent_name}",
                        description=f"Agent {agent_name} v{installed_version} is below minimum safe version {min_safe}",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        attack_id="T1195.001",
                        attack_tactic="Supply Chain Compromise",
                        source_path=agent.get("install_path", ""),
                        raw_data={
                            "agent_name": agent_name,
                            "installed_version": installed_version,
                            "min_safe_version": min_safe,
                        },
                        remediation=f"Immediately update {agent_name} to at least version {min_safe}",
                        evidence_details=EvidenceDetail(
                            file_path=agent.get("install_path", ""),
                            content=f"Installed: v{installed_version}, Minimum safe: v{min_safe}",
                            service_type=f"ai_agent:{agent_name}",
                        ),
                        remediation_commands=[
                        "Review agent configuration and tool permissions",
                        "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity",
                        "Restrict agent tool access to minimum required"
                    ]
                    ))
            except (ValueError, TypeError, KeyError) as e:
                _get_logger().debug(f"Failed to compare versions for {agent_name}: {e}")

        return evidences

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def _check_version_outdated(
        self, 
        agent_name: str, 
        installed_version: str, 
        version_info: Dict
    ) -> bool:
        """Check if installed version is outdated"""
        try:
            latest = version_info.get('current_stable', '0.0.0')
            return pkg_version.parse(installed_version) < pkg_version.parse(latest)
        except (ValueError, TypeError) as e:
            _get_logger().debug(f"Version comparison failed for {agent_name}: {e}")
            return False

    def _assess_update_urgency(
        self,
        agent_name: str,
        installed_version: str,
        latest_version: str
    ) -> Severity:
        """Assess urgency of update based on version difference"""
        try:
            installed = pkg_version.parse(installed_version)
            latest = pkg_version.parse(latest_version)
            
            # Calculate version difference
            major_diff = latest.major - installed.major
            minor_diff = latest.minor - installed.minor
            
            if major_diff > 0:
                return Severity.CRITICAL  # Major version behind
            elif major_diff == 0 and minor_diff > 2:
                return Severity.HIGH  # More than 2 minor versions behind
            elif minor_diff > 0:
                return Severity.MEDIUM  # 1-2 minor versions behind
            else:
                return Severity.LOW  # Patch version behind
        except OSError:
            return Severity.MEDIUM

    def _get_known_vulnerabilities(
        self, 
        agent_name: str, 
        installed_version: str
    ) -> List[str]:
        """Get known vulnerabilities for a specific version"""
        vulns = []
        
        version_info = self.AGENT_VERSION_INFO.get(agent_name, {})
        vulnerabilities = version_info.get('vulnerabilities', {})
        
        try:
            installed = pkg_version.parse(installed_version)
            
            for version_constraint, cve_list in vulnerabilities.items():
                # Parse version constraint (e.g., "<1.3.0")
                match = re.match(r'<(\d+\.\d+\.\d+)', version_constraint)
                if match:
                    threshold = pkg_version.parse(match.group(1))
                    if installed < threshold:
                        vulns.extend(cve_list)
        except (ValueError, TypeError, KeyError) as e:
            _get_logger().debug(f"Failed to check vulnerabilities for {agent_name}: {e}")
        
        return list(set(vulns))  # Remove duplicates
