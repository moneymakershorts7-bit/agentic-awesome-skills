"""Lateral Movement Temporal Correlation Engine

Detects multi-stage lateral movement campaigns by correlating events across time windows.

ATT&CK Mapping:
- T1021 - Remote Services (lateral movement stages)
- T1570 - Lateral Tool Transfer
- T1072 - Software Deployment Tools
- T1563.001 - SSH Hijacking
- T1046 - Network Service Scanning (reconnaissance stage)
- T1078 - Valid Accounts (credential access stage)

ASI Mapping:
- ASI08 - Lateral Movement via Agent
"""
from typing import List, Dict, Optional
from datetime import timedelta
from collections import defaultdict

from ..reporter.evidence import Evidence, Severity
from ..utils.datetime_compat import fromisoformat
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

class CampaignEvidence:
    """Represents evidence within a correlated campaign"""
    
    def __init__(self, evidence: Evidence, timestamp: Optional[str] = None):
        self.evidence = evidence
        self.timestamp = timestamp or evidence.timestamp
        self.stage = self._classify_stage(evidence)
    
    def _classify_stage(self, evidence: Evidence) -> str:
        """Classify evidence into attack stage"""
        attack_id = evidence.attack_id or ""
        
        if attack_id in ["T1046", "T1595"]:
            return "reconnaissance"
        elif attack_id in ["T1552", "T1003", "T1110"]:
            return "credential_access"
        elif attack_id in ["T1021", "T1021.004", "T1021.007", "T1570", "T1072", "T1563.001"]:
            return "lateral_movement"
        elif attack_id in ["T1059", "T1204"]:
            return "execution"
        elif attack_id in ["T1078", "T1098"]:
            return "valid_accounts"
        else:
            return "unknown"

class LateralMovementCampaign:
    """Represents a detected lateral movement campaign"""
    
    def __init__(self, campaign_id: str, start_time: str, end_time: str):
        self.campaign_id = campaign_id
        self.start_time = start_time
        self.end_time = end_time
        self.stages: Dict[str, List[CampaignEvidence]] = defaultdict(list)
        self.involved_hosts: set = set()
        self.involved_users: set = set()
        self.severity = Severity.MEDIUM
        self.confidence = 0.0
    
    def add_evidence(self, evidence: CampaignEvidence):
        """Add evidence to campaign"""
        self.stages[evidence.stage].append(evidence)
        
        # Extract hosts and users from raw data
        raw_data = evidence.evidence.raw_data or {}
        if "target_host" in raw_data:
            self.involved_hosts.add(raw_data["target_host"])
        if "user" in raw_data:
            self.involved_users.add(raw_data["user"])
        if "pid" in raw_data:
            self.involved_hosts.add(f"PID:{raw_data['pid']}")
        
        # Update severity based on stage count
        self._recalculate_severity()
    
    def _recalculate_severity(self):
        """Recalculate campaign severity based on detected stages"""
        stage_count = len([s for s in self.stages.values() if len(s) > 0])
        
        if stage_count >= 4:
            self.severity = Severity.CRITICAL
            self.confidence = 0.95
        elif stage_count >= 3:
            self.severity = Severity.HIGH
            self.confidence = 0.85
        elif stage_count >= 2:
            self.severity = Severity.MEDIUM
            self.confidence = 0.75
        else:
            self.severity = Severity.LOW
            self.confidence = 0.60
    
    def get_unique_stages(self) -> List[str]:
        """Get list of stages with evidence"""
        return [stage for stage, evts in self.stages.items() if len(evts) > 0]
    
    def to_evidence(self) -> Evidence:
        """Convert campaign to Evidence object"""
        unique_stages = self.get_unique_stages()
        total_events = sum(len(evts) for evts in self.stages.values())
        
        stage_descriptions = []
        for stage in unique_stages:
            count = len(self.stages[stage])
            stage_descriptions.append(f"{stage}: {count} event(s)")
        
        return Evidence(
            id=f"campaign_{self.campaign_id}",
            module="lateral_movement_correlator",
            title=f"Lateral Movement Campaign Detected ({len(unique_stages)} stages)",
            description=(
                f"Multi-stage lateral movement campaign detected over {self.start_time} to {self.end_time}. "
                f"Total events: {total_events}. Stages: {', '.join(stage_descriptions)}. "
                f"Involved hosts: {len(self.involved_hosts)}, Users: {len(self.involved_users)}."
            ),
            severity=self.severity,
            confidence=self.confidence,
            attack_id="T1021+T1570+T1072",
            attack_tactic="Lateral Movement",
            source_path="multiple_sources",
            timestamp=self.start_time,
            raw_data={
                "campaign_id": self.campaign_id,
                "stages": {
                    stage: [e.evidence.id for e in events]
                    for stage, events in self.stages.items()
                },
                "involved_hosts": list(self.involved_hosts)[:20],
                "involved_users": list(self.involved_users)[:10],
                "stage_count": len(unique_stages),
                "total_events": total_events,
                "start_time": self.start_time,
                "end_time": self.end_time
            },
            remediation=(
                "URGENT: Multi-stage lateral movement campaign detected. "
                "1. Isolate affected systems immediately. "
                "2. Conduct full incident response investigation. "
                "3. Review all systems accessed by compromised accounts. "
                "4. Rotate credentials for all involved users. "
                "5. Check for persistence mechanisms installed during lateral movement."
            )
        )

class LateralMovementCorrelator(BaseAnalyzer):
    """Temporal correlation engine for lateral movement detection
    
    Detects multi-stage attack campaigns by correlating events across:
    - Time windows (default 30 minutes)
    - Multiple hosts
    - Different attack techniques
    - User activity patterns
    """
    
    name = "lateral_movement_correlator"
    timeout = 60
    required_collectors = ["process", "network", "log"]
    
    # Correlation rules defining dangerous stage sequences
    CORRELATION_RULES = [
        {
            'name': 'Auth + Transfer Pattern',
            'stages': ['credential_access', 'lateral_movement'],
            'time_window_minutes': 5,
            'min_events': 2,
            'severity': Severity.HIGH,
            'description': 'SSH/remote login followed by file transfer within 5 minutes'
        },
        {
            'name': 'Recon + Exploit Pattern',
            'stages': ['reconnaissance', 'lateral_movement'],
            'time_window_minutes': 30,
            'min_events': 2,
            'severity': Severity.HIGH,
            'description': 'Network scan followed by exploitation attempt'
        },
        {
            'name': 'Credential Access + Lateral Movement',
            'stages': ['credential_access', 'valid_accounts', 'lateral_movement'],
            'time_window_minutes': 15,
            'min_events': 3,
            'severity': Severity.CRITICAL,
            'description': 'Password/hash dump followed by remote access using valid accounts'
        },
        {
            'name': 'Multi-Host Pattern',
            'stages': ['lateral_movement'],
            'time_window_minutes': 30,
            'min_events': 3,
            'min_hosts': 3,
            'severity': Severity.CRITICAL,
            'description': 'Same technique observed on 3+ hosts within 30 minutes'
        },
        {
            'name': 'Full Kill Chain Pattern',
            'stages': ['reconnaissance', 'credential_access', 'lateral_movement', 'execution'],
            'time_window_minutes': 60,
            'min_events': 4,
            'severity': Severity.CRITICAL,
            'description': 'Complete attack chain from recon to execution'
        }
    ]
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def __init__(self, workspace_dir: str = None):
        super().__init__(workspace_dir)
        self.time_window = timedelta(minutes=30)
        self.events: List[CampaignEvidence] = []
        self.campaigns: List[LateralMovementCampaign] = []
        self.campaign_counter = 0
    
    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Analyze collected data for correlated lateral movement campaigns
        
        Args:
            collected_data: Dictionary containing collector results
            
        Returns:
            List of Evidence objects for detected campaigns
        """
        evidences = []
        
        try:
            # Extract data from collectors
            process_data = self._get_data(collected_data, "process")
            network_data = self._get_data(collected_data, "network")
            log_data = self._get_data(collected_data, "log")
            
            # Parse and collect events
            self._collect_events(process_data, network_data, log_data)
            
            if not self.events:
                return evidences
            
            # Sort events by timestamp
            self.events.sort(key=lambda e: e.timestamp or "")
            
            # Run correlation analysis
            self._detect_campaigns()
            
            # Convert campaigns to evidence
            for campaign in self.campaigns:
                evidences.append(campaign.to_evidence())
            
            # Sort by severity
            evidences.sort(key=lambda e: e.severity.score, reverse=True)
            
        except (OSError, ValueError, KeyError, TypeError) as e:
            _get_logger().warning(f"[{self.name}] Correlation analysis error: {e}")
        
        return evidences
    
    def _collect_events(self, process_data: Dict, network_data: Dict, log_data: Dict):
        """Collect and classify events from collector data"""
        
        # Process events
        processes = process_data.get("processes", [])
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            
            # Create synthetic evidence for interesting processes
            if self._is_lateral_movement_related(cmdline):
                evidence = Evidence(
                    id=f"proc_{proc.get('pid', 'unknown')}",
                    module="lateral_movement_correlator",
                    title="Process related to lateral movement",
                    description=f"Command: {cmdline[:200]}",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    attack_id="",
                    attack_tactic="Lateral Movement",
                    source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                    timestamp=proc.get("start_time", ""),
                    raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "user": proc.get("user")},
                    remediation=""
                )
                self.events.append(CampaignEvidence(evidence))
        
        # Network events
        connections = network_data.get("connections", [])
        for conn in connections:
            remote_ip = conn.get("remote_ip", "")
            remote_port = conn.get("remote_port", 0)
            
            # Check for suspicious connections
            if self._is_suspicious_connection(remote_ip, remote_port):
                evidence = Evidence(
                    id=f"net_{conn.get('local_ip', '')}:{remote_ip}:{remote_port}",
                    module="lateral_movement_correlator",
                    title="Suspicious network connection",
                    description=f"Connection to {remote_ip}:{remote_port}",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    attack_id="T1021",
                    attack_tactic="Lateral Movement",
                    source_path="/proc/net/tcp",
                    timestamp=conn.get("timestamp", ""),
                    raw_data={"remote_ip": remote_ip, "remote_port": remote_port},
                    remediation=""
                )
                self.events.append(CampaignEvidence(evidence))
        
        # Log events
        entries = log_data.get("entries", [])
        for entry in entries:
            message = entry.get("message", "")
            if not message:
                continue
            
            # Check for authentication events
            if self._is_auth_event(message):
                evidence = Evidence(
                    id=f"log_{entry.get('timestamp', '')[:20]}",
                    module="lateral_movement_correlator",
                    title="Authentication event",
                    description=f"Log: {message[:200]}",
                    severity=Severity.LOW,
                    confidence=0.5,
                    attack_id="T1078",
                    attack_tactic="Valid Accounts",
                    source_path=entry.get("source", ""),
                    timestamp=entry.get("timestamp", ""),
                    raw_data={"message": message},
                    remediation=""
                )
                self.events.append(CampaignEvidence(evidence))
    
    def _is_lateral_movement_related(self, cmdline: str) -> bool:
        """Check if command line is related to lateral movement"""
        lateral_keywords = [
            'ssh ', 'scp ', 'rsync ', 'ansible', 'salt ', 'kubectl exec',
            'aws ssm', 'az vm', 'gcloud compute', 'nc ', 'netcat',
            'nmap', 'masscan', 'psexec', 'wmiexec'
        ]
        cmdline_lower = cmdline.lower()
        return any(kw in cmdline_lower for kw in lateral_keywords)
    
    def _is_suspicious_connection(self, remote_ip: str, remote_port: int) -> bool:
        """Check if network connection is suspicious"""
        # Internal IP ranges
        internal_ranges = [
            remote_ip.startswith('10.'),
            remote_ip.startswith('172.16.') or remote_ip.startswith('172.17.') or
            remote_ip.startswith('172.18.') or remote_ip.startswith('172.19.') or
            remote_ip.startswith('172.2') or remote_ip.startswith('172.3'),
            remote_ip.startswith('192.168.'),
        ]
        
        is_internal = any(internal_ranges)
        
        # Suspicious ports for lateral movement
        suspicious_ports = [22, 445, 3389, 5985, 5986, 8080, 8443]
        
        return is_internal and remote_port in suspicious_ports
    
    def _is_auth_event(self, message: str) -> bool:
        """Check if log message is an authentication event"""
        auth_patterns = [
            'accepted password',
            'accepted publickey',
            'failed password',
            'invalid user',
            'session opened',
            'session closed',
            'authentication failure',
            'sudo:'
        ]
        message_lower = message.lower()
        return any(pattern in message_lower for pattern in auth_patterns)
    
    def _detect_campaigns(self):
        """Detect campaigns using correlation rules"""
        self.campaigns = []
        
        for rule in self.CORRELATION_RULES:
            rule['name']
            required_stages = rule['stages']
            time_window = timedelta(minutes=rule['time_window_minutes'])
            min_events = rule['min_events']
            min_hosts = rule.get('min_hosts', 1)
            
            # Find events matching required stages
            candidate_events = []
            for event in self.events:
                if event.stage in required_stages:
                    candidate_events.append(event)
            
            if len(candidate_events) < min_events:
                continue
            
            # Group events by time windows
            time_groups = self._group_by_time_window(candidate_events, time_window)
            
            for group in time_groups:
                if len(group) < min_events:
                    continue
                
                # Check host diversity for multi-host pattern
                hosts_in_group = set()
                for event in group:
                    raw_data = event.evidence.raw_data or {}
                    if "target_host" in raw_data:
                        hosts_in_group.add(raw_data["target_host"])
                    if "remote_ip" in raw_data:
                        hosts_in_group.add(raw_data["remote_ip"])
                    if "pid" in raw_data:
                        hosts_in_group.add(f"PID:{raw_data['pid']}")
                
                if len(hosts_in_group) < min_hosts:
                    continue
                
                # Create campaign
                self.campaign_counter += 1
                campaign = LateralMovementCampaign(
                    campaign_id=f"{self.campaign_counter:04d}",
                    start_time=group[0].timestamp or "",
                    end_time=group[-1].timestamp or ""
                )
                
                for event in group:
                    campaign.add_evidence(event)
                
                self.campaigns.append(campaign)
    
    def _group_by_time_window(self, events: List[CampaignEvidence], 
                              window: timedelta) -> List[List[CampaignEvidence]]:
        """Group events by time window"""
        if not events:
            return []
        
        groups = []
        current_group = [events[0]]
        
        for i in range(1, len(events)):
            try:
                prev_time = fromisoformat(current_group[-1].timestamp)
                curr_time = fromisoformat(events[i].timestamp)
                
                if curr_time - prev_time <= window:
                    current_group.append(events[i])
                else:
                    if len(current_group) >= 2:
                        groups.append(current_group)
                    current_group = [events[i]]
            except (ValueError, AttributeError):
                # If timestamp parsing fails, add to current group
                current_group.append(events[i])
        
        # Don't forget the last group
        if len(current_group) >= 2:
            groups.append(current_group)
        
        return groups
