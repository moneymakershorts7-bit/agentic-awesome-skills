"""Pub/Sub CLI Tools Abuse Detection Analyzer (AN0003)"""
import re
import subprocess
from typing import List, Dict, Any
from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
from .base import BaseAnalyzer


class PubSubAbuseAnalyzer(BaseAnalyzer):
    """Detect abuse of pub/sub CLI tools for C2 communication
    
    MITRE ATT&CK Analytics: AN0003
    Detects suspicious usage of message queue and event-driven architecture
    manipulation tools like Redis CLI, RabbitMQ admin, NATS CLI for command-and-control.
    
    ATT&CK Techniques:
    - T1059.004: Unix Shell (Command and Scripting Interpreter)
    - T1095: Non-Application Layer Protocol
    """
    name = "pubsub_abuse_analyzer"
    timeout = 30
    required_collectors = ["process", "network", "filesystem"]
    
    # Smart scheduling attributes
    estimated_time = 3.0
    analyzer_type = BaseAnalyzer.IMPORTANT
    
    # Known pub/sub CLI tools with detection patterns
    PUBSUB_TOOLS = {
        'redis-cli': {
            'patterns': [
                re.compile(r'redis-cli\s+.*\s+(EVAL|SCRIPT|MODULE)\b', re.IGNORECASE),
                re.compile(r'redis-cli\s+-h\s+\S+\s+-p\s+\d+', re.IGNORECASE),
                re.compile(r'redis-cli\s+--eval\b', re.IGNORECASE),
                re.compile(r'redis-cli\s+xadd\b', re.IGNORECASE),
            ],
            'severity': Severity.MEDIUM,
            'attack_id': 'T1059.004',
            'description': 'Redis CLI tool used for remote code execution or data exfiltration'
        },
        'rabbitmqadmin': {
            'patterns': [
                re.compile(r'rabbitmqadmin\s+(publish|get)\b', re.IGNORECASE),
            ],
            'severity': Severity.HIGH,
            'attack_id': 'T1059.004',
            'description': 'RabbitMQ admin tool used for unauthorized message queue operations'
        },
        'rabbitmqctl': {
            'patterns': [
                re.compile(r'rabbitmqctl\s+add_user\b', re.IGNORECASE),
                re.compile(r'rabbitmqctl\s+set_permissions\b', re.IGNORECASE),
                re.compile(r'rabbitmqctl\s+declare\s+user\b', re.IGNORECASE),
            ],
            'severity': Severity.HIGH,
            'attack_id': 'T1059.004',
            'description': 'RabbitMQ control tool used for user management and persistence'
        },
        'nats': {
            'patterns': [
                re.compile(r'nats\s+pub\s+', re.IGNORECASE),
                re.compile(r'nats\s+sub\s+', re.IGNORECASE),
                re.compile(r'nats\s+context\s+save\b', re.IGNORECASE),
            ],
            'severity': Severity.MEDIUM,
            'attack_id': 'T1095',
            'description': 'NATS CLI tool used for covert communication channel'
        },
        'kafka-console-producer': {
            'patterns': [
                re.compile(r'kafka-console-producer\b', re.IGNORECASE),
            ],
            'severity': Severity.LOW,
            'attack_id': 'T1095',
            'description': 'Kafka console producer used for data staging or exfiltration'
        },
        'kafka-console-consumer': {
            'patterns': [
                re.compile(r'kafka-console-consumer\b', re.IGNORECASE),
            ],
            'severity': Severity.LOW,
            'attack_id': 'T1095',
            'description': 'Kafka console consumer used for retrieving staged data'
        },
        'mosquitto_pub': {
            'patterns': [
                re.compile(r'mosquitto_pub\s+', re.IGNORECASE),
            ],
            'severity': Severity.LOW,
            'attack_id': 'T1095',
            'description': 'MQTT publisher used for lightweight C2 communication'
        },
        'mosquitto_sub': {
            'patterns': [
                re.compile(r'mosquitto_sub\s+', re.IGNORECASE),
            ],
            'severity': Severity.LOW,
            'attack_id': 'T1095',
            'description': 'MQTT subscriber used for receiving C2 commands'
        }
    }
    
    # Suspicious network patterns for pub/sub protocols
    SUSPICIOUS_PORTS = {
        6379: ('Redis', Severity.HIGH),
        5672: ('RabbitMQ AMQP', Severity.MEDIUM),
        15672: ('RabbitMQ Management', Severity.MEDIUM),
        4222: ('NATS', Severity.MEDIUM),
        8883: ('MQTT TLS', Severity.LOW),
        1883: ('MQTT', Severity.LOW),
        9092: ('Kafka', Severity.LOW),
    }
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Analyze for pub/sub CLI tools abuse
        
        In quick mode: Only check processes and network (lightweight)
        In full mode: Also check filesystem for scripts (more thorough)
        
        Args:
            collected_data: Collected system data from collectors
            
        Returns:
            List of evidence objects for suspicious pub/sub activity
        """
        evidences = []
        
        # Check process list for suspicious pub/sub usage (always runs)
        try:
            process_data = self._get_data(collected_data, "process")
            if process_data:
                evidences.extend(self._check_process_abuse(process_data))
        except KeyError:
            pass
        
        # Check network connections for pub/sub protocols (always runs)
        try:
            network_data = self._get_data(collected_data, "network")
            if network_data:
                evidences.extend(self._check_network_patterns(network_data))
        except KeyError:
            pass
        
        # Check for unauthorized scripts using pub/sub (full mode only)
        # This is more expensive due to filesystem scanning
        try:
            fs_data = self._get_data(collected_data, "filesystem")
            if fs_data:
                evidences.extend(self._check_script_usage(fs_data))
        except KeyError:
            pass
        
        return evidences
    
    def _is_tool_installed(self, tool_name: str) -> bool:
        """Check if a pub/sub CLI tool is actually installed
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool is found in PATH, False otherwise
        """
        try:
            result = subprocess.run(
                ['which', tool_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _check_process_abuse(self, process_data: Dict) -> List[Evidence]:
        """Check process list for suspicious pub/sub CLI usage
        
        Args:
            process_data: Process collector output
            
        Returns:
            List of evidence for suspicious process activity
        """
        evidences = []
        
        for proc in process_data.get("processes", []):
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            
            for tool_name, tool_info in self.PUBSUB_TOOLS.items():
                if tool_name.lower() in cmdline.lower():
                    for pattern in tool_info['patterns']:
                        if pattern.search(cmdline):
                            # Verify tool is installed to reduce false positives
                            is_installed = self._is_tool_installed(tool_name)
                            
                            severity = tool_info['severity']
                            confidence = 0.7 if is_installed else 0.5
                            
                            evidences.append(self._create_evidence(
                                title=f"Suspicious Pub/Sub CLI Usage: {tool_name}",
                                description=(
                                    f"{tool_info['description']}. "
                                    f"Process detected using {tool_name} with "
                                    f"suspicious parameters: {cmdline[:150]}"
                                ),
                                severity=severity,
                                confidence=confidence,
                                attack_id=tool_info['attack_id'],
                                source_path=proc.get("exe", ""),
                                raw_data={
                                    "pid": proc.get("pid"),
                                    "cmdline": cmdline,
                                    "tool": tool_name,
                                    "installed": is_installed
                                },
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid", 0)
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                            break  # Avoid duplicate alerts for same process
        
        return evidences
    
    def _check_network_patterns(self, network_data: Dict) -> List[Evidence]:
        """Check network connections for suspicious pub/sub protocol usage
        
        Args:
            network_data: Network collector output
            
        Returns:
            List of evidence for suspicious network activity
        """
        evidences = []
        
        connections = network_data.get("connections", [])
        for conn in connections:
            remote_port = conn.get("remote_port", 0)
            local_port = conn.get("local_port", 0)
            
            # Check if connection involves known pub/sub ports
            for port, (service, base_severity) in self.SUSPICIOUS_PORTS.items():
                if remote_port == port or local_port == port:
                    state = conn.get("state", "")
                    
                    # Only flag established or listening connections
                    if state in ["ESTABLISHED", "LISTEN"]:
                        evidences.append(self._create_evidence(
                            title=f"Pub/Sub Protocol Connection: {service}",
                            description=(
                                f"Network connection detected on {service} port {port}. "
                                f"State: {state}, Remote: {conn.get('remote_addr', 'unknown')}"
                            ),
                            severity=base_severity,
                            confidence=0.5,
                            attack_id="T1095",
                            source_path="/proc/net/tcp",
                            raw_data={
                                "port": port,
                                "service": service,
                                "state": state,
                                "remote_addr": conn.get("remote_addr"),
                                "local_port": local_port,
                                "remote_port": remote_port
                            },
                            evidence_details=EvidenceDetail(
                            ),
                            remediation_commands=[
                        "Stop and disable suspicious service",
                        "Review service configuration and logs",
                        "Check service dependencies and startup order",
                        "Investigate service origin and remove if malicious"
                    ]
                        ))
        
        return evidences
    
    def _check_script_usage(self, fs_data: Dict) -> List[Evidence]:
        """Check filesystem for scripts containing pub/sub automation
        
        Args:
            fs_data: Filesystem collector output
            
        Returns:
            List of evidence for suspicious script files
        """
        evidences = []
        
        # Check for scripts in suspicious locations that use pub/sub tools
        suspicious_locations = ["/tmp/", "/dev/shm/", "/var/tmp/"]
        
        files = fs_data.get("files", [])
        for file_info in files:
            filepath = file_info.get("path", "")
            
            # Skip if not in suspicious location
            if not any(filepath.startswith(loc) for loc in suspicious_locations):
                continue
            
            # Check if it's a script file
            if not filepath.endswith(('.sh', '.py', '.pl', '.rb')):
                continue
            
            content_preview = file_info.get("preview", "")
            if not content_preview:
                continue
            
            # Check for pub/sub tool usage in scripts
            for tool_name, tool_info in self.PUBSUB_TOOLS.items():
                if tool_name.lower() in content_preview.lower():
                    for pattern in tool_info['patterns']:
                        if pattern.search(content_preview):
                            evidences.append(self._create_evidence(
                                title=f"Pub/Sub Script Found: {filepath}",
                                description=(
                                    f"Script in suspicious location uses {tool_name}. "
                                    f"This may indicate automated C2 communication."
                                ),
                                severity=Severity.HIGH,
                                confidence=0.75,
                                attack_id=tool_info['attack_id'],
                                source_path=filepath,
                                raw_data={
                                    "path": filepath,
                                    "tool": tool_name,
                                    "preview": content_preview[:200]
                                },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Review pub/sub service authentication and access",
                        "Audit message queue configurations and permissions",
                        "Implement message validation and filtering",
                        "Monitor for continued pub/sub abuse"
                    ]))
                            break
        
        return evidences
