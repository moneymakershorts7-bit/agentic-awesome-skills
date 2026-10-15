"""Container Escape & K8s Lateral Movement Detection Mixin.

Provides container escape indicators and Kubernetes lateral movement detection.
Split from credential_relay.py to stay under 500 lines - zero functional change.
"""
import re
from typing import List, Dict
from ...reporter.evidence import Evidence, EvidenceDetail
from ...reporter.severity import Severity


class ContainerEscapeMixin:
    """Container escape and K8s lateral movement detection capabilities."""

    CONTAINER_ESCAPE_INDICATORS = [
        (re.compile(r'/var/run/docker\.sock'),
         "Docker socket access (escape possible)", Severity.CRITICAL, "T1611"),
        (re.compile(r'/var/run/containerd/containerd\.sock'),
         "Containerd socket access", Severity.HIGH, "T1611"),
        (re.compile(r'--privileged\s*(true)?', re.IGNORECASE),
         "Privileged container flag", Severity.CRITICAL, "T1611"),
        (re.compile(r'--cap-add\s+SYS_ADMIN', re.IGNORECASE),
         "SYS_ADMIN capability added", Severity.CRITICAL, "T1611"),
        (re.compile(r'--cap-add\s+ALL', re.IGNORECASE),
         "All capabilities added", Severity.CRITICAL, "T1611"),
        (re.compile(r'--pid=host', re.IGNORECASE),
         "Host PID namespace sharing", Severity.HIGH, "T1611"),
        (re.compile(r'--net=host|--network=host', re.IGNORECASE),
         "Host network namespace sharing", Severity.HIGH, "T1611"),
        (re.compile(r'--volume=/:/|:/mnt/host|/host:', re.IGNORECASE),
         "Host root filesystem mount", Severity.CRITICAL, "T1611"),
        (re.compile(r'/proc/\d+/root'),
         "Process root filesystem access", Severity.HIGH, "T1611"),
        (re.compile(r'nsenter\s+--target\s+\d+', re.IGNORECASE),
         "Namespace enter command", Severity.HIGH, "T1611"),
    ]

    K8S_LATERAL_MOVEMENT_PATTERNS = [
        (re.compile(r'kubectl\s+exec\s+-n\s+\S+\s+\S+\s+--', re.IGNORECASE),
         "Kubectl exec in namespace", Severity.MEDIUM, "T1021"),
        (re.compile(r'kubectl\s+run\s+.*--image=', re.IGNORECASE),
         "Kubectl run with image", Severity.MEDIUM, "T1021"),
        (re.compile(r'kubectl\s+apply\s+-f\s+.*\.yaml', re.IGNORECASE),
         "Kubectl apply manifest", Severity.LOW, "T1021"),
        (re.compile(r'kubectl\s+auth\s+can-i', re.IGNORECASE),
         "Kubernetes permission enumeration", Severity.MEDIUM, "T1069"),
        (re.compile(r'kubectl\s+get\s+(secrets|serviceaccounts)', re.IGNORECASE),
         "Kubernetes secrets/serviceaccounts enumeration", Severity.HIGH, "T1069"),
    ]

    def _detect_container_escape(self, process_data: Dict, filesystem_data: Dict) -> List[Evidence]:
        """Detect container escape and lateral movement"""
        evidences = []
        processes = process_data.get("processes", [])
        files = filesystem_data.get("scanned_paths", [])
        evidence_id_counter = 0

        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            for pattern, title, severity, attack_id in self.CONTAINER_ESCAPE_INDICATORS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_container_escape_{evidence_id_counter}",
                        module=self.name, title=title,
                        description=f"Container escape indicator: {cmdline[:200]}",
                        severity=severity, confidence=0.85,
                        attack_id=attack_id, attack_tactic="Defense Evasion",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="", raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Review container security configuration and remove privileged options",
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid"), cmdline=cmdline[:500],
                            executable=proc.get("exe", ""), user=proc.get("user", ""),
                            parent_pid=proc.get("ppid"),
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                            f"cat /proc/{proc.get('pid', 'PID')}/environ 2>/dev/null | tr '\\0' '\\n' | head -10",
                            "ss -tunap | head -20",
                        ],
                    ))

        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            for pattern, title, severity, attack_id in self.K8S_LATERAL_MOVEMENT_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_k8s_{evidence_id_counter}",
                        module=self.name, title=title,
                        description=f"K8s lateral movement: {cmdline[:200]}",
                        severity=severity, confidence=0.8,
                        attack_id=attack_id, attack_tactic="Lateral Movement",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="", raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Audit kubectl commands and review RBAC permissions",
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid"), cmdline=cmdline[:500],
                            executable=proc.get("exe", ""), user=proc.get("user", ""),
                            parent_pid=proc.get("ppid"),
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                            f"cat /proc/{proc.get('pid', 'PID')}/environ 2>/dev/null | tr '\\0' '\\n' | head -10",
                            "ss -tunap | head -20",
                        ],
                    ))

        docker_socket_paths = ["/var/run/docker.sock", "/var/run/containerd/containerd.sock"]
        for file_path in files:
            for socket_path in docker_socket_paths:
                if socket_path in file_path:
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_docker_socket_{evidence_id_counter}",
                        module=self.name,
                        title="Sensitive container socket accessed",
                        description=f"Access to {socket_path} detected",
                        severity=Severity.HIGH, confidence=0.8,
                        attack_id="T1611", attack_tactic="Defense Evasion",
                        source_path=file_path, timestamp="",
                        raw_data={"file": file_path},
                        remediation="Restrict Docker socket access to trusted users only",
                        evidence_details=EvidenceDetail(
                            file_path=file_path, content="Detected suspicious file access",
                        ),
                        remediation_commands=[
                            "ls -la {file_path}", "stat {file_path}",
                            "cat {file_path} 2>/dev/null | head -20",
                        ],
                    ))
        return evidences
