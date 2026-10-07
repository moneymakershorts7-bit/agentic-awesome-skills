"""Cloud Lateral Movement Detection Mixin.
Split from credential_relay.py to stay under 500 lines - zero functional change.
"""
import re
from typing import List, Dict
from ...reporter.evidence import Evidence, EvidenceDetail
from ...reporter.severity import Severity


class CloudLateralMixin:
    """Cloud service lateral movement and enumeration detection."""

    CLOUD_LATERAL_PATTERNS = [
        (re.compile(r'aws\s+ssm\s+start-session\s+--target\s+i-', re.IGNORECASE),
         "AWS SSM Session Manager lateral movement", Severity.HIGH, "T1021.007"),
        (re.compile(r'aws\s+ssm\s+send-command\s+--instance-ids', re.IGNORECASE),
         "AWS SSM Send Command execution", Severity.HIGH, "T1021.007"),
        (re.compile(r'az\s+vm\s+run-command\s+invoke', re.IGNORECASE),
         "Azure VM run-command invocation", Severity.HIGH, "T1021.007"),
        (re.compile(r'gcloud\s+compute\s+ssh\s+\S+@\S+', re.IGNORECASE),
         "GCP gcloud SSH remote access", Severity.MEDIUM, "T1021.007"),
        (re.compile(r'gcloud\s+compute\s+os-login\s+', re.IGNORECASE),
         "GCP OS Login API usage", Severity.MEDIUM, "T1021.007"),
        (re.compile(r'aws\s+ec2-instance-connect\s+send-ssh-public-key', re.IGNORECASE),
         "AWS EC2 Instance Connect key injection", Severity.HIGH, "T1021.007"),
        (re.compile(r'az\s+role\s+assignment\s+create\s+--assignee', re.IGNORECASE),
         "Azure RBAC role assignment for lateral movement", Severity.CRITICAL, "T1530"),
        (re.compile(r'aws\s+iam\s+put-role-policy.*--policy-document', re.IGNORECASE),
         "AWS IAM policy modification for privilege escalation", Severity.CRITICAL, "T1530"),
    ]
    CLOUD_ENUMERATION_PATTERNS = [
        (re.compile(r'aws\s+ec2\s+describe-instances\s+--all', re.IGNORECASE),
         "AWS EC2 instance enumeration across all regions", Severity.MEDIUM, "T1613"),
        (re.compile(r'aws\s+sts\s+get-caller-identity', re.IGNORECASE),
         "AWS STS identity enumeration", Severity.LOW, "T1069"),
        (re.compile(r'az\s+account\s+list', re.IGNORECASE),
         "Azure account enumeration", Severity.LOW, "T1069"),
        (re.compile(r'gcloud\s+projects\s+list', re.IGNORECASE),
         "GCP project enumeration", Severity.LOW, "T1069"),
    ]

    def _detect_cloud_lateral_movement(self, process_data: Dict) -> List[Evidence]:
        """Detect cloud service lateral movement (T1021.007)"""
        evidences = []
        processes = process_data.get("processes", [])
        evidence_id_counter = 2000
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue
            for pattern, title, severity, attack_id in self.CLOUD_LATERAL_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(self._mk_cloud_evidence(evidence_id_counter, "lateral_cloud", title,
                        f"Cloud lateral movement detected: {cmdline[:200]}", severity, 0.9, attack_id,
                        "Lateral Movement", cmdline, proc))
            for pattern, title, severity, attack_id in self.CLOUD_ENUMERATION_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(self._mk_cloud_evidence(evidence_id_counter, "lateral_cloud_enum", title,
                        f"Cloud enumeration activity: {cmdline[:200]}", severity, 0.75, attack_id,
                        "Discovery", cmdline, proc))
        return evidences
    def _mk_cloud_evidence(self, counter, prefix, title, desc, severity, confidence, attack_id, tactic, cmdline, proc):
        return Evidence(
            id=f"{prefix}_{counter}", module=self.name, title=title, description=desc,
            severity=severity, confidence=confidence, attack_id=attack_id, attack_tactic=tactic,
            source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline", timestamp="",
            raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "user": proc.get("user")},
            remediation="Audit cloud CLI usage and verify authorization",
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
        )
