"""Tunnel Tool & Reverse Proxy Detection Mixin.

Provides tunnel tool process detection and reverse proxy pattern matching
for the LateralMovementAnalyzer.

Split from remote_exploit.py to stay under 500 lines - zero functional change.
"""
import re
from typing import List, Dict
from ...reporter.evidence import Evidence, EvidenceDetail
from ...reporter.severity import Severity


class TunnelDetectorMixin:
    """Mixin providing tunnel tool and reverse proxy detection capabilities."""

    # Remote service tunnel tools
    TUNNEL_TOOL_PROCESSES = {
        "frpc": ("frp client process", Severity.HIGH, "T1572"),
        "frps": ("frp server process", Severity.HIGH, "T1572"),
        "ngrok": ("ngrok tunnel tool", Severity.HIGH, "T1572"),
        "gost": ("GO simple tunnel tool", Severity.HIGH, "T1572"),
        "regeorg": ("reGeorg tunnel script", Severity.CRITICAL, "T1572"),
        "stowaway": ("Stowaway tunnel tool", Severity.HIGH, "T1572"),
        "chisel": ("Chisel TCP tunnel", Severity.HIGH, "T1572"),
        "ligolo": ("Ligolo-ng tunnel tool", Severity.CRITICAL, "T1572"),
        "earthworm": ("Earthworm tunnel tool", Severity.HIGH, "T1572"),
        "termite": ("Termite tunnel framework", Severity.HIGH, "T1572"),
    }

    REVERSE_PROXY_PATTERNS = [
        (re.compile(r'.*proxy\.config\.json', re.IGNORECASE),
         "Proxy configuration file", Severity.MEDIUM, "T1572"),
        (re.compile(r'listen\s+.*socks', re.IGNORECASE),
         "SOCKS proxy listener", Severity.HIGH, "T1572"),
        (re.compile(r'upstream\s+.*https?://', re.IGNORECASE),
         "HTTP upstream proxy", Severity.MEDIUM, "T1572"),
    ]

    def _detect_tunnel_tools(self, process_data: Dict, network_data: Dict) -> List[Evidence]:
        """Detect remote service tunnel tools"""
        evidences = []
        processes = process_data.get("processes", [])

        evidence_id_counter = 0

        # Check for tunnel tool processes
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")

            # Check process name
            if comm.lower() in self.TUNNEL_TOOL_PROCESSES:
                desc, severity, attack_id = self.TUNNEL_TOOL_PROCESSES[comm.lower()]
                evidence_id_counter += 1
                evidences.append(Evidence(
                    id=f"lateral_tunnel_tool_{evidence_id_counter}",
                    module=self.name,
                    title=f"Tunnel tool detected: {comm}",
                    description=f"{desc} - Process: {cmdline[:200]}",
                    severity=severity,
                    confidence=0.9,
                    attack_id=attack_id,
                    attack_tactic="Command and Control",
                    source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                    timestamp="",
                    raw_data={"cmdline": cmdline, "pid": proc.get("pid"), "comm": comm},
                    remediation="Investigate tunnel tool usage and verify authorization",
                    evidence_details=EvidenceDetail(
                        pid=proc.get("pid"),
                        cmdline=cmdline[:500],
                        executable=proc.get("exe", ""),
                        user=proc.get("user", ""),
                        parent_pid=proc.get("ppid"),
                    ),
                    remediation_commands=[
                        f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                        f"kill -9 {proc.get('pid', 'PID')}",
                        f"netstat -tunap | grep {proc.get('pid', 'PID')}",
                        f"find / -name '{comm}' -type f 2>/dev/null",
                    ],
                ))
            else:
                # Check cmdline for tunnel tools
                for tool_name, (desc, severity, attack_id) in self.TUNNEL_TOOL_PROCESSES.items():
                    if tool_name in cmdline.lower():
                        evidence_id_counter += 1
                        evidences.append(Evidence(
                            id=f"lateral_tunnel_cmd_{evidence_id_counter}",
                            module=self.name,
                            title=f"Tunnel tool in command: {tool_name}",
                            description=f"{desc} - Command: {cmdline[:200]}",
                            severity=severity,
                            confidence=0.85,
                            attack_id=attack_id,
                            attack_tactic="Command and Control",
                            source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                            timestamp="",
                            raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                            remediation="Investigate tunnel tool usage and verify authorization",
                            evidence_details=EvidenceDetail(
                                pid=proc.get("pid"),
                                cmdline=cmdline[:500],
                                executable=proc.get("exe", ""),
                                user=proc.get("user", ""),
                                parent_pid=proc.get("ppid"),
                            ),
                            remediation_commands=[
                                f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                                f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                                f"cat /proc/{proc.get('pid', 'PID')}/environ 2>/dev/null | tr '\\0' '\\n' | head -10",
                                "ss -tunap | head -20",
                            ],
                        ))
                        break

        # Check reverse proxy patterns
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            if not cmdline:
                continue

            for pattern, title, severity, attack_id in self.REVERSE_PROXY_PATTERNS:
                if pattern.search(cmdline):
                    evidence_id_counter += 1
                    evidences.append(Evidence(
                        id=f"lateral_reverse_proxy_{evidence_id_counter}",
                        module=self.name,
                        title=title,
                        description=f"Reverse proxy pattern: {cmdline[:200]}",
                        severity=severity,
                        confidence=0.75,
                        attack_id=attack_id,
                        attack_tactic="Command and Control",
                        source_path=f"/proc/{proc.get('pid', 'unknown')}/cmdline",
                        timestamp="",
                        raw_data={"cmdline": cmdline, "pid": proc.get("pid")},
                        remediation="Review proxy configuration and verify legitimacy",
                        evidence_details=EvidenceDetail(
                            pid=proc.get("pid"),
                            cmdline=cmdline[:500],
                            executable=proc.get("exe", ""),
                            user=proc.get("user", ""),
                            parent_pid=proc.get("ppid"),
                        ),
                        remediation_commands=[
                            f"ps -p {proc.get('pid', 'PID')} -o pid,user,cmd --no-headers",
                            f"lsof -p {proc.get('pid', 'PID')} 2>/dev/null | head -20",
                            f"cat /proc/{proc.get('pid', 'PID')}/environ 2>/dev/null | tr '\\0' '\\n' | head -10",
                            "ss -tunap | head -20",
                        ],
                    ))

        return evidences
