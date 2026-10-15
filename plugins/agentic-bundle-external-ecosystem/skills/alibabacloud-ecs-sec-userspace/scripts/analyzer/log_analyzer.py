"""Log Anomaly Analyzer"""
import re
from bisect import bisect_right
from datetime import datetime, timedelta
from collections import defaultdict
from .base import BaseAnalyzer
from ..utils.datetime_compat import fromisoformat
from ..reporter.evidence import EvidenceDetail
from ..reporter.severity import Severity


class LogAnalyzer(BaseAnalyzer):
    """Log Anomaly Analyzer"""
    name = "log_analyzer"
    timeout = 30
    estimated_time = 1.0  # Reduced for quick mode (auditd + log clearing only)
    analyzer_type = BaseAnalyzer.CRITICAL
    required_collectors = ["log"]
    
    # Pre-compiled regex patterns
    TIMESTAMP_PATTERN = re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
    
    def analyze(self, collected_data: dict):
        """Analyze log data"""
        evidences = []
        self._collected_data = collected_data  # Save reference for _get_system_uptime

        log_data = self._get_data(collected_data, "log")
        if not log_data:
            return evidences

        # Quick mode: only critical log checks

        # Full mode: all checks
        # 1. Log clearing trace detection
        evidences.extend(self._detect_log_clearing(log_data))

        # 2. Log time gap detection
        evidences.extend(self._detect_time_gaps(log_data))

        # 3. Brute force pattern detection (log dimension)
        evidences.extend(self._detect_brute_force_from_log(log_data))

        # 4. Privilege escalation failure record detection
        evidences.extend(self._detect_privilege_escalation_failures(log_data))

        # 5. auditd status detection (T1562.001)
        evidences.extend(self._check_auditd_status(log_data))

        return evidences
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def _detect_log_clearing(self, log_data: dict) -> list:
        """Detect log clearing traces"""
        evidences = []
        
        log_files = log_data.get("log_files", [])
        wtmp_info = log_data.get("wtmp_info", {})
        
        # Get system uptime (seconds)
        system_uptime = self._get_system_uptime()
        
        # If system uptime < 1 hour, skip log clearing detection (may be newly installed system)
        if system_uptime < 3600:
            return evidences
        
        # Check if critical log files are empty
        critical_logs = ["auth.log", "syslog", "secure"]
        for log_file in log_files:
            path = log_file.get("path", "")
            is_empty = log_file.get("is_empty", False)
            exists = log_file.get("exists", False)
            
            # If critical log file exists but is empty (and system running > 1 hour)
            if exists and is_empty and any(name in path for name in critical_logs):
                evidence = self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1070.002",
                    title="关键日志文件为空",
                    description=f"日志文件 {path} 大小为 0，可能是新安装系统或日志被清除（系统运行{system_uptime // 3600}小时）",
                    confidence=0.5,  # Lower confidence
                    raw_data={"path": path, "system_uptime_hours": system_uptime // 3600},
                    evidence_details=EvidenceDetail(
                        file_path=path,
                        content=f"Log file empty, system uptime: {system_uptime // 3600}h",
                    ),
                    remediation_commands=[
                        f"cat {path}",
                        "Review log integrity",
                        "Check for log tampering",
                        "Verify log configuration"
                    ]
                )
                evidences.append(evidence)
        
        # Check if wtmp is empty (only when system running > 24 hours)
        if wtmp_info.get("path") and wtmp_info.get("is_empty") and system_uptime > 86400:
            evidence = self._create_evidence(
                severity=Severity.MEDIUM,
                attack_id="T1070.002",
                title="wtmp 登录记录为空",
                description=f"wtmp 文件为空，系统运行{system_uptime // 3600}小时，可能是新系统或登录记录被清除",
                confidence=0.4,  # Even lower confidence
                raw_data={"path": wtmp_info.get("path"), "system_uptime_hours": system_uptime // 3600},
                evidence_details=EvidenceDetail(
                    file_path=wtmp_info.get("path", ""),
                    content="wtmp login records empty",
                ),
                remediation_commands=[
                    f"last -f {wtmp_info.get('path', '/var/log/wtmp')}",
                    "Review log integrity",
                    "Check for log tampering",
                    "Verify log configuration"
                ]
            )
            evidences.append(evidence)
        
        return evidences
    
    def _get_system_uptime(self) -> int:
        """Get system uptime (seconds)"""
        # Prefer collected_data (supports mock testing)
        if hasattr(self, '_collected_data') and self._collected_data:
            try:
                system_data = self._get_data(self._collected_data, "system")
            except KeyError:
                system_data = {}
            if isinstance(system_data, dict):
                uptime = system_data.get("uptime_seconds")
                if uptime is not None:
                    return int(uptime)
        # Fall back to /proc/uptime
        try:
            with open("/proc/uptime", "r", errors='replace', encoding='utf-8') as f:
                uptime_str = f.read(64).split()[0]  # Limit 64 bytes
                return int(float(uptime_str))
        except (OSError, ValueError):
            # When uptime unavailable, return conservative value (assume newly started system)
            return 0
    
    def _parse_log_timestamp(self, timestamp_str: str) -> datetime:
        """Parse log timestamp, supports both ISO and syslog formats"""
        if not timestamp_str:
            raise ValueError("empty timestamp")
        # Try ISO format
        try:
            return fromisoformat(timestamp_str)
        except (ValueError, TypeError):
            pass
        # Try syslog format: "Mar 15 08:00:01"
        try:
            # Syslog doesn't include year, use current year
            current_year = datetime.now().year
            return datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        except (ValueError, TypeError):
            pass
        raise ValueError(f"unsupported timestamp format: {timestamp_str}")

    def _detect_time_gaps(self, log_data: dict) -> list:
        """Detect log time gaps"""
        evidences = []
        
        auth_log = log_data.get("auth_log", {})
        failed_logins = auth_log.get("failed_logins", [])
        successful_logins = auth_log.get("successful_logins", [])
        sudo_events = auth_log.get("sudo_events", [])
        
        # Merge all events and sort by time
        all_events = []
        for event_list in [failed_logins, successful_logins, sudo_events]:
            for event in event_list:
                timestamp_str = event.get("timestamp", "")
                if timestamp_str:
                    try:
                        timestamp = self._parse_log_timestamp(timestamp_str)
                        all_events.append(timestamp)
                    except (ValueError, TypeError):
                        pass
        
        if len(all_events) < 2:
            return evidences
        
        all_events.sort()
        
        # Detect time gaps > 24 hours
        for i in range(1, len(all_events)):
            time_diff = all_events[i] - all_events[i-1]
            if time_diff > timedelta(hours=24):
                evidence = self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1070.002",
                    title="日志时间断层检测",
                    description=f"检测到日志时间间隔超过 24 小时：{time_diff.days}天",
                    confidence=0.6,
                    raw_data={
                        "gap_start": all_events[i-1].isoformat(),
                        "gap_end": all_events[i].isoformat(),
                        "gap_days": time_diff.days
                    },
                    evidence_details=EvidenceDetail(
                        file_path="/var/log/auth.log",
                        content=f"Time gap: {time_diff.days} days between {all_events[i-1].isoformat()} and {all_events[i].isoformat()}",
                    ),
                    remediation_commands=[
                        "cat /var/log/auth.log",
                        "Review log integrity",
                        "Check for log tampering",
                        "Verify log configuration"
                    ]
                )
                evidences.append(evidence)
                break  # Only report the largest gap
        
        return evidences
    
    def _detect_brute_force_from_log(self, log_data: dict) -> list:
        """Detect brute force patterns from logs"""
        evidences = []
        
        auth_log = log_data.get("auth_log", {})
        failed_logins = auth_log.get("failed_logins", [])
        successful_logins = auth_log.get("successful_logins", [])
        
        if not failed_logins:
            return evidences
        
        # Group failed logins by source_ip_hash (using hash to protect privacy)
        ip_failures = defaultdict(list)
        for failure in failed_logins:
            source_ip_hash = failure.get("source_ip_hash", "")
            timestamp_str = failure.get("timestamp", "")
            if source_ip_hash and timestamp_str:
                try:
                    timestamp = self._parse_log_timestamp(timestamp_str)
                    ip_failures[source_ip_hash].append(timestamp)
                except (ValueError, TypeError):
                    pass
        
        # Check failure count per IP
        for ip_hash, timestamps in ip_failures.items():
            if len(timestamps) < 10:
                continue
            
            timestamps.sort()
            
            # Check failure count in 5-minute window (using bisect binary search, O(n log n))
            for i in range(len(timestamps)):
                window_end = timestamps[i] + timedelta(minutes=5)
                j = bisect_right(timestamps, window_end)
                count_in_window = j - i
                
                if count_in_window >= 10:
                    # Check if this IP has successful logins (using hash match)
                    ip_success = [
                        s for s in successful_logins
                        if s.get("source_ip_hash") == ip_hash
                    ]
                    
                    severity = Severity.HIGH if ip_success else Severity.MEDIUM
                    confidence = 0.8
                    
                    title = f"暴力破解检测：IP (hash:{ip_hash[:8]}...) 5 分钟内失败{count_in_window}次"
                    if ip_success:
                        title += " 且已成功登录"
                    
                    evidence = self._create_evidence(
                        severity=severity,
                        attack_id="T1110",
                        title=title,
                        description=f"IP (hash:{ip_hash[:8]}...) 在 5 分钟内失败登录{count_in_window}次",
                        confidence=confidence,
                        raw_data={
                            "source_ip_hash": ip_hash,
                            "failures_in_window": count_in_window,
                            "has_success": len(ip_success) > 0
                        },
                        evidence_details=EvidenceDetail(
                            file_path="/var/log/auth.log",
                            content=f"Brute force: {count_in_window} failures in 5min from IP hash:{ip_hash[:8]}...",
                        ),
                        remediation_commands=[
                            "cat /var/log/auth.log | grep failed",
                            "Review log integrity",
                            "Check for log tampering",
                            "Verify log configuration"
                        ]
                    )
                    evidences.append(evidence)
                    break  # Report once per IP
        
        return evidences
    
    def _detect_privilege_escalation_failures(self, log_data: dict) -> list:
        """Detect privilege escalation failure records"""
        evidences = []
        
        auth_log = log_data.get("auth_log", {})
        sudo_events = auth_log.get("sudo_events", [])
        
        if not sudo_events:
            return evidences
        
        # Count failure records
        failed_sudos = [e for e in sudo_events if not e.get("success", True)]
        
        if not failed_sudos:
            return evidences
        
        # Group by user
        user_failures = defaultdict(list)
        for event in failed_sudos:
            user = event.get("user", "")
            if user:
                user_failures[user].append(event)
        
        # Check same user with multiple failures
        for user, events in user_failures.items():
            if len(events) >= 3:  # 3 or more failures
                evidence = self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1548",
                    title=f"用户 {user} 多次 sudo 失败",
                    description=f"用户 {user} 有 {len(events)} 次 sudo 失败记录",
                    confidence=0.5,
                    raw_data={
                        "user": user,
                        "failure_count": len(events),
                        "commands": [e.get("command", "") for e in events[:5]]
                    },
                    evidence_details=EvidenceDetail(
                        file_path="/var/log/auth.log",
                        content=f"User {user} failed sudo {len(events)} times",
                    ),
                    remediation_commands=[
                        "cat /var/log/auth.log | grep sudo",
                        "Review log integrity",
                        "Check for log tampering",
                        "Verify log configuration"
                    ]
                )
                evidences.append(evidence)
        
        return evidences
    
    def _check_auditd_status(self, log_data: dict) -> list:
        """Detect auditd audit system status (T1562.001)
        
        Detects attacker behavior of disabling audit systems to hide activity.
        """
        evidences = []
        
        auditd_info = log_data.get("auditd_info", {})
        if not auditd_info:
            return evidences
        
        # 1. Detect if auditd service is running
        service_status = auditd_info.get("service_status", "")
        if service_status and service_status.lower() not in ("running", "active"):
            evidences.append(self._create_evidence(
                severity=Severity.HIGH,
                attack_id="T1562.001",
                title="auditd 审计服务未运行",
                description=f"auditd 服务状态为 {service_status}，系统审计能力已禁用",
                confidence=0.8,
                raw_data={"service_status": service_status},
                evidence_details=EvidenceDetail(
                    file_path="/var/log/audit/audit.log",
                    content=f"auditd service status: {service_status}",
                ),
                remediation_commands=[
                    "systemctl status auditd",
                    "Review log integrity",
                    "Check for log tampering",
                    "Verify log configuration"
                ]
            ))
        
        # 2. Detect if audit rules have been cleared
        rule_count = auditd_info.get("rule_count", -1)
        if rule_count == 0:
            evidences.append(self._create_evidence(
                severity=Severity.HIGH,
                attack_id="T1562.001",
                title="auditd 审计规则为空",
                description="auditd 规则计数为 0，可能被攻击者清除",
                confidence=0.7,
                raw_data={"rule_count": rule_count},
                evidence_details=EvidenceDetail(
                    file_path="/etc/audit/audit.rules",
                    content="auditd rule count is 0",
                ),
                remediation_commands=[
                    "auditctl -l",
                    "Review log integrity",
                    "Check for log tampering",
                    "Verify log configuration"
                ]
            ))
        
        # 3. Detect if audit log has been truncated or interrupted
        audit_log_gap = auditd_info.get("log_gap_hours", 0)
        if audit_log_gap > 24:
            evidences.append(self._create_evidence(
                severity=Severity.MEDIUM,
                attack_id="T1562.001",
                title="auditd 审计日志存在时间间隙",
                description=f"审计日志存在超过 {audit_log_gap} 小时的间隙",
                confidence=0.6,
                raw_data={"log_gap_hours": audit_log_gap},
                evidence_details=EvidenceDetail(
                    file_path="/var/log/audit/audit.log",
                    content=f"auditd log gap: {audit_log_gap} hours",
                ),
                remediation_commands=[
                    "cat /var/log/audit/audit.log",
                    "Review log integrity",
                    "Check for log tampering",
                    "Verify log configuration"
                ]
            ))
        
        return evidences
