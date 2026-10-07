"""Persistence Mechanism Analyzer"""
import re
import os
import subprocess
from typing import List, Dict, Any, Optional
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

class PersistenceAnalyzer(BaseAnalyzer):
    """Persistence Mechanism Analyzer"""
    name = "persistence_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 30)
    
    # Quick mode performance limits
    QUICK_MODE_CRON_LIMIT = 10  # Reduced from 20 for performance
    QUICK_MODE_SERVICE_LIMIT = 15  # Reduced from 30 for performance
    QUICK_MODE_BUDGET = 1.0  # 1 second budget for quick mode
    
    required_collectors = ["cron", "service"]
    
    # Smart scheduling attributes
    estimated_time = 5.0  # Crontab/Systemd config scan
    analyzer_type = BaseAnalyzer.CRITICAL  # Critical security check

    # Systemd service whitelist (known legitimate system services)
    SYSTEMD_SERVICE_WHITELIST = {
        # Alibaba Cloud Linux 3 / StarAgent services
        "sysak.service",
        "sysak_livetrace.service",
        "selinux-autorelabel-mark.service",
        "staragent.service",
        "argusagent.service",
    }

    # Legitimate system timers whitelist (to prevent false positives)
    LEGITIMATE_SYSTEM_TIMERS = {
        "sysstat-collect.timer",
        "sysstat-summary.timer",
        "logrotate.timer",
        "man-db.timer",
        "apt-daily.timer",
        "apt-daily-upgrade.timer",
        "dnf-makecache.timer",
        "systemd-tmpfiles-clean.timer",
        "fstrim.timer",
        "certbot-renew.timer",
        "fwupd-refresh.timer",
        "unattended-upgrades.timer",
        "e2scrub_all.timer",
        "mlocate.timer",
        "shadow-utils.timer",
    }

    # Legitimate system cronjobs whitelist
    LEGITIMATE_CRONJOBS = {
        # Log management
        "/usr/sbin/logrotate",
        "/etc/cron.daily/logrotate",
        
        # Package manager updates
        "/usr/lib/apt/apt.systemd.daily",
        "/etc/cron.daily/apt-compat",
        "/usr/lib/apt/apt-daily-upgrade",
        "/etc/cron.daily/apt-daily-upgrade",
        
        # Filesystem maintenance
        "/usr/sbin/e2scrub_all",
        "/etc/cron.weekly/e2scrub_all",
        
        # Manual page database
        "/usr/bin/mandb",
        "/etc/cron.weekly/man-db",
        
        # Security updates
        "/usr/libexec/generate-rndc-key.sh",
        
        # System monitoring (sysstat)
        "/usr/lib64/sa/sa1",
        "/usr/lib64/sa/sa2",
        "/usr/lib/x86_64-linux-gnu/sa/sa1",
        "/usr/lib/x86_64-linux-gnu/sa/sa2",
        "/usr/lib/sysstat/sa1",
        "/usr/lib/sysstat/sa2",
        
        # Time synchronization
        "/usr/sbin/ntpdate",
        
        # Disk health checks
        "/usr/sbin/smartctl",
        
        # Certificate updates
        "/usr/sbin/update-ca-certificates",
        
        # Locate database updates
        "/usr/bin/updatedb",
        "/etc/cron.daily/mlocate",
        
        # Temporary file cleanup
        "/usr/bin/tmpreaper",
        "/usr/sbin/tmpwatch",
        
    }
    
    # Pre-compiled suspicious cron patterns
    SUSPICIOUS_CRON_PATTERNS = [
        re.compile(r"/dev/tcp/"),
        re.compile(r"curl\s.*\|\s*bash"),
        re.compile(r"wget\s.*\|\s*bash"),
        re.compile(r"/tmp/\."),
        re.compile(r"/dev/shm/"),
        re.compile(r"base64\s+-d"),
        re.compile(r"python.*-c\s+['\"]import"),
        re.compile(r"nc\s+-.*-e"),
    ]
    
    # CWD validation patterns for persistence mechanisms
    EXPECTED_CWD_FOR_SERVICES = {
        # System services typically run from system directories
        'systemd': ['/usr', '/etc', '/var', '/'],  # Root '/' is normal for systemd services
        'cron': ['/usr', '/etc', '/var/spool/cron', '/'],
        'sshd': ['/usr', '/etc/ssh', '/'],
        'nginx': ['/usr', '/etc/nginx', '/var/www', '/'],
        'apache': ['/usr', '/etc/apache2', '/var/www', '/'],
    }
    
    # System core services that always have cwd = '/' (completely skip CWD validation)
    SYSTEM_CORE_SERVICES = {
        'systemd-udevd',
        'systemd-logind', 
        'systemd-journald',
        'systemd-resolved',
        'systemd-networkd',
        'systemd-timesyncd',
        'systemd-modules-load',
        'systemd-sysctl',
        'systemd-tmpfiles',
        'systemd-udev',
        'rpcbind',
        'dbus-daemon',
        'sshd',
        'cron',
        'crond',
        'rsyslogd',
    }
    
    # Container runtime components whitelist (to prevent false positives)
    CONTAINER_RUNTIME_WHITELIST = {
        'containerd-shim',
        'containerd-shim-runc-v1',
        'containerd-shim-runc-v2',
        'runc',
        'runsc',
        'crun',
        'dockerd',
        'docker-proxy',
        'containerd',
        'crio',
        'conmon',
    }
    
    RISKY_CWD_FOR_SERVICES = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/']
    
    def _find_pattern_context(self, content: str, patterns: list, context_lines: int = 3) -> tuple:
        """Find pattern matches with line numbers and context.
        
        Args:
            content: File content to search
            patterns: List of compiled regex patterns
            context_lines: Number of context lines before/after match
            
        Returns:
            Tuple of (matched_pattern_names, first_match_line, context_before, context_after)
        """
        lines = content.split('\n')
        matched_patterns = []
        first_match_line = None
        context_before = []
        context_after = []
        
        for pattern in patterns:
            for line_num, line in enumerate(lines, 1):
                if pattern.search(line):
                    matched_patterns.append(pattern.pattern)
                    if first_match_line is None:
                        first_match_line = line_num
                        context_before = lines[max(0, line_num - 1 - context_lines):line_num - 1]
                        context_after = lines[line_num:min(len(lines), line_num + context_lines)]
                    break
        
        return matched_patterns, first_match_line, context_before, context_after
    
    def should_skip(self) -> tuple:
        """Run lightweight persistence check in quick mode.
        
        Quick mode checks only critical paths (/etc/crontab, key systemd services).
        Full mode performs comprehensive cron and systemd file scanning.
        """
        return False, ""
    
    def analyze(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Analyze persistence mechanisms.
        
        In quick mode, only critical paths are checked:
        - /etc/crontab for suspicious entries
        - Key systemd services for anomalies
        
        In full mode, comprehensive persistence scanning is performed.
        """
        evidences = []
        
        # Get collected data
        cron_data = self._get_data(collected_data, "cron", default={}, strict=False)
        service_data = self._get_data(collected_data, "service", default={}, strict=False)
        
        # Guard: ensure data is dict (collectors may return list or None in edge cases)
        if not isinstance(cron_data, dict):
            _get_logger().debug(f'[persistence_analyzer] cron_data is {type(cron_data).__name__}, using empty dict')
            cron_data = {}
        if not isinstance(service_data, dict):
            _get_logger().debug(f'[persistence_analyzer] service_data is {type(service_data).__name__}, using empty dict')
            service_data = {}
        
        # Quick mode: lightweight checks only
        # Full mode: comprehensive analysis
        # 1. Cron backdoor detection
        evidences.extend(self._detect_cron_backdoor(cron_data))
        
        # 2. Systemd malicious service detection
        evidences.extend(self._detect_malicious_systemd(service_data))
        
        # 3. Systemd Timer malicious detection (T1053.005)
        evidences.extend(self._detect_malicious_timers(cron_data, service_data))
        
        # 4. Shell configuration injection detection
        evidences.extend(self._detect_shell_injection(service_data))
        
        # 5. rc.local backdoor detection
        evidences.extend(self._detect_rclocal_backdoor(service_data))
        
        # 6. LD_PRELOAD hijack detection
        evidences.extend(self._detect_ldpreload(service_data))
        
        # 7. T1547.001 - Linux auto-start persistence detection
        evidences.extend(self._detect_startup_persistence(collected_data))
        
        # 8. PATH modification detection (AN0010)
        evidences.extend(self._check_path_modification(collected_data))
        
        # 9. CWD validation for persistent services
        evidences.extend(self._validate_service_cwd(collected_data))
        
        # 10. Systemd socket activation backdoor detection (T1543.002, T1571)
        evidences.extend(self._check_socket_activation_backdoors(service_data))
        
        # 11. Systemd path-activated services detection (T1543.002)
        evidences.extend(self._check_path_activated_services(service_data))
        
        # 12. Systemd drop-in override detection (T1543.002)
        evidences.extend(self._check_systemd_dropin_overrides(service_data))
        
        return evidences
    def _is_legitimate_cronjob(self, cron_cmd: str, cron_path: str) -> bool:
        """Check if cronjob is from a known legitimate system task."""
        # Check against whitelist
        if cron_path in self.LEGITIMATE_CRONJOBS:
            return True
        
        # Check if command starts with whitelisted binary
        cmd_binary = cron_cmd.split()[0] if cron_cmd else ""
        if cmd_binary in self.LEGITIMATE_CRONJOBS:
            return True
        
        # Check package origin
        if self._verify_cronjob_package_origin(cron_path):
            return True
        
        return False
    
    def _verify_cronjob_package_origin(self, cron_path: str) -> bool:
        """Check if cronjob belongs to a system package."""
        try:
            # Check RPM-based systems
            result = subprocess.run(
                ["rpm", "-qf", cron_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            if result.returncode == 0:
                return True
            
            # Check DEB-based systems
            result = subprocess.run(
                ["dpkg", "-S", cron_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return False
    
    def _detect_cron_backdoor(self, cron_data: dict) -> List[Evidence]:
        """Detect cron backdoors"""
        
        evidences = []
        
        if not cron_data:
            return evidences
        
        # Check all cron entries (system_crontab + cron_d_entries + user_crontabs)
        all_entries = (
            cron_data.get("system_crontab", []) +
            cron_data.get("cron_d_entries", [])
        )
        
        # User crontabs nested in {"user": "root", "entries": [...]} structure
        for user_crontab in cron_data.get("user_crontabs", []):
            for entry in user_crontab.get("entries", []):
                entry.setdefault("source", f"/var/spool/cron/crontabs/{user_crontab.get('user', 'unknown')}")
                all_entries.append(entry)
        
        for entry in all_entries:
            command = entry.get("command", "")
            if not command:
                continue
            
            # Skip legitimate cronjobs
            source = entry.get("source", "")
            if self._is_legitimate_cronjob(command, source):
                continue
            
            # Match suspicious patterns
            for pattern in self.SUSPICIOUS_CRON_PATTERNS:
                if pattern.search(command):
                    # Extract context with line numbers
                    matched_patterns, match_line, context_before, context_after = self._find_pattern_context(
                        command, self.SUSPICIOUS_CRON_PATTERNS
                    )
                    
                    evidence_detail = EvidenceDetail(
                        file_path=entry.get("source", "unknown"),
                        content=command[:200] if len(command) > 200 else command,
                        line_number=match_line,
                        context_before=context_before,
                        context_after=context_after,
                    )
                    remediation_cmds = [
                        f"cat {entry.get('source', '')}" if entry.get("source") else "# Review cron source",
                        f"crontab -l | grep -v '{command[:50]}'",
                    ]
                    evidences.append(self._create_evidence(
                        title=f"可疑Cron命令: {pattern.pattern}",
                        description=f"检测到可疑的Cron命令: {command[:100]}",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        attack_id="T1053.003",
                        source_path=entry.get("source", "unknown"),
                        raw_data={"command": command, "schedule": entry.get("schedule", "")},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break  # Avoid duplicate reporting
        
        # Check cron_periodic script content
        for periodic in cron_data.get("cron_periodic", []):
            preview = periodic.get("content_preview", "")
            if not preview:
                continue
            
            # Skip legitimate periodic scripts
            periodic_file = periodic.get("file", "")
            if self._is_legitimate_cronjob("", periodic_file):
                continue
            
            for pattern in self.SUSPICIOUS_CRON_PATTERNS:
                if pattern.search(preview):
                    # Extract context with line numbers
                    matched_patterns, match_line, context_before, context_after = self._find_pattern_context(
                        preview, self.SUSPICIOUS_CRON_PATTERNS
                    )
                    
                    evidence_detail = EvidenceDetail(
                        file_path=periodic.get("file", "unknown"),
                        content=preview[:200] if len(preview) > 200 else preview,
                        line_number=match_line,
                        context_before=context_before,
                        context_after=context_after,
                    )
                    remediation_cmds = [
                        f"cat {periodic.get('file', '')}" if periodic.get("file") else "# Review periodic script",
                        f"rm {periodic.get('file', '')}" if periodic.get("file") else "# Remove suspicious script",
                    ]
                    evidences.append(self._create_evidence(
                        title=f"可疑Cron周期脚本: {periodic.get('file', 'unknown')}",
                        description=f"周期脚本包含可疑命令: {preview[:100]}",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        attack_id="T1053.003",
                        source_path=periodic.get("file", "unknown"),
                        raw_data={"preview": preview[:200], "period": periodic.get("period", "")},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break
        
        return evidences
    
    def _detect_malicious_systemd(self, service_data: dict) -> List[Evidence]:
        """Detect systemd malicious services"""
        evidences = []
        
        if not service_data:
            return evidences
        
        for svc in service_data.get("systemd_services", []):
            service_name = svc.get("name", "")
            
            # Skip whitelisted services
            if service_name in self.SYSTEMD_SERVICE_WHITELIST:
                continue

            exec_start = svc.get("exec_start", "")
            if not exec_start:
                continue
            
            # Detect reverse shell
            if "/dev/tcp/" in exec_start:
                # Extract context with line numbers
                matched_patterns, match_line, context_before, context_after = self._find_pattern_context(
                    exec_start, self.SUSPICIOUS_CRON_PATTERNS
                )
                
                evidence_detail = EvidenceDetail(
                    file_path=svc.get("unit_file", "unknown"),
                    content=exec_start[:200] if len(exec_start) > 200 else exec_start,
                    service_type="systemd",
                    line_number=match_line,
                    context_before=context_before,
                    context_after=context_after,
                )
                remediation_cmds = [
                    f"systemctl stop {service_name}" if service_name else "# Stop malicious service",
                    f"rm {svc.get('unit_file', '')}" if svc.get("unit_file") else "# Remove unit file",
                    "systemctl daemon-reload",
                ]
                evidences.append(self._create_evidence(
                    title=f"恶意Systemd服务: {svc.get('name', 'unknown')}",
                    description=f"服务ExecStart包含反弹Shell命令: {exec_start[:100]}",
                    severity=Severity.CRITICAL,
                    confidence=0.8,
                    attack_id="T1543.002",
                    source_path=svc.get("unit_file", "unknown"),
                    raw_data={"exec_start": exec_start},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
            
            # Detect hidden paths or /tmp
            elif "/tmp/" in exec_start or "/." in exec_start:
                # Extract context with line numbers
                matched_patterns, match_line, context_before, context_after = self._find_pattern_context(
                    exec_start, self.SUSPICIOUS_CRON_PATTERNS
                )
                
                evidence_detail = EvidenceDetail(
                    file_path=svc.get("unit_file", "unknown"),
                    content=exec_start[:200] if len(exec_start) > 200 else exec_start,
                    service_type="systemd",
                    line_number=match_line,
                    context_before=context_before,
                    context_after=context_after,
                )
                remediation_cmds = [
                    f"systemctl stop {service_name}" if service_name else "# Stop suspicious service",
                    f"cat {svc.get('unit_file', '')}" if svc.get("unit_file") else "# Review unit file",
                ]
                evidences.append(self._create_evidence(
                    title=f"可疑Systemd服务: {svc.get('name', 'unknown')}",
                    description=f"服务引用可疑路径: {exec_start[:100]}",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    attack_id="T1543.002",
                    source_path=svc.get("unit_file", "unknown"),
                    raw_data={"exec_start": exec_start},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
        
        return evidences
    
    def _is_legitimate_system_timer(self, timer_name: str) -> bool:
        """Check if timer is from a known legitimate system package."""
        return timer_name in self.LEGITIMATE_SYSTEM_TIMERS
    
    def _detect_malicious_timers(self, cron_data: dict, service_data: dict) -> List[Evidence]:
        """Detect suspicious systemd timers (T1053.005)"""
        evidences = []
        
        timers = cron_data.get("systemd_timers", [])
        if not timers:
            return evidences
        
        # Build service name to info mapping
        services_by_name = {}
        for svc in service_data.get("systemd_services", []):
            services_by_name[svc.get("name", "")] = svc
        
        for timer in timers:
            timer_name = timer.get("name", "")
            unit_file = timer.get("unit_file", "")
            
            if not timer_name:
                continue
            
            # Skip known legitimate system timers
            if self._is_legitimate_system_timer(timer_name):
                continue
            
            # Find associated service
            service_name = timer_name.replace(".timer", ".service")
            associated_svc = services_by_name.get(service_name)
            
            if not associated_svc:
                continue
            
            exec_start = associated_svc.get("exec_start", "")
            if not exec_start:
                continue
            
            # Detect suspicious command patterns
            for pattern in self.SUSPICIOUS_CRON_PATTERNS:
                if pattern.search(exec_start):
                    # Extract context with line numbers
                    matched_patterns, match_line, context_before, context_after = self._find_pattern_context(
                        exec_start, self.SUSPICIOUS_CRON_PATTERNS
                    )
                    
                    evidence_detail = EvidenceDetail(
                        file_path=unit_file,
                        content=exec_start[:200] if len(exec_start) > 200 else exec_start,
                        service_type="systemd_timer",
                        line_number=match_line,
                        context_before=context_before,
                        context_after=context_after,
                    )
                    remediation_cmds = [
                        f"systemctl stop {timer_name}",
                        f"systemctl disable {timer_name}",
                        f"rm {unit_file}" if unit_file else "# Remove timer unit",
                        f"rm {associated_svc.get('unit_file', '')}" if associated_svc.get("unit_file") else "# Remove service unit",
                        "systemctl daemon-reload",
                    ]
                    evidences.append(self._create_evidence(
                        title=f"可疑 Systemd Timer: {timer_name}",
                        description=f"Timer 关联服务 {service_name} 包含可疑命令: {exec_start[:100]}",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        attack_id="T1053.005",
                        source_path=unit_file,
                        raw_data={"timer": timer_name, "service": service_name, "exec_start": exec_start},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break
            
            # Detect suspicious paths
            suspicious_paths = ["/tmp/", "/dev/shm/", "/."]
            if any(p in exec_start for p in suspicious_paths):
                # Extract context with line numbers
                matched_patterns, match_line, context_before, context_after = self._find_pattern_context(
                    exec_start, self.SUSPICIOUS_CRON_PATTERNS
                )
                
                evidence_detail = EvidenceDetail(
                    file_path=unit_file,
                    content=exec_start[:200] if len(exec_start) > 200 else exec_start,
                    service_type="systemd_timer",
                    line_number=match_line,
                    context_before=context_before,
                    context_after=context_after,
                )
                remediation_cmds = [
                    f"systemctl stop {timer_name}",
                    f"rm {unit_file}" if unit_file else "# Remove timer unit",
                    "systemctl daemon-reload",
                ]
                evidences.append(self._create_evidence(
                    title=f"可疑 Systemd Timer 路径: {timer_name}",
                    description=f"Timer 关联服务 {service_name} 引用可疑路径: {exec_start[:100]}",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    attack_id="T1053.005",
                    source_path=unit_file,
                    raw_data={"timer": timer_name, "service": service_name, "exec_start": exec_start},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
        
        return evidences
    
    def _detect_shell_injection(self, service_data: dict) -> List[Evidence]:
        """Detect shell configuration injection"""
        evidences = []
        
        # profile.d script detection
        for script in service_data.get("profile_d_scripts", []):
            preview = script.get("content_preview", "")
            if not preview:
                continue
            
            for pattern in self.SUSPICIOUS_CRON_PATTERNS:
                if pattern.search(preview):
                    # Extract context with line numbers
                    matched_patterns, match_line, context_before, context_after = self._find_pattern_context(
                        preview, self.SUSPICIOUS_CRON_PATTERNS
                    )
                    
                    evidence_detail = EvidenceDetail(
                        file_path=script.get("name", "unknown"),
                        content=preview[:200] if len(preview) > 200 else preview,
                        line_number=match_line,
                        context_before=context_before,
                        context_after=context_after,
                    )
                    remediation_cmds = [
                        f"cat {script.get('name', '')}" if script.get("name") else "# Review profile.d script",
                        f"rm {script.get('name', '')}" if script.get("name") else "# Remove suspicious script",
                        "source /etc/profile",
                    ]
                    evidences.append(self._create_evidence(
                        title=f"Shell配置注入: {script.get('name', 'unknown')}",
                        description=f"profile.d脚本包含可疑命令",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        attack_id="T1546.004",
                        source_path=script.get("name", "unknown"),
                        raw_data={"preview": preview[:100]},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
                    break
        
        return evidences
    
    def _detect_rclocal_backdoor(self, service_data: dict) -> List[Evidence]:
        """Detect rc.local backdoors"""
        evidences = []

        rc_local = service_data.get("rc_local", {})
        # Validate rc_local is a dict, not a list (schema compatibility)
        if not isinstance(rc_local, dict):
            return evidences
        if not rc_local.get("exists", False):
            return evidences
        
        content = rc_local.get("content", "")
        if not content:
            return evidences
        
        for pattern in self.SUSPICIOUS_CRON_PATTERNS:
            if pattern.search(content):
                # Extract context with line numbers
                matched_patterns, match_line, context_before, context_after = self._find_pattern_context(
                    content, self.SUSPICIOUS_CRON_PATTERNS
                )
                
                evidence_detail = EvidenceDetail(
                    file_path="/etc/rc.local",
                    content=content[:200] if len(content) > 200 else content,
                    line_number=match_line,
                    context_before=context_before,
                    context_after=context_after,
                )
                remediation_cmds = [
                    "cat /etc/rc.local",
                    "chmod -x /etc/rc.local",
                    "rm /etc/rc.local",
                ]
                evidences.append(self._create_evidence(
                    title="rc.local包含可疑命令",
                    description=f"rc.local包含可疑pattern: {pattern.pattern}",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    attack_id="T1037.004",
                    source_path="/etc/rc.local",
                    raw_data={"content": content[:100]},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
                break
        
        return evidences
    
    def _detect_ldpreload(self, service_data: dict) -> List[Evidence]:
        """Detect LD_PRELOAD hijacking"""
        evidences = []
        
        ld_preload = service_data.get("ld_so_preload", {})
        # Validate ld_preload is a dict, not a list (schema compatibility)
        if not isinstance(ld_preload, dict):
            return evidences
        if not ld_preload.get("exists", False):
            return evidences
        
        content = ld_preload.get("content", "")
        if not content:
            return evidences
        
        # Check if path is suspicious
        suspicious_paths = ["/tmp/", "/dev/shm/", "/."]
        is_suspicious = any(path in content for path in suspicious_paths)
        
        evidence_detail = EvidenceDetail(
            file_path="/etc/ld.so.preload",
            content=content,
        )
        remediation_cmds = [
            "cat /etc/ld.so.preload",
            "rm /etc/ld.so.preload",
            "ldconfig",
        ]
        
        evidences.append(self._create_evidence(
            title="LD_PRELOAD劫持检测",
            description=f"/etc/ld.so.preload存在且包含: {content[:100]}",
            severity=Severity.CRITICAL if is_suspicious else Severity.HIGH,
            confidence=0.9,
            attack_id="T1574.006",
            source_path="/etc/ld.so.preload",
            raw_data={"content": content},
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        ))
        
        return evidences

    def _detect_startup_persistence(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Detect T1547.001 - Linux auto-start persistence
        
        Detection locations:
        - ~/.bashrc, ~/.profile, /etc/bash.bashrc
        - /etc/profile.d/*.sh
        - ~/.config/autostart/*.desktop
        - XDG configuration directories
        
        ATT&CK: T1547.001 - Registry Run Keys / Startup Folder (Linux equivalent)
        """
        evidences = []
        
        # No filesystem data needed, directly scan system files
        
        # Startup files to detect
        startup_files = [
            ("/etc/bash.bashrc", "System-level bashrc"),
            ("/etc/profile", "System-level profile"),
        ]
        
        # Check system-level startup files
        for filepath, desc in startup_files:
            evidence = self._check_startup_file(filepath, desc)
            if evidence:
                evidences.append(evidence)
        
        # Check /etc/profile.d directory
        profile_d_dir = "/etc/profile.d"
        if os.path.isdir(profile_d_dir):
            try:
                for entry in os.scandir(profile_d_dir):
                    if entry.is_file() and entry.name.endswith(".sh"):
                        evidence = self._check_startup_file(entry.path, f"profile.d script: {entry.name}")
                        if evidence:
                            evidences.append(evidence)
            except OSError:
                pass
        
        # Check user-level startup files (from user collector data)
        try:
            user_data = self._get_data(collected_data, "user")
            if user_data is None:
                user_data = {}
            for user_info in user_data.get("users", []):
                home = user_info.get("home", "")
                username = user_info.get("username", "unknown")
                
                if not home:
                    continue
                
                user_startup_files = [
                    (os.path.join(home, ".bashrc"), f"{username}'s .bashrc"),
                    (os.path.join(home, ".profile"), f"{username}'s .profile"),
                    (os.path.join(home, ".bash_profile"), f"{username}'s .bash_profile"),
                ]
                
                for filepath, desc in user_startup_files:
                    evidence = self._check_startup_file(filepath, desc)
                    if evidence:
                        evidences.append(evidence)
                
                # Check XDG autostart directory
                xdg_autostart = os.path.join(home, ".config", "autostart")
                if os.path.isdir(xdg_autostart):
                    try:
                        for entry in os.scandir(xdg_autostart):
                            if entry.is_file() and entry.name.endswith(".desktop"):
                                evidence = self._check_desktop_file(entry.path, username)
                                if evidence:
                                    evidences.append(evidence)
                    except OSError:
                        pass
        except KeyError:
            # Skip user-level detection when user data unavailable
            pass
        
        return evidences
    
    def _check_startup_file(self, filepath: str, desc: str) -> Evidence:
        """Check if startup file contains suspicious commands"""
        if not os.path.isfile(filepath):
            return None
        
        try:
            with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                content = f.read(8192)  # Limit read size
        except OSError:
            return None
        
        # Check suspicious patterns
        for pattern in self.SUSPICIOUS_CRON_PATTERNS:
            if pattern.search(content):
                # Extract context with line numbers
                matched_patterns, match_line, context_before, context_after = self._find_pattern_context(
                    content, self.SUSPICIOUS_CRON_PATTERNS
                )
                
                evidence_detail = EvidenceDetail(
                    file_path=filepath,
                    content=content[:200] if len(content) > 200 else content,
                    line_number=match_line,
                    context_before=context_before,
                    context_after=context_after,
                )
                remediation_cmds = [
                    f"cat {filepath}",
                    f"vi {filepath}",
                ]
                return self._create_evidence(
                    title=f"T1547.001 - 自启动持久化：{desc}",
                    description=f"启动文件 {filepath} 包含可疑命令：{pattern.pattern}",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    attack_id="T1547.001",
                    source_path=filepath,
                    raw_data={"preview": content[:200]},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                )
        
        return None
    
    def _check_desktop_file(self, filepath: str, username: str) -> Evidence:
        """Check .desktop autostart files"""
        try:
            with open(filepath, 'r', errors='ignore', encoding='utf-8') as f:
                content = f.read(4096)
        except OSError:
            return None
        
        # Check Exec field
        exec_match = re.search(r'^Exec=(.+)$', content, re.MULTILINE)
        if not exec_match:
            return None
        
        exec_cmd = exec_match.group(1)
        
        # Check suspicious paths or commands
        suspicious_patterns = ["/tmp/", "/dev/shm/", "/.", "curl", "wget", "bash -c"]
        for pattern in suspicious_patterns:
            if pattern.lower() in exec_cmd.lower():
                evidence_detail = EvidenceDetail(
                    file_path=filepath,
                    content=exec_cmd,
                )
                remediation_cmds = [
                    f"cat {filepath}",
                    f"rm {filepath}",
                ]
                return self._create_evidence(
                    title=f"T1547.001 - XDG 自动启动异常：{username}",
                    description=f"用户 {username} 的自动启动文件 {filepath} 包含可疑 Exec 命令：{exec_cmd[:100]}",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    attack_id="T1547.001",
                    source_path=filepath,
                    raw_data={"exec": exec_cmd},
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                )
        
        return None

    def _check_path_modification(self, collected_data: Dict) -> List[Evidence]:
        """Detect PATH environment variable manipulation (AN0010)

        Checks for PATH modifications in system-wide and user-level configuration
        files that could be used for persistence or privilege escalation.

        MITRE ATT&CK: T1574.007 - PATH Modification
        Analytics: AN0010

        Args:
            collected_data: Collected data from collectors

        Returns:
            List of Evidence objects for suspicious PATH modifications
        """
        evidences = []

        # Check system-wide PATH configuration
        evidences.extend(self._check_system_path_modifications())

        # Check user-level PATH configuration
        evidences.extend(self._check_user_path_modifications(collected_data))

        return evidences

    def _check_system_path_modifications(self) -> List[Evidence]:
        """Check system-wide PATH configuration files for suspicious modifications."""
        evidences = []

        system_paths = self._get_system_config_paths()

        for config_file in system_paths:
            if not os.path.exists(config_file):
                continue

            content = self._read_file_safely(config_file)
            if not content:
                continue

            path_matches = re.findall(r'PATH\s*=\s*["\']?([^"\';\n]+)', content)
            for path_value in path_matches:
                evidences.extend(
                    self._check_path_value_for_suspicious_dirs(
                        path_value, config_file, "system", file_content=content
                    )
                )

        return evidences

    def _check_user_path_modifications(self, collected_data: Dict) -> List[Evidence]:
        """Check user-level PATH configuration files."""
        evidences = []

        user_homes = self._get_user_homes(collected_data)
        for home_dir in user_homes:
            user_configs = self._get_user_config_paths(home_dir)

            for config_file in user_configs:
                if not os.path.exists(config_file):
                    continue

                content = self._read_file_safely(config_file)
                if not content:
                    continue

                # Check for command substitution in PATH (highly suspicious)
                if self._has_path_command_substitution(content):
                    evidence = self._create_path_substitution_evidence(
                        content, config_file, home_dir
                    )
                    if evidence:
                        evidences.append(evidence)

                # Check for suspicious directories in user PATH
                path_matches = re.findall(r'PATH\s*=\s*["\']?([^"\';\n]+)', content)
                for path_value in path_matches:
                    evidences.extend(
                        self._check_path_value_for_suspicious_dirs(
                            path_value, config_file, "user", home_dir, file_content=content
                        )
                    )

        return evidences

    def _get_system_config_paths(self) -> List[str]:
        """Get list of system-wide PATH configuration file paths."""
        system_paths = [
            '/etc/environment',
            '/etc/profile',
            '/etc/bash.bashrc',
        ]

        # Add /etc/profile.d/*.sh files
        profile_d_dir = '/etc/profile.d'
        if os.path.isdir(profile_d_dir):
            try:
                for entry in os.scandir(profile_d_dir):
                    if entry.is_file() and entry.name.endswith('.sh'):
                        system_paths.append(entry.path)
            except OSError:
                pass

        return system_paths

    def _get_user_config_paths(self, home_dir: str) -> List[str]:
        """Get list of user-level PATH configuration file paths."""
        return [
            os.path.join(home_dir, '.bashrc'),
            os.path.join(home_dir, '.profile'),
            os.path.join(home_dir, '.bash_profile'),
            os.path.join(home_dir, '.zshrc'),
        ]

    def _read_file_safely(self, filepath: str) -> Optional[str]:
        """Read file content with error handling."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except OSError:
            return None

    def _has_path_command_substitution(self, content: str) -> bool:
        """Check if content has command substitution in PATH definition."""
        return bool(re.search(r'export\s+PATH=.*[\$\(].*[\)]', content))

    def _find_path_line_context(
        self, content: str, search_text: str, context_lines: int = 3
    ) -> tuple:
        """Find line number and context for PATH definition."""
        path_lines = content.split('\n')
        for i, line in enumerate(path_lines, 1):
            if search_text in line:
                return (
                    i,
                    path_lines[max(0, i - 1 - context_lines):i - 1],
                    path_lines[i:min(len(path_lines), i + context_lines)],
                )
        return None, [], []

    def _check_path_value_for_suspicious_dirs(
        self,
        path_value: str,
        config_file: str,
        file_type: str,
        home_dir: str = None,
        file_content: str = None
    ) -> List[Evidence]:
        """Check if PATH value contains suspicious directories."""
        evidences = []
        suspicious_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/home/']

        for susp_dir in suspicious_dirs:
            if susp_dir in path_value:
                # Use provided content or read file
                content = file_content
                if not content:
                    content = self._read_file_safely(config_file) or ""

                path_line_num, context_before, context_after = self._find_path_line_context(
                    content, susp_dir
                )

                evidence_detail = EvidenceDetail(
                    file_path=config_file,
                    content=path_value,
                    line_number=path_line_num,
                    context_before=context_before,
                    context_after=context_after,
                )
                remediation_cmds = [
                    f"cat {config_file}",
                    f"vi {config_file}",
                ]

                raw_data = {
                    "path_value": path_value,
                    "suspicious_dir": susp_dir,
                    "file_type": file_type
                }
                if home_dir:
                    raw_data["home_dir"] = home_dir

                title = (
                    f"System-Wide PATH Modification: {config_file}"
                    if file_type == "system"
                    else f"User PATH Modification: {config_file}"
                )
                description = (
                    f"PATH includes suspicious directory '{susp_dir}' "
                    f"in system configuration file {config_file}. "
                    f"This could be used for persistence via PATH hijacking."
                    if file_type == "system"
                    else f"User PATH includes suspicious directory "
                    f"'{susp_dir}' in {config_file}."
                )
                severity = Severity.HIGH if file_type == "system" else Severity.MEDIUM
                confidence = 0.7 if file_type == "system" else 0.6

                evidences.append(self._create_evidence(
                    title=title,
                    description=description,
                    severity=severity,
                    confidence=confidence,
                    attack_id="T1574.007",
                    source_path=config_file,
                    raw_data=raw_data,
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))

        return evidences

    def _create_path_substitution_evidence(
        self, content: str, config_file: str, home_dir: str
    ) -> Optional[Evidence]:
        """Create evidence for PATH with command substitution."""
        path_line_num, context_before, context_after = self._find_path_line_context(
            content, 'export PATH='
        )

        evidence_detail = EvidenceDetail(
            file_path=config_file,
            line_number=path_line_num,
            context_before=context_before,
            context_after=context_after,
        )
        remediation_cmds = [
            f"cat {config_file}",
            f"vi {config_file}",
        ]

        return self._create_evidence(
            title=f"User PATH with Command Substitution: {config_file}",
            description=(
                f"PATH definition includes command substitution in "
                f"{config_file}. This allows dynamic PATH manipulation "
                f"and could be used for persistence."
            ),
            severity=Severity.MEDIUM,
            confidence=0.6,
            attack_id="T1574.007",
            source_path=config_file,
            raw_data={
                "file": config_file,
                "file_type": "user",
                "home_dir": home_dir
            },
            evidence_details=evidence_detail,
            remediation_commands=remediation_cmds,
        )
    
    def _get_user_homes(self, collected_data: Dict) -> List[str]:
        """Get list of user home directories
        
        Args:
            collected_data: Collected data with user information
            
        Returns:
            List of user home directory paths
        """
        homes = []
        
        # Try to get from user collector first
        try:
            user_data = self._get_data(collected_data, "user")
            if user_data is None:
                user_data = {}
            for user_info in user_data.get("users", []):
                home = user_info.get("home", "")
                uid = user_info.get("uid", -1)
                
                # Include regular users (UID >= 1000) and root
                if home and (uid >= 1000 or uid == 0):
                    homes.append(home)
        except KeyError:
            pass
        
        # Fallback to parsing /etc/passwd
        if not homes:
            try:
                with open('/etc/passwd', 'r', encoding='utf-8') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 6:
                            uid = int(parts[2])
                            # Regular users (UID >= 1000) and root (UID 0)
                            if uid >= 1000 or uid == 0:
                                homes.append(parts[5])
            except OSError:
                pass
        
        return homes
    
    def _validate_service_cwd(self, collected_data: Dict) -> List[Evidence]:
        """Validate cwd of persistent services
        
        Check if services started by cron/systemd have appropriate cwd:
        - System services should have cwd in system directories
        - Service cwd in /tmp or /dev/shm is suspicious
        - User service cwd in unexpected locations may indicate compromise
        
        Args:
            collected_data: Collected data with process information
            
        Returns:
            List of Evidence objects for suspicious service cwd
        """
        evidences = []
        
        # Get process data
        process_data = self._get_data(collected_data, "process")
        if not process_data:
            return evidences
        
        processes = process_data.get("processes", [])
        
        # Get service names from systemd and cron data
        known_services = set()
        
        service_data = self._get_data(collected_data, "service")
        if service_data:
            # Add systemd service names
            for svc in service_data.get("systemd_services", []):
                name = svc.get("name", "")
                if name:
                    # Remove .service suffix for matching
                    known_services.add(name.replace(".service", ""))
            
            # Add cron jobs as known scheduled tasks
            for entry in service_data.get("cron_d_entries", []):
                cmd = entry.get("command", "")
                if cmd:
                    # Extract command name
                    parts = cmd.split()
                    if parts:
                        known_services.add(parts[0].split("/")[-1])
        
        # Check each process
        for proc in processes:
            comm = proc.get("comm", "")
            cwd = proc.get("cwd", "")
            pid = proc.get("pid", 0)
            exe = proc.get("exe", "")
            
            if not cwd or not comm:
                continue
            
            # FP FIX: Skip system core services - they always have cwd = '/'
            if comm.lower() in self.SYSTEM_CORE_SERVICES:
                if cwd == '/':
                    continue  # Root directory is normal for system core services
            
            # FP FIX: Skip container runtime processes - their CWD is typically in /run/containerd/
            if any(container_bin in comm.lower() for container_bin in self.CONTAINER_RUNTIME_WHITELIST):
                _get_logger().debug(
                    f"[{self.name}] Skipping container runtime process CWD check: "
                    f"{comm} (PID: {pid})"
                )
                continue
            
            # Check if this is a known service
            is_known_service = any(
                svc.lower() in comm.lower() for svc in known_services
            )
            
            if not is_known_service:
                continue
            
            # Check if cwd is in risky location
            is_risky_cwd = any(cwd.startswith(risky) for risky in self.RISKY_CWD_FOR_SERVICES)
            
            if is_risky_cwd:
                evidence_detail = EvidenceDetail(
                    pid=pid,
                    cmdline=comm,
                    executable=exe,
                    content=f"cwd={cwd}",
                )
                remediation_cmds = [
                    f"ls -la /proc/{pid}/cwd",
                    f"ps aux | grep {pid}",
                    f"cat /proc/{pid}/cmdline",
                ]
                evidences.append(self._create_evidence(
                    title=f"Persistent service with suspicious cwd: {comm}",
                    description=f"Service {comm} (PID {pid}) working directory in risky location: {cwd}",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    attack_id="T1543.002",
                    source_path=f"/proc/{pid}/cwd",
                    raw_data={
                        "pid": pid,
                        "comm": comm,
                        "cwd": cwd,
                        "exe": exe,
                        "known_services": list(known_services)[:10]
                    },
                    evidence_details=evidence_detail,
                    remediation_commands=remediation_cmds,
                ))
            
            # Check if cwd matches expected pattern for known services
            for svc_name, expected_prefixes in self.EXPECTED_CWD_FOR_SERVICES.items():
                if svc_name.lower() in comm.lower():
                    has_expected_cwd = any(cwd.startswith(prefix) for prefix in expected_prefixes)
                    
                    if not has_expected_cwd and not is_risky_cwd:
                        # CWD is not in expected location but also not risky
                        # Lower severity, just for awareness
                        evidence_detail = EvidenceDetail(
                            pid=pid,
                            cmdline=comm,
                            content=f"cwd={cwd}, expected={expected_prefixes}",
                        )
                        remediation_cmds = [
                            f"ls -la /proc/{pid}/cwd",
                            f"ps aux | grep {comm}",
                        ]
                        evidences.append(self._create_evidence(
                            title=f"Service cwd mismatch: {comm}",
                            description=f"Service {comm} (PID {pid}) cwd {cwd} doesn't match expected prefixes: {expected_prefixes}",
                            severity=Severity.LOW,
                            confidence=0.5,
                            attack_id="T1543.002",
                            source_path=f"/proc/{pid}/cwd",
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "cwd": cwd,
                                "expected_prefixes": expected_prefixes
                            },
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))
                    break
        
        return evidences
    def _check_socket_activation_backdoors(self, service_data: dict) -> List[Evidence]:
        """Detect socket activation backdoors (T1543.002, T1571)"""
        evidences = []
        
        if not service_data:
            return evidences
        
        socket_units = service_data.get("systemd_socket_units", [])
        if not socket_units:
            return evidences
        
        services_by_name = {}
        for svc in service_data.get("systemd_services", []):
            services_by_name[svc.get("name", "")] = svc
        
        legitimate_sockets = {
            "dbus.socket", "sshd.socket", "systemd-journald.socket",
            "systemd-udevd-control.socket", "systemd-rfkill.socket",
        }
        
        for socket_unit in socket_units:
            socket_name = socket_unit.get("name", "")
            listen_stream = socket_unit.get("listen_stream", "")
            unit_file = socket_unit.get("unit_file", "")
            service_name = socket_unit.get("service", "").replace(".socket", ".service")
            
            if not socket_name:
                continue
            
            if socket_name in legitimate_sockets:
                continue
            
            if listen_stream:
                suspicious_port_patterns = [
                    re.compile(r':(4444|5555|6666|7777|8888|9999|1337|31337)$'),
                ]
                for pattern in suspicious_port_patterns:
                    if pattern.search(str(listen_stream)):
                        evidence_detail = EvidenceDetail(
                            file_path=unit_file,
                            content=f"ListenStream={listen_stream}",
                            service_type="systemd_socket",
                        )
                        remediation_cmds = [
                            f"systemctl stop {socket_name}",
                            f"systemctl disable {socket_name}",
                            f"rm {unit_file}" if unit_file else "# Remove socket unit",
                            "systemctl daemon-reload",
                        ]
                        evidences.append(self._create_evidence(
                            title=f"可疑 Socket Activation: {socket_name}",
                            description=f"Socket {socket_name} 监听可疑端口 {listen_stream}",
                            severity=Severity.HIGH,
                            confidence=0.75,
                            attack_id="T1571",
                            source_path=unit_file,
                            raw_data={"socket": socket_name, "listen_stream": listen_stream, "service": service_name},
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))
                        break
            
            associated_svc = services_by_name.get(service_name)
            if associated_svc:
                exec_start = associated_svc.get("exec_start", "")
                if exec_start:
                    suspicious_indicators = ["/tmp/", "/dev/shm/", "/.", "curl", "wget", "bash -c", "python -c"]
                    for indicator in suspicious_indicators:
                        if indicator.lower() in exec_start.lower():
                            evidence_detail = EvidenceDetail(
                                file_path=unit_file,
                                content=exec_start[:200] if len(exec_start) > 200 else exec_start,
                                service_type="systemd_socket",
                            )
                            remediation_cmds = [
                                f"systemctl stop {service_name}" if service_name else "# Stop associated service",
                                f"rm {unit_file}" if unit_file else "# Remove socket unit",
                                "systemctl daemon-reload",
                            ]
                            evidences.append(self._create_evidence(
                                title=f"Socket Activation 后门: {socket_name}",
                                description=f"Socket {socket_name} 关联服务 {service_name} 包含可疑命令: {exec_start[:100]}",
                                severity=Severity.CRITICAL,
                                confidence=0.85,
                                attack_id="T1543.002",
                                source_path=unit_file,
                                raw_data={"socket": socket_name, "service": service_name, "exec_start": exec_start},
                                evidence_details=evidence_detail,
                                remediation_commands=remediation_cmds,
                            ))
                            break
            
            if unit_file:
                suspicious_locations = ["/tmp/", "/dev/shm/", "/var/tmp/", "/home/"]
                if any(loc in unit_file for loc in suspicious_locations):
                    evidence_detail = EvidenceDetail(
                        file_path=unit_file,
                        service_type="systemd_socket",
                    )
                    remediation_cmds = [
                        f"rm {unit_file}" if unit_file else "# Remove suspicious unit file",
                        "systemctl daemon-reload",
                    ]
                    evidences.append(self._create_evidence(
                        title=f"可疑 Socket 单元位置: {socket_name}",
                        description=f"Socket 单元文件位于可疑位置: {unit_file}",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        attack_id="T1543.002",
                        source_path=unit_file,
                        raw_data={"socket": socket_name, "unit_file": unit_file},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
        
        return evidences
    
    def _check_path_activated_services(self, service_data: dict) -> List[Evidence]:
        """Detect path-activated suspicious services (T1543.002)"""
        evidences = []
        
        if not service_data:
            return evidences
        
        path_activated = service_data.get("systemd_path_activated", [])
        if not path_activated:
            return evidences
        
        suspicious_path_patterns = [
            re.compile(r'/tmp/', re.IGNORECASE),
            re.compile(r'/dev/shm/', re.IGNORECASE),
            re.compile(r'/var/tmp/', re.IGNORECASE),
        ]
        
        for path_svc in path_activated:
            service_name = path_svc.get("name", "")
            paths = path_svc.get("paths", [])
            exec_start = path_svc.get("exec_start", "")
            unit_file = path_svc.get("unit_file", "")
            
            if not service_name or not paths:
                continue
            
            for path in paths:
                for pattern in suspicious_path_patterns:
                    if pattern.search(path):
                        evidence_detail = EvidenceDetail(
                            file_path=unit_file,
                            content=f"Paths={', '.join(paths)}",
                            service_type="systemd_path_activated",
                        )
                        remediation_cmds = [
                            f"systemctl stop {service_name}" if service_name else "# Stop service",
                            f"rm {unit_file}" if unit_file else "# Remove unit file",
                            "systemctl daemon-reload",
                        ]
                        evidences.append(self._create_evidence(
                            title=f"可疑 Path-Activated 服务: {service_name}",
                            description=f"服务 {service_name} 监控可疑路径 {path}",
                            severity=Severity.HIGH,
                            confidence=0.75,
                            attack_id="T1543.002",
                            source_path=unit_file,
                            raw_data={"service": service_name, "monitored_paths": paths, "exec_start": exec_start[:200]},
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))
                        break
            
            if exec_start:
                for pattern in self.SUSPICIOUS_CRON_PATTERNS:
                    if pattern.search(exec_start):
                        evidence_detail = EvidenceDetail(
                            file_path=unit_file,
                            content=exec_start[:200] if len(exec_start) > 200 else exec_start,
                            service_type="systemd_path_activated",
                        )
                        remediation_cmds = [
                            f"systemctl stop {service_name}" if service_name else "# Stop service",
                            f"rm {unit_file}" if unit_file else "# Remove unit file",
                            "systemctl daemon-reload",
                        ]
                        evidences.append(self._create_evidence(
                            title=f"Path-Activated 服务可疑命令: {service_name}",
                            description=f"服务 {service_name} 包含可疑命令: {exec_start[:100]}",
                            severity=Severity.HIGH,
                            confidence=0.8,
                            attack_id="T1543.002",
                            source_path=unit_file,
                            raw_data={"service": service_name, "exec_start": exec_start},
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))
                        break
        
        return evidences
    
    def _check_systemd_dropin_overrides(self, service_data: dict) -> List[Evidence]:
        """Detect systemd drop-in override tampering (T1543.002)"""
        evidences = []
        
        if not service_data:
            return evidences
        
        dropin_files = service_data.get("systemd_dropin_overrides", [])
        if not dropin_files:
            return evidences
        
        for dropin in dropin_files:
            dropin_path = dropin.get("path", "")
            service_name = dropin.get("service", "")
            content = dropin.get("content", "")
            
            if not dropin_path or not content:
                continue
            
            exec_patterns = [
                (re.compile(r'ExecStart\s*=\s*(.*)', re.MULTILINE), "ExecStart override"),
                (re.compile(r'ExecStartPre\s*=\s*(.*)', re.MULTILINE), "ExecStartPre addition"),
                (re.compile(r'ExecStartPost\s*=\s*(.*)', re.MULTILINE), "ExecStartPost addition"),
            ]
            
            for pattern, desc in exec_patterns:
                match = pattern.search(content)
                if match:
                    exec_cmd = match.group(1).strip()
                    
                    suspicious_indicators = [
                        "/tmp/", "/dev/shm/", "/var/tmp/",
                        "curl ", "wget ", "bash -c", "sh -c",
                        "python ", "perl ", "/dev/tcp/", "base64"
                    ]
                    
                    is_suspicious = any(indicator.lower() in exec_cmd.lower() 
                                       for indicator in suspicious_indicators)
                    
                    if is_suspicious:
                        evidence_detail = EvidenceDetail(
                            file_path=dropin_path,
                            content=exec_cmd[:200] if len(exec_cmd) > 200 else exec_cmd,
                            service_type="systemd_dropin",
                        )
                        remediation_cmds = [
                            f"rm {dropin_path}" if dropin_path else "# Remove drop-in file",
                            f"systemctl stop {service_name}" if service_name else "# Stop service",
                            "systemctl daemon-reload",
                        ]
                        evidences.append(self._create_evidence(
                            title=f"Systemd Drop-In 篡改: {service_name}",
                            description=f"Drop-in 文件 {dropin_path} {desc} 包含可疑命令: {exec_cmd[:100]}",
                            severity=Severity.CRITICAL,
                            confidence=0.85,
                            attack_id="T1543.002",
                            source_path=dropin_path,
                            raw_data={"service": service_name, "dropin_path": dropin_path, "override_type": desc, "command": exec_cmd},
                            evidence_details=evidence_detail,
                            remediation_commands=remediation_cmds,
                        ))
            
            security_settings = ["SELinuxContext", "AppArmorProfile", "ProtectSystem", "ProtectHome", "NoNewPrivileges", "PrivateTmp"]
            for setting in security_settings:
                if re.search(rf'{setting}\s*=\s*false', content, re.IGNORECASE):
                    evidence_detail = EvidenceDetail(
                        file_path=dropin_path,
                        content=f"{setting}=false",
                        service_type="systemd_dropin",
                    )
                    remediation_cmds = [
                        f"rm {dropin_path}" if dropin_path else "# Remove drop-in file",
                        f"systemctl stop {service_name}" if service_name else "# Stop service",
                        "systemctl daemon-reload",
                    ]
                    evidences.append(self._create_evidence(
                        title=f"Systemd Drop-In 安全设置篡改: {service_name}",
                        description=f"Drop-in 文件 {dropin_path} 禁用了安全设置 {setting}",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        attack_id="T1543.002",
                        source_path=dropin_path,
                        raw_data={"service": service_name, "dropin_path": dropin_path, "security_setting": setting},
                        evidence_details=evidence_detail,
                        remediation_commands=remediation_cmds,
                    ))
        
        return evidences
