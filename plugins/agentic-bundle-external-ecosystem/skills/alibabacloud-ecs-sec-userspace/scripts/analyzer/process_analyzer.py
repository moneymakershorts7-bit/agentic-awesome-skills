"""Process anomaly detection analyzer."""
import re
import os
import threading
from typing import List, Dict, Optional, TYPE_CHECKING, Set

if TYPE_CHECKING:
    from ..reporter.evidence import Evidence

# Import BaseAnalyzer early (lightweight at 75ms)
from .base import BaseAnalyzer

_import_cache = {}
_import_cache_lock = threading.Lock()

def _get_logger():
    if 'logger' not in _import_cache:
        with _import_cache_lock:
            if 'logger' not in _import_cache:
                import logging
                _import_cache['logger'] = logging.getLogger("sec-userspace")
    return _import_cache['logger']


def _get_evidence_classes():
    if 'evidence' not in _import_cache:
        with _import_cache_lock:
            if 'evidence' not in _import_cache:
                from ..reporter.evidence import Evidence, EvidenceDetail
                _import_cache['evidence'] = Evidence
                _import_cache['evidence_detail'] = EvidenceDetail
    return _import_cache['evidence'], _import_cache['evidence_detail']


def _get_severity():
    if 'severity' not in _import_cache:
        with _import_cache_lock:
            if 'severity' not in _import_cache:
                from ..reporter.severity import Severity
                _import_cache['severity'] = Severity
    return _import_cache['severity']


def _get_time_module():
    if 'time' not in _import_cache:
        with _import_cache_lock:
            if 'time' not in _import_cache:
                import time
                _import_cache['time'] = time
    return _import_cache['time']


def _get_datetime_classes():
    if 'datetime' not in _import_cache:
        with _import_cache_lock:
            if 'datetime' not in _import_cache:
                from datetime import datetime, timedelta, timezone
                _import_cache['datetime'] = datetime
                _import_cache['timedelta'] = timedelta
                _import_cache['timezone'] = timezone
    return _import_cache


def _get_subprocess_module():
    if 'subprocess' not in _import_cache:
        with _import_cache_lock:
            if 'subprocess' not in _import_cache:
                import subprocess
                _import_cache['subprocess'] = subprocess
    return _import_cache['subprocess']


_fp_tracker_cache = {}
_fp_tracker_cache_lock = threading.Lock()

def _get_attack_tactic_name():
    """Lazy import i18n get_attack_tactic_name to reduce import time."""
    if 'gatn' not in _fp_tracker_cache:
        with _fp_tracker_cache_lock:
            if 'gatn' not in _fp_tracker_cache:
                from ..utils.i18n import get_attack_tactic_name as _gatn
                _fp_tracker_cache['gatn'] = _gatn
    return _fp_tracker_cache['gatn']

def _get_tracker():
    """Lazy import get_tracker from fp_tracker."""
    if 'get_tracker' not in _fp_tracker_cache:
        with _fp_tracker_cache_lock:
            if 'get_tracker' not in _fp_tracker_cache:
                from ..utils.fp_tracker import get_tracker as _gt
                _fp_tracker_cache['get_tracker'] = _gt
    return _fp_tracker_cache['get_tracker']

def is_false_positive(analyzer: str, evidence_type: str, **kwargs) -> bool:
    """Lazy import is_false_positive from fp_tracker."""
    if 'is_false_positive' not in _fp_tracker_cache:
        with _fp_tracker_cache_lock:
            if 'is_false_positive' not in _fp_tracker_cache:
                from ..utils.fp_tracker import is_false_positive as _ifp
                _fp_tracker_cache['is_false_positive'] = _ifp
    return _fp_tracker_cache['is_false_positive'](analyzer, evidence_type, **kwargs)

def record_fp(analyzer: str, evidence_type: str, **kwargs):
    """Lazy import record_fp from fp_tracker."""
    if 'record_fp' not in _fp_tracker_cache:
        with _fp_tracker_cache_lock:
            if 'record_fp' not in _fp_tracker_cache:
                from ..utils.fp_tracker import record_fp as _rfp
                _fp_tracker_cache['record_fp'] = _rfp
    return _fp_tracker_cache['record_fp'](analyzer, evidence_type, **kwargs)

def _get_cloud_detector():
    """Lazy import cloud_env_detector module to reduce import time."""
    if 'get_cloud_detector' not in _fp_tracker_cache:
        with _fp_tracker_cache_lock:
            if 'get_cloud_detector' not in _fp_tracker_cache:
                from ..utils.cloud_env_detector import get_cloud_detector as _gcd
                _fp_tracker_cache['get_cloud_detector'] = _gcd
    return _fp_tracker_cache['get_cloud_detector']

class ProcessAnalyzer(BaseAnalyzer):
    """Process Anomaly Detection Analyzer"""
    name = "process_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 30)

    required_collectors = ["process"]

    # Smart scheduling attributes
    estimated_time = 2.0  # Fast /proc data read
    analyzer_type = BaseAnalyzer.CRITICAL  # Critical security check

    # Pre-compiled regex patterns
    SUSPICIOUS_NAME_PATTERNS = [
        re.compile(r"^\..*"),  # Hidden processes starting with .
        re.compile(r"(kworker|kthread|migration|ksoftirq).*"),  # Disguised as kernel threads
    ]

    # PowerShell detection pattern (T1059.001)
    POWERSHELL_PATTERNS = [
        (re.compile(r'powershell', re.IGNORECASE), "PowerShell process"),
        (re.compile(r'pwsh', re.IGNORECASE), "PowerShell Core process"),
        (re.compile(r'-EncodedCommand', re.IGNORECASE), "Base64 encoded command execution"),
        (re.compile(r'-enc\s+', re.IGNORECASE), "Base64 encoded command abbreviation"),
        (re.compile(r'-ExecutionPolicy\s+Bypass', re.IGNORECASE), "Bypass execution policy"),
        (re.compile(r'-ep\s+bypass', re.IGNORECASE), "Bypass execution policy abbreviation"),
        (re.compile(r'-windowstyle\s+hidden', re.IGNORECASE), "Run with hidden window"),
        (re.compile(r'-nop\s+', re.IGNORECASE), "NoProfile parameter"),
        (re.compile(r'-noprofile\s+', re.IGNORECASE), "Do not load profile"),
    ]

    # Common short process name whitelist (not flagged as suspicious)
    SHORT_NAME_WHITELIST = {"sh", "bash", "zsh", "ash", "dash", "fish", "csh", "tcsh",
                            "py", "python", "python3", "node", "npm", "java", "go",
                            "vim", "vi", "nano", "ls", "ps", "grep", "find", "cat",
                            "cp", "mv", "rm", "mkdir", "chmod", "chown", "tar", "gzip"}

    SHELL_NAMES = {"bash", "sh", "zsh", "ash", "dash", "fish", "csh", "tcsh"}

    # Legitimate shell path prefixes (standard system directories)
    LEGITIMATE_SHELL_PATHS = {"/bin/", "/usr/bin/", "/usr/local/bin/", "/sbin/", "/usr/sbin/"}

    # T1105 file download command detection patterns
    DOWNLOAD_COMMANDS = ['wget', 'curl', 'certutil', 'bitsadmin', 'fetch', 'lynx', 'httpie']
    
    # Suspicious download paths
    @property
    def SUSPICIOUS_DOWNLOAD_PATHS(self):
        cfg = self._get_config("suspicious_download_paths")
        if cfg:
            return cfg
        return ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/', '/.hidden']
    
    # Legitimate download sources (whitelist)
    LEGITIMATE_DOWNLOAD_SOURCES = [
        'github.com', 'raw.githubusercontent.com', 'gitlab.com',
        'npmjs.com', 'pypi.org', 'files.pythonhosted.org',
        'nodejs.org', 'rust-lang.org', 'golang.org',
        'amazonaws.com', 'azure.com', 'microsoft.com',
        'ubuntu.com', 'debian.org', 'centos.org',
    ]
    
    # Installation script patterns (benign)
    INSTALL_SCRIPT_PATTERNS = [
        re.compile(r'(install|setup|init|bootstrap)\.sh', re.IGNORECASE),
        re.compile(r'#.*installation\s+script', re.IGNORECASE),
        re.compile(r'mkdir\s+-p\s+"\$\{?[^}]*\}?/bin"', re.IGNORECASE),  # Creating bin directory
    ]
    
    # Suspicious URL patterns (IP addresses, short links, suspicious TLDs)
    SUSPICIOUS_URL_PATTERNS = [
        re.compile(r'\d+\.\d+\.\d+\.\d+'),  # IP address
        re.compile(r'bit\.ly|t\.co|goo\.gl|tinyurl\.com', re.IGNORECASE),  # Short links
        re.compile(r'\.(xyz|top|club|work|loan|cf|gq|ml|ga|tk)/', re.IGNORECASE),  # Suspicious TLDs
    ]
    
    # T1570 lateral movement command patterns
    LATERAL_MOVEMENT_COMMANDS = {
        'scp': re.compile(r'scp\s+.+?(?:\d+\.\d+\.\d+\.\d+|[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+\.)'),
        'rsync': re.compile(r'rsync\s+.+?(?:\d+\.\d+\.\d+\.\d+|:.*@)'),
        'ssh': re.compile(r'ssh\s+(?:.*-o.*StrictHostKeyChecking=no)?(?:root@admin@\d+\.\d+\.\d+\.\d+|admin@\d+\.\d+\.\d+\.\d+)'),
        'sftp': re.compile(r'sftp\s+.*@\d+\.\d+\.\d+\.\d+'),
    }
    
    # Internal IP range regex
    INTERNAL_IP_PATTERN = re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')

    # T1204.002 - Malicious Script Execution patterns (curl|bash anti-patterns)
    CURL_PIPE_BASH_PATTERNS = [
        (re.compile(r'curl\s+\S+\s*\|\s*(sudo\s+)?(ba)?sh'), "curl piped to shell execution"),
        (re.compile(r'wget\s+-qO-\s+\S+\s*\|\s*(sudo\s+)?(ba)?sh'), "wget piped to shell execution"),
        (re.compile(r'curl\s+-fs?SL?\s+\S+\s*\|\s*(sudo\s+)?(ba)?sh'), "curl with flags piped to shell"),
        (re.compile(r'wget\s+-O-\s+\S+\s*\|\s*(sudo\s+)?(ba)?sh'), "wget output to stdout piped to shell"),
        (re.compile(r'curl\s+\S+\s*\|\s*python3?\b'), "curl piped to Python execution"),
        (re.compile(r'wget\s+\S+\s*\|\s*python3?\b'), "wget piped to Python execution"),
    ]
    
    # Suspicious script download and execute patterns
    DOWNLOAD_EXECUTE_PATTERNS = [
        (re.compile(r'(curl|wget)\s+\S+.*&&\s*(chmod\s+\+x\s+)?.*/tmp/\S+'), "Download to /tmp and execute"),
        (re.compile(r'(curl|wget)\s+\S+.*&&\s*/dev/shm/\S+'), "Download to /dev/shm and execute"),
        (re.compile(r'mktemp\s+.*&&\s*(curl|wget)\s+\S+.*\|\s*(ba)?sh'), "Temp file creation then download and execute"),
    ]
    
    # File extension mismatch patterns
    EXTENSION_MISMATCH_PATTERNS = [
        (re.compile(r'\.txt$', re.IGNORECASE), "text/plain", "File with .txt extension but executable content"),
        (re.compile(r'\.log$', re.IGNORECASE), "text/plain", "File with .log extension but executable content"),
        (re.compile(r'\.pdf$', re.IGNORECASE), "application/pdf", "File with .pdf extension but executable content"),
    ]

    # Risky cwd patterns (often used by malware or attackers)
    @property
    def RISKY_CWD_PATTERNS(self):
        cfg_paths = self._get_config("risky_paths")
        if cfg_paths:
            return [(p, 'Temporary/risky directory') for p in cfg_paths]
        # Fallback to code defaults
        return [
            ('/tmp/', 'Temporary directory - often used by malware'),
            ('/dev/shm/', 'Shared memory - used by fileless malware'),
            ('/var/tmp/', 'Persistent temporary directory'),
            ('/run/', 'Runtime directory'),
        ]
    
    # Pre-computed sensitive directory prefixes for faster matching
    SENSITIVE_DIRS = ('/etc/ssh/', '/root/.ssh/', '/etc/sudoers.d/')
    SENSITIVE_DIR_CHECK = ('/etc/', '/root/', '/sys/', '/proc/')

    # AI tool temporary execution paths (benign)
    @property
    def AI_TOOL_TEMP_PATHS(self):
        cfg = self._get_config("ai_tool_temp_paths")
        if cfg:
            return cfg
        return [
            '/tmp/.claude-code-',
            '/tmp/.qoder-',
            '/tmp/.cursor-',
            '/tmp/qoder-',
            '/tmp/claude-',
            '/tmp/cursor-',
            '/tmp/npx-cache-',
            '/tmp/npm-cache-',
            '/tmp/yarn--',
        ]

    # Pre-compiled AI tool cmdline regex patterns
    AI_TOOL_CMDLINE_PATTERNS = [
        re.compile(r'.*(claude|qoder|cursor|copilot|anthropic).*', re.IGNORECASE),
        re.compile(r'^npx\s+(claude|qoder|cursor|anthropic|@anthropic-ai).*', re.IGNORECASE),
        re.compile(r'^node\s+.*(claude|qoder|cursor|copilot|anthropic).*', re.IGNORECASE),
    ]

    # Safe cwd patterns (legitimate business directories)
    SAFE_CWD_PATTERNS = [
        '/usr/',
        '/opt/',
        '/home/',
        '/workspace/',
        '/data/',
        '/var/www/',
        '/var/log/',
        '/etc/',
        '/',  # Root directory is safe for system services
    ]
    
    # System core processes that typically have cwd = '/' (skip CWD mismatch detection)
    SYSTEM_CORE_PROCESSES = {
        'systemd', 'systemd-udevd', 'systemd-logind', 'systemd-journald', 'systemd-journal',
        'systemd-resolved', 'systemd-networkd', 'init', 'dockerd', 'containerd',
        'rpcbind', 'dbus-daemon', 'sshd', 'cron', 'crond', 'rsyslogd',
    }

    _cloud_detector = None
    _cloud_detector_lock = threading.Lock()
    _class_package_cache = {}
    _class_package_cache_lock = threading.Lock()

    def _get_cloud_detector(self):
        """Get cloud detector singleton using lazy import."""
        if self._cloud_detector is None:
            with self._cloud_detector_lock:
                if self._cloud_detector is None:
                    detector_factory = _get_cloud_detector()
                    ProcessAnalyzer._cloud_detector = detector_factory()
        return self._cloud_detector
    
    def _calc_start_time(self, runtime_seconds: Optional[float], pid: Optional[int] = None) -> Optional[str]:
        """Calculate process start time from runtime_seconds with caching and validation.

        Args:
            runtime_seconds: Seconds since process started
            pid: Optional process ID for caching

        Returns:
            ISO 8601 formatted start time string, or None if runtime_seconds is invalid
        """
        if runtime_seconds is None or runtime_seconds <= 0:
            return None

        # Check cache first
        if pid is not None and pid in self._start_time_cache:
            return self._start_time_cache[pid]

        dt_classes = _get_datetime_classes()
        datetime_cls = dt_classes['datetime']
        timedelta_cls = dt_classes['timedelta']
        timezone_cls = dt_classes['timezone']

        now = datetime_cls.now(timezone_cls.utc)
        start_dt = now - timedelta_cls(seconds=runtime_seconds)

        # Validate: not in the future (with 1 second tolerance for clock drift)
        if start_dt > now + timedelta_cls(seconds=1):
            return None

        # Validate: not before reasonable system boot time (system uptime > 0)
        # If runtime_seconds > 10 years, likely invalid
        if runtime_seconds > 315360000:  # 10 years in seconds
            return None

        result = start_dt.isoformat()

        # Cache the result
        if pid is not None:
            self._start_time_cache[pid] = result

        return result

    # Package origin verification cache and limits
    @property
    def _max_package_checks(self):
        return self._get_config("thresholds.max_package_checks", 5)

    @property
    def _package_check_timeout(self):
        return self._get_config("thresholds.package_check_timeout", 1.0)

    def __init__(self, workspace_dir: str = None):
        super().__init__(workspace_dir)
        self._package_cache = {}
        self._package_check_count = 0
        self._shell_names_lower = {s.lower() for s in self.SHELL_NAMES}
        self._system_core_processes_lower = {s.lower() for s in self.SYSTEM_CORE_PROCESSES}
        self._start_time_cache: Dict[int, str] = {}
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    # System daemon whitelist with allowed CWD configurations
    # Format: 'process_name': {'allowed_cwd': [list of allowed working directories], 'package': 'package_name', 'description': 'service description'}
    SYSTEM_DAEMON_WHITELIST = {
        # Random number generation
        'rngd': {
            'allowed_cwd': ['/', '/var/lib/rngtools'],
            'package': 'rng-tools',
            'description': 'Kernel RNG daemon'
        },
        # System logging
        'rsyslogd': {
            'allowed_cwd': ['/'],
            'package': 'rsyslog',
            'description': 'System logging daemon'
        },
        # Cron daemon
        'crond': {
            'allowed_cwd': ['/'],
            'package': 'cronie',
            'description': 'Cron daemon'
        },
        'cron': {
            'allowed_cwd': ['/'],
            'package': 'cron',
            'description': 'Cron daemon'
        },
        # SSH daemon
        'sshd': {
            'allowed_cwd': ['/'],
            'package': 'openssh-server',
            'description': 'SSH daemon'
        },
        # D-Bus daemon
        'dbus-daemon': {
            'allowed_cwd': ['/'],
            'package': 'dbus',
            'description': 'D-Bus message bus daemon'
        },
        # Systemd daemons
        'systemd-udevd': {
            'allowed_cwd': ['/'],
            'package': 'systemd',
            'description': 'Device manager'
        },
        'systemd-logind': {
            'allowed_cwd': ['/'],
            'package': 'systemd',
            'description': 'Login manager'
        },
        'systemd-journald': {
            'allowed_cwd': ['/'],
            'package': 'systemd',
            'description': 'Journal logging daemon'
        },
        'systemd-journal': {
            'allowed_cwd': ['/'],
            'package': 'systemd',
            'description': 'Journal logging daemon (alias name)'
        },
        'systemd-resolved': {
            'allowed_cwd': ['/'],
            'package': 'systemd',
            'description': 'Network name resolution manager'
        },
        'systemd-networkd': {
            'allowed_cwd': ['/'],
            'package': 'systemd',
            'description': 'Network configuration manager'
        },
        # Network daemons
        'NetworkManager': {
            'allowed_cwd': ['/'],
            'package': 'networkmanager',
            'description': 'Network connection manager'
        },
        'dhclient': {
            'allowed_cwd': ['/'],
            'package': 'dhcp-client',
            'description': 'DHCP client'
        },
        'dhcpcd': {
            'allowed_cwd': ['/'],
            'package': 'dhcpcd',
            'description': 'DHCP client'
        },
        # Logging and monitoring
        'auditd': {
            'allowed_cwd': ['/'],
            'package': 'audit',
            'description': 'Audit daemon'
        },
        'polkitd': {
            'allowed_cwd': ['/'],
            'package': 'polkit',
            'description': 'PolicyKit daemon'
        },
        # Hardware management
        'irqbalance': {
            'allowed_cwd': ['/'],
            'package': 'irqbalance',
            'description': 'IRQ balance daemon'
        },
        'lm_sensors': {
            'allowed_cwd': ['/'],
            'package': 'lm_sensors',
            'description': 'Hardware monitoring daemon'
        },
        # Time synchronization
        'chronyd': {
            'allowed_cwd': ['/'],
            'package': 'chrony',
            'description': 'NTP daemon'
        },
        'ntpd': {
            'allowed_cwd': ['/'],
            'package': 'ntp',
            'description': 'NTP daemon'
        },
        # RPC services
        'rpcbind': {
            'allowed_cwd': ['/'],
            'package': 'rpcbind',
            'description': 'RPC port mapper'
        },
        # Init system
        'init': {
            'allowed_cwd': ['/'],
            'package': 'sysvinit',
            'description': 'Init system'
        },
        # Container runtimes
        'dockerd': {
            'allowed_cwd': ['/'],
            'package': 'docker',
            'description': 'Docker daemon'
        },
        'containerd': {
            'allowed_cwd': ['/'],
            'package': 'containerd',
            'description': 'Container runtime'
        },
        'containerd-shim': {
            'allowed_cwd': ['/'],
            'package': 'containerd',
            'description': 'Container shim'
        },
    }

    def _stream_analyze_item(self, proc: dict) -> List['Evidence']:
        """Analyze a single process for all per-process detection checks.

        This method is called by stream_analyze() for each process in the
        processes list, enabling single-pass O(n) processing instead of
        9 independent O(n) passes.

        Args:
            proc: Single process dictionary with pid, comm, exe, cmdline, etc.

        Returns:
            List of Evidence objects for this process
        """
        evidences = []

        evidences.extend(self._detect_deleted_binaries_single(proc))
        evidences.extend(self._detect_suspicious_process_names_single(proc))
        evidences.extend(self._detect_abnormal_environ_single(proc))
        evidences.extend(self._detect_suspicious_powershell_single(proc))
        evidences.extend(self._detect_download_behavior_single(proc))
        evidences.extend(self._detect_lateral_movement_single(proc))
        evidences.extend(self._detect_cwd_anomalies_single(proc))
        evidences.extend(self._detect_malicious_script_execution_single(proc))

        return evidences

    def _detect_deleted_binaries_single(self, proc: dict) -> List['Evidence']:
        """Detect process running with deleted binary (single process version)."""
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        exe = proc.get("exe", "")
        if exe and "(deleted)" in exe:
            context = f"{proc.get('comm', '')} (PID {proc.get('pid', 0)})"
            if is_false_positive('process_analyzer', 'deleted_binary',
                               context=context):
                record_fp('process_analyzer', 'deleted_binary',
                         context=f'Suppressed: {context}')
            else:
                pid = proc.get("pid")
                exe_raw = proc.get("exe", "")
                exe_clean = exe_raw.replace(" (deleted)", "") if exe_raw else ""
                evidence_detail = EvidenceDetail(
                    pid=pid,
                    cmdline=proc.get("cmdline", "")[:500] if proc.get("cmdline") else None,
                    executable=exe_clean if exe_clean else None,
                    user=str(proc.get("uid", "")) if proc.get("uid") is not None else None,
                    parent_pid=proc.get("ppid"),
                    start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
                )
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1070.004",
                    attack_tactic=_get_attack_tactic_name()("T1070.004"),
                    title="Deleted Binary Running Process",
                    description=f"Process {proc.get('comm', '')} (PID {pid}) executable has been deleted: {exe_raw}",
                    confidence=0.85,
                    raw_data={"pid": pid, "exe": exe_raw, "comm": proc.get("comm")},
                    evidence_details=evidence_detail,
                    remediation_commands=[f"kill -9 {pid}", f"ls -la /proc/{pid}/exe"]
                ))
        return evidences

    def _detect_suspicious_process_names_single(self, proc: dict) -> List['Evidence']:
        """Detect suspicious process name (single process version)."""
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        comm = proc.get("comm", "")
        exe = proc.get("exe", "")

        if not exe or ("[" in exe and "]" in exe):
            return evidences

        comm_lower = comm.lower()
        if comm_lower in self.SHORT_NAME_WHITELIST:
            if comm_lower in self._shell_names_lower:
                if any(exe.startswith(path) for path in self.LEGITIMATE_SHELL_PATHS):
                    return evidences
            else:
                return evidences

        for pattern in self.SUSPICIOUS_NAME_PATTERNS:
            if pattern.match(comm):
                context = f"{comm} (PID {proc.get('pid', 0)})"
                if is_false_positive('process_analyzer', 'suspicious_process_name',
                                   context=context):
                    record_fp('process_analyzer', 'suspicious_process_name',
                             context=f'Suppressed: {context}')
                else:
                    pid = proc.get("pid")
                    evidence_detail = EvidenceDetail(
                        pid=pid,
                        cmdline=proc.get("cmdline", "")[:500] if proc.get("cmdline") else None,
                        executable=exe if exe else None,
                        user=str(proc.get("uid", "")) if proc.get("uid") is not None else None,
                        parent_pid=proc.get("ppid"),
                        start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
                    )
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1036.005",
                        attack_tactic=_get_attack_tactic_name()("T1036.005"),
                        title="Suspicious Process Name",
                        description=f"Process name '{comm}' (PID {pid}) matches suspicious pattern",
                        confidence=0.7,
                        raw_data={"pid": pid, "comm": comm, "exe": exe},
                        evidence_details=evidence_detail,
                        remediation_commands=[f"kill -9 {pid}", f"cat /proc/{pid}/cmdline"]
                    ))
                break

        return evidences

    def _detect_abnormal_environ_single(self, proc: dict) -> List['Evidence']:
        """Detect abnormal environment variables (single process version)."""
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        environ = proc.get("environ", {})
        ld_preload = environ.get("LD_PRELOAD", "")

        if ld_preload:
            suspicious_paths = {"/tmp", "/dev/shm"}
            is_suspicious = any(ld_preload.startswith(path) for path in suspicious_paths)
            if is_suspicious or ld_preload.startswith("."):
                context = f"{proc.get('comm', '')} LD_PRELOAD={ld_preload}"
                if is_false_positive('process_analyzer', 'ld_preload',
                                   context=context):
                    record_fp('process_analyzer', 'ld_preload',
                             context=f'Suppressed: {context}')
                else:
                    pid = proc.get("pid")
                    exe = proc.get("exe", "")
                    evidence_detail = EvidenceDetail(
                        pid=pid,
                        cmdline=proc.get("cmdline", "")[:500] if proc.get("cmdline") else None,
                        executable=exe if exe else None,
                        user=str(proc.get("uid", "")) if proc.get("uid") is not None else None,
                        parent_pid=proc.get("ppid"),
                        start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
                    )
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1574.006",
                        attack_tactic=_get_attack_tactic_name()("T1574.006"),
                        title="Abnormal LD_PRELOAD",
                        description=f"Process {proc.get('comm', '')} (PID {pid}) using suspicious LD_PRELOAD: {ld_preload}",
                        confidence=0.85,
                        raw_data={"pid": pid, "comm": proc.get("comm"), "LD_PRELOAD": ld_preload},
                        evidence_details=evidence_detail,
                        remediation_commands=[f"kill -9 {pid}", f"cat /proc/{pid}/environ | tr '\\0' '\\n' | grep LD_PRELOAD"]
                    ))

        return evidences

    def _detect_suspicious_powershell_single(self, proc: dict) -> List['Evidence']:
        """Detect suspicious PowerShell behavior (single process version)."""
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        cmdline = proc.get("cmdline", "")
        comm = proc.get("comm", "")

        is_powershell = any(pattern.search(cmdline) or pattern.search(comm)
                           for pattern, _ in self.POWERSHELL_PATTERNS[:2])

        if not is_powershell:
            return evidences

        suspicious_params = []
        for pattern, desc in self.POWERSHELL_PATTERNS[2:]:
            if pattern.search(cmdline):
                suspicious_params.append(desc)

        if suspicious_params:
            pid = proc.get("pid")
            exe = proc.get("exe", "")
            evidence_detail = EvidenceDetail(
                pid=pid,
                cmdline=cmdline[:500] if cmdline else None,
                executable=exe if exe else None,
                user=str(proc.get("uid", "")) if proc.get("uid") is not None else None,
                parent_pid=proc.get("ppid"),
                start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
            )
            evidences.append(self._create_evidence(
                severity=Severity.HIGH,
                attack_id="T1059.001",
                attack_tactic=_get_attack_tactic_name()("T1059.001"),
                title=f"Suspicious PowerShell execution: {', '.join(suspicious_params)}",
                description=f"Process {comm} (PID {pid}) using suspicious parameters: {suspicious_params}",
                confidence=0.8,
                raw_data={
                    "pid": pid,
                    "comm": comm,
                    "cmdline": cmdline[:500],
                    "suspicious_params": suspicious_params
                },
                evidence_details=evidence_detail,
                remediation_commands=[f"kill -9 {pid}", f"cat /proc/{pid}/cmdline"]
            ))

        return evidences

    def _detect_download_behavior_single(self, proc: dict) -> List['Evidence']:
        """Detect T1105 file download behavior (single process version)."""
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        cmdline = proc.get("cmdline", "")
        comm = proc.get("comm", "")

        is_download_cmd = any(cmd in cmdline.lower() or cmd == comm.lower()
                             for cmd in self.DOWNLOAD_COMMANDS)

        if not is_download_cmd:
            return evidences

        is_install_script = any(pattern.search(cmdline)
                               for pattern in self.INSTALL_SCRIPT_PATTERNS)
        if is_install_script:
            return evidences

        has_legitimate_source = any(source in cmdline.lower()
                                   for source in self.LEGITIMATE_DOWNLOAD_SOURCES)
        if has_legitimate_source:
            return evidences

        has_suspicious_url = any(pattern.search(cmdline)
                                for pattern in self.SUSPICIOUS_URL_PATTERNS)
        has_suspicious_path = any(path in cmdline for path in self.SUSPICIOUS_DOWNLOAD_PATHS)

        should_flag = has_suspicious_url or (has_suspicious_path and not has_legitimate_source)

        if should_flag:
            reasons = []
            if has_suspicious_url:
                reasons.append("Suspicious URL")
            if has_suspicious_path:
                reasons.append("Suspicious download path")

            pid = proc.get("pid")
            exe = proc.get("exe", "")
            evidence_detail = EvidenceDetail(
                pid=pid,
                cmdline=cmdline[:500] if cmdline else None,
                executable=exe if exe else None,
                user=str(proc.get("uid", "")) if proc.get("uid") is not None else None,
                parent_pid=proc.get("ppid"),
                start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
            )
            evidences.append(self._create_evidence(
                severity=Severity.HIGH if has_suspicious_url else Severity.MEDIUM,
                attack_id="T1105",
                attack_tactic=_get_attack_tactic_name()("T1105"),
                title=f"Suspicious file download ({', '.join(reasons)})",
                description=f"Process {comm} (PID {pid}) executed download: {cmdline[:200]}",
                confidence=0.75 if has_suspicious_url else 0.6,
                raw_data={
                    "pid": pid,
                    "comm": comm,
                    "cmdline": cmdline[:500],
                    "reasons": reasons
                },
                evidence_details=evidence_detail,
                remediation_commands=[f"kill -9 {pid}", f"rm -f {cmdline.split()[-1] if cmdline.split() else 'unknown'}"]
            ))

        return evidences

    def _detect_lateral_movement_single(self, proc: dict) -> List['Evidence']:
        """Detect T1570 lateral movement tools (single process version)."""
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        cmdline = proc.get("cmdline", "")
        comm = proc.get("comm", "")

        for cmd_name, pattern in self.LATERAL_MOVEMENT_COMMANDS.items():
            if cmd_name != comm.lower() and cmd_name not in cmdline.lower():
                continue

            if pattern.search(cmdline):
                is_internal_target = bool(self.INTERNAL_IP_PATTERN.search(cmdline))
                has_dangerous_opt = '-o stricthostkeychecking=no' in cmdline.lower() or \
                                   '-ostricthostkeychecking=no' in cmdline.lower()

                severity = Severity.HIGH if has_dangerous_opt else Severity.MEDIUM
                reasons = []
                if has_dangerous_opt:
                    reasons.append("Host key checking disabled")
                if is_internal_target:
                    reasons.append("Targeting internal network IP")

                pid = proc.get("pid")
                exe = proc.get("exe", "")
                evidence_detail = EvidenceDetail(
                    pid=pid,
                    cmdline=cmdline[:500] if cmdline else None,
                    executable=exe if exe else None,
                    user=str(proc.get("uid", "")) if proc.get("uid") is not None else None,
                    parent_pid=proc.get("ppid"),
                    start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
                )
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1570",
                    attack_tactic=_get_attack_tactic_name()("T1570"),
                    title=f"Lateral Movement Tool Usage ({cmd_name}, {', '.join(reasons) if reasons else 'Internal Transfer'})",
                    description=f"Process {comm} (PID {pid}) executing command: {cmdline[:200]}",
                    confidence=0.8 if has_dangerous_opt else 0.65,
                    raw_data={
                        "pid": pid,
                        "comm": comm,
                        "cmdline": cmdline[:500],
                        "tool": cmd_name,
                        "is_internal_target": is_internal_target,
                        "has_dangerous_opt": has_dangerous_opt
                    },
                    evidence_details=evidence_detail,
                    remediation_commands=[f"kill -9 {pid}", f"netstat -tlnp | grep {pid}"]
                ))
                break

        return evidences

    def _detect_cwd_anomalies_single(self, proc: dict) -> List['Evidence']:
        """Detect CWD-based anomalies (single process version)."""
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        cwd = proc.get("cwd", "")
        exe = proc.get("exe", "")
        comm = proc.get("comm", "")
        pid = proc.get("pid", 0)
        uid = proc.get("uid", 0)

        if not cwd:
            return evidences

        if not exe or ("[" in exe and "]" in exe):
            return evidences

        is_system_core = comm.lower() in self._system_core_processes_lower
        if is_system_core and cwd == '/':
            return evidences

        if self._is_cloud_monitor_agent(comm, cwd):
            return evidences

        if self._is_legitimate_system_daemon(comm, cwd):
            return evidences

        cmdline = proc.get("cmdline", "")
        if self._is_ai_tool_temp_execution(comm, cwd, cmdline):
            return evidences

        # Pre-compute risky cwd check
        is_risky_cwd = False
        risky_reason = ""
        for pattern, reason in self.RISKY_CWD_PATTERNS:
            if cwd.startswith(pattern):
                is_risky_cwd = True
                risky_reason = reason
                break

        if is_risky_cwd:
            if exe and self._verify_package_origin(exe):
                return evidences

            risk_factors = []

            is_suspicious_name = comm.startswith('.') or len(comm) > 50
            exe_dir = os.path.dirname(exe) if exe else ""
            cwd_mismatch = exe_dir and not cwd.startswith(exe_dir)
            is_sensitive = cwd.startswith(self.SENSITIVE_DIR_CHECK)
            is_unpriv = uid > 0

            if is_suspicious_name:
                risk_factors.append("Suspicious process name")
            if cwd_mismatch:
                risk_factors.append("CWD mismatch with executable")
            if is_sensitive and is_unpriv:
                risk_factors.append("Unprivileged access to sensitive directory")

            if risk_factors:
                severity = Severity.HIGH if len(risk_factors) >= 2 else Severity.MEDIUM
                confidence = 0.7 + (0.1 * len(risk_factors))

                evidence_detail = EvidenceDetail(
                    pid=pid,
                    cmdline=proc.get("cmdline", "")[:500] if proc.get("cmdline") else None,
                    executable=exe if exe else None,
                    user=str(uid) if uid is not None else None,
                    parent_pid=proc.get("ppid"),
                    start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
                )
                evidences.append(self._create_evidence(
                    severity=severity,
                    attack_id="T1564.001",
                    attack_tactic=_get_attack_tactic_name()("T1564.001"),
                    title=f"Process in risky directory ({risky_reason})",
                    description=f"Process {comm} (PID {pid}) working directory in risky location: {cwd}. Risk factors: {', '.join(risk_factors)}",
                    confidence=min(confidence, 0.95),
                    raw_data={
                        "pid": pid,
                        "comm": comm,
                        "cwd": cwd,
                        "exe": exe,
                        "uid": uid,
                        "risk_factors": risk_factors
                    },
                    evidence_details=evidence_detail,
                    remediation_commands=[f"kill -9 {pid}", f"ls -la /proc/{pid}/cwd"]
                ))

        elif cwd.startswith(self.SENSITIVE_DIRS):
            is_legit_system_proc = any(cwd.startswith(legit) for legit in self.SAFE_CWD_PATTERNS)

            if not is_legit_system_proc:
                evidence_detail = EvidenceDetail(
                    pid=pid,
                    cmdline=proc.get("cmdline", "")[:500] if proc.get("cmdline") else None,
                    executable=exe if exe else None,
                    user=str(uid) if uid is not None else None,
                    parent_pid=proc.get("ppid"),
                    start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
                )
                evidences.append(self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1552.001",
                    attack_tactic=_get_attack_tactic_name()("T1552.001"),
                    title=f"Process accessing sensitive directory",
                    description=f"Process {comm} (PID {pid}) working directory in sensitive location: {cwd}",
                    confidence=0.6,
                    raw_data={
                        "pid": pid,
                        "comm": comm,
                        "cwd": cwd,
                        "exe": exe,
                        "uid": uid
                    },
                    evidence_details=evidence_detail,
                    remediation_commands=[f"kill -9 {pid}", f"ls -la /proc/{pid}/cwd"]
                ))

        return evidences

    def _detect_malicious_script_execution_single(self, proc: dict) -> List['Evidence']:
        """Detect T1204.002 - Malicious Script Execution (single process version)."""
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        cmdline = proc.get("cmdline", "")
        comm = proc.get("comm", "")
        pid = proc.get("pid", 0)

        if not cmdline:
            return evidences

        patterns_to_check = self.CURL_PIPE_BASH_PATTERNS

        for pattern, description in patterns_to_check:
            if pattern.search(cmdline):
                has_legitimate_source = any(source in cmdline.lower()
                                           for source in self.LEGITIMATE_DOWNLOAD_SOURCES)
                if has_legitimate_source:
                    return evidences

                is_install_script = any(pattern.search(cmdline)
                                       for pattern in self.INSTALL_SCRIPT_PATTERNS)
                if is_install_script:
                    return evidences

                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1204.002",
                    attack_tactic=_get_attack_tactic_name()("T1204.002"),
                    title=f"Suspicious script execution: {description}",
                    description=f"Process {comm} (PID {pid}) executed potentially malicious script: {cmdline[:200]}",
                    confidence=0.75,
                    raw_data={
                        "pid": pid,
                        "comm": comm,
                        "cmdline": cmdline[:500],
                        "pattern": description
                    },
                    evidence_details=EvidenceDetail(
                        pid=pid,
                        cmdline=cmdline[:500] if cmdline else None,
                        executable=proc.get("exe", "") if proc.get("exe") else None,
                        user=str(proc.get("uid", "")) if proc.get("uid") is not None else None,
                        parent_pid=proc.get("ppid"),
                        start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
                    ),
                    remediation_commands=[f"kill -9 {pid}", f"cat /proc/{pid}/cmdline"]
                ))
                break

        for pattern, description in self.DOWNLOAD_EXECUTE_PATTERNS:
            if pattern.search(cmdline):
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1204.002",
                    attack_tactic=_get_attack_tactic_name()("T1204.002"),
                    title=f"Download and execute pattern detected: {description}",
                    description=f"Process {comm} (PID {pid}) downloaded and executed file: {cmdline[:200]}",
                    confidence=0.8,
                    raw_data={
                        "pid": pid,
                        "comm": comm,
                        "cmdline": cmdline[:500],
                        "pattern": description
                    },
                    evidence_details=EvidenceDetail(
                        pid=pid,
                        cmdline=cmdline[:500] if cmdline else None,
                        executable=proc.get("exe", "") if proc.get("exe") else None,
                        user=str(proc.get("uid", "")) if proc.get("uid") is not None else None,
                        parent_pid=proc.get("ppid"),
                        start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
                    ),
                    remediation_commands=[f"kill -9 {pid}", f"cat /proc/{pid}/cmdline"]
                ))
                break

        return evidences

    def analyze(self, collected_data: dict) -> List['Evidence']:
        """Execute process anomaly analysis using streaming for per-process checks.

        In quick mode: runs only critical checks (hidden processes, deleted binaries,
        suspicious names, LD_PRELOAD, malicious script execution).

        In survival mode: enforces strict timeout (15s max) with aggressive process limits.

        In full mode: runs all checks including parent-child relationships, download
        behavior, lateral movement, CWD anomalies, and comprehensive script analysis.

        The per-process checks (deleted binaries, suspicious names, environ,
        powershell, download, lateral movement, CWD, script execution) are
        consolidated into a single pass via stream_analyze(), reducing
        complexity from O(9n) to O(n).

        Hidden process detection and parent-child relationship detection
        run separately as they require special handling (/proc scanning
        and full process map respectively).
        """
        evidences = []

        tracker = _get_tracker()()  # Call get_tracker function to get tracker instance
        tracker.record_detection('process_analyzer', 1)

        process_data = self._get_data(collected_data, "process")
        if not process_data:
            return evidences

        # Check for cooperative cancellation before starting expensive operations
        if self._check_and_cancel("initialization"):
            return evidences

        processes = process_data.get("processes", [])

        # Always run hidden process detection (critical security check)
        if not self._check_and_cancel("hidden process detection"):
            evidences.extend(self._detect_hidden_processes())

        # Full mode: run all checks
        if not self._check_and_cancel("parent-child relationship detection"):
            evidences.extend(self._detect_abnormal_parent_child(processes))

        for evidence in self.stream_analyze(collected_data, "process", "processes"):
            # Check cancellation flag periodically
            if self._check_and_cancel("stream analysis"):
                break
            evidences.append(evidence)

        return evidences

    def _detect_hidden_processes(self) -> List['Evidence']:
        """Detect hidden processes with TOCTOU mitigation.

        Mitigates Time-Of-Check-Time-Of-Use (TOCTOU) race conditions by:
        1. Verifying PID accessibility via /proc/{pid}/comm
        2. Cross-checking with cmdline to exclude kernel threads
        3. Reducing confidence score for race condition possibility

        Performance optimization: Strict time limits in quick mode to prevent
        excessive scanning when many processes exist.

        Returns:
            List of Evidence objects for detected hidden processes
        """
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        try:
            # Hidden process detection: scan /proc filesystem
            _time = _get_time_module()
            scan_start = _time.monotonic()
            
            # Single pass: collect all PIDs and their accessibility status
            # This avoids TOCTOU by checking accessibility immediately
            inaccessible_pids: Set[int] = set()

            for entry in os.scandir('/proc'):
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                proc_path = f'/proc/{pid}'

                try:
                    # Quick accessibility check via comm file
                    # Kernel threads and hidden processes will fail here
                    os.stat(f'{proc_path}/comm')
                except (PermissionError, FileNotFoundError):
                    # Track inaccessible for second-pass verification
                    inaccessible_pids.add(pid)

            # Second pass: verify truly hidden PIDs (exclude kernel threads)
            check_limit = 20  # Limit to avoid performance impact
            checked_count = 0
            hidden_pids: List[int] = []
            
            for pid in sorted(inaccessible_pids):
                if checked_count >= check_limit:
                    _get_logger().debug(f"[process_analyzer] Hidden process check limit reached ({check_limit})")
                    break
                    
                checked_count += 1
                proc_path = f'/proc/{pid}'
                try:
                    # Check if /proc/{pid} exists but comm is inaccessible
                    # Use os.lstat to avoid following symlinks
                    os.lstat(proc_path)
                    # Path exists - verify it's not a kernel thread by checking cmdline
                    try:
                        with open(f'{proc_path}/cmdline', 'rb') as f:
                            cmdline = f.read(4096)
                            if cmdline.strip():  # Has cmdline = userspace process
                                hidden_pids.append(pid)
                    except OSError:
                        # Cannot read cmdline, likely hidden
                        hidden_pids.append(pid)
                except OSError:
                    # Path doesn't exist or inaccessible - not a hidden process
                    continue

            # Aggregate report all hidden processes
            if hidden_pids:
                remediation_cmds = [f"kill -9 {pid}" for pid in hidden_pids[:5]]
                remediation_cmds.extend([f"ls -la /proc/{pid}/exe" for pid in hidden_pids[:5]])
                evidences.append(self._create_evidence(
                    severity=Severity.CRITICAL,
                    attack_id="T1564.001",
                    attack_tactic=_get_attack_tactic_name()("T1564.001"),
                    title=f"Hidden Process Detection ({len(hidden_pids)} found)",
                    description=f"Found {len(hidden_pids)} hidden processes: {hidden_pids[:10]}",
                    confidence=0.85,  # Reduced from 0.9 due to race condition possibility
                    raw_data={"hidden_pids": hidden_pids},
                    evidence_details=EvidenceDetail(
                        pid=hidden_pids[0] if hidden_pids else None,
                    ),
                    remediation_commands=remediation_cmds
                ))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            _get_logger().debug(f"[process_analyzer] Hidden process detection error: {e}")

        return evidences

    def _detect_abnormal_parent_child(self, processes: list) -> List['Evidence']:
        """Detect abnormal parent-child relationships"""
        evidences = []
        _, EvidenceDetail = _get_evidence_classes()
        Severity = _get_severity()
        # Build PID to process mapping, filtering out None entries
        proc_map = {p.get("pid"): p for p in processes if p is not None and isinstance(p, dict)}

        for proc in processes:
            if proc is None or not isinstance(proc, dict):
                continue
            comm = proc.get("comm", "")
            ppid = proc.get("ppid", 0)

            # Check shell process
            if comm in self.SHELL_NAMES:
                parent = proc_map.get(ppid, {})
                parent_comm = parent.get("comm", "")

                # Web server spawning shell
                web_servers = {"apache2", "httpd", "nginx", "lighttpd"}
                if parent_comm in web_servers:
                    # Check FP exceptions for web server shell spawning
                    context = f"{parent_comm} -> {comm}"
                    if is_false_positive('process_analyzer', 'web_server_shell', 
                                       context=context):
                        record_fp('process_analyzer', 'web_server_shell', 
                                 context=f'Suppressed: {context}')
                    else:
                        pid = proc.get("pid")
                        evidence_detail = EvidenceDetail(
                            pid=pid,
                            cmdline=proc.get("cmdline", "")[:500] if proc.get("cmdline") else None,
                            executable=proc.get("exe", "") if proc.get("exe") else None,
                            user=str(proc.get("uid", "")) if proc.get("uid") is not None else None,
                            parent_pid=ppid,
                            start_time=self._calc_start_time(proc.get("runtime_seconds"), pid=pid),
                        )
                        evidences.append(self._create_evidence(
                        severity=Severity.MEDIUM,
                        attack_id="T1059.004",
                        attack_tactic=_get_attack_tactic_name()("T1059.004"),
                        title="Web Server Spawning Shell",
                        description=f"Web server {parent_comm} (PPID {ppid}) spawned shell process {comm} (PID {pid})",
                        confidence=0.6,
                        raw_data={"pid": pid, "comm": comm, "ppid": ppid, "parent_comm": parent_comm},
                        evidence_details=evidence_detail,
                        remediation_commands=[f"kill -9 {pid}", f"pstree -p {ppid}"]
                    ))

        return evidences

    def _is_cloud_monitor_agent(self, proc_name: str, proc_cwd: str) -> bool:
        """Check if the process is a cloud provider monitoring agent
        
        Uses CloudEnvDetector for unified cloud environment detection.
        
        Args:
            proc_name: Process name (comm field)
            proc_cwd: Process current working directory
            
        Returns:
            True if the process is a whitelisted cloud monitoring agent
        """
        detector = self._get_cloud_detector()
        return detector.should_whitelist(
            proc_name, 'process', context={'cwd': proc_cwd}
        )
    
    def _is_ai_tool_temp_execution(self, proc_name: str, proc_cwd: str, proc_cmdline: str = "") -> bool:
        """Check if the process is an AI tool executing from temporary directory
        
        Args:
            proc_name: Process name (comm field)
            proc_cwd: Process current working directory
            proc_cmdline: Process command line (optional)
            
        Returns:
            True if the process is an AI tool running from temp directory
        """
        # Check if cwd matches AI tool temp paths
        for ai_path in self.AI_TOOL_TEMP_PATHS:
            if proc_cwd.startswith(ai_path):
                return True
        
        # Check if process name matches AI tools
        ai_tool_names = {
            'claude', 'claude-code', 'qoder', 'qoder-cli', 
            'cursor', 'copilot', 'anthropic', 'npx', 'node'
        }
        if proc_name.lower() in ai_tool_names:
            return True
        
        # Check cmdline for AI tool patterns
        if proc_cmdline:
            for pattern in self.AI_TOOL_CMDLINE_PATTERNS:
                if pattern.search(proc_cmdline):
                    return True
        
        return False
    
    def _is_legitimate_system_daemon(self, proc_name: str, proc_cwd: str) -> bool:
        """Check if the process is a legitimate system daemon with allowed CWD
        
        Args:
            proc_name: Process name (comm field)
            proc_cwd: Process current working directory
            
        Returns:
            True if the process is a whitelisted system daemon with allowed CWD
        """
        if proc_name not in self.SYSTEM_DAEMON_WHITELIST:
            return False
        
        allowed_cwds = self.SYSTEM_DAEMON_WHITELIST[proc_name].get('allowed_cwd', [])
        return proc_cwd in allowed_cwds
    
    def _verify_package_origin(self, exe_path: str, expected_package: Optional[str] = None) -> bool:
        """Verify if the process belongs to a system package
        
        Uses caching and global limits to prevent performance degradation.
        
        Args:
            exe_path: Full path to the executable
            expected_package: Expected package name (optional, for stricter verification)
            
        Returns:
            True if the executable belongs to a system package
        """
        if not exe_path or not os.path.exists(exe_path):
            return False
        
        # Check cache first
        cache_key = (exe_path, expected_package)
        if cache_key in self._package_cache:
            return self._package_cache[cache_key]
        
        # Check class-level cache for cross-instance sharing
        with self._class_package_cache_lock:
            if cache_key in self.__class__._class_package_cache:
                result = self.__class__._class_package_cache[cache_key]
                self._package_cache[cache_key] = result
                return result

        # Enforce global limit to prevent performance degradation
        self._package_check_count += 1
        if self._package_check_count > self._max_package_checks:
            _get_logger().debug(f"[process_analyzer] Package origin check limit reached, skipping: {exe_path}")
            self._package_cache[cache_key] = False
            return False

        # Try Debian/Ubuntu dpkg with reduced timeout
        subprocess = _get_subprocess_module()
        try:
            result = subprocess.run(
                ['dpkg', '-S', exe_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=self._package_check_timeout
            )
            if result.returncode == 0:
                if expected_package is None or expected_package in result.stdout:
                    self._package_cache[cache_key] = True
                    with self._class_package_cache_lock:
                        self.__class__._class_package_cache[cache_key] = True
                    return True
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Try RHEL/CentOS/Alibaba Cloud Linux rpm with reduced timeout
        subprocess = _get_subprocess_module()
        try:
            result = subprocess.run(
                ['rpm', '-qf', exe_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=self._package_check_timeout
            )
            if result.returncode == 0 and 'not owned' not in result.stdout.lower():
                if expected_package is None or expected_package in result.stdout:
                    self._package_cache[cache_key] = True
                    with self._class_package_cache_lock:
                        self.__class__._class_package_cache[cache_key] = True
                    return True
        except (subprocess.TimeoutExpired, OSError):
            pass
        
        self._package_cache[cache_key] = False
        return False
