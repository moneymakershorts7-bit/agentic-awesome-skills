"""File Anomaly Analyzer - Enhanced with Runtime Behavior Analysis"""
import os
import re
from typing import List
from collections import defaultdict
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

class FileAnalyzer(BaseAnalyzer):
    """File System Anomaly Analyzer with Runtime Access Pattern Detection
    
    ATT&CK Coverage: T1083 (File and Directory Discovery), T1005 (Data from Local System),
                     T1552 (Unsecured Credentials), T1564 (Hide Artifacts)
    """
    name = "file_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 30)

    estimated_time = 2.0  # Reduced from default for quick mode
    analyzer_type = BaseAnalyzer.CRITICAL
    required_collectors = ["filesystem"]

    @property
    def MAX_FILE_LIST_SIZE(self):
        return self._get_config("thresholds.max_file_list_size", 1000)
    
    # SUID whitelist (Debian 12 default)
    SUID_WHITELIST = {
        # Basic authentication and permission management tools
        "/usr/bin/passwd", "/bin/passwd",
        "/usr/bin/chfn", "/bin/chfn",
        "/usr/bin/chsh", "/bin/chsh",
        "/usr/bin/newgrp", "/bin/newgrp",
        "/usr/bin/gpasswd", "/bin/gpasswd",
        "/usr/bin/sudo", "/bin/sudo",
        "/usr/bin/su", "/bin/su",
        
        # Mount related
        "/usr/bin/mount", "/bin/mount",
        "/usr/bin/umount", "/bin/umount",
        "/usr/bin/fusermount", "/bin/fusermount",
        "/usr/bin/fusermount3", "/bin/fusermount3",
        
        # System management tools
        "/usr/bin/pkexec", "/bin/pkexec",
        "/usr/bin/crontab", "/bin/crontab",
        "/usr/bin/at", "/bin/at",
        
        # D-Bus related
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        
        # SSH related
        "/usr/lib/openssh/ssh-keysign",
        "/usr/bin/ssh-agent",
        
        # X11 related
        "/usr/lib/xorg/Xorg.wrap",
        
        # Snap related
        "/usr/lib/snapd/snap-confine",
        
        # Network tools
        "/usr/bin/kismet", "/usr/bin/mtr",
        
        # Terminal tools
        "/usr/bin/wall", "/usr/bin/write",
        
        # Other common SUID files
        "/usr/bin/screen",
        "/usr/bin/ping", "/bin/ping",
        "/usr/bin/ping6",

        # Alibaba Cloud Linux 3 / RHEL 8 standard SUID files
        # SystemTap runtime
        "/usr/bin/staprun", "/bin/staprun",
        # Password/permission management
        "/usr/bin/chage", "/bin/chage",
        "/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd",
        "/usr/sbin/pam_timestamp_check", "/sbin/pam_timestamp_check",
        # Network/filesystem
        "/usr/sbin/mount.nfs", "/sbin/mount.nfs",
        "/usr/sbin/usernetctl", "/sbin/usernetctl",
        # Boot management
        "/usr/sbin/grub2-set-bootflag", "/sbin/grub2-set-bootflag",
    }
    
    # GTFOBins exploitable binaries
    GTFOBINS = {
        "find", "vim", "nmap", "python", "python3", "perl", "ruby",
        "less", "more", "awk", "env", "tar", "zip", "cp", "mv",
    }
    
    # Hidden file whitelist for known benign patterns
    HIDDEN_FILE_WHITELIST_PATTERNS = {
        # Electron/Chrome cache files
        '.fcb',  # Electron cache shared objects
        '.com.google.',  # Google Chrome/Chromium
        '.org.chromium.',  # Chromium
        '.org.mozilla.',  # Firefox
        
        # Common temp/cache files
        '.swf',  # Flash temp files
        '.tmp',  # Generic temp files
        
        # IDE and development tools
        '.idea',  # JetBrains IDEs
        '.vscode',  # VS Code
        '.cache',  # Generic cache directories
    }
    
    # Paths where hidden files are common and less suspicious
    @property
    def LOW_CONFIDENCE_PATHS(self):
        cfg = self._get_config("paths.low_confidence_paths")
        if cfg:
            return set(cfg)
        return {'/tmp', '/var/tmp', '/dev/shm'}

    # Paths where hidden files should be whitelisted (no alerts)
    @property
    def HIDDEN_FILE_EXEMPT_PATHS(self):
        cfg = self._get_config("paths.hidden_file_exempt_paths")
        if cfg:
            return set(cfg)
        return {'/tmp', '/var/tmp', '/dev/shm'}
    
    # Sensitive file paths that indicate credential theft or reconnaissance
    SENSITIVE_FILES = {
        '/etc/shadow': ('T1552.004', 'Credential theft target'),
        '/etc/passwd': ('T1552.004', 'User account enumeration'),
        '/etc/sudoers': ('T1552.003', 'Privilege configuration'),
        '/root/.ssh/authorized_keys': ('T1098', 'SSH key manipulation'),
        '/home/*/.ssh/authorized_keys': ('T1098', 'SSH key manipulation'),
        '/root/.ssh/id_rsa': ('T1552.004', 'Private key theft'),
        '/home/*/.ssh/id_rsa': ('T1552.004', 'Private key theft'),
        '/root/.bash_history': ('T1056.001', 'History file access'),
        '/home/*/.bash_history': ('T1056.001', 'History file access'),
        '/var/lib/mysql/mysql/user.frm': ('T1005', 'Database credential access'),
        '/var/lib/postgresql/*/main/pg_hba.conf': ('T1005', 'Database auth config'),
    }
    
    # File access patterns indicating mass enumeration
    ENUMERATION_PATTERNS = {
        'mass_ssh_key_access': {
            'description': 'Multiple SSH key files accessed',
            'threshold': 3,
            'pattern': re.compile(r'\.ssh/(id_rsa|id_ed25519|authorized_keys)'),
            'attack_id': 'T1098',
            'severity': Severity.HIGH
        },
        'mass_history_access': {
            'description': 'Multiple history files accessed',
            'threshold': 3,
            'pattern': re.compile(r'\.(bash_|zsh_|sh_)?history'),
            'attack_id': 'T1056.001',
            'severity': Severity.MEDIUM
        },
        'mass_config_access': {
            'description': 'Multiple configuration files enumerated',
            'threshold': 5,
            'pattern': re.compile(r'\.(conf|cfg|ini|yaml|yml)$'),
            'attack_id': 'T1005',
            'severity': Severity.LOW
        }
    }

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute file anomaly analysis with runtime behavior detection"""
        evidences = []

        # Get file collection data
        fs_data = self._get_data(collected_data, "filesystem")
        if not fs_data:
            return evidences

        # Truncate large file lists to prevent processing timeout
        for key in ['suid_files', 'sgid_files', 'tmp_executables', 'hidden_files', 'sensitive_files']:
            if key in fs_data and isinstance(fs_data[key], list):
                original_count = len(fs_data[key])
                if original_count > self.MAX_FILE_LIST_SIZE:
                    _get_logger().warning(
                        f"[{self.name}] File list '{key}' exceeds limit: "
                        f"{original_count} > {self.MAX_FILE_LIST_SIZE}, truncating"
                    )
                    fs_data[key] = fs_data[key][:self.MAX_FILE_LIST_SIZE]

        # Quick mode: only run critical checks

        # Full mode: run all checks
        # 1. SUID/SGID anomaly detection
        evidences.extend(self._check_suid_abnormal(fs_data))

        # 2. Temp directory executable file detection
        evidences.extend(self._check_tmp_executables(fs_data))

        # 3. Hidden file anomaly detection
        evidences.extend(self._check_hidden_files(fs_data))

        # 4. Runtime file access pattern analysis (NEW)
        evidences.extend(self._detect_sensitive_file_access(fs_data))

        # 5. Mass file enumeration detection (NEW)
        evidences.extend(self._detect_file_enumeration(fs_data))

        return evidences
    def _check_suid_abnormal(self, fs_data: dict) -> List[Evidence]:
        """Check SUID/SGID anomalies"""
        evidences = []
        suid_files = fs_data.get("suid_files", [])
        
        for suid_file in suid_files:
            filepath = suid_file.get("path", "")
            
            # Not in whitelist
            if filepath not in self.SUID_WHITELIST:
                # Check if it's a GTFOBins binary
                filename = os.path.basename(filepath)
                if filename in self.GTFOBINS:
                    evidences.append(self._create_evidence(
                        title=f"GTFOBins SUID 权限：{filepath}",
                        description=f"发现 GTFOBins 二进制文件具有 SUID 权限，可能被用于权限提升：{filepath}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        attack_id="T1548.001",
                        raw_data={"path": filepath, "permissions": suid_file.get("permissions")},
                        evidence_details=EvidenceDetail(
                            file_path=filepath,
                            permission_level=suid_file.get("permissions"),
                            cmdline=None,
                            executable=None,
                            user=None,
                        ),
                        remediation_commands=[
                            f"ls -la {filepath}",
                            f"chmod u-s {filepath}",
                            f"Check if GTFOBins binary is needed: which {filename}",
                            "Consider removing or restricting SUID permission"
                        ]
                    ))
                else:
                    evidences.append(self._create_evidence(
                        title=f"非standard SUID 文件：{filepath}",
                        description=f"发现不在白名单中的 SUID 文件：{filepath}",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        attack_id="T1548.001",
                        raw_data={"path": filepath, "permissions": suid_file.get("permissions")},
                        evidence_details=EvidenceDetail(
                            file_path=filepath,
                            permission_level=suid_file.get("permissions"),
                            cmdline=None,
                            executable=None,
                            user=None,
                        ),
                        remediation_commands=[
                            f"ls -la {filepath}",
                            f"stat {filepath}",
                            "Review SUID necessity: find / -perm -4000 -type f",
                            "Consider removing SUID if not required"
                        ]
                    ))
        
        return evidences
    
    def _check_tmp_executables(self, fs_data: dict) -> List[Evidence]:
        """Check temp directory executable files"""
        evidences = []
        tmp_executables = fs_data.get("tmp_executables", [])
        
        for tmp_file in tmp_executables:
            filepath = tmp_file.get("path", "")

            # Check if it's an ELF executable
            is_elf = False
            try:
                with open(filepath, 'rb') as f:
                    magic = f.read(4)
                    is_elf = magic == b'\x7fELF'
            except OSError:
                pass
            
            if is_elf:
                evidences.append(self._create_evidence(
                    title=f"临时目录 ELF 可执行文件：{filepath}",
                    description=f"在临时目录发现 ELF 可执行文件，可能是恶意载荷：{filepath}",
                    severity=Severity.HIGH,
                    confidence=0.7,
                    attack_id="T1059",
                    raw_data={"path": filepath, "size": tmp_file.get("size")},
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        ),
                    remediation_commands=[
                        f"ls -la {filepath}",
                        f"file {filepath}",
                        f"md5sum {filepath}",
                        "Check file origin: strings <filepath>"
                    ]
                ))
            elif filepath.endswith(('.sh', '.py', '.pl')):
                evidences.append(self._create_evidence(
                    title=f"临时目录脚本文件：{filepath}",
                    description=f"在临时目录发现脚本文件：{filepath}",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    attack_id="T1059",
                    raw_data={"path": filepath},
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        ),
                    remediation_commands=[
                        f"ls -la {filepath}",
                        f"cat {filepath}",
                        f"file {filepath}",
                        "Check script content and purpose"
                    ]
                ))
        
        return evidences
    
    def _check_hidden_files(self, fs_data: dict) -> List[Evidence]:
        """Check hidden file anomalies"""
        evidences = []
        hidden_files = fs_data.get("hidden_files_suspicious", [])
        
        suspicious_patterns = ['.cache/update', '.x', '.hidden_shell', '.backdoor']
        
        # Electron/chromium cache patterns in /tmp/ (FP prevention)
        tmp_cache_pattern = re.compile(r'^\.fcb[0-9a-f]{12}-[0-9a-f]{8}\.so$')
        
        for hidden_file in hidden_files:
            filepath = hidden_file.get("path", "")
            filename = os.path.basename(filepath)
            
            # Check whitelist - skip known benign patterns
            if any(pattern in filename for pattern in self.HIDDEN_FILE_WHITELIST_PATTERNS):
                _get_logger().debug(f"[file_analyzer] Skipping whitelisted hidden file: {filepath}")
                continue
            
            # Skip Electron/Chromium cache files in /tmp/ (FP prevention)
            if filepath.startswith("/tmp/") and tmp_cache_pattern.match(filename):
                continue
            
            # Skip all hidden files in /tmp, /var/tmp, /dev/shm (temporary directories)
            # These are typically application temp files and cleaned up on reboot
            if any(filepath.startswith(path + '/') or filepath == path for path in self.HIDDEN_FILE_EXEMPT_PATHS):
                _get_logger().debug(f"[file_analyzer] Skipping hidden file in temp directory: {filepath}")
                continue
            
            # Check if filename matches suspicious patterns
            is_suspicious = any(pattern in filename for pattern in suspicious_patterns)
            
            # Reduce confidence for files in temp directories
            is_in_temp_path = any(filepath.startswith(path) for path in self.LOW_CONFIDENCE_PATHS)
            
            if is_suspicious:
                evidences.append(self._create_evidence(
                    title=f"可疑隐藏文件：{filepath}",
                    description=f"发现可疑隐藏文件：{filepath}",
                    severity=Severity.HIGH,
                    confidence=0.6,
                    attack_id="T1564.001",
                    raw_data={"path": filepath, "size": hidden_file.get("size")},
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        ),
                    remediation_commands=[
                        f"ls -la {filepath}",
                        f"file {filepath}",
                        f"md5sum {filepath}",
                        "Check file content and origin"
                    ]
                ))
            else:
                # Lower severity for hidden files in temp directories
                if is_in_temp_path:
                    severity = Severity.INFO
                    confidence = 0.3
                else:
                    severity = Severity.MEDIUM
                    confidence = 0.5
                    
                evidences.append(self._create_evidence(
                    title=f"隐藏文件：{filepath}",
                    description=f"发现隐藏文件：{filepath}",
                    severity=severity,
                    confidence=confidence,
                    attack_id="T1564.001",
                    raw_data={"path": filepath},
                    evidence_details=EvidenceDetail(
                        file_path=filepath,
                        ),
                    remediation_commands=[
                        f"ls -la {filepath}",
                        f"file {filepath}",
                        "Check if file is legitimate application data"
                    ]
                ))
        
        return evidences
    
    def _detect_sensitive_file_access(self, fs_data: dict) -> List[Evidence]:
        """Detect access to sensitive files indicating credential theft or reconnaissance
        
        This method analyzes file access patterns to detect:
        - Credential file access (/etc/shadow, SSH keys)
        - Configuration file tampering
        - History file manipulation
        """
        evidences = []
        
        # Get file access data from collector (if available)
        accessed_files = fs_data.get("accessed_files", [])
        if not accessed_files:
            return evidences
        
        for access_record in accessed_files:
            filepath = access_record.get("path", "")
            accessing_process = access_record.get("accessing_process", "")
            access_type = access_record.get("access_type", "read")
            
            # Check against sensitive file patterns
            for pattern, (attack_id, description) in self.SENSITIVE_FILES.items():
                # Handle wildcard patterns
                if '*' in pattern:
                    regex_pattern = pattern.replace('*', '[^/]+')
                    if re.match(regex_pattern, filepath):
                        evidence = self._create_evidence(
                            title=f"Sensitive File Access: {description}",
                            description=(
                                f"Process '{accessing_process}' accessed sensitive file:\n"
                                f"File: {filepath}\n"
                                f"Access Type: {access_type}\n"
                                f"Risk: {description}"
                            ),
                            severity=Severity.HIGH,
                            confidence=0.80,
                            attack_id=attack_id,
                            attack_tactic="Credential Access",
                            source_path=filepath,
                            raw_data={
                                "filepath": filepath,
                                "accessing_process": accessing_process,
                                "access_type": access_type,
                                "pattern": "sensitive_file_access"
                            },
                            remediation=(
                                f"Investigate why '{accessing_process}' is accessing {filepath}. "
                                f"This may indicate credential theft or reconnaissance."
                            ),
                            evidence_details=EvidenceDetail(
                                file_path=filepath,
                                ),
                            remediation_commands=[
                                f"ls -la {filepath}",
                                f"Check which process accessed: auditctl -w {filepath} -p r",
                                f"Review process logs: journalctl | grep {accessing_process}",
                                "Verify if access is authorized"
                            ]
                        )
                        evidences.append(evidence)
                        break
                else:
                    # Exact match
                    if filepath == pattern:
                        evidence = self._create_evidence(
                            title=f"Sensitive File Access: {description}",
                            description=(
                                f"Process '{accessing_process}' accessed sensitive file:\n"
                                f"File: {filepath}\n"
                                f"Access Type: {access_type}\n"
                                f"Risk: {description}"
                            ),
                            severity=Severity.HIGH,
                            confidence=0.85,
                            attack_id=attack_id,
                            attack_tactic="Credential Access",
                            source_path=filepath,
                            raw_data={
                                "filepath": filepath,
                                "accessing_process": accessing_process,
                                "access_type": access_type,
                                "pattern": "sensitive_file_access"
                            },
                            remediation=(
                                f"Investigate why '{accessing_process}' is accessing {filepath}. "
                                f"This may indicate credential theft or reconnaissance."
                            ),
                            evidence_details=EvidenceDetail(
                                file_path=filepath,
                                ),
                            remediation_commands=[
                                f"ls -la {filepath}",
                                f"Check which process accessed: auditctl -w {filepath} -p r",
                                f"Review process logs: journalctl | grep {accessing_process}",
                                "Verify if access is authorized"
                            ]
                        )
                        evidences.append(evidence)
                        break
        
        return evidences
    
    def _detect_file_enumeration(self, fs_data: dict) -> List[Evidence]:
        """Detect mass file enumeration patterns indicating reconnaissance
        
        This method identifies:
        - Mass SSH key file access
        - Multiple history file reads
        - Configuration file enumeration
        """
        evidences = []
        
        accessed_files = fs_data.get("accessed_files", [])
        if not accessed_files:
            return evidences
        
        # Count matches for each enumeration pattern
        pattern_counts = defaultdict(list)
        
        for access_record in accessed_files:
            filepath = access_record.get("path", "")
            
            for pattern_name, pattern_info in self.ENUMERATION_PATTERNS.items():
                if pattern_info['pattern'].search(filepath):
                    pattern_counts[pattern_name].append(access_record)
        
        # Check thresholds and generate alerts
        for pattern_name, matched_files in pattern_counts.items():
            pattern_info = self.ENUMERATION_PATTERNS[pattern_name]
            
            if len(matched_files) >= pattern_info['threshold']:
                evidence = self._create_evidence(
                    title=f"Mass File Enumeration Detected: {pattern_info['description']}",
                    description=(
                        f"Detected {len(matched_files)} file accesses matching pattern '{pattern_name}':\n"
                        f"Threshold: {pattern_info['threshold']}\n"
                        f"Files accessed:\n" + 
                        "\n".join([f"  - {f.get('path', '')}" for f in matched_files[:10]])
                    ),
                    severity=pattern_info['severity'],
                    confidence=0.75,
                    attack_id=pattern_info['attack_id'],
                    attack_tactic="Collection",
                    source_path="multiple",
                    raw_data={
                        "pattern": pattern_name,
                        "file_count": len(matched_files),
                        "threshold": pattern_info['threshold'],
                        "files": [f.get("path", "") for f in matched_files[:20]]
                    },
                    remediation=(
                        f"Investigate process performing mass file enumeration. "
                        f"This may indicate reconnaissance activity. "
                        f"Check if this is authorized security scanning."
                    ),
                    evidence_details=EvidenceDetail(
                        file_path="multiple",
                        ),
                    remediation_commands=[
                        "Check audit logs for file access: ausearch -f <suspicious_file>",
                        "Review process activity: ps aux | grep <suspicious_process>",
                        "Monitor for continued enumeration: auditctl -w /etc -p r",
                        "Verify if this is authorized scanning activity"
                    ]
                )
                evidences.append(evidence)
        
        return evidences
