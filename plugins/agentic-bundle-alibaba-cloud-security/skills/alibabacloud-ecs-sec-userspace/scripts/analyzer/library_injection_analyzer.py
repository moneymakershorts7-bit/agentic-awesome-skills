"""Library Injection Detection Analyzer - LD_PRELOAD and Shared Library Hijacking

Detects LD_PRELOAD and shared library injection attacks including:
1. /etc/ld.so.preload file tampering (system-wide library injection)
2. Process LD_PRELOAD environment variable injection
3. Suspicious shared libraries in temporary directories
4. System library integrity verification
5. Abnormal library file permissions (world-writable)
6. Hidden directory .so files
7. Library timestamp anomalies
8. Known malicious library signature matching

ATT&CK mapping:
- T1574.006 - Dynamic Linker Hijacking (Primary)
- T1078 - Valid Accounts (Privilege Escalation)
- T1564.001 - Hidden Files and Directories
- T1070.006 - Indicator Removal on Host (timestamp manipulation)

References:
- Elastic Security Labs - "Hooked on Linux: Rootkit Detection Engineering" (2026-02)
- MITRE ATT&CK - T1574.006: Dynamic Linker Hijacking
- OWASP - Code Injection Prevention Cheat Sheet
"""
import os
import re
import stat
import subprocess
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from ..reporter.evidence import Evidence
from ..reporter.severity import Severity
from .base import BaseAnalyzer
from ..utils.remediation_generator import generate_generic_remediation
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

class LibraryInjectionAnalyzer(BaseAnalyzer):
    """LD_PRELOAD and Shared Library Injection Detection Analyzer
    
    Detects sophisticated library injection techniques:
    - System-wide ld.so.preload tampering
    - Per-process LD_PRELOAD injection
    - Malicious shared libraries in suspicious locations
    - System library replacement attacks
    - Library permission abuse
    - Hidden library deployment
    - Timestamp manipulation detection
    - Known malicious library signatures
    """
    name = 'library_injection_analyzer'
    timeout = 30
    required_collectors = ['filesystem', 'process', 'service']
    estimated_time = 1.0
    analyzer_type = BaseAnalyzer.CRITICAL

    def should_skip(self) -> tuple:
        """Do not skip in any mode - library injection detection is critical."""
        return (False, '')
    SUSPICIOUS_LIB_PATHS = ['/tmp', '/var/tmp', '/dev/shm', '/run/user']
    SYSTEM_LIBRARIES = ['/lib/x86_64-linux-gnu/libc.so.6', '/lib/x86_64-linux-gnu/libdl.so.2', '/lib/x86_64-linux-gnu/libpthread.so.0', '/usr/lib/x86_64-linux-gnu/libstdc++.so.6', '/lib/x86_64-linux-gnu/libm.so.6', '/lib/x86_64-linux-gnu/librt.so.1']
    LEGITIMATE_LD_PRELOAD_PATTERNS = [re.compile('^\\s*#'), re.compile('^\\s*$')]
    LEGITIMATE_PRELOAD_PATHS = {'/usr/lib/libeatmydata.so', '/usr/lib/x86_64-linux-gnu/libeatmydata.so', '/usr/lib/libfakeroot/libfakeroot-sysv.so', '/usr/lib/x86_64-linux-gnu/libfakeroot/libfakeroot-sysv.so', '/usr/lib64/libfakeroot/libfakeroot-sysv.so', '/usr/lib/valgrind/', '/usr/lib64/valgrind/', '/usr/lib/libabsl.so', '/usr/lib/x86_64-linux-gnu/libabsl.so'}
    LEGITIMATE_LIBRARY_PREFIXES = ('/usr/lib/', '/usr/lib64/', '/lib/', '/lib64/', '/opt/', '/usr/local/lib/', '/usr/local/lib64/')
    SUSPICIOUS_PRELOAD_CONTENT_PATTERNS = [(re.compile('\\$\\(.*\\)'), 'Command substitution in LD_PRELOAD', Severity.CRITICAL, 0.85), (re.compile('`.*`'), 'Backtick command substitution in LD_PRELOAD', Severity.CRITICAL, 0.85), (re.compile(';|\\|'), 'Command chaining in LD_PRELOAD', Severity.CRITICAL, 0.85), (re.compile('\\.\\./'), 'Relative path traversal in LD_PRELOAD', Severity.HIGH, 0.75)]
    SUSPICIOUS_HOOK_FUNCTIONS = ['open', 'read', 'write', 'execve', 'fork', 'ptrace', 'connect', 'accept', 'bind', 'listen', 'getuid', 'geteuid', 'getgid', 'getegid', 'pam_authenticate', 'crypt']
    KNOWN_BUILD_TOOL_PATTERNS = [re.compile('/tmp/\\.[a-f0-9]{8,16}-[a-f0-9]{8}\\.so$'), re.compile('/\\.cache/uv/\\.tmp\\w+/'), re.compile('\\.cpython-\\d+-[a-zA-Z0-9_-]+\\.so$'), re.compile('/pip-build-'), re.compile('/pip-install-'), re.compile('/easy_install-'), re.compile('/CMakeFiles/'), re.compile('/node_modules/.+\\.(node|so)$')]
    KNOWN_MALICIOUS_SIGNATURES = {}

    def analyze(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Analyze library injection attacks"""
        evidences = []
        evidences.extend(self._check_ld_so_preload(collected_data))
        evidences.extend(self._check_process_ld_preload(collected_data))
        evidences.extend(self._check_ld_preload_content_patterns(collected_data))
        evidences.extend(self._check_ld_so_conf_d())
        evidences.extend(self._check_suspicious_shared_libs())
        evidences.extend(self._check_system_library_integrity())
        evidences.extend(self._check_library_permissions())
        evidences.extend(self._check_hidden_directory_libs())
        evidences.extend(self._check_library_timestamps())
        evidences.extend(self._check_malicious_signatures(collected_data))
        return evidences
    def _check_ld_so_preload(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Check 1: /etc/ld.so.preload file tampering (CRITICAL)
        
        The ld.so.preload file allows system-wide library preloading.
        Any non-empty, non-comment content is highly suspicious.
        """
        evidences = []
        service_data = self._get_data(collected_data, 'service')
        if not service_data:
            return evidences
        ld_preload_info = service_data.get('ld_so_preload', {})
        # Validate ld_preload_info is a dict, not a list (schema compatibility)
        if not isinstance(ld_preload_info, dict):
            return evidences
        if not ld_preload_info.get('exists', False):
            return evidences
        content = ld_preload_info.get('content', '').strip()
        lines = content.split('\n')
        non_empty_lines = [line.strip() for line in lines if line.strip()]
        if not non_empty_lines:
            return evidences
        all_comments = all((line.startswith('#') for line in non_empty_lines))
        if all_comments:
            return evidences
        suspicious_paths_found = [path for path in self.SUSPICIOUS_LIB_PATHS if path in content]
        severity = Severity.CRITICAL if suspicious_paths_found else Severity.HIGH
        confidence = 0.95 if suspicious_paths_found else 0.85
        evidences.append(self._create_evidence(title='LD_PRELOAD System-Wide Injection Detected', description=f"/etc/ld.so.preload contains suspicious library entries: {content[:200]}. This enables system-wide library hijacking affecting all processes. Suspicious paths detected: {(', '.join(suspicious_paths_found) if suspicious_paths_found else 'none')}", severity=severity, confidence=confidence, attack_id='T1574.006', attack_tactic='Persistence, Privilege Escalation', source_path='/etc/ld.so.preload', raw_data={'content': content, 'suspicious_paths': suspicious_paths_found}, remediation='1. Backup /etc/ld.so.preload for forensic analysis\n2. Identify and remove malicious .so files referenced\n3. Clear /etc/ld.so.preload content\n4. Scan system for other persistence mechanisms\n5. Verify system library integrity with package manager', evidence_details=self._create_evidence_details(service_type='library_injection'), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'library_injection_analyzer'})))
        return evidences

    def _check_process_ld_preload(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Check 2: Process LD_PRELOAD environment variable injection (HIGH)
        
        Individual processes can have LD_PRELOAD set in their environment,
        allowing targeted library injection without system-wide changes.
        """
        evidences = []
        process_data = self._get_data(collected_data, 'process')
        if not process_data:
            return evidences
        processes = process_data.get('processes', [])
        for proc in processes:
            pid = proc.get('pid', 0)
            cmdline = proc.get('cmdline', '')
            environ_raw = proc.get('environ', '')
            if not environ_raw:
                continue
            # Parse environ: can be a string like "KEY1=VAL1\nKEY2=VAL2" or a dict
            if isinstance(environ_raw, dict):
                env_vars = environ_raw
            else:
                env_vars = {}
                for line in str(environ_raw).splitlines():
                    if '=' in line:
                        k, v = line.split('=', 1)
                        env_vars[k] = v
            if not env_vars:
                continue
            ld_preload = env_vars.get('LD_PRELOAD', '')
            ld_library_path = env_vars.get('LD_LIBRARY_PATH', '')
            if not ld_preload and (not ld_library_path):
                continue
            if ld_preload and self._is_legitimate_preload(ld_preload):
                continue
            if ld_library_path and self._is_legitimate_preload(ld_library_path):
                continue
            suspicious = False
            suspicious_var = ''
            suspicious_content = ''
            if ld_preload:
                for path in self.SUSPICIOUS_LIB_PATHS:
                    if path in ld_preload:
                        suspicious = True
                        suspicious_var = 'LD_PRELOAD'
                        suspicious_content = ld_preload
                        break
            if ld_library_path and (not suspicious):
                for path in self.SUSPICIOUS_LIB_PATHS:
                    if path in ld_library_path:
                        suspicious = True
                        suspicious_var = 'LD_LIBRARY_PATH'
                        suspicious_content = ld_library_path
                        break
            severity = Severity.CRITICAL if suspicious else Severity.MEDIUM
            confidence = 0.9 if suspicious else 0.7
            if suspicious or (cmdline and (not self._is_standard_process(cmdline))):
                evidences.append(self._create_evidence(title=f"Process Library Injection via {suspicious_var or 'Environment'}", description=f"Process PID {pid} ({cmdline[:100]}) has {suspicious_var or 'LD_LIBRARY_PATH'} set: {suspicious_content or ld_library_path}. This may indicate targeted library injection for privilege escalation or evasion.", severity=severity, confidence=confidence, attack_id='T1574.006', attack_tactic='Defense Evasion, Privilege Escalation', source_path=f'/proc/{pid}/environ', raw_data={'pid': pid, 'cmdline': cmdline, 'LD_PRELOAD': ld_preload, 'LD_LIBRARY_PATH': ld_library_path}, remediation=f'1. Investigate process {pid} origin and legitimacy\n2. Check if {suspicious_content or ld_library_path} contains malicious libraries\n3. Restart process without injected variables if malicious\n4. Review process parent chain for compromise indicators', evidence_details=self._create_evidence_details(pid=pid, cmdline=cmdline), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'library_injection_analyzer'})))
        return evidences

    def _check_ld_preload_content_patterns(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Check 2.5: LD_PRELOAD content pattern analysis
        
        Detects command injection patterns in LD_PRELOAD values:
        - Command substitution: $(...)
        - Backtick execution: `...`
        - Command chaining: ; or |
        - Relative path traversal: ../
        """
        evidences = []
        process_data = self._get_data(collected_data, 'process')
        if not process_data:
            return evidences
        processes = process_data.get('processes', [])
        for proc in processes:
            pid = proc.get('pid', 0)
            cmdline = proc.get('cmdline', '')
            environ_raw = proc.get('environ', '')
            if not environ_raw:
                continue
            # Parse environ: can be a string or a dict
            if isinstance(environ_raw, dict):
                env_vars = environ_raw
            else:
                env_vars = {}
                for line in str(environ_raw).splitlines():
                    if '=' in line:
                        k, v = line.split('=', 1)
                        env_vars[k] = v
            if not env_vars:
                continue
            ld_preload = env_vars.get('LD_PRELOAD', '')
            if not ld_preload:
                continue
            for pattern, desc, severity, confidence in self.SUSPICIOUS_PRELOAD_CONTENT_PATTERNS:
                if pattern.search(ld_preload):
                    evidences.append(self._create_evidence(title=f'LD_PRELOAD Injection Pattern: {desc}', description=f'Process PID {pid} ({cmdline[:100]}) has LD_PRELOAD with {desc}.\nValue: {ld_preload}\nThis may indicate dynamic command injection or obfuscation.', severity=severity, confidence=confidence, attack_id='T1574.006', attack_tactic='Defense Evasion, Privilege Escalation', source_path=f'/proc/{pid}/environ', raw_data={'pid': pid, 'cmdline': cmdline, 'ld_preload': ld_preload, 'pattern': desc}, remediation=f'1. Inspect process {pid} and its parent chain\n2. Check if LD_PRELOAD is expected for this application\n3. Investigate the command injection pattern', evidence_details=self._create_evidence_details(pid=pid, cmdline=cmdline), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'library_injection_analyzer'})))
        return evidences

    def _check_ld_so_conf_d(self) -> List[Evidence]:
        """Check 2.6: /etc/ld.so.conf.d suspicious configuration paths
        
        Attackers may add suspicious directories to the library search path
        via configuration files in /etc/ld.so.conf.d/.
        """
        evidences = []
        conf_dir = '/etc/ld.so.conf.d'
        if not os.path.isdir(conf_dir):
            return evidences
        try:
            for filename in os.listdir(conf_dir):
                if not filename.endswith('.conf'):
                    continue
                filepath = os.path.join(conf_dir, filename)
                try:
                    with open(filepath, 'r', errors='replace', encoding='utf-8') as f:
                        content = f.read()
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#') or line.startswith('include '):
                            continue
                        for suspicious_path in self.SUSPICIOUS_LIB_PATHS:
                            if line.startswith(suspicious_path):
                                evidences.append(self._create_evidence(title=f'Suspicious Library Path in ld.so.conf.d: {filename}', description=f'Suspicious library directory in {filepath}.\nPath: {line}\nReason: Points to {suspicious_path} which is commonly abused for library injection.', severity=Severity.HIGH, confidence=0.7, attack_id='T1574.006', attack_tactic='Privilege Escalation', source_path=filepath, raw_data={'file': filepath, 'path': line, 'suspicious_directory': suspicious_path}, remediation=f'Review and remove suspicious paths from {filepath}. Run ldconfig after modification.', evidence_details=self._create_evidence_details(file_path=line), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'library_injection_analyzer'})))
                                break
                except OSError as e:
                    _get_logger().warning(f'Failed to read {filepath}: {e}')
        except OSError as e:
            _get_logger().warning(f'Failed to list {conf_dir}: {e}')
        return evidences

    def _is_known_build_artifact(self, filepath: str) -> bool:
        """Check if file is a known build tool artifact
        
        Returns True if the file matches known build tool patterns
        that should be excluded from detection to reduce false positives.
        """
        for pattern in self.KNOWN_BUILD_TOOL_PATTERNS:
            if pattern.search(filepath):
                return True
        return False

    def _is_recent_build_artifact(self, filepath: str, max_age_seconds: int=3600) -> bool:
        """Check if file is a recent build artifact (< max_age_seconds old)
        
        Recent files are likely active build artifacts rather than malicious payloads.
        Default threshold: 1 hour (3600 seconds).
        """
        try:
            stat_result = os.stat(filepath)
            import time
            file_age = time.time() - stat_result.st_mtime
            return file_age < max_age_seconds
        except OSError:
            return False

    def _check_suspicious_shared_libs(self) -> List[Evidence]:
        """Check 3: Suspicious .so files in temporary directories (HIGH)
        
        Attackers often place malicious shared libraries in world-writable
        temporary directories like /tmp, /dev/shm, /var/tmp.
        
        Excludes known build tool artifacts and recent files to reduce false positives.
        """
        evidences = []
        for tmp_dir in self.SUSPICIOUS_LIB_PATHS:
            if not os.path.exists(tmp_dir):
                continue
            try:
                for entry in os.scandir(tmp_dir):
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    if not entry.name.endswith('.so') and '.so.' not in entry.name:
                        continue
                    if self._is_known_build_artifact(entry.path):
                        _get_logger().debug(f'Skipping known build artifact: {entry.path}')
                        continue
                    if self._is_recent_build_artifact(entry.path, max_age_seconds=3600):
                        _get_logger().debug(f'Skipping recent build artifact: {entry.path}')
                        continue
                    try:
                        stat = entry.stat()
                        size = stat.st_size
                        if size < 1024 or size > 100 * 1024 * 1024:
                            severity = Severity.HIGH
                            confidence = 0.75
                        else:
                            severity = Severity.MEDIUM
                            confidence = 0.6
                        evidences.append(self._create_evidence(title=f'Suspicious Shared Library in Temporary Directory', description=f'Found shared library {entry.path} in temporary directory {tmp_dir}. Size: {size} bytes. Legitimate libraries should not reside in temporary directories.', severity=severity, confidence=confidence, attack_id='T1574.006', attack_tactic='Defense Evasion', source_path=entry.path, raw_data={'path': entry.path, 'size': size, 'directory': tmp_dir}, remediation=f'1. Analyze {entry.path} with file command and strings\n2. Check for exported symbols indicating hooking\n3. Compare hash against threat intelligence\n4. Remove if confirmed malicious\n5. Investigate how library was placed there', evidence_details=self._create_evidence_details(file_path=entry.path), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'library_injection_analyzer'})))
                    except OSError as e:
                        _get_logger().warning(f'Failed to stat {entry.path}: {e}')
                        continue
            except OSError as e:
                _get_logger().warning(f'Failed to scan {tmp_dir}: {e}')
                continue
        return evidences

    def _check_system_library_integrity(self) -> List[Evidence]:
        """Check 4: System library integrity verification (MEDIUM)
        
        Verify that critical system libraries haven't been replaced
        with trojanized versions by checking package manager records.
        """
        evidences = []
        for lib_path in self.SYSTEM_LIBRARIES:
            if not os.path.exists(lib_path):
                continue
            try:
                pkg_verified = False
                result = subprocess.run(['rpm', '-V', lib_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
                if result.returncode == 0:
                    pkg_verified = True
                elif result.returncode == 1 and result.stdout.strip():
                    evidences.append(self._create_evidence(title='System Library Integrity Violation', description=f'System library {lib_path} has been modified from its original package state. RPM verification output: {result.stdout.strip()[:200]}', severity=Severity.HIGH, confidence=0.85, attack_id='T1574.006', attack_tactic='Defense Evasion', source_path=lib_path, raw_data={'library': lib_path, 'rpm_output': result.stdout.strip()}, remediation=f'1. Reinstall package containing {lib_path}\n2. Run: rpm -qf {lib_path} to identify package\n3. Run: yum reinstall <package> or dnf reinstall <package>\n4. Investigate when and how library was modified', evidence_details=self._create_evidence_details(file_path=lib_path), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'library_injection_analyzer'})))
                    pkg_verified = True
                if not pkg_verified:
                    result = subprocess.run(['dpkg', '-V', lib_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
                    if result.returncode == 1 and result.stdout.strip():
                        evidences.append(self._create_evidence(title='System Library Integrity Violation (DPKG)', description=f'System library {lib_path} verification failed via dpkg. Output: {result.stdout.strip()[:200]}', severity=Severity.HIGH, confidence=0.85, attack_id='T1574.006', attack_tactic='Defense Evasion', source_path=lib_path, raw_data={'library': lib_path, 'dpkg_output': result.stdout.strip()}, remediation=f'1. Reinstall package: apt-get install --reinstall $(dpkg -S {lib_path})\n2. Investigate modification timeline\n3. Check for other compromised system libraries', evidence_details=self._create_evidence_details(file_path=lib_path), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'library_injection_analyzer'})))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
            except (OSError, ValueError, subprocess.SubprocessError) as e:
                _get_logger().warning(f'Failed to verify {lib_path}: {e}')
                continue
        return evidences

    def _check_library_permissions(self) -> List[Evidence]:
        """Check 5: Abnormal library file permissions (MEDIUM)
        
        World-writable libraries can be modified by any user,
        enabling easy privilege escalation.
        """
        evidences = []
        lib_dirs = ['/lib', '/usr/lib', '/lib64', '/usr/lib64']
        for lib_dir in lib_dirs:
            if not os.path.exists(lib_dir):
                continue
            try:
                for entry in os.scandir(lib_dir):
                    if not entry.name.endswith('.so') and '.so.' not in entry.name:
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    try:
                        stat_result = entry.stat()
                        mode = stat_result.st_mode
                        if mode & stat.S_IWOTH:
                            evidences.append(self._create_evidence(title='World-Writable Shared Library', description=f'Library {entry.path} is world-writable (permissions: {oct(mode)}). Any user can modify this library, enabling privilege escalation.', severity=Severity.MEDIUM, confidence=0.9, attack_id='T1078', attack_tactic='Privilege Escalation', source_path=entry.path, raw_data={'path': entry.path, 'permissions': oct(mode)}, remediation=f'1. Fix permissions: chmod o-w {entry.path}\n2. Investigate who modified permissions\n3. Check library integrity\n4. Review audit logs for unauthorized modifications', evidence_details=self._create_evidence_details(file_path=entry.path), remediation_commands=generate_generic_remediation(attack_id='1078', context={'analyzer': 'library_injection_analyzer'})))
                    except OSError:
                        continue
            except OSError:
                continue
        return evidences

    def _check_hidden_directory_libs(self) -> List[Evidence]:
        """Check 6: Hidden directory .so files (MEDIUM)
        
        Attackers use hidden directories (starting with .) to store
        malicious libraries and evade casual inspection.
        
        Excludes known build tool artifacts to reduce false positives.
        """
        evidences = []
        search_roots = ['/tmp', '/var/tmp', '/dev/shm', '/home', '/root', '/opt']
        for root in search_roots:
            if not os.path.exists(root):
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root):
                    hidden_dirs = [d for d in dirnames if d.startswith('.')]
                    for hidden_dir in hidden_dirs:
                        hidden_path = os.path.join(dirpath, hidden_dir)
                        try:
                            for entry in os.scandir(hidden_path):
                                if not entry.is_file(follow_symlinks=False):
                                    continue
                                if not entry.name.endswith('.so') and '.so.' not in entry.name:
                                    continue
                                if self._is_known_build_artifact(entry.path):
                                    _get_logger().debug(f'Skipping known build artifact: {entry.path}')
                                    continue
                                if self._is_recent_build_artifact(entry.path, max_age_seconds=3600):
                                    _get_logger().debug(f'Skipping recent build artifact: {entry.path}')
                                    continue
                                evidences.append(self._create_evidence(title='Shared Library in Hidden Directory', description=f'Found shared library {entry.path} in hidden directory {hidden_dir}. Hidden directories are commonly used to hide malicious payloads.', severity=Severity.MEDIUM, confidence=0.7, attack_id='T1564.001', attack_tactic='Defense Evasion', source_path=entry.path, raw_data={'path': entry.path, 'hidden_dir': hidden_dir}, remediation=f'1. Examine library contents: strings {entry.path}\n2. Check exported symbols: nm -D {entry.path}\n3. Calculate hash and check threat intelligence\n4. Remove if malicious and investigate access logs', evidence_details=self._create_evidence_details(file_path=entry.path), remediation_commands=generate_generic_remediation(attack_id='1564.001', context={'analyzer': 'library_injection_analyzer'})))
                        except OSError:
                            continue
            except OSError:
                continue
        return evidences

    def _check_library_timestamps(self) -> List[Evidence]:
        """Check 7: Library timestamp anomalies (LOW)
        
        Modified timestamps that don't match package installation dates
        may indicate post-installation tampering.
        """
        evidences = []
        for lib_path in self.SYSTEM_LIBRARIES:
            if not os.path.exists(lib_path):
                continue
            try:
                stat_result = os.stat(lib_path)
                mtime = datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc)
                install_time = self._get_package_install_time(lib_path)
                if install_time and mtime > install_time:
                    time_diff = (mtime - install_time).days
                    if time_diff > 1:
                        evidences.append(self._create_evidence(title='System Library Timestamp Anomaly', description=f'Library {lib_path} was modified {time_diff} days after package installation. Modified: {mtime.isoformat()}, Installed: {install_time.isoformat()}. This may indicate post-installation tampering.', severity=Severity.LOW, confidence=0.6, attack_id='T1070.006', attack_tactic='Defense Evasion', source_path=lib_path, raw_data={'library': lib_path, 'modified_time': mtime.isoformat(), 'install_time': install_time.isoformat(), 'days_after_install': time_diff}, remediation=f'1. Verify library integrity with package manager\n2. Check if modification was due to legitimate update\n3. Review system logs around modification time\n4. Compare hash with known good version', evidence_details=self._create_evidence_details(file_path=lib_path), remediation_commands=generate_generic_remediation(attack_id='1070.006', context={'analyzer': 'library_injection_analyzer'})))
            except OSError:
                continue
        return evidences

    def _is_legitimate_preload(self, path: str) -> bool:
        """Check if a path is a known legitimate LD_PRELOAD library"""
        if path in self.LEGITIMATE_PRELOAD_PATHS:
            return True
        for legit_path in self.LEGITIMATE_PRELOAD_PATHS:
            if legit_path.endswith('/') and path.startswith(legit_path):
                return True
        if path.startswith(self.LEGITIMATE_LIBRARY_PREFIXES):
            return True
        return False

    def _is_standard_process(self, cmdline: str) -> bool:
        """Check if process is a standard system process"""
        standard_processes = ['systemd', 'init', 'sshd', 'cron', 'rsyslog', 'nginx', 'apache', 'httpd', 'mysqld', 'postgres', 'docker', 'containerd', 'kubelet']
        cmdline_lower = cmdline.lower()
        return any((proc in cmdline_lower for proc in standard_processes))

    def _get_package_install_time(self, filepath: str) -> Optional[datetime]:
        """Get package installation time for a file"""
        try:
            result = subprocess.run(['rpm', '-q', '--queryformat', '%{INSTALLTIME}', '-f', filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip().isdigit():
                install_time = int(result.stdout.strip())
                return datetime.fromtimestamp(install_time, tz=timezone.utc)
            result = subprocess.run(['dpkg', '-s', filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('Install-Date:'):
                        date_str = line.split(':', 1)[1].strip()
                        try:
                            return datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                        except ValueError:
                            pass
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass
        return None

    def _check_malicious_signatures(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Check 8: Known malicious library signature matching (CRITICAL)
        
        Compare found libraries against known malicious signatures from threat intelligence.
        This includes hash matching and pattern-based detection.
        """
        evidences = []
        filesystem_data = self._get_data(collected_data, 'filesystem')
        if not filesystem_data:
            return evidences
        all_libs = []
        for category in ['tmp_executables', 'suid_files', 'sgid_files', 'hidden_files_suspicious']:
            all_libs.extend(filesystem_data.get(category, []))
        for lib_info in all_libs:
            filepath = lib_info.get('path', '')
            if not filepath.endswith('.so') and '.so.' not in filepath:
                continue
            filename = os.path.basename(filepath)
            malicious_patterns = [re.compile('rootkit|backdoor|keylog|reverse.shell', re.IGNORECASE), re.compile('C2\\.beacon|implant\\.dll|payload\\.so', re.IGNORECASE), re.compile('hook_function|intercept_call|trojan', re.IGNORECASE)]
            for pattern in malicious_patterns:
                if pattern.search(filename):
                    evidences.append(self._create_evidence(title='Known Malicious Library Signature Detected', description=f'Library {filepath} matches known malicious signature pattern. This strongly indicates system compromise with trojanized library.', severity=Severity.CRITICAL, confidence=0.95, attack_id='T1574.006', attack_tactic='Defense Evasion, Persistence', source_path=filepath, raw_data={'file': filepath, 'matched_pattern': pattern.pattern, **lib_info}, remediation='1. Immediately isolate the system from network\n2. Do NOT remove the file (preserve forensic evidence)\n3. Capture full disk image for analysis\n4. Analyze library with malware analysis tools (strings, nm, objdump)\n5. Initiate incident response procedures\n6. Check for other indicators of compromise', evidence_details=self._create_evidence_details(service_type='library_injection'), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'library_injection_analyzer'})))
                    break
            lib_hash = lib_info.get('hash', '')
            if lib_hash and lib_hash in self.KNOWN_MALICIOUS_SIGNATURES:
                evidences.append(self._create_evidence(title='Malicious Library Hash Match', description=f'Library {filepath} hash {lib_hash} matches known malicious signature in threat intelligence database.', severity=Severity.CRITICAL, confidence=0.98, attack_id='T1574.006', attack_tactic='Defense Evasion, Persistence', source_path=filepath, raw_data={'file': filepath, 'hash': lib_hash, 'threat_intel_match': self.KNOWN_MALICIOUS_SIGNATURES[lib_hash], **lib_info}, remediation='1. Isolate system immediately\n2. Preserve all evidence\n3. Engage incident response team\n4. Perform full system forensic analysis\n5. Review threat intelligence report for this signature', evidence_details=self._create_evidence_details(service_type='library_injection'), remediation_commands=generate_generic_remediation(attack_id='1574.006', context={'analyzer': 'library_injection_analyzer'})))
        return evidences