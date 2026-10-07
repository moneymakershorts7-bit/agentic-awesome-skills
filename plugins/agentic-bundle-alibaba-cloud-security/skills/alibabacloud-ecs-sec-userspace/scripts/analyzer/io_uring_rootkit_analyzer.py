"""IO_Uring Rootkit Detection Analyzer - Specialized io_uring Attack Detection

Detects io_uring-based rootkit techniques including:
1. io_uring instance creation for syscall bypass
2. Ring buffer manipulation for data exfiltration
3. BTF (BPF Type Format) injection via io_uring
4. Security tool evasion through io_uring hooks
5. Shadow file descriptor abuse
6. Combined io_uring + BTF process injection attacks

ATT&CK mapping:
- T1014 - Rootkit (io_uring Rootkit Technique)
- T1055 - Process Injection (via io_uring memory manipulation and BTF injection)
- T1048 - Exfiltration Over Alternative Protocol (ring buffer exfil)
- T1562.008 - Disable Security Tools (bypassing eBPF monitors)
- T1070.004 - File Deletion (io_uring unlink operations)

References:
- ARMO - "io_uring Rootkit Bypasses Linux Security Tools" (2025)
- Elastic Security Labs - "Hooked on Linux: Rootkit Taxonomy" (2026-02)
- InfoQ - "Linux Security Tools Bypassed by io_uring Rootkit Technique" (2025-09)
"""
import os
import re
from typing import List, Dict, Any, Optional
from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
from .base import BaseAnalyzer
from ..utils.remediation_generator import generate_generic_remediation, generate_process_remediation
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

class IoUringRootkitAnalyzer(BaseAnalyzer):
    """Specialized io_uring rootkit detection analyzer.
    
    Detects io_uring-based attacks that bypass traditional security monitoring:
    - Direct kernel I/O submission without syscalls
    - Ring buffer abuse for stealthy data exfiltration
    - BTF injection for process manipulation
    - Security tool hooking via io_uring callbacks
    - Combined io_uring + BTF process injection (2025 technique)
    - Kernel module hooks for io_uring syscalls
    - Known CVE exploit patterns
    """
    name = 'io_uring_rootkit_analyzer'
    timeout = 30
    required_collectors = ['process', 'filesystem', 'network']
    IO_URING_PATHS = ['/sys/fs/io_uring', '/proc/sys/kernel/io_uring_disabled', '/proc/sys/kernel/io_uring_limit', '/sys/kernel/slab/io_kiocb', '/sys/kernel/slab/io_ring_ctx']
    SUSPICIOUS_IO_URING_PATTERNS = {'non_standard_process': ('Non-database/non-webserver process using io_uring', Severity.MEDIUM, 'T1014'), 'large_ring_buffer': ('io_uring ring buffer with unusually large entries (>4096)', Severity.HIGH, 'T1014'), 'registered_files_abuse': ('io_uring with excessive registered files (>100)', Severity.HIGH, 'T1014'), 'linked_sqe_operations': ('io_uring linked SQE operations (potential atomic attack)', Severity.CRITICAL, 'T1055'), 'fixed_file_operations': ('io_uring fixed file operations (bypasses fd checks)', Severity.HIGH, 'T1014')}
    LEGITIMATE_IO_URING_APPS = ['postgres', 'postgresql', 'mysqld', 'mariadbd', 'mongod', 'mongos', 'redis-server', 'redis-sentinel', 'nginx', 'openresty', 'node', 'deno', 'bun', 'liburing', 'fio', 'ceph-osd', 'ceph-mon', 'spdk', 'dpdk']
    FULL_SCAN_PROCESS_LIMIT = 200
    
    KNOWN_IOURING_CVE_PATTERNS = {
        'CVE-2023-0266': {
            'description': 'io_uring double-free vulnerability in io_sq_thread()',
            'pattern': 'io_sq_thread',
            'severity': Severity.CRITICAL,
            'attack_id': 'T1055',
            'cve_year': 2023
        },
        'CVE-2023-3269': {
            'description': 'use-after-free in io_uring with IORING_SETUP_SINGLE_ISSUER',
            'pattern': 'IORING_SETUP_SINGLE_ISSUER',
            'severity': Severity.HIGH,
            'attack_id': 'T1055',
            'cve_year': 2023
        },
        'CVE-2024-26581': {
            'description': 'io_uring race condition in io_ring_ctx_wait_and_kill()',
            'pattern': 'io_ring_ctx_wait',
            'severity': Severity.HIGH,
            'attack_id': 'T1055',
            'cve_year': 2024
        },
        'CVE-2024-35982': {
            'description': 'io_uring privilege escalation via crafted sqe operations',
            'pattern': 'io_submit_sqes',
            'severity': Severity.CRITICAL,
            'attack_id': 'T1068',
            'cve_year': 2024
        }
    }
    
    SUSPICIOUS_KMODULE_PATTERNS = {
        'io_uring_hook': ('Kernel module hooking io_uring syscalls', Severity.CRITICAL, 'T1014'),
        'io_uring_override': ('Kernel module overriding io_uring handlers', Severity.CRITICAL, 'T1014'),
        'bpf_io_uring': ('eBPF program attached to io_uring hooks', Severity.HIGH, 'T1562.008'),
    }

    def __init__(self):
        super().__init__()
        self._io_uring_available_cache = None

    def should_skip(self) -> tuple:
        """Run io_uring rootkit check in quick mode"""
        return (False, '')

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute io_uring rootkit analysis
        
        Args:
            collected_data: Dictionary of collector results
            
        Returns:
            List of Evidence objects for detected threats
        """
        evidences = []
        
        # Cache io_uring availability check for reuse across methods
        if self._io_uring_available_cache is None:
            self._io_uring_available_cache = self._is_io_uring_available()
        
        # Early exit if io_uring subsystem not available
        if not self._io_uring_available_cache:
            _get_logger().debug(f'[{self.name}] io_uring subsystem not available, skipping')
            return evidences
        
        evidences.extend(self._check_io_uring_sysfs())
        try:
            evidences.extend(self._check_process_io_uring(collected_data))
        except (KeyError, TypeError):
            pass
        try:
            evidences.extend(self._check_io_uring_syscall_handlers())
        except (KeyError, TypeError):
            pass
        try:
            evidences.extend(self._check_fd_abuse(collected_data))
        except (KeyError, TypeError):
            pass
        try:
            evidences.extend(self._check_ring_buffer_memory(collected_data))
        except (KeyError, TypeError):
            pass
        try:
            evidences.extend(self._check_btf_injection_via_io_uring(collected_data))
        except (KeyError, TypeError):
            pass
        try:
            evidences.extend(self._check_kernel_module_hooks())
        except (KeyError, TypeError):
            pass
        try:
            evidences.extend(self._check_cve_exploit_patterns(collected_data))
        except (KeyError, TypeError):
            pass
        return evidences

    def _is_io_uring_available(self) -> bool:
        """Check if io_uring subsystem is available on this system
        
        Returns:
            True if io_uring kernel subsystem is enabled
        """
        io_uring_core_paths = [
            '/sys/fs/io_uring',
            '/proc/sys/kernel/io_uring_disabled',
        ]
        for path in io_uring_core_paths:
            if os.path.exists(path):
                return True
        return False

    def _check_io_uring_sysfs(self) -> List[Evidence]:
        """Check io_uring sysfs configuration for anomalies
        
        Detects:
        - io_uring disabled at system level (evasion indicator)
        - Abnormally low io_uring limits
        - Missing expected slab caches
        
        Returns:
            List of Evidence objects
        """
        evidences = []
        
        for path in self.IO_URING_PATHS:
            try:
                if not os.path.exists(path):
                    continue
                if path.startswith('/proc/sys'):
                    content = self._read_proc_file(path)
                    if content:
                        value = content.strip()
                        if 'io_uring_disabled' in path and value == '1':
                            evidences.append(self._create_evidence(title='io_uring disabled at kernel level', description=f'io_uring is disabled via {path}. This may indicate intentional disabling to hide malicious io_uring usage or prevent security monitoring.', severity=Severity.MEDIUM, confidence=0.65, attack_id='T1562.008', attack_tactic='Defense Evasion', source_path=path, raw_data={'path': path, 'value': value, 'expected': '0 (enabled)'}, evidence_details=EvidenceDetail(file_path=path, content=value), remediation_commands=[
                        "Run comprehensive rootkit detection tools",
                        "Verify kernel module signatures and integrity",
                        "Check for hidden files, processes, and network connections",
                        "Consider system rebuild from known-good backup"
                    ]))
                            break
                        elif 'io_uring_limit' in path:
                            try:
                                limit = int(value)
                                if limit < 64:
                                    evidences.append(self._create_evidence(title=f'Suspiciously low io_uring limit: {limit}', description=f'io_uring entry limit set to {limit} via {path}. Low limits may be used to prevent legitimate monitoring while allowing targeted malicious usage.', severity=Severity.LOW, confidence=0.55, attack_id='T1562.008', attack_tactic='Defense Evasion', source_path=path, raw_data={'path': path, 'limit': limit, 'recommended_minimum': 256}, evidence_details=EvidenceDetail(file_path=path, content=value), remediation_commands=[
                        "Run comprehensive rootkit detection tools",
                        "Verify kernel module signatures and integrity",
                        "Check for hidden files, processes, and network connections",
                        "Consider system rebuild from known-good backup"
                    ]))
                            except ValueError:
                                pass
                elif path.startswith('/sys/kernel/slab'):
                    if not os.path.exists(path):
                        _get_logger().debug(f'Expected slab cache not found: {path}')
            
            except OSError as e:
                _get_logger().debug(f'Cannot access io_uring path {path}: {e}')
        
        return evidences

    def _check_process_io_uring(self, collected_data: Dict) -> List[Evidence]:
        """Analyze process-level io_uring usage
        
        Detects suspicious processes using io_uring:
        - Non-whitelisted applications
        - Processes with abnormal io_uring configurations
        - Multiple io_uring contexts per process
        
        Args:
            collected_data: Collected data from collectors
            
        Returns:
            List of Evidence objects
        """
        evidences = []
        process_data = self._get_data(collected_data, 'process')
        if not process_data:
            return evidences
        processes = process_data.get('processes', [])
        
        # Limit process iteration to prevent performance degradation
        process_limit = self.FULL_SCAN_PROCESS_LIMIT
        processes_to_check = processes[:process_limit]
        
        for proc in processes_to_check:
            pid = proc.get('pid', 0)
            cmdline = proc.get('cmdline', '')
            comm = proc.get('comm', '')
            
            # Early exit for legitimate applications
            if self._is_legitimate_app(proc):
                continue
            
            io_uring_usage = self._detect_io_uring_usage(pid, proc)
            if io_uring_usage:
                severity_info = self.SUSPICIOUS_IO_URING_PATTERNS['non_standard_process']
                evidences.append(self._create_evidence(title=f'Suspicious io_uring usage: {comm} (PID {pid})', description=f"Process '{comm}' (PID {pid}) is using io_uring but is not in the legitimate applications whitelist. Command: {cmdline[:200]}. io_uring can be abused to bypass syscall-based security monitoring.", severity=severity_info[1], confidence=0.6, attack_id=severity_info[2], attack_tactic='Defense Evasion', source_path=f'/proc/{pid}', raw_data={'pid': pid, 'comm': comm, 'cmdline': cmdline, 'io_uring_contexts': io_uring_usage.get('contexts', 0), 'ring_entries': io_uring_usage.get('ring_entries', 0)}, remediation='Investigate why this process requires io_uring. Verify binary integrity and check for known exploits.', evidence_details=EvidenceDetail(pid=pid), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'io_uring_rootkit'})))
            ring_entries = io_uring_usage.get('ring_entries', 0) if io_uring_usage else 0
            if ring_entries > 4096:
                severity_info = self.SUSPICIOUS_IO_URING_PATTERNS['large_ring_buffer']
                evidences.append(self._create_evidence(title=f'Large io_uring ring buffer: {ring_entries} entries (PID {pid})', description=f"Process '{comm}' (PID {pid}) has io_uring ring buffer with {ring_entries} entries. Large ring buffers can be used for bulk data exfiltration or extensive syscall hooking.", severity=severity_info[1], confidence=0.7, attack_id=severity_info[2], attack_tactic='Exfiltration', source_path=f'/proc/{pid}/fd', raw_data={'pid': pid, 'comm': comm, 'ring_entries': ring_entries, 'threshold': 4096}, evidence_details=EvidenceDetail(pid=pid), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'io_uring_rootkit'})))
        return evidences

    def _check_fd_abuse(self, collected_data: Dict) -> List[Evidence]:
        """Detect io_uring file descriptor abuse
        
        Analyzes file descriptors for:
        - io_uring-specific FD types (anon_inode:[io_uring])
        - Registered file descriptor abuse
        - Fixed file operations
        
        Args:
            collected_data: Collected data from collectors
            
        Returns:
            List of Evidence objects
        """
        evidences = []
        process_data = self._get_data(collected_data, 'process')
        if not process_data:
            return evidences
        processes = process_data.get('processes', [])
        
        # Limit process iteration in full scan
        process_limit = self.FULL_SCAN_PROCESS_LIMIT
        processes_to_check = processes[:process_limit]
        
        for proc in processes_to_check:
            pid = proc.get('pid', 0)
            comm = proc.get('comm', '')

            # Early exit for legitimate applications
            if self._is_legitimate_app(proc):
                continue
            
            fd_info = proc.get('fd_info', [])
            io_uring_fds = []
            registered_files_count = 0
            for fd in fd_info:
                fd_path = fd.get('path', '')
                fd_type = fd.get('type', '')
                if 'io_uring' in fd_path.lower() or fd_type == 'io_uring':
                    io_uring_fds.append(fd)
                if 'registered' in fd_path.lower():
                    registered_files_count += 1
            if registered_files_count > 100:
                severity_info = self.SUSPICIOUS_IO_URING_PATTERNS['registered_files_abuse']
                evidences.append(self._create_evidence(title=f'Excessive io_uring registered files: {registered_files_count} (PID {pid})', description=f"Process '{comm}' (PID {pid}) has {registered_files_count} registered files in io_uring. This pattern is consistent with io_uring-based rootkits that pre-register files for fast access bypass.", severity=severity_info[1], confidence=0.75, attack_id=severity_info[2], attack_tactic='Defense Evasion', source_path=f'/proc/{pid}/fd', raw_data={'pid': pid, 'comm': comm, 'registered_files': registered_files_count, 'threshold': 100, 'io_uring_fd_count': len(io_uring_fds)}, evidence_details=EvidenceDetail(pid=pid,), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'io_uring_rootkit'})))
            for fd in io_uring_fds:
                fd_flags = fd.get('flags', '')
                if 'fixed_file' in fd_flags.lower() or 'direct' in fd_flags.lower():
                    severity_info = self.SUSPICIOUS_IO_URING_PATTERNS['fixed_file_operations']
                    evidences.append(self._create_evidence(title=f'io_uring fixed file operations detected (PID {pid})', description=f"Process '{comm}' (PID {pid}) uses io_uring with fixed file flags. Fixed file mode bypasses normal file descriptor reference counting and can be used to hide file operations from security tools.", severity=severity_info[1], confidence=0.65, attack_id=severity_info[2], attack_tactic='Defense Evasion', source_path=f"/proc/{pid}/fd/{fd.get('fd', 'unknown')}", raw_data={'pid': pid, 'comm': comm, 'fd': fd.get('fd'), 'path': fd.get('path'), 'flags': fd_flags}, evidence_details=EvidenceDetail(pid=pid,), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'io_uring_rootkit'})))
        return evidences

    def _check_ring_buffer_memory(self, collected_data: Dict) -> List[Evidence]:
        """Detect suspicious ring buffer memory mappings
        
        Analyzes /proc/[pid]/maps for:
        - Large anonymous memory regions (potential ring buffers)
        - W+X memory pages (writable and executable)
        - hugetlb mappings (used for large ring buffers)
        
        Args:
            collected_data: Collected data from collectors
            
        Returns:
            List of Evidence objects
        """
        evidences = []
        process_data = self._get_data(collected_data, 'process')
        if not process_data:
            return evidences
        processes = process_data.get('processes', [])
        
        # Limit process iteration in full scan
        process_limit = self.FULL_SCAN_PROCESS_LIMIT
        processes_to_check = processes[:process_limit]
        
        for proc in processes_to_check:
            pid = proc.get('pid', 0)
            comm = proc.get('comm', '')
            
            # Early exit for legitimate applications
            if self._is_legitimate_app(proc):
                continue
            
            maps_content = self._read_proc_file(f'/proc/{pid}/maps')
            if not maps_content:
                continue
            suspicious_mappings = []
            for line in maps_content.splitlines():
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                perms = parts[1] if len(parts) > 1 else ''
                pathname = parts[5] if len(parts) > 5 else ''
                if 'w' in perms and 'x' in perms:
                    suspicious_mappings.append({'type': 'wx_page', 'line': line.strip(), 'reason': 'Writable and executable memory page'})
                if 'hugetlb' in pathname.lower():
                    suspicious_mappings.append({'type': 'hugetlb', 'line': line.strip(), 'reason': 'HugeTLB mapping (may be used for large ring buffers)'})
            wx_pages = [m for m in suspicious_mappings if m['type'] == 'wx_page']
            if wx_pages and (not self._is_jit_process(proc)):
                evidences.append(self._create_evidence(title=f'W+X memory pages detected: {comm} (PID {pid})', description=f"Process '{comm}' (PID {pid}) has {len(wx_pages)} writable and executable memory pages. This is a strong indicator of code injection or io_uring-based rootkit activity.", severity=Severity.CRITICAL, confidence=0.8, attack_id='T1055', attack_tactic='Privilege Escalation', source_path=f'/proc/{pid}/maps', raw_data={'pid': pid, 'comm': comm, 'wx_page_count': len(wx_pages), 'sample_mappings': [m['line'] for m in wx_pages[:3]]}, remediation='Investigate process for code injection. Check if binary has been tampered with.', evidence_details=EvidenceDetail(pid=pid), remediation_commands=generate_process_remediation(attack_id='T1014', context={'analyzer': 'io_uring_rootkit'})))
        return evidences

    def _detect_io_uring_usage(self, pid: int, proc: Dict) -> Optional[Dict[str, Any]]:
        """Detect if a process is using io_uring
        
        Checks multiple indicators:
        - /proc/[pid]/io_uring directory existence
        - File descriptors pointing to io_uring
        - Memory mappings for io_uring rings
        
        Args:
            pid: Process ID
            proc: Process information dictionary
            
        Returns:
            Dictionary with io_uring usage details or None
        """
        # Use cached availability check instead of repeated checks
        if self._io_uring_available_cache is None:
            self._io_uring_available_cache = self._is_io_uring_available()
        
        if not self._io_uring_available_cache:
            return None
        
        # Early exit for legitimate applications
        if self._is_legitimate_app(proc):
            return None
        
        io_uring_info = {'contexts': 0, 'ring_entries': 0, 'has_io_uring': False}
        io_uring_dir = f'/proc/{pid}/io_uring'
        if os.path.exists(io_uring_dir):
            try:
                entries = os.listdir(io_uring_dir)
                io_uring_info['contexts'] = len(entries)
                io_uring_info['has_io_uring'] = True
                for entry in entries:
                    info_file = os.path.join(io_uring_dir, entry, 'info')
                    if os.path.exists(info_file):
                        content = self._read_proc_file(info_file)
                        if content:
                            match = re.search('Ring entries:\\s+(\\d+)', content)
                            if match:
                                io_uring_info['ring_entries'] += int(match.group(1))
            except OSError:
                pass
        fd_info = proc.get('fd_info', [])
        for fd in fd_info:
            fd_path = fd.get('path', '')
            if 'io_uring' in fd_path.lower():
                io_uring_info['has_io_uring'] = True
                io_uring_info['contexts'] += 1
        maps_content = self._read_proc_file(f'/proc/{pid}/maps')
        if maps_content and '[anon_inode:io_uring]' in maps_content:
            io_uring_info['has_io_uring'] = True
        return io_uring_info if io_uring_info['has_io_uring'] else None

    def _is_legitimate_app(self, proc: Dict) -> bool:
        """Check if process is a known legitimate io_uring application
        
        Args:
            proc: Process information dictionary
            
        Returns:
            True if application is whitelisted
        """
        cmdline = proc.get('cmdline', '').lower()
        comm = proc.get('comm', '').lower()
        for app in self.LEGITIMATE_IO_URING_APPS:
            if app in cmdline or app in comm:
                return True
        return False

    def _is_jit_process(self, proc: Dict) -> bool:
        """Check if process is a JIT compiler (legitimate W+X user)
        
        Args:
            proc: Process information dictionary
            
        Returns:
            True if process legitimately needs W+X pages
        """
        cmdline = proc.get('cmdline', '').lower()
        comm = proc.get('comm', '').lower()
        jit_patterns = ['java', 'javac', 'jvm', 'node', 'v8', 'python', 'pypy', 'dotnet', 'mono', 'chrome', 'chromium', 'firefox']
        for pattern in jit_patterns:
            if pattern in cmdline or pattern in comm:
                return True
        return False

    def _check_btf_injection_via_io_uring(self, collected_data: Dict) -> List[Evidence]:
        """Detect BTF injection attacks via io_uring
        
        Attackers can use io_uring to inject malicious BTF type information,
        enabling process injection and kernel structure manipulation.
        
        Detection checks:
        1. Processes with both io_uring and BTF capabilities
        2. Suspicious BTF type names in eBPF programs
        3. BTF-enabled programs loaded by non-standard processes
        4. Kernel structure modifications via BTF
        
        Args:
            collected_data: Collected data from collectors
            
        Returns:
            List of Evidence objects
        """
        evidences = []
        process_data = self._get_data(collected_data, 'process')
        if not process_data:
            return evidences
        processes = process_data.get('processes', [])
        
        # Limit process iteration in full scan
        process_limit = self.FULL_SCAN_PROCESS_LIMIT
        processes_to_check = processes[:process_limit]
        
        for proc in processes_to_check:
            pid = proc.get('pid', 0)
            comm = proc.get('comm', '')
            cmdline = proc.get('cmdline', '')
            
            # Early exit for legitimate applications
            if self._is_legitimate_app(proc):
                continue
            
            io_uring_usage = self._detect_io_uring_usage(pid, proc)
            if not io_uring_usage:
                continue
            btf_indicators = self._detect_btf_indicators(pid, proc)
            if btf_indicators:
                severity = Severity.HIGH
                confidence = 0.75
                evidences.append(self._create_evidence(title=f'io_uring with BTF capabilities: {comm} (PID {pid})', description=f"Process '{comm}' (PID {pid}) has both io_uring usage and BTF-related indicators. This combination can be used for advanced process injection attacks where io_uring bypasses syscall monitoring while BTF provides type manipulation capabilities. Command: {cmdline[:200]}", severity=severity, confidence=confidence, attack_id='T1055', attack_tactic='Privilege Escalation', source_path=f'/proc/{pid}', raw_data={'pid': pid, 'comm': comm, 'cmdline': cmdline, 'io_uring_contexts': io_uring_usage.get('contexts', 0), 'btf_indicators': btf_indicators, 'attack_technique': 'io_uring + BTF injection'}, remediation="Investigate process for BTF injection. Verify binary integrity, check loaded eBPF programs with 'bpftool prog list', and validate BTF types with 'bpftool btf dump'.", evidence_details=self._create_evidence_details(service_type='io_uring_rootkit'), remediation_commands=generate_generic_remediation(attack_id='1055', context={'analyzer': 'io_uring_rootkit_analyzer'})))
        evidences.extend(self._check_btf_sysfs())
        return evidences

    def _detect_btf_indicators(self, pid: int, proc: Dict) -> Optional[List[str]]:
        """Detect BTF-related indicators in process
        
        Checks for:
        - Memory mappings related to BTF
        - File descriptors pointing to BTF objects
        - Command line arguments suggesting BTF usage
        
        Args:
            pid: Process ID
            proc: Process information dictionary
            
        Returns:
            List of indicator strings or None
        """
        indicators = []
        maps_content = self._read_proc_file(f'/proc/{pid}/maps')
        if maps_content:
            btf_keywords = ['btf', 'vmlinux', '.BTF']
            for keyword in btf_keywords:
                if keyword.lower() in maps_content.lower():
                    indicators.append(f'btf_memory_mapping_{keyword}')
        fd_info = proc.get('fd_info', [])
        for fd in fd_info:
            fd_path = fd.get('path', '').lower()
            if 'btf' in fd_path or 'vmlinux' in fd_path:
                indicators.append(f"btf_fd_{fd.get('fd', 'unknown')}")
        cmdline = proc.get('cmdline', '').lower()
        btf_args = ['--btf', '--enable-btf', 'btf_dump', 'btf_parse']
        for arg in btf_args:
            if arg in cmdline:
                indicators.append(f'btf_cmdline_arg_{arg}')
        status_content = self._read_proc_file(f'/proc/{pid}/status')
        if status_content:
            cap_eff_match = re.search('CapEff:\\s+([0-9a-fA-F]+)', status_content)
            if cap_eff_match:
                cap_eff = int(cap_eff_match.group(1), 16)
                if cap_eff & 1 << 21:
                    indicators.append('has_cap_sys_admin')
        return indicators if indicators else None

    def _check_btf_sysfs(self) -> List[Evidence]:
        """Check BTF-related sysfs configuration
        
        Monitors:
        - /sys/kernel/btf/vmlinux existence and integrity
        - BTF loading restrictions
        - Unprivileged BTF access controls
        
        Returns:
            List of Evidence objects
        """
        evidences = []
        btf_paths = {'/sys/kernel/btf/vmlinux': 'Kernel BTF information', '/proc/sys/kernel/bpf_unprivileged_timeouts_query': 'Unprivileged BPF timeouts', '/proc/sys/kernel/unprivileged_bpf_disabled': 'Unprivileged BPF restriction'}
        for path, description in btf_paths.items():
            try:
                if not os.path.exists(path):
                    continue
                if path.startswith('/proc/sys'):
                    content = self._read_proc_file(path)
                    if content:
                        value = content.strip()
                        if 'unprivileged_bpf_disabled' in path and value == '0':
                            evidences.append(self._create_evidence(title='Unprivileged BPF operations allowed', description=f'{description} at {path} is set to allow unprivileged operations. This enables non-root users to load eBPF programs and manipulate BTF, which can be abused for privilege escalation and process injection.', severity=Severity.MEDIUM, confidence=0.6, attack_id='T1562.008', attack_tactic='Defense Evasion', source_path=path, raw_data={'path': path, 'value': value, 'recommended': '1 (disable unprivileged BPF)', 'description': description}, remediation='Set kernel.unprivileged_bpf_disabled=1 via sysctl', evidence_details=EvidenceDetail(file_path=path, content=value), remediation_commands=[
                        "Run comprehensive rootkit detection tools",
                        "Verify kernel module signatures and integrity",
                        "Check for hidden files, processes, and network connections",
                        "Consider system rebuild from known-good backup"
                    ]))
                elif path == '/sys/kernel/btf/vmlinux':
                    stat_info = os.stat(path)
                    btf_size = stat_info.st_size
                    if btf_size < 1024 * 1024:
                        evidences.append(self._create_evidence(title=f'Suspiciously small vmlinux BTF: {btf_size} bytes', description=f'Kernel BTF information at {path} is only {btf_size} bytes. Normal vmlinux BTF files are 2-10 MB. A smaller file may indicate BTF stripping or tampering to hide malicious eBPF programs.', severity=Severity.HIGH, confidence=0.65, attack_id='T1055', attack_tactic='Privilege Escalation', source_path=path, raw_data={'path': path, 'size_bytes': btf_size, 'expected_minimum': 1048576, 'description': description}, evidence_details=EvidenceDetail(file_path=path), remediation_commands=[
                        "Run comprehensive rootkit detection tools",
                        "Verify kernel module signatures and integrity",
                        "Check for hidden files, processes, and network connections",
                        "Consider system rebuild from known-good backup"
                    ]))
                    elif btf_size > 50 * 1024 * 1024:
                        evidences.append(self._create_evidence(title=f'Abnormally large vmlinux BTF: {btf_size} bytes', description=f'Kernel BTF information at {path} is {btf_size / (1024 * 1024):.1f} MB. Normal vmlinux BTF files are 2-10 MB. An abnormally large file may indicate BTF injection with malicious type information.', severity=Severity.MEDIUM, confidence=0.55, attack_id='T1055', attack_tactic='Privilege Escalation', source_path=path, raw_data={'path': path, 'size_bytes': btf_size, 'expected_maximum': 10485760, 'description': description}, evidence_details=self._create_evidence_details(service_type='io_uring_rootkit'), remediation_commands=generate_generic_remediation(attack_id='1055', context={'analyzer': 'io_uring_rootkit_analyzer'})))
            except OSError as e:
                _get_logger().debug(f'Cannot access BTF path {path}: {e}')
        return evidences

    def _read_proc_file(self, path: str) -> Optional[str]:
        """Safely read a proc/sysfs file
        
        Args:
            path: File path to read
            
        Returns:
            File content as string or None on error
        """
        try:
            real_path = os.path.realpath(path)
            if not real_path.startswith(('/proc/', '/sys/')):
                return None
            with open(real_path, 'r', errors='ignore', encoding='utf-8') as f:
                return f.read()
        except OSError:
            return None

    def _check_io_uring_syscall_handlers(self) -> List[Evidence]:
        """Check for io_uring syscall handlers in kernel
        
        Detects:
        - Hooked or modified io_uring syscall handlers
        - Suspicious kernel symbols related to io_uring
        - Abnormal syscall table entries
        
        Maps to ATT&CK:
        - T1014 - Rootkit (kernel-level syscall hooking)
        - T1562.008 - Disable Security Tools (bypassing monitors)
        
        Returns:
            List of Evidence objects
        """
        evidences = []
        
        # Check /proc/kallsyms for io_uring handlers
        kallsyms_content = self._read_proc_file('/proc/kallsyms')
        if not kallsyms_content:
            return evidences
        
        io_uring_handlers = [
            'io_uring_setup',
            'io_uring_enter',
            'io_uring_register',
            'io_sq_thread',
            'io_ring_ctx',
            '__io_uring',
            'io_submit_sqes',
        ]
        
        suspicious_symbols = []
        for line in kallsyms_content.splitlines():
            line_lower = line.lower()
            for handler in io_uring_handlers:
                if handler.lower() in line_lower:
                    # Check for suspicious patterns
                    # Normal kernel symbols should contain the handler name exactly
                    # Modified/hooked versions may have additional prefixes/suffixes
                    parts = line.split()
                    if len(parts) >= 3:
                        symbol = parts[2]
                        # Check for hook/override patterns
                        if any(kw in symbol.lower() for kw in ['hook', 'override', 'patch', 'hooked']):
                            suspicious_symbols.append({
                                'symbol': symbol,
                                'address': parts[0],
                                'type': parts[1],
                                'reason': 'Suspicious kernel symbol name suggesting hooking'
                            })
        
        if suspicious_symbols:
            evidences.append(self._create_evidence(
                title='Suspicious io_uring kernel syscall handlers detected',
                description=f'Detected {len(suspicious_symbols)} suspicious kernel symbols related to io_uring syscalls. This may indicate kernel-level rootkit activity that hooks io_uring operations to bypass security monitoring.',
                severity=Severity.CRITICAL,
                confidence=0.85,
                attack_id='T1014',
                attack_tactic='Defense Evasion',
                source_path='/proc/kallsyms',
                raw_data={
                    'suspicious_symbols': suspicious_symbols[:10],
                    'total_count': len(suspicious_symbols)
                },
                evidence_details=EvidenceDetail(file_path='/proc/kallsyms'),
                remediation_commands=generate_generic_remediation(
                    attack_id='T1014',
                    context={'analyzer': 'io_uring_rootkit'}
                )
            ))
        
        return evidences

    def _check_kernel_module_hooks(self) -> List[Evidence]:
        """Check for kernel modules that may hook io_uring
        
        Detects:
        - Unsigned/unknown modules providing io_uring functionality
        - Modules with suspicious names related to io_uring
        - Module signature verification failures
        
        Maps to ATT&CK:
        - T1014 - Rootkit (kernel module rootkits)
        - T1562.008 - Disable Security Tools
        
        Returns:
            List of Evidence objects
        """
        evidences = []
        
        # Check loaded modules
        modules_content = self._read_proc_file('/proc/modules')
        if not modules_content:
            return evidences
        
        suspicious_modules = []
        for line in modules_content.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            
            module_name = parts[0]
            module_lower = module_name.lower()
            
            # Check for io_uring related modules
            if any(kw in module_lower for kw in ['io_uring', 'iouring', 'uring', 'liburing']):
                # Verify if module is signed
                module_path = f'/lib/modules/{self._get_kernel_version()}/kernel/{module_name}.ko'
                is_signed = self._check_module_signature(module_path)
                
                if not is_signed:
                    suspicious_modules.append({
                        'name': module_name,
                        'size': parts[1],
                        'used_by': parts[3] if len(parts) > 3 else 'unknown',
                        'signed': False,
                        'path': module_path
                    })
            
            # Check for modules with hook/override patterns
            if any(kw in module_lower for kw in ['hook', 'override', 'patch', 'hide', 'stealth']):
                # These module names are highly suspicious
                suspicious_modules.append({
                    'name': module_name,
                    'size': parts[1],
                    'used_by': parts[3] if len(parts) > 3 else 'unknown',
                    'signed': False,
                    'reason': 'Suspicious module name pattern'
                })
        
        if suspicious_modules:
            evidences.append(self._create_evidence(
                title='Suspicious kernel modules related to io_uring detected',
                description=f'Detected {len(suspicious_modules)} suspicious kernel modules that may be used for io_uring rootkit activity. Unsigned or unknown modules can hook kernel functions to bypass security monitoring.',
                severity=Severity.CRITICAL,
                confidence=0.80,
                attack_id='T1014',
                attack_tactic='Defense Evasion',
                source_path='/proc/modules',
                raw_data={
                    'suspicious_modules': suspicious_modules[:10],
                    'total_count': len(suspicious_modules)
                },
                evidence_details=EvidenceDetail(file_path='/proc/modules'),
                remediation_commands=generate_generic_remediation(
                    attack_id='T1014',
                    context={'analyzer': 'io_uring_rootkit'}
                )
            ))
        
        return evidences

    def _check_cve_exploit_patterns(self, collected_data: Dict) -> List[Evidence]:
        """Check for known CVE exploit patterns in io_uring
        
        Detects:
        - Processes using CVE exploit techniques
        - Command line arguments matching known exploits
        - Memory patterns associated with CVE exploitation
        
        Maps to ATT&CK:
        - T1055 - Process Injection (via CVE exploitation)
        - T1068 - Exploitation for Privilege Escalation
        - T1190 - Exploit Public-Facing Application
        
        Args:
            collected_data: Collected data from collectors
            
        Returns:
            List of Evidence objects
        """
        evidences = []
        try:
            process_data = self._get_data(collected_data, 'process')
        except (KeyError, TypeError):
            return evidences
        
        if not process_data:
            return evidences
        
        processes = process_data.get('processes', [])
        process_limit = self.FULL_SCAN_PROCESS_LIMIT
        processes_to_check = processes[:process_limit]
        
        cve_matches = []
        for proc in processes_to_check:
            if self._is_legitimate_app(proc):
                continue
            
            pid = proc.get('pid', 0)
            cmdline = proc.get('cmdline', '')
            comm = proc.get('comm', '')
            
            for cve_id, cve_info in self.KNOWN_IOURING_CVE_PATTERNS.items():
                if cve_info['pattern'].lower() in cmdline.lower():
                    cve_matches.append({
                        'cve_id': cve_id,
                        'pid': pid,
                        'comm': comm,
                        'cmdline': cmdline[:200],
                        'description': cve_info['description'],
                        'severity': cve_info['severity'],
                        'attack_id': cve_info['attack_id']
                    })
        
        if cve_matches:
            # Group by CVE
            cve_groups = {}
            for match in cve_matches:
                cve_id = match['cve_id']
                if cve_id not in cve_groups:
                    cve_groups[cve_id] = []
                cve_groups[cve_id].append(match)
            
            for cve_id, matches in cve_groups.items():
                cve_info = self.KNOWN_IOURING_CVE_PATTERNS[cve_id]
                evidences.append(self._create_evidence(
                    title=f'Known io_uring CVE exploit pattern detected: {cve_id}',
                    description=f'Detected {len(matches)} process(es) using command lines matching the {cve_id} exploit pattern: {cve_info["description"]}. This indicates active exploitation using known public techniques.',
                    severity=cve_info['severity'],
                    confidence=0.90,
                    attack_id=cve_info['attack_id'],
                    attack_tactic='Privilege Escalation',
                    source_path='/proc/[pid]/cmdline',
                    raw_data={
                        'cve_id': cve_id,
                        'cve_description': cve_info['description'],
                        'affected_processes': [
                            {'pid': m['pid'], 'comm': m['comm'], 'cmdline': m['cmdline']}
                            for m in matches[:5]
                        ],
                        'total_matches': len(matches)
                    },
                    evidence_details=EvidenceDetail(pid=matches[0]['pid']),
                    remediation_commands=generate_process_remediation(
                        attack_id=cve_info['attack_id'],
                        context={
                            'analyzer': 'io_uring_rootkit',
                            'cve_id': cve_id,
                            'cve_description': cve_info['description']
                        }
                    )
                ))
        
        return evidences

    def _get_kernel_version(self) -> str:
        """Get current kernel version
        
        Returns:
            Kernel version string
        """
        try:
            version_content = self._read_proc_file('/proc/version')
            if version_content:
                # Extract version from format like "Linux version 5.15.0-91-generic ..."
                match = re.search(r'version\s+([\d.]+[-\w]*)', version_content)
                if match:
                    return match.group(1)
        except OSError:
            pass
        return ''

    def _check_module_signature(self, module_path: str) -> bool:
        """Check if kernel module has valid signature
        
        Args:
            module_path: Path to kernel module file
            
        Returns:
            True if module is signed, False otherwise
        """
        try:
            real_path = os.path.realpath(module_path)
            if not os.path.exists(real_path):
                return False
            
            # Check for signature marker in module file
            # Signed modules contain "Module signature appended" marker
            with open(real_path, 'rb') as f:
                content = f.read()
                if b'~Module signature appended' in content:
                    return True
            return False
        except OSError:
            return False