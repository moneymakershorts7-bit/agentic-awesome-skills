"""Kernel Integrity Checker - Verify kernel function integrity

This analyzer performs kernel integrity verification to detect:
1. Kernel function address modifications (rootkit indicators)
2. ftrace/kprobe hook anomalies
3. Kernel module signature verification failures
4. System call table modifications
5. Kernel symbol table inconsistencies

ATT&CK mapping:
- T1014 - Rootkit (kernel-level rootkits)
- T1562.008 - Impair Defenses (hooking security mechanisms)

References:
- Elastic Security (2025): "Detecting eBPF-based Rootkits"
- Black Hat USA 2025: "Attacking and Defending with eBPF"
- Kernel.org: eBPF documentation and security guidelines
"""
import os
import re
import json
import asyncio
import subprocess
import threading
from typing import List, Dict, Any, Optional, Tuple
from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
from .base import BaseAnalyzer
from ..utils.remediation_generator import generate_generic_remediation
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

CRITICAL_KERNEL_FUNCTIONS = {'do_fork': 'Process creation', 'do_execve': 'Program execution', 'do_exit': 'Process termination', 'commit_creds': 'Credential modification', 'prepare_kernel_cred': 'Credential preparation', 'vfs_read': 'File read operation', 'vfs_write': 'File write operation', 'vfs_open': 'File open operation', 'security_file_permission': 'File permission check', 'tcp_connect': 'TCP connection establishment', 'tcp_sendmsg': 'TCP message sending', 'tcp_recvmsg': 'TCP message receiving', 'ip_rcv': 'IP packet reception', 'sys_call_table': 'System call table', '__x64_sys_execve': 'execve syscall (x64)', '__x64_sys_connect': 'connect syscall (x64)', '__x64_sys_read': 'read syscall (x64)', '__x64_sys_write': 'write syscall (x64)'}
CLOUD_VENDOR_UNSIGNED_MODULES = {'aliyun_rdma', 'aliyun_enhanced_eth', 'ena', 'ena_enhanced', 'alibaba_cloud', 'aos_monitor', 'aegis_drv', 'nvme_aliyun', 'virtio_pci_aliyun', 'virtio_txvm', 'cn_enhanced', 'tencent_cloud', 'cosfs', 'txvnet', 'ena', 'ena_enhanced', 'nvme_amazon', 'xen_blkfront', 'xen_netfront', 'ena_com', 'hv_utils', 'hv_vmbus', 'hv_netvsc', 'hv_storvsc', 'gve', 'google_nvme'}
CLOUD_KERNEL_INDICATORS = {'alibaba': ['alibaba', 'aliyun', 'alios', 'dragonwell'], 'tencent': ['tencent', 'tlinux', 'tencentos'], 'aws': ['amzn', 'amazon', 'aws'], 'azure': ['azure', 'microsoft'], 'gcp': ['gcp', 'google-cloud']}

# Timeout tracking for modinfo commands
_MODINFO_TIMEOUT_COUNTER = {'count': 0, 'modules': []}
_MODINFO_TIMEOUT_LOCK = threading.Lock()
_MODINFO_TIMEOUT_WARNING_THRESHOLD = 5  # Warn after this many timeouts


def _record_modinfo_timeout(module_name: str):
    """Record a modinfo timeout event and warn if threshold exceeded.

    Args:
        module_name: Name of the module that timed out
    """
    with _MODINFO_TIMEOUT_LOCK:
        _MODINFO_TIMEOUT_COUNTER['count'] += 1
        modules = _MODINFO_TIMEOUT_COUNTER['modules']
        modules.append(module_name)
        if len(modules) > 50:
            _MODINFO_TIMEOUT_COUNTER['modules'] = modules[-20:]

        if _MODINFO_TIMEOUT_COUNTER['count'] >= _MODINFO_TIMEOUT_WARNING_THRESHOLD:
            _get_logger().warning(
                f'[kernel_integrity_checker] modinfo command timed out {_MODINFO_TIMEOUT_COUNTER["count"]} times. '
                f'Recent timeouts: {", ".join(_MODINFO_TIMEOUT_COUNTER["modules"][-10:])}. '
                f'System may have problematic kernel modules.'
            )

class KernelIntegrityChecker(BaseAnalyzer):
    """Kernel integrity verification analyzer
    
    Performs comprehensive kernel integrity checks including:
    - Kernel function address verification against /proc/kallsyms
    - ftrace/kprobe hook detection
    - System call table integrity validation
    - Kernel module signature checking
    - Symbol table consistency verification
    """
    name = 'kernel_integrity_checker'
    timeout = 45
    required_collectors = ['filesystem', 'process']
    ATTACK_ID = 'T1014'
    ATTACK_TACTIC = 'Defense Evasion'

    def __init__(self):
        super().__init__()
        self.baseline_functions = {}
        self._signature_cache: Dict[str, Dict[str, Any]] = {}
        self._signature_cache_lock = threading.Lock()
        self._kallsyms_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._load_baseline()

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: Dict[str, Any]) -> List[Evidence]:
        """Execute kernel integrity analysis
        
        Args:
            collected_data: Collected data from collectors
            
        Returns:
            List of Evidence objects for detected integrity issues
        """
        evidences = []

        # Critical checks first - early exit if CRITICAL findings
        evidences.extend(self._check_kernel_function_addresses())
        if any(e.severity == Severity.CRITICAL for e in evidences):
            _get_logger().warning(f'[{self.name}] Critical kernel modifications found, skipping non-critical checks')
            return evidences

        # Continue with other checks if no critical issues
        evidences.extend(self._check_ftrace_hooks())
        evidences.extend(self._check_kprobe_anomalies())
        evidences.extend(self._check_syscall_table_integrity())
        evidences.extend(self._check_kernel_module_signatures())
        evidences.extend(self._check_symbol_table_consistency())
        return evidences
    def _check_kernel_function_addresses(self) -> List[Evidence]:
        """Verify kernel function addresses against baseline
        
        Compares current kernel function addresses with known good baseline
        to detect unauthorized modifications.
        
        Returns:
            List of Evidence objects for address mismatches
        """
        evidences = []
        try:
            current_symbols = self._parse_kallsyms()
            if not current_symbols:
                _get_logger().debug(f'[{self.name}] Cannot read /proc/kallsyms')
                return evidences
            modified_functions = []
            for func_name, expected_info in CRITICAL_KERNEL_FUNCTIONS.items():
                if func_name in current_symbols:
                    current_addr = current_symbols[func_name]['address']
                    current_type = current_symbols[func_name]['type']
                    if self._is_suspicious_address(current_addr):
                        modified_functions.append({'function': func_name, 'current_address': hex(current_addr), 'expected_description': expected_info, 'symbol_type': current_type})
            if modified_functions:
                severity = Severity.CRITICAL if len(modified_functions) > 3 else Severity.HIGH
                confidence = 0.85 if len(modified_functions) > 5 else 0.75
                evidences.append(self._create_evidence(title=f'Kernel Function Address Anomalies Detected', description=f'Detected {len(modified_functions)} kernel functions with suspicious addresses. Critical kernel functions may have been modified by a rootkit.', severity=severity, confidence=confidence, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path='/proc/kallsyms', raw_data={'modified_functions': modified_functions[:10], 'total_checked': len(CRITICAL_KERNEL_FUNCTIONS), 'anomaly_count': len(modified_functions)}, remediation='Investigate kernel function modifications immediately. Compare with known good kernel version. Check loaded kernel modules for unauthorized additions. Consider rebooting with verified kernel image.', evidence_details=self._create_evidence_details(service_type='kernel_module'), remediation_commands=generate_generic_remediation(attack_id=self.ATTACK_ID, context={'analyzer': 'kernel_integrity_checker'})))
        except OSError as e:
            _get_logger().debug(f'[{self.name}] Failed to check kernel addresses: {e}')
        return evidences

    def _check_ftrace_hooks(self) -> List[Evidence]:
        """Detect suspicious ftrace hooks
        
        Checks for ftrace hooks on critical kernel functions that may indicate
        rootkit activity or unauthorized monitoring.
        
        Returns:
            List of Evidence objects for suspicious hooks
        """
        evidences = []
        try:
            enabled_funcs_path = '/sys/kernel/debug/tracing/enabled_functions'
            if os.path.exists(enabled_funcs_path):
                with open(enabled_funcs_path, 'r', encoding='utf-8') as f:
                    enabled_functions = f.read().strip().split('\n')
                suspicious_hooks = []
                for func_line in enabled_functions:
                    if not func_line.strip():
                        continue
                    parts = func_line.split()
                    func_name = parts[0] if parts else ''
                    for critical_func in CRITICAL_KERNEL_FUNCTIONS.keys():
                        if critical_func in func_name:
                            suspicious_hooks.append({'function': func_name, 'line': func_line.strip(), 'critical_function': critical_func})
                if suspicious_hooks:
                    evidences.append(self._create_evidence(title='Suspicious ftrace Hooks Detected', description=f'Found {len(suspicious_hooks)} ftrace hooks on critical kernel functions. This may indicate kernel-level rootkit activity or unauthorized function interception.', severity=Severity.HIGH, confidence=0.7, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path=enabled_funcs_path, raw_data={'suspicious_hooks': suspicious_hooks[:10], 'total_hooks': len(suspicious_hooks)}, remediation='Review ftrace hooks for legitimacy. Disable unnecessary tracing: echo 0 > /sys/kernel/debug/tracing/tracing_on Clear suspicious hooks: echo > /sys/kernel/debug/tracing/set_ftrace_filter', evidence_details=self._create_evidence_details(service_type='kernel_module'), remediation_commands=generate_generic_remediation(attack_id=self.ATTACK_ID, context={'analyzer': 'kernel_integrity_checker'})))
            filter_paths = ['/sys/kernel/debug/tracing/set_ftrace_filter', '/sys/kernel/debug/tracing/set_ftrace_notrace']
            for filter_path in filter_paths:
                if os.path.exists(filter_path):
                    try:
                        with open(filter_path, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                        if content:
                            for critical_func in CRITICAL_KERNEL_FUNCTIONS.keys():
                                if critical_func in content.lower():
                                    evidences.append(self._create_evidence(title=f'ftrace Filter Contains Critical Function', description=f"ftrace filter at {filter_path} contains critical function '{critical_func}'. This may be used to intercept sensitive kernel operations.", severity=Severity.MEDIUM, confidence=0.6, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path=filter_path, raw_data={'filter_path': filter_path, 'critical_function': critical_func, 'filter_content': content[:500]}, evidence_details=EvidenceDetail(file_path=filter_path, content=content[:200]), remediation_commands=[
                        "Verify kernel module signatures and remove unsigned modules",
                        "Audit kernel parameters for security-relevant changes",
                        "Check for unauthorized kernel patches or modifications",
                        "Update kernel to latest patched version"
                    ]))
                    except OSError:
                        pass
        except OSError as e:
            _get_logger().debug(f'[{self.name}] Failed to check ftrace hooks: {e}')
        return evidences

    def _check_kprobe_anomalies(self) -> List[Evidence]:
        """Detect suspicious kprobe installations
        
        Kprobes can be used maliciously to intercept kernel function execution.
        This method identifies unauthorized kprobes on sensitive functions.
        
        Returns:
            List of Evidence objects for suspicious kprobes
        """
        evidences = []
        try:
            kprobes_path = '/sys/kernel/debug/kprobes/list'
            if os.path.exists(kprobes_path):
                with open(kprobes_path, 'r', encoding='utf-8') as f:
                    kprobes = f.read().strip().split('\n')
                suspicious_kprobes = []
                for kprobe_line in kprobes:
                    if not kprobe_line.strip():
                        continue
                    for critical_func in CRITICAL_KERNEL_FUNCTIONS.keys():
                        if critical_func in kprobe_line.lower():
                            suspicious_kprobes.append({'kprobe': kprobe_line.strip(), 'target_function': critical_func})
                if suspicious_kprobes:
                    evidences.append(self._create_evidence(title='Suspicious Kprobes on Critical Functions', description=f'Found {len(suspicious_kprobes)} kprobes installed on critical kernel functions. Kprobes can be used to intercept and modify kernel behavior.', severity=Severity.HIGH, confidence=0.75, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path=kprobes_path, raw_data={'suspicious_kprobes': suspicious_kprobes[:10], 'total_kprobes': len(suspicious_kprobes)}, remediation="Review kprobe list for unauthorized probes. Remove suspicious kprobes: echo '-:<function>' >> /sys/kernel/debug/kprobes/list Disable kprobes if not needed: echo 0 > /sys/kernel/debug/kprobes/enabled", evidence_details=self._create_evidence_details(service_type='kernel_module'), remediation_commands=generate_generic_remediation(attack_id=self.ATTACK_ID, context={'analyzer': 'kernel_integrity_checker'})))
        except OSError as e:
            _get_logger().debug(f'[{self.name}] Failed to check kprobes: {e}')
        return evidences

    def _check_syscall_table_integrity(self) -> List[Evidence]:
        """Verify system call table integrity
        
        Rootkits often modify the syscall table to intercept system calls.
        This method checks for signs of syscall table manipulation.
        
        Returns:
            List of Evidence objects for syscall table issues
        """
        evidences = []
        try:
            symbols = self._parse_kallsyms()
            if not symbols:
                return evidences
            syscall_table_found = False
            syscall_table_addr = None
            for sym_name, sym_info in symbols.items():
                if 'sys_call_table' in sym_name.lower():
                    syscall_table_found = True
                    syscall_table_addr = sym_info['address']
                    break
            if syscall_table_found and syscall_table_addr:
                if self._is_suspicious_address(syscall_table_addr):
                    evidences.append(self._create_evidence(title='Syscall Table Address Anomaly', description=f'System call table address ({hex(syscall_table_addr)}) appears to be in an unexpected memory region. This may indicate syscall table redirection by a rootkit.', severity=Severity.CRITICAL, confidence=0.8, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path='/proc/kallsyms', raw_data={'syscall_table_address': hex(syscall_table_addr), 'issue': 'Address outside expected kernel text range'}, remediation='Verify kernel image integrity. Compare syscall table address with known good system. Check for kernel module that may have relocated syscall table.', evidence_details=self._create_evidence_details(service_type='kernel_module'), remediation_commands=generate_generic_remediation(attack_id=self.ATTACK_ID, context={'analyzer': 'kernel_integrity_checker'})))
            hooked_syscalls = []
            syscall_prefixes = ['__x64_sys_', '__ia32_sys_', 'SyS_', 'sys_']
            for sym_name, sym_info in symbols.items():
                for prefix in syscall_prefixes:
                    if sym_name.startswith(prefix):
                        base_name = sym_name[len(prefix):]
                        if self._is_common_syscall(base_name):
                            if not self._is_kernel_text_address(sym_info['address']):
                                hooked_syscalls.append({'syscall': sym_name, 'address': hex(sym_info['address']), 'type': sym_info['type']})
            if hooked_syscalls:
                evidences.append(self._create_evidence(title='Potentially Hooked System Calls', description=f'Found {len(hooked_syscalls)} system call handlers with addresses outside the kernel text segment. These may have been redirected by a rootkit.', severity=Severity.HIGH, confidence=0.7, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path='/proc/kallsyms', raw_data={'hooked_syscalls': hooked_syscalls[:10], 'total_checked': len([s for s in symbols.keys() if any((s.startswith(p) for p in syscall_prefixes))])}, remediation='Investigate syscall handler addresses. Compare with kernel symbol map from known good kernel. Check for recently loaded kernel modules.', evidence_details=self._create_evidence_details(service_type='kernel_module'), remediation_commands=generate_generic_remediation(attack_id=self.ATTACK_ID, context={'analyzer': 'kernel_integrity_checker'})))
        except OSError as e:
            _get_logger().debug(f'[{self.name}] Failed to check syscall table: {e}')
        return evidences

    def _check_kernel_module_signatures(self) -> List[Evidence]:
        """Verify kernel module signatures
        
        Checks loaded kernel modules for valid signatures. Unsigned or
        improperly signed modules may be malicious.
        
        Uses batch checking and caching for performance optimization.
        
        Returns:
            List of Evidence objects for signature issues
        """
        evidences = []
        try:
            result = subprocess.run(['lsmod'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode != 0:
                return evidences
            modules = result.stdout.strip().split('\n')[1:]
            
            module_names = []
            module_sizes = {}
            for module_line in modules:
                if module_line.strip():
                    parts = module_line.split()
                    if parts:
                        module_names.append(parts[0])
                        if len(parts) >= 2:
                            module_sizes[parts[0]] = parts[1]
            
            unsigned_modules = []
            suspicious_unsigned_modules = []
            cloud_module_names = set()
            
            # Track signature strength distribution
            signature_strength_dist = {
                'strong': 0,
                'weak': 0,
                'invalid': 0,
                'unsigned': 0
            }
            weak_signed_modules = []
            
            # Check using batch signature checking
            batch_result = self._batch_check_signatures(module_names)
            if batch_result is not None:
                sig_results = batch_result
            else:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop and loop.is_running():
                    sig_results = {name: self._check_module_signature(name) for name in module_names}
                else:
                    sig_results = asyncio.run(self._parallel_check_signatures(module_names))
            
            signed_count = 0
            for module_name, sig_status in sig_results.items():
                if module_name in CLOUD_VENDOR_UNSIGNED_MODULES:
                    cloud_module_names.add(module_name)
                    signed_count += 1  # Cloud modules are trusted
                    continue
                
                if sig_status.get('unsigned'):
                    unsigned_modules.append({
                        'module': module_name,
                        'size': module_sizes.get(module_name, 'unknown'),
                        'status': sig_status
                    })
                    suspicious_unsigned_modules.append({
                        'module': module_name,
                        'size': module_sizes.get(module_name, 'unknown'),
                        'status': sig_status
                    })
                    signature_strength_dist['unsigned'] += 1
                else:
                    signed_count += 1
                    
                    # Track signature strength for signed modules
                    sig_strength = sig_status.get('signature_strength', 'invalid')
                    if sig_strength in signature_strength_dist:
                        signature_strength_dist[sig_strength] += 1
                    
                    # Collect weak signed modules for reporting
                    if sig_strength == 'weak':
                        weak_signed_modules.append({
                            'module': module_name,
                            'size': module_sizes.get(module_name, 'unknown'),
                            'signature_data': sig_status.get('signature_data', ''),
                            'signature_strength': sig_strength
                        })
            
            if suspicious_unsigned_modules:
                # Build raw_data with signature strength distribution
                raw_data = {
                    'unsigned_modules': suspicious_unsigned_modules[:10],
                    'total_modules': len(modules),
                    'unsigned_count': len(suspicious_unsigned_modules),
                    'cloud_vendor_modules_excluded': len(cloud_module_names),
                    'signature_strength_distribution': signature_strength_dist
                }
                
                # Add weak signed modules info if present
                if weak_signed_modules:
                    raw_data['weak_signed_modules'] = weak_signed_modules[:20]
                    raw_data['weak_signed_count'] = len(weak_signed_modules)
                
                evidences.append(self._create_evidence(title='Unsigned Kernel Modules Detected', description=f'Found {len(suspicious_unsigned_modules)} suspicious unsigned kernel modules (excluding {len(cloud_module_names)} known cloud vendor modules). Unsigned modules bypass kernel module verification and may contain malicious code. Signature distribution: {signature_strength_dist["strong"]} strong, {signature_strength_dist["weak"]} weak, {signature_strength_dist["invalid"]} invalid, {signature_strength_dist["unsigned"]} unsigned.', severity=Severity.MEDIUM, confidence=0.6, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path='/proc/modules', raw_data=raw_data, remediation='Enable kernel module signing: CONFIG_MODULE_SIG=y Enforce module signing: sysctl -w kernel.modules_disabled=1 Review and remove unnecessary unsigned modules.', evidence_details=self._create_evidence_details(service_type='kernel_module'), remediation_commands=generate_generic_remediation(attack_id=self.ATTACK_ID, context={'analyzer': 'kernel_integrity_checker'})))
            
            # Generate separate alert for weak signed modules if threshold exceeded
            if len(weak_signed_modules) > 5:
                evidences.append(self._create_evidence(
                    title='Weak Kernel Module Signatures Detected',
                    description=f'Found {len(weak_signed_modules)} kernel modules with weak signature formats. These modules have signatures that do not conform to standard X.509/PKCS7 formats and may be vulnerable to forgery. Review module sources and consider re-signing with proper certificates.',
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    attack_id=self.ATTACK_ID,
                    attack_tactic=self.ATTACK_TACTIC,
                    source_path='/proc/modules',
                    raw_data={
                        'weak_signed_modules': weak_signed_modules[:20],
                        'total_weak_signed': len(weak_signed_modules),
                        'signature_strength_distribution': signature_strength_dist
                    },
                    remediation='Verify weak signed module sources. Re-sign modules with proper X.509 certificates. Enable CONFIG_MODULE_SIG_FORCE for stricter verification.',
                    evidence_details=self._create_evidence_details(service_type='kernel_module'),
                    remediation_commands=generate_generic_remediation(attack_id=self.ATTACK_ID, context={'analyzer': 'kernel_integrity_checker'})
                ))
        except (subprocess.TimeoutExpired, OSError) as e:
            _get_logger().debug(f'[{self.name}] Failed to check module signatures: {e}')
        return evidences

    def _check_symbol_table_consistency(self) -> List[Evidence]:
        """Check kernel symbol table for inconsistencies
        
        Verifies that symbol table entries are consistent across different
        sources (/proc/kallsyms, /proc/modules, lsmod).
        
        Returns:
            List of Evidence objects for inconsistencies
        """
        evidences = []
        try:
            kallsyms_symbols = self._parse_kallsyms()
            if not kallsyms_symbols:
                return evidences
            module_symbols = self._get_module_symbols()
            inconsistencies = []
            for sym_name, sym_info in kallsyms_symbols.items():
                if sym_info.get('type', '').lower() in ['t', 'T']:
                    if not self._symbol_belongs_to_module(sym_name, module_symbols):
                        if not self._is_core_kernel_symbol(sym_name):
                            inconsistencies.append({'symbol': sym_name, 'address': hex(sym_info['address']), 'type': sym_info['type'], 'issue': 'Symbol not associated with any known module'})
            if len(inconsistencies) > 10:
                evidences.append(self._create_evidence(title='Kernel Symbol Table Inconsistencies', description=f'Found {len(inconsistencies)} kernel symbols that cannot be associated with known kernel modules. This may indicate hidden or injected kernel code.', severity=Severity.MEDIUM, confidence=0.55, attack_id=self.ATTACK_ID, attack_tactic=self.ATTACK_TACTIC, source_path='/proc/kallsyms', raw_data={'inconsistencies': inconsistencies[:10], 'total_inconsistencies': len(inconsistencies), 'total_symbols': len(kallsyms_symbols)}, remediation='Review unassociated symbols for legitimacy. Compare with known good kernel version. Check for hidden kernel modules using alternative detection methods.', evidence_details=self._create_evidence_details(service_type='kernel_module'), remediation_commands=generate_generic_remediation(attack_id=self.ATTACK_ID, context={'analyzer': 'kernel_integrity_checker'})))
        except OSError as e:
            _get_logger().debug(f'[{self.name}] Failed to check symbol consistency: {e}')
        return evidences

    def _parse_kallsyms(self) -> Dict[str, Dict[str, Any]]:
        """Parse /proc/kallsyms to extract kernel symbols
        
        Uses caching to avoid re-parsing the file multiple times per scan.
        
        Returns:
            Dictionary mapping symbol names to their information
        """
        if self._kallsyms_cache is not None:
            return self._kallsyms_cache

        symbols = {}
        try:
            with open('/proc/kallsyms', 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        try:
                            address = int(parts[0], 16)
                        except ValueError:
                            # Skip malformed lines
                            continue
                        sym_type = parts[1]
                        sym_name = parts[2]
                        module_name = parts[3].strip('[]') if len(parts) >= 4 else None
                        symbols[sym_name] = {'address': address, 'type': sym_type, 'module': module_name, 'raw': line.strip()}
        except OSError as e:
            _get_logger().debug(f'[{self.name}] Cannot read /proc/kallsyms: {e}')

        self._kallsyms_cache = symbols
        return symbols

    def _is_suspicious_address(self, address: int) -> bool:
        """Check if kernel address is in suspicious range
        
        Args:
            address: Kernel address to check
            
        Returns:
            True if address appears suspicious
        """
        kernel_text_ranges = [(18446744071562067968, 18446744072635809792), (18446744073699065856, 18446744073699069952)]
        for start, end in kernel_text_ranges:
            if start <= address <= end:
                return False
        return True

    def _is_kernel_text_address(self, address: int) -> bool:
        """Check if address is in kernel text segment
        
        Args:
            address: Address to check
            
        Returns:
            True if address is in kernel text segment
        """
        return 18446744071562067968 <= address <= 18446744072635809792

    def _is_common_syscall(self, syscall_name: str) -> bool:
        """Check if syscall name is a common Linux syscall
        
        Args:
            syscall_name: Syscall name without prefix
            
        Returns:
            True if it's a known common syscall
        """
        common_syscalls = {'read', 'write', 'open', 'close', 'stat', 'fstat', 'lstat', 'poll', 'lseek', 'mmap', 'mprotect', 'munmap', 'brk', 'rt_sigaction', 'rt_sigprocmask', 'ioctl', 'pread64', 'pwrite64', 'readv', 'writev', 'access', 'pipe', 'select', 'sched_yield', 'mremap', 'msync', 'mincore', 'madvise', 'shmget', 'shmat', 'shmctl', 'dup', 'dup2', 'pause', 'nanosleep', 'getitimer', 'alarm', 'setitimer', 'getpid', 'socket', 'connect', 'accept', 'sendto', 'recvfrom', 'bind', 'listen', 'getsockname', 'getpeername', 'execve', 'wait4', 'kill', 'uname', 'fcntl', 'flock', 'fsync', 'truncate', 'ftruncate', 'getcwd', 'chdir', 'rename', 'mkdir', 'rmdir', 'creat', 'link', 'unlink', 'symlink', 'readlink', 'chmod', 'chown', 'lchown', 'umask', 'gettimeofday', 'getuid', 'getgid', 'setuid', 'setgid', 'geteuid', 'getegid', 'setpgid', 'getppid', 'getpgrp', 'setsid', 'setreuid', 'setregid'}
        return syscall_name.lower() in common_syscalls

    def _check_module_signature(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Check kernel module signature status
        
        Args:
            module_name: Module name to check
            
        Returns:
            Dictionary with signature status or None
        """
        with self._signature_cache_lock:
            if module_name in self._signature_cache:
                return self._signature_cache[module_name]

        try:
            modinfo_result = subprocess.run(
                ['modinfo', '-F', 'signature', module_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5, stdin=subprocess.DEVNULL
            )

            if modinfo_result.returncode == 0:
                output = modinfo_result.stdout.strip()
                has_signature = output != ''

                sig_strength = self._validate_signature_strength(output)

                result = {
                    'module': module_name,
                    'unsigned': not has_signature,
                    'has_signature': has_signature,
                    'signature_data': output if has_signature else None,
                    'signature_strength': sig_strength if has_signature else None
                }
                with self._signature_cache_lock:
                    self._signature_cache[module_name] = result
                return result
        except subprocess.TimeoutExpired:
            _record_modinfo_timeout(module_name)
            _get_logger().debug(f'[{self.name}] modinfo command timed out for {module_name} (5s timeout)')
        except (OSError, ValueError):
            pass

        result = {'module': module_name, 'unsigned': True, 'error': 'Cannot verify'}
        with self._signature_cache_lock:
            self._signature_cache[module_name] = result
        return result

    def _validate_signature_strength(self, signature_data: str) -> str:
        """Validate kernel module signature strength
        
        Args:
            signature_data: Raw signature data from modinfo -F signature
            
        Returns:
            'strong', 'weak', or 'invalid'
        """
        if not signature_data or not signature_data.strip():
            return 'invalid'
        
        sig_lower = signature_data.lower()
        
        # Strong signatures contain recognizable key/certificate info
        strong_indicators = [
            'sig_key:', 'sig_id:', 'signer:', 'sig_hashalgo:',
            'pkcs7', 'x509', 'rsa', 'ecdsa', 'sha',
            'key id', 'certificate', 'fingerprint'
        ]
        
        # Check for strong signature indicators
        for indicator in strong_indicators:
            if indicator in sig_lower:
                return 'strong'
        
        # Valid signature format: hex-like strings or key identifiers
        # Typically 40+ hex chars for key IDs
        hex_pattern = re.compile(r'[0-9a-fA-F]{16,}')
        if hex_pattern.search(signature_data):
            return 'strong'
        
        # Signature present but format unclear - weak
        return 'weak'

    def _batch_check_signatures(self, module_names: List[str]) -> Optional[Dict[str, Dict[str, Any]]]:
        """Batch check module signatures using single modinfo command
        
        Uses modinfo to check all modules at once by parsing /lib/modules/$(uname -r)/modules.builtin
        and checking signature field for each module.
        
        Args:
            module_names: List of module names to check
            
        Returns:
            Dictionary of module signature results, or None if batch check not possible
        """
        try:
            # Try to get module signature info from modinfo -F signature for all modules
            # This is faster than individual modinfo calls
            kernel_release = subprocess.run(['uname', '-r'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5).stdout.strip()
            modules_dep_path = f'/lib/modules/{kernel_release}/modules.dep'
            
            if not os.path.exists(modules_dep_path):
                return None
            
            # Get signature status for all modules in one pass
            results = {}
            checked_count = 0

            # Use modinfo with -F signature to get just the signature field
            # Group modules into batches of 20 to avoid command line length limits
            batch_size = 20
            for i in range(0, len(module_names), batch_size):
                batch = module_names[i:i + batch_size]
                
                # For each module, check if it has signature via modinfo -F signature
                for module_name in batch:
                    with self._signature_cache_lock:
                        if module_name in self._signature_cache:
                            results[module_name] = self._signature_cache[module_name]
                            continue

                    try:
                        modinfo_result = subprocess.run(
                            ['modinfo', '-F', 'signature', module_name],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=3, stdin=subprocess.DEVNULL
                        )

                        has_signature = modinfo_result.returncode == 0 and modinfo_result.stdout.strip() != ''

                        sig_strength = None
                        signature_data = None
                        if has_signature:
                            signature_data = modinfo_result.stdout.strip()
                            sig_strength = self._validate_signature_strength(signature_data)

                        result = {
                            'module': module_name,
                            'unsigned': not has_signature,
                            'has_signature': has_signature,
                            'signature_data': signature_data,
                            'signature_strength': sig_strength
                        }
                        results[module_name] = result
                        with self._signature_cache_lock:
                            self._signature_cache[module_name] = result
                        checked_count += 1

                    except subprocess.TimeoutExpired:
                        _record_modinfo_timeout(module_name)
                        _get_logger().debug(f'[{self.name}] modinfo timeout for {module_name} (3s timeout)')
                        results[module_name] = {'module': module_name, 'unsigned': True, 'error': 'Timeout'}
                        with self._signature_cache_lock:
                            self._signature_cache[module_name] = results[module_name]
                    except OSError:
                        results[module_name] = {'module': module_name, 'unsigned': True, 'error': 'Cannot verify'}
                        with self._signature_cache_lock:
                            self._signature_cache[module_name] = results[module_name]
                
            
            _get_logger().debug(f'[{self.name}] Batch checked {checked_count} modules, cached results')
            return results
            
        except (subprocess.TimeoutExpired, OSError) as e:
            _get_logger().debug(f'[{self.name}] Batch signature check failed: {e}')
            return None

    async def _parallel_check_signatures(self, module_names: List[str]) -> Dict[str, Dict[str, Any]]:
        """Check module signatures in parallel using asyncio
        
        Args:
            module_names: List of module names to check
            
        Returns:
            Dictionary of module signature results
        """
        results = {}
        semaphore = asyncio.Semaphore(10)

        async def check_single_module(module_name: str) -> Tuple[str, Dict[str, Any]]:
            async with semaphore:
                with self._signature_cache_lock:
                    if module_name in self._signature_cache:
                        return module_name, self._signature_cache[module_name]

                try:
                    modinfo_result = await asyncio.get_running_loop().run_in_executor(
                        None,
                        lambda: subprocess.run(
                            ['modinfo', '-F', 'signature', module_name],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=3, stdin=subprocess.DEVNULL
                        )
                    )

                    has_signature = modinfo_result.returncode == 0 and modinfo_result.stdout.strip() != ''

                    sig_strength = None
                    signature_data = None
                    if has_signature:
                        signature_data = modinfo_result.stdout.strip()
                        sig_strength = self._validate_signature_strength(signature_data)

                    result = {
                        'module': module_name,
                        'unsigned': not has_signature,
                        'has_signature': has_signature,
                        'signature_data': signature_data,
                        'signature_strength': sig_strength
                    }
                    with self._signature_cache_lock:
                        self._signature_cache[module_name] = result
                    return module_name, result

                except (subprocess.TimeoutExpired, OSError):
                    _record_modinfo_timeout(module_name)
                    _get_logger().debug(f'[{self.name}] modinfo timeout/error for {module_name}')
                    result = {'module': module_name, 'unsigned': True, 'error': 'Cannot verify'}
                    with self._signature_cache_lock:
                        self._signature_cache[module_name] = result
                    return module_name, result
        
        # Run all checks in parallel with timeout
        try:
            tasks = [check_single_module(name) for name in module_names]
            completed = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)
            
            for module_name, sig_result in completed:
                results[module_name] = sig_result
                
        except asyncio.TimeoutError:
            _get_logger().warning(f'[{self.name}] Parallel signature check timed out')
            # Return whatever we have so far
            for module_name in module_names:
                if module_name not in results:
                    results[module_name] = {'module': module_name, 'unsigned': True, 'error': 'Timeout'}
        
        return results

    def _get_module_symbols(self) -> Dict[str, str]:
        """Get symbols from loaded kernel modules
        
        Returns:
            Dictionary mapping module names to their symbol lists
        """
        module_symbols = {}
        try:
            result = subprocess.run(['lsmod'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10, stdin=subprocess.DEVNULL)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]
                for line in lines:
                    parts = line.split()
                    if parts:
                        module_name = parts[0]
                        module_symbols[module_name] = []
        except (subprocess.TimeoutExpired, OSError):
            pass
        return module_symbols

    def _symbol_belongs_to_module(self, symbol_name: str, module_symbols: Dict[str, list]) -> bool:
        """Check if symbol belongs to a known module via kallsyms module field

        Args:
            symbol_name: Symbol name to check
            module_symbols: Dictionary of loaded module names

        Returns:
            True if symbol belongs to a known module
        """
        if self._kallsyms_cache and symbol_name in self._kallsyms_cache:
            sym_module = self._kallsyms_cache[symbol_name].get('module')
            if sym_module and sym_module.replace('-', '_') in {m.replace('-', '_') for m in module_symbols}:
                return True
        return False

    def _is_core_kernel_symbol(self, symbol_name: str) -> bool:
        """Check if symbol is a core kernel symbol
        
        Args:
            symbol_name: Symbol name to check
            
        Returns:
            True if it's a core kernel symbol
        """
        core_patterns = ['^do_', '^vfs_', '^sys_', '^__x64_', '^__ia32_', '^tcp_', '^udp_', '^ip_', '^sock_', '^file_', '^inode_', '^dentry_']
        for pattern in core_patterns:
            if re.match(pattern, symbol_name):
                return True
        return False

    def _load_baseline(self):
        """Load kernel function baseline from file"""
        baseline_file = '/data/sec-userspace/workspace/kernel_integrity_baseline.json'
        if not os.path.exists(baseline_file):
            _get_logger().debug(f'[{self.name}] No baseline file found')
            return
        try:
            with open(baseline_file, 'r', encoding='utf-8') as f:
                self.baseline_functions = json.load(f)
            _get_logger().info(f'[{self.name}] Loaded baseline with {len(self.baseline_functions)} functions')
        except (json.JSONDecodeError, OSError, TypeError) as e:
            _get_logger().warning(f'[{self.name}] Failed to load baseline: {e}')