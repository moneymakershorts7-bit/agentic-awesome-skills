"""Runtime Security Detection Module based on /proc filesystem.

This module provides runtime security detection capabilities including:
1. Abnormal syscall detection (ptrace, process_vm_readv)
2. Process injection detection (LD_PRELOAD hijacking, shared library injection)
3. Container escape detection (namespace breakthrough, cgroup escape)
4. Covert channel communication (shared memory, signals)
5. Suspicious memory operations

References:
- https://linuxsecurity.com/features/ebpf-security-tools-rootkit-evasion
- docs/detection-methods.md
"""
import re
from typing import List, Dict
from .base import BaseAnalyzer
from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from ..utils.fp_tracker import get_tracker, is_false_positive, record_fp
from ..utils.i18n import get_attack_tactic_name
from ..utils.proc import read_proc_file
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

# Pre-compiled constant sets to avoid recreation in loops
_DEBUGGERS = frozenset(('strace', 'ltrace', 'gdb'))
_NS_TOOLS = frozenset(('nsenter', 'unshare', 'setns', 'clone', 'fork'))
_SUSPICIOUS_OPTS = frozenset(('--user', '--pid', '--net', '--mount'))

class RuntimeDetector(BaseAnalyzer):
    """Runtime Security Detection Analyzer using /proc filesystem.
    
    Detects the following attack patterns:
    1. T1055 - Process Injection (ptrace-based injection, LD_PRELOAD hijacking)
    2. T1574.006 - Dynamic Linker Hijacking
    3. T1611 - Escape to Host (container escape)
    4. T1008 - Fallback Channels (covert channel communication)
    5. T1055.003 - Thread Local Storage Injection
    """
    
    name = "runtime_detector"
    timeout = 30
    required_collectors = ["process"]
    
    # Suspicious syscalls that may indicate process injection
    INJECTION_SYSCALLS = {
        'ptrace': re.compile(r'ptrace\s*\('),
        'process_vm_readv': re.compile(r'process_vm_readv\s*\('),
        'process_vm_writev': re.compile(r'process_vm_writev\s*\('),
    }
    
    # Known malicious library paths
    SUSPICIOUS_LIB_PATHS = frozenset([
        '/tmp/', '/dev/shm/', '/var/tmp/', '/run/', 
        '/.hidden', '/proc/', '/sys/'
    ])
    
    # Namespace escape indicators
    NS_ESCAPE_PATTERNS = {
        'nsenter': re.compile(r'nsenter\s+.*--(mount|pid|net|ipc|uts|user)'),
        'unshare': re.compile(r'unshare\s+.*--(mount|pid|net|ipc|uts|user)'),
        'setns': re.compile(r'setns\s*\('),
    }
    
    # Shared memory abuse patterns
    SHM_ABUSE_PATTERNS = [
        re.compile(r'/dev/shm/\.[^/]+'),
        re.compile(r'mmap\s*\([^)]*MAP_SHARED'),
        re.compile(r'shm_open\s*\('),
    ]
    
    # Signal-based covert channel patterns
    SIGNAL_ABUSE_PATTERNS = [
        re.compile(r'kill\s+-\d+\s+\d+'),
        re.compile(r'sigqueue\s*\('),
    ]
    
    # Container escape paths
    ESCAPE_PATHS = frozenset([
        '/proc/1/root/',
        '/host/',
        '/mnt/host/',
        '/rootfs/',
    ])
    
    def should_skip(self) -> tuple:
        """This analyzer is critical and should never skip."""
        return False, ""
    def analyze(self, collected_data: dict) -> List[Evidence]:
        """Execute runtime security analysis."""
        evidences = []
        
        tracker = get_tracker()
        tracker.record_detection('runtime_detector', 1)
        
        process_data = self._get_data(collected_data, "process")
        if not process_data:
            return evidences
        
        processes = process_data.get("processes", [])
        
        # Build PID map for cross-reference
        pid_map = {p.get("pid"): p for p in processes}
        
        # 1. Detect ptrace-based process injection (T1055)
        evidences.extend(self._detect_ptrace_injection(processes))
        
        # 2. Detect LD_PRELOAD hijacking (T1574.006)
        evidences.extend(self._detect_ld_preload_hijack(processes))
        
        # 3. Detect suspicious memory mappings (T1055.003)
        evidences.extend(self._detect_suspicious_maps(processes))
        
        # 4. Detect container escape attempts (T1611)
        evidences.extend(self._detect_container_escape(processes))
        
        # 5. Detect covert channel communication (T1008)
        evidences.extend(self._detect_covert_channels(processes))
        
        # 6. Detect namespace manipulation
        evidences.extend(self._detect_namespace_abuse(processes))
        
        return evidences
    
    def _detect_ptrace_injection(self, processes: List[Dict]) -> List[Evidence]:
        """Detect ptrace-based process injection (T1055).
        
        Ptrace can be used to inject code into another process by:
        - Attaching to a target process
        - Writing shellcode to its memory
        - Modifying registers to execute injected code
        """
        evidences = []
        
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            pid = proc.get("pid", 0)
            
            # Check for strace/ltrace usage (legitimate but can be abused)
            is_debugger = comm in _DEBUGGERS
            
            # Check for suspicious ptrace patterns in cmdline
            has_ptrace = any(pattern.search(cmdline) for pattern in self.INJECTION_SYSCALLS.values())
            
            # Flag if: non-debugger with ptrace-related strings
            should_flag = has_ptrace and not is_debugger
            
            if should_flag:
                context = f"{comm} (PID {pid})"
                if not is_false_positive('runtime_detector', 'ptrace_injection', context=context):
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1055",
                        attack_tactic=get_attack_tactic_name("T1055"),
                        title="Potential Process Injection via ptrace",
                        description=f"Process {comm} (PID {pid}) shows ptrace-related activity: {cmdline[:200]}",
                        confidence=0.75,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "cmdline": cmdline[:500],
                            "is_debugger": is_debugger
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                else:
                    record_fp('runtime_detector', 'ptrace_injection', context=f'Suppressed: {context}')
        
        return evidences
    
    def _detect_ld_preload_hijack(self, processes: List[Dict]) -> List[Evidence]:
        """Detect LD_PRELOAD hijacking attacks (T1574.006).
        
        Attackers can use LD_PRELOAD to:
        - Inject malicious shared libraries
        - Intercept and modify function calls
        - Hide malicious activity
        """
        evidences = []
        
        for proc in processes:
            environ_raw = proc.get("environ", "")
            comm = proc.get("comm", "")
            pid = proc.get("pid", 0)
            
            # Parse environ: can be a string or a dict
            if isinstance(environ_raw, dict):
                environ = environ_raw
            else:
                environ = {}
                for line in str(environ_raw).splitlines():
                    if '=' in line:
                        k, v = line.split('=', 1)
                        environ[k] = v
            
            ld_preload = environ.get("LD_PRELOAD", "")
            if not ld_preload:
                continue
            
            # Check if pointing to suspicious location
            is_suspicious_path = any(path in ld_preload for path in self.SUSPICIOUS_LIB_PATHS)
            
            # Also check for relative paths (current directory)
            is_relative = ld_preload.startswith('./') or ld_preload.startswith('../')
            
            if is_suspicious_path or is_relative:
                context = f"{comm} (PID {pid}) LD_PRELOAD={ld_preload}"
                if not is_false_positive('runtime_detector', 'ld_preload_hijack', context=context):
                    severity = Severity.CRITICAL if is_suspicious_path else Severity.HIGH
                    evidences.append(self._create_evidence(
                        severity=severity,
                        attack_id="T1574.006",
                        attack_tactic=get_attack_tactic_name("T1574.006"),
                        title="Suspicious LD_PRELOAD Usage",
                        description=f"Process {comm} (PID {pid}) using LD_PRELOAD from suspicious location: {ld_preload}",
                        confidence=0.85,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "LD_PRELOAD": ld_preload,
                            "is_suspicious_path": is_suspicious_path,
                            "is_relative": is_relative
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid,
                        file_path=proc.get('file_path', proc.get('path', ''))
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                else:
                    record_fp('runtime_detector', 'ld_preload_hijack', context=f'Suppressed: {context}')
        
        return evidences
    
    def _detect_suspicious_maps(self, processes: List[Dict]) -> List[Evidence]:
        """Detect suspicious memory mappings indicating code injection (T1055.003).
        
        Look for:
        - Anonymous writable+executable mappings (RWX)
        - Libraries loaded from suspicious locations
        - Multiple mappings to same file (potential hooking)
        """
        evidences = []
        
        for proc in processes:
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            
            try:
                # Read /proc/{pid}/maps directly for efficiency
                maps_content = read_proc_file(pid, "maps")
                if not maps_content:
                    continue
                
                suspicious_maps = []
                for line in maps_content.split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    
                    perms = parts[1] if len(parts) > 1 else ""
                    pathname = parts[4] if len(parts) > 4 else ""
                    
                    # Check for RWX (readable+writable+executable) pages
                    if 'r' in perms and 'w' in perms and 'x' in perms:
                        # Anonymous RWX mapping is highly suspicious
                        if not pathname or pathname == '[anon]':
                            suspicious_maps.append({
                                "perms": perms,
                                "pathname": pathname or "[anon]",
                                "reason": "Anonymous RWX mapping"
                            })
                        # Library from suspicious location
                        elif any(pathname.startswith(p) for p in self.SUSPICIOUS_LIB_PATHS):
                            suspicious_maps.append({
                                "perms": perms,
                                "pathname": pathname,
                                "reason": "Library from suspicious path"
                            })
                
                if suspicious_maps:
                    context = f"{comm} (PID {pid})"
                    if not is_false_positive('runtime_detector', 'suspicious_maps', context=context):
                        evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1055.003",
                            attack_tactic=get_attack_tactic_name("T1055.003"),
                            title=f"Suspicious Memory Mappings Detected ({len(suspicious_maps)} found)",
                            description=f"Process {comm} (PID {pid}) has {len(suspicious_maps)} suspicious memory mappings",
                            confidence=0.7,
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "suspicious_maps": suspicious_maps[:10]
                            },
                            evidence_details=EvidenceDetail(
                                pid=proc.get('pid', 0),
                                cmdline=proc.get('cmdline', '')[:300],
                                executable=proc.get('exe', ''),
                                remote_address=proc.get('remote_address', proc.get('ip', '')),
                                connection_state=proc.get('state', '')
                            ),
                            remediation_commands=[
                        "Audit runtime dependencies and verify integrity",
                        "Monitor for unauthorized package installations",
                        "Review package installation logs and sources",
                        "Implement runtime application self-protection"
                    ]
                        ))
                    else:
                        record_fp('runtime_detector', 'suspicious_maps', context=f'Suppressed: {context}')
                        
            except (OSError, ValueError, KeyError) as e:
                _get_logger().debug(f"[runtime_detector] Failed to analyze maps for PID {pid}: {e}")
        
        return evidences
    
    def _detect_container_escape(self, processes: List[Dict]) -> List[Evidence]:
        """Detect container escape attempts (T1611).
        
        Container escape techniques include:
        - Accessing host filesystem via /proc/1/root
        - Breaking out of cgroups
        - Mounting host directories
        - Using nsenter/unshare to escape namespaces
        """
        evidences = []
        
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            pid = proc.get("pid", 0)
            cwd = proc.get("cwd", "")
            
            escape_indicators = []
            
            # Check for access to escape paths
            for escape_path in self.ESCAPE_PATHS:
                if escape_path in cmdline or escape_path in cwd:
                    escape_indicators.append(f"Access to {escape_path}")
            
            # Check for nsenter/unshare usage
            for tool_name, pattern in self.NS_ESCAPE_PATTERNS.items():
                if pattern.search(cmdline):
                    escape_indicators.append(f"Namespace tool: {tool_name}")
            
            # Check for mount commands that could escape container
            if 'mount' in cmdline.lower():
                if any(opt in cmdline for opt in ['--bind', '-o bind', '--rbind']):
                    escape_indicators.append("Bind mount detected")
            
            if escape_indicators:
                context = f"{comm} (PID {pid})"
                if not is_false_positive('runtime_detector', 'container_escape', context=context):
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL,
                        attack_id="T1611",
                        attack_tactic=get_attack_tactic_name("T1611"),
                        title=f"Container Escape Indicators ({len(escape_indicators)} found)",
                        description=f"Process {comm} (PID {pid}) shows container escape indicators: {escape_indicators}",
                        confidence=0.8,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "cmdline": cmdline[:500],
                            "cwd": cwd,
                            "escape_indicators": escape_indicators
                        },
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', ''),
                            content=proc.get('container_id', '')
                        ),
                        remediation_commands=[
                        "Inspect container runtime configuration",
                        "Review pod security policies and context",
                        "Check container image provenance and signatures",
                        "Audit Kubernetes RBAC and network policies"
                    ]
                    ))
                else:
                    record_fp('runtime_detector', 'container_escape', context=f'Suppressed: {context}')
        
        return evidences
    
    def _detect_covert_channels(self, processes: List[Dict]) -> List[Evidence]:
        """Detect covert channel communication (T1008).
        
        Covert channels can be established via:
        - Shared memory (/dev/shm)
        - Signal manipulation
        - File-based communication
        - Network covert channels
        """
        evidences = []
        
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            pid = proc.get("pid", 0)
            
            covert_indicators = []
            
            # Check for shared memory abuse
            for pattern in self.SHM_ABUSE_PATTERNS:
                if pattern.search(cmdline):
                    covert_indicators.append("Shared memory manipulation")
                    break
            
            # Check for hidden files in /dev/shm
            if '/dev/shm/.' in cmdline:
                covert_indicators.append("Hidden file in shared memory")
            
            # Check for signal-based communication
            for pattern in self.SIGNAL_ABUSE_PATTERNS:
                if pattern.search(cmdline):
                    covert_indicators.append("Signal-based communication")
                    break
            
            if covert_indicators:
                context = f"{comm} (PID {pid})"
                if not is_false_positive('runtime_detector', 'covert_channels', context=context):
                    evidences.append(self._create_evidence(
                        severity=Severity.MEDIUM,
                        attack_id="T1008",
                        attack_tactic=get_attack_tactic_name("T1008"),
                        title=f"Covert Channel Indicators ({len(covert_indicators)} found)",
                        description=f"Process {comm} (PID {pid}) shows covert channel indicators: {covert_indicators}",
                        confidence=0.6,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "cmdline": cmdline[:500],
                            "indicators": covert_indicators
                        },
                        evidence_details=EvidenceDetail(
                            pid=proc.get('pid', 0),
                            cmdline=proc.get('cmdline', '')[:300],
                            executable=proc.get('exe', ''),
                            remote_address=proc.get('remote_address', proc.get('ip', '')),
                            connection_state=proc.get('state', '')
                        ),
                        remediation_commands=[
                        "Audit runtime dependencies and verify integrity",
                        "Monitor for unauthorized package installations",
                        "Review package installation logs and sources",
                        "Implement runtime application self-protection"
                    ]
                    ))
                else:
                    record_fp('runtime_detector', 'covert_channels', context=f'Suppressed: {context}')
        
        return evidences
    
    def _detect_namespace_abuse(self, processes: List[Dict]) -> List[Evidence]:
        """Detect namespace manipulation for privilege escalation or escape.
        
        Namespace abuse includes:
        - Creating new namespaces to hide activity
        - Joining existing namespaces to access restricted resources
        - Manipulating user namespaces for privilege escalation
        """
        evidences = []
        
        for proc in processes:
            cmdline = proc.get("cmdline", "")
            comm = proc.get("comm", "")
            pid = proc.get("pid", 0)
            
            # Check for namespace manipulation tools
            if comm in _NS_TOOLS or any(tool in cmdline for tool in _NS_TOOLS):
                # Check for suspicious parameters
                has_suspicious_opt = any(opt in cmdline for opt in _SUSPICIOUS_OPTS)
                
                if has_suspicious_opt:
                    context = f"{comm} (PID {pid})"
                    if not is_false_positive('runtime_detector', 'namespace_abuse', context=context):
                        evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1611",
                            attack_tactic=get_attack_tactic_name("T1611"),
                            title="Namespace Manipulation Detected",
                            description=f"Process {comm} (PID {pid}) manipulating namespaces: {cmdline[:200]}",
                            confidence=0.75,
                            raw_data={
                                "pid": pid,
                                "comm": comm,
                                "cmdline": cmdline[:500]
                            },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Review process execution chain",
                        "Scan system for additional indicators"
                    ]))
                    else:
                        record_fp('runtime_detector', 'namespace_abuse', context=f'Suppressed: {context}')
        
        return evidences
