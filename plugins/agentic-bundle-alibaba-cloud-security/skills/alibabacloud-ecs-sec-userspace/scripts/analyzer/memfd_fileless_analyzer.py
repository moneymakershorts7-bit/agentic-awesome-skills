"""Memfd Fileless and Shared Memory Rootkit Detection Analyzer"""
import os
import re
from typing import List, Dict
from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from .base import BaseAnalyzer
from ..utils.fp_tracker import get_tracker, is_false_positive, record_fp
from ..utils.i18n import get_attack_tactic_name
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


class MemfdFilelessAnalyzer(BaseAnalyzer):
    """Memfd Fileless and Shared Memory Rootkit Detection Analyzer
    
    Detects fileless malware techniques using:
    - memfd_create() syscall for in-memory execution
    - /dev/shm shared memory abuse for C2 communication
    - Anonymous executable memory mappings
    - File-backed execution without disk persistence
    
    ATT&CK: T1620 (Reflective Code Loading), T1055 (Process Injection)
    """
    name = "memfd_fileless_analyzer"
    timeout = 45
    required_collectors = ["process"]
    
    def should_skip(self) -> tuple:
        """Check if memfd fileless analyzer should be skipped.
        
        In quick mode, runs lightweight memfd pattern check on process
        exe and cmdline fields without filesystem enumeration.
        
        In full mode, runs comprehensive analysis including fd scanning,
        /dev/shm enumeration, and anonymous memory mapping analysis.
        """
        return False, ""
    
    estimated_time = 3.0
    analyzer_type = BaseAnalyzer.CRITICAL

    MEMFD_PATTERN = re.compile(r'memfd:', re.IGNORECASE)
    ANON_INODE_PATTERN = re.compile(r'anon_inode:', re.IGNORECASE)
    SHM_RANDOM_NAME_PATTERN = re.compile(r'^[a-f0-9]{16,}$', re.IGNORECASE)

    SHM_SUSPICIOUS_EXTENSIONS = {'.so', '.elf', '.bin', '.sh', '.py', '.js', '.tmp', '.dat'}
    
    SHM_NORMAL_PROCESSES = {
        'systemd', 'dbus-daemon', 'pulseaudio', 'Xorg', 'pipewire',
        'gnome-shell', 'kwin', 'plasmashell', 'mutter',
    }

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute memfd fileless analysis.
        
        In quick mode: runs lightweight memfd pattern check on process
        exe and cmdline fields only (no filesystem I/O).
        
        In full mode: runs comprehensive analysis including:
        - memfd file descriptor scanning
        - memfd execution detection
        - /dev/shm C2 communication analysis
        - Anonymous executable memory mapping detection
        """
        evidences = []
        
        tracker = get_tracker()
        tracker.record_detection('memfd_fileless_analyzer', 1)

        process_data = self._get_data(collected_data, "process")
        if not process_data:
            return evidences

        processes = process_data.get("processes", [])

        # Full mode: comprehensive analysis
        evidences.extend(self._check_memfd_file_descriptors(processes))
        evidences.extend(self._check_memfd_execution(processes))
        evidences.extend(self._check_shm_c2(processes))
        evidences.extend(self._check_anonymous_exec_mappings(processes))
        
        return evidences

    def _is_normal_shm_process(self, proc: Dict) -> bool:
        """Check if process is known to legitimately use shared memory"""
        comm = proc.get("comm", "")
        exe = proc.get("exe", "")
        
        if comm in self.SHM_NORMAL_PROCESSES:
            return True
        
        normal_paths = ['/usr/bin/pulseaudio', '/usr/bin/Xorg', '/usr/lib/']
        if any(exe.startswith(p) for p in normal_paths):
            return True
            
        return False

    def _check_memfd_file_descriptors(self, processes: List[Dict]) -> List[Evidence]:
        """Scan /proc/[pid]/fd/ for memfd file descriptors"""
        evidences = []
        
        for proc in processes:
            if self._is_normal_shm_process(proc):
                continue
            
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            fd_info = proc.get("fd_info", [])
            
            if not fd_info:
                continue
            
            memfd_fds = []
            for fd_entry in fd_info:
                fd_path = fd_entry.get("path", "")
                if self.MEMFD_PATTERN.search(fd_path):
                    memfd_name = fd_path.split("memfd:", 1)[-1] if "memfd:" in fd_path else "unknown"
                    memfd_fds.append({
                        "fd": fd_entry.get("fd"),
                        "path": fd_path,
                        "name": memfd_name
                    })
            
            if memfd_fds:
                context = f"{comm} PID={pid} memfd_count={len(memfd_fds)}"
                if is_false_positive('memfd_fileless_analyzer', 'memfd_fd', context=context):
                    record_fp('memfd_fileless_analyzer', 'memfd_fd',
                             context=f'Suppressed: {context}')
                else:
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL,
                        attack_id="T1620",
                        attack_tactic=get_attack_tactic_name("T1620"),
                        title=f"Memfd file descriptors detected in process {comm}",
                        description=f"Process {comm} (PID {pid}) has {len(memfd_fds)} memfd file descriptor(s), indicating fileless execution via memfd_create() syscall",
                        confidence=0.9,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "memfd_fds": memfd_fds,
                            "exe": proc.get("exe", ""),
                            "cmdline": proc.get("cmdline", "")[:500]
                        },
                        remediation="Investigate process origin, check parent process, capture memory dump for forensic analysis",
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Quarantine suspicious files for malware analysis",
                        "Verify file integrity using cryptographic checksums",
                        "Audit file access logs and permissions",
                        "Scan with updated antivirus signatures"
                    ]
                    ))
        
        return evidences

    def _check_memfd_execution(self, processes: List[Dict]) -> List[Evidence]:
        """Detect processes executing from memfd-backed files"""
        evidences = []
        
        for proc in processes:
            if self._is_normal_shm_process(proc):
                continue
            
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            exe = proc.get("exe", "")
            cmdline = proc.get("cmdline", "")
            
            if self.MEMFD_PATTERN.search(exe):
                context = f"{comm} PID={pid} exe={exe}"
                if is_false_positive('memfd_fileless_analyzer', 'memfd_exe', context=context):
                    record_fp('memfd_fileless_analyzer', 'memfd_exe',
                             context=f'Suppressed: {context}')
                else:
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL,
                        attack_id="T1620",
                        attack_tactic=get_attack_tactic_name("T1620"),
                        title=f"Process executing from memfd: {comm}",
                        description=f"Process {comm} (PID {pid}) is executing from a memfd-backed file ({exe}), which exists only in memory with no disk persistence",
                        confidence=0.95,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "exe": exe,
                            "cmdline": cmdline[:500],
                            "ppid": proc.get("ppid", 0)
                        },
                        remediation="Immediately isolate host, capture full memory dump, trace parent process chain, check for lateral movement",
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Quarantine suspicious files for malware analysis",
                        "Verify file integrity using cryptographic checksums",
                        "Audit file access logs and permissions",
                        "Scan with updated antivirus signatures"
                    ]
                    ))
            
            if self.MEMFD_PATTERN.search(cmdline) and exe not in ("", "[kthread]", "[]"):
                context = f"{comm} PID={pid} cmdline_memfd"
                if is_false_positive('memfd_fileless_analyzer', 'memfd_cmdline', context=context):
                    record_fp('memfd_fileless_analyzer', 'memfd_cmdline',
                             context=f'Suppressed: {context}')
                else:
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1620",
                        attack_tactic=get_attack_tactic_name("T1620"),
                        title=f"Memfd reference in process cmdline: {comm}",
                        description=f"Process {comm} (PID {pid}) cmdline contains memfd reference, may indicate fileless payload delivery",
                        confidence=0.75,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "exe": exe,
                            "cmdline": cmdline[:500]
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Quarantine suspicious files for malware analysis",
                        "Verify file integrity using cryptographic checksums",
                        "Audit file access logs and permissions",
                        "Scan with updated antivirus signatures"
                    ]))
        
        return evidences

    def _check_shm_c2(self, processes: List[Dict]) -> List[Evidence]:
        """Detect suspicious shared memory usage for C2 communication"""
        evidences = []
        shm_files = self._enumerate_shm_files()
        
        if not shm_files:
            return evidences
        
        suspicious_shm = []
        for shm_file in shm_files:
            if self._is_suspicious_shm_file(shm_file):
                suspicious_shm.append(shm_file)
        
        if suspicious_shm:
            proc_names = set()
            for proc in processes:
                exe = proc.get("exe", "")
                cmdline = proc.get("cmdline", "")
                if '/dev/shm/' in exe or '/dev/shm/' in cmdline:
                    proc_names.add(proc.get("comm", ""))
            
            if proc_names or suspicious_shm:
                context = f"shm_files={len(suspicious_shm)} procs={','.join(proc_names)}"
                if is_false_positive('memfd_fileless_analyzer', 'shm_c2', context=context):
                    record_fp('memfd_fileless_analyzer', 'shm_c2',
                             context=f'Suppressed: {context}')
                else:
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1055",
                        attack_tactic=get_attack_tactic_name("T1055"),
                        title=f"Suspicious files detected in /dev/shm ({len(suspicious_shm)} files)",
                        description=f"Found {len(suspicious_shm)} suspicious file(s) in /dev/shm that may indicate shared memory abuse for C2 communication or inter-process coordination",
                        confidence=0.7,
                        raw_data={
                            "suspicious_files": [f.get("path", "") for f in suspicious_shm[:20]],
                            "total_suspicious": len(suspicious_shm),
                            "related_processes": list(proc_names) if proc_names else []
                        },
                        remediation="Review file contents and permissions, check for network connections from related processes, monitor for new files",
                        evidence_details=EvidenceDetail(
                            file_path=suspicious_shm[0].get('path', '') if suspicious_shm else ''
                        ),
                        remediation_commands=[
                        "Quarantine suspicious files for malware analysis",
                        "Verify file integrity using cryptographic checksums",
                        "Audit file access logs and permissions",
                        "Scan with updated antivirus signatures"
                    ]
                    ))
        
        for proc in processes:
            if self._is_normal_shm_process(proc):
                continue
                
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            exe = proc.get("exe", "")
            cmdline = proc.get("cmdline", "")
            cwd = proc.get("cwd", "")
            
            shm_refs = []
            for field in [exe, cmdline, cwd]:
                if '/dev/shm/' in field:
                    shm_refs.append(field[:200])
            
            if shm_refs:
                context = f"{comm} PID={pid} shm_refs={len(shm_refs)}"
                if is_false_positive('memfd_fileless_analyzer', 'shm_process', context=context):
                    record_fp('memfd_fileless_analyzer', 'shm_process',
                             context=f'Suppressed: {context}')
                else:
                    has_exec_ext = any(
                        any(ref.endswith(ext) for ext in self.SHM_SUSPICIOUS_EXTENSIONS)
                        for ref in shm_refs
                    )
                    
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL if has_exec_ext else Severity.MEDIUM,
                        attack_id="T1055",
                        attack_tactic=get_attack_tactic_name("T1055"),
                        title=f"Process accessing /dev/shm: {comm}",
                        description=f"Process {comm} (PID {pid}) has {len(shm_refs)} reference(s) to /dev/shm, may indicate shared memory abuse",
                        confidence=0.8 if has_exec_ext else 0.6,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "exe": exe,
                            "cwd": cwd,
                            "cmdline": cmdline[:500],
                            "shm_references": shm_refs[:5]
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Quarantine suspicious files for malware analysis",
                        "Verify file integrity using cryptographic checksums",
                        "Audit file access logs and permissions",
                        "Scan with updated antivirus signatures"
                    ]))
        
        return evidences

    def _check_anonymous_exec_mappings(self, processes: List[Dict]) -> List[Evidence]:
        """Detect anonymous executable memory mappings"""
        evidences = []
        
        for proc in processes:
            if self._is_normal_shm_process(proc):
                continue
            
            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            exe = proc.get("exe", "")
            
            if exe in ("", "[kthread]", "[]"):
                continue
            
            maps_summary = proc.get("maps_summary", [])
            if not maps_summary:
                continue
            
            anon_exec_maps = []
            for map_path in maps_summary:
                if not map_path:
                    continue
                
                if self.MEMFD_PATTERN.search(map_path):
                    anon_exec_maps.append({
                        "path": map_path,
                        "type": "memfd"
                    })
                elif self.ANON_INODE_PATTERN.search(map_path) and ".so" in map_path:
                    anon_exec_maps.append({
                        "path": map_path,
                        "type": "anon_inode_so"
                    })
            
            if anon_exec_maps:
                context = f"{comm} PID={pid} anon_maps={len(anon_exec_maps)}"
                if is_false_positive('memfd_fileless_analyzer', 'anon_exec_maps', context=context):
                    record_fp('memfd_fileless_analyzer', 'anon_exec_maps',
                             context=f'Suppressed: {context}')
                else:
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1055",
                        attack_tactic=get_attack_tactic_name("T1055"),
                        title=f"Anonymous executable memory mappings detected: {comm}",
                        description=f"Process {comm} (PID {pid}) has {len(anon_exec_maps)} anonymous executable memory mapping(s), which may indicate reflective loading or process injection",
                        confidence=0.8,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "exe": exe,
                            "anonymous_maps": anon_exec_maps[:10],
                            "cmdline": proc.get("cmdline", "")[:500]
                        },
                        remediation="Analyze memory mappings for reflective loading, check for network connections, review process ancestry",
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Quarantine suspicious files for malware analysis",
                        "Verify file integrity using cryptographic checksums",
                        "Audit file access logs and permissions",
                        "Scan with updated antivirus signatures"
                    ]
                    ))
        
        return evidences

    def _enumerate_shm_files(self) -> List[Dict]:
        """Enumerate files in /dev/shm with metadata"""
        shm_files = []
        shm_path = "/dev/shm"
        
        try:
            if not os.path.exists(shm_path):
                return shm_files
            
            for entry in os.listdir(shm_path):
                full_path = os.path.join(shm_path, entry)
                try:
                    stat_result = os.stat(full_path)
                    shm_files.append({
                        "path": full_path,
                        "name": entry,
                        "size": stat_result.st_size,
                        "mode": oct(stat_result.st_mode),
                        "uid": stat_result.st_uid,
                        "gid": stat_result.st_gid,
                        "mtime": stat_result.st_mtime,
                        "is_executable": bool(stat_result.st_mode & 0o111)
                    })
                except (OSError, ValueError):
                    continue
        except OSError:
            pass
        
        return shm_files

    def _is_suspicious_shm_file(self, shm_file: Dict) -> bool:
        """Check if a shared memory file exhibits suspicious characteristics"""
        name = shm_file.get("name", "")
        size = shm_file.get("size", 0)
        is_exec = shm_file.get("is_executable", False)
        if is_exec and size > 0:
            return True
        
        if any(name.endswith(ext) for ext in self.SHM_SUSPICIOUS_EXTENSIONS):
            if size > 1024:
                return True
        
        if name.startswith('.') and size > 0:
            return True
        
        base_name = name.split('.')[0]
        if self.SHM_RANDOM_NAME_PATTERN.match(base_name) and size > 0:
            return True
        
        return False
