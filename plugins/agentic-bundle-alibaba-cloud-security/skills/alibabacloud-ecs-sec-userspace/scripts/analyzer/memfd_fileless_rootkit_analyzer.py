"""Memfd Fileless Rootkit Detection Analyzer"""
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
    """Detects fileless malware and rootkits using memfd_create() and shared memory
    
    Detects:
    - memfd file descriptors in /proc/[pid]/fd/
    - Memory-based ELF execution via memfd
    - Shared memory (/dev/shm) C2 communication
    - Anonymous executable memory mappings
    """
    name = "memfd_fileless_analyzer"
    timeout = 30
    required_collectors = ["process"]
    ATTACK_ID = "T1620"
    ATTACK_TACTIC = "Reflective Code Loading"
    
    estimated_time = 2.0
    analyzer_type = BaseAnalyzer.IMPORTANT

    MEMFD_PATTERN = re.compile(r'memfd:([^/\s]+)')
    
    ANONYMOUS_EXEC_MAPPING_PATTERN = re.compile(
        r'^[0-9a-f]+-[0-9a-f]+\s+r-xp\s',
        re.MULTILINE
    )
    
    SUSPICIOUS_SHM_PATTERNS = [
        re.compile(r'/dev/shm/\.[a-zA-Z0-9_]{8,}', re.IGNORECASE),
        re.compile(r'/dev/shm/.*\.(so|elf|bin|exe)', re.IGNORECASE),
        re.compile(r'/dev/shm/.*(c2|beacon|callback|shell)', re.IGNORECASE),
    ]
    
    LEGITIMATE_MEMFD_USERS = {
        'systemd',
        'pipewire',
        'pulseaudio',
        'flatpak',
        'dbus',
    }
    
    LEGITIMATE_SHM_FILES = {
        '/dev/shm/pulse',
        '/dev/shm/sem.',
        '/dev/shm/mpich',
        '/dev/shm/openmpi',
    }

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute memfd fileless rootkit analysis"""
        evidences = []
        
        tracker = get_tracker()
        tracker.record_detection('memfd_fileless_analyzer', 1)

        try:
            process_data = self._get_data(collected_data, "process")
        except KeyError:
            return evidences
        
        if not process_data:
            return evidences

        processes = process_data.get("processes", [])

        evidences.extend(self._check_memfd_file_descriptors(processes))
        evidences.extend(self._check_memfd_execution(processes))
        evidences.extend(self._check_shm_c2(processes))
        evidences.extend(self._check_anonymous_exec_mappings(processes))

        return evidences

    def _is_legitimate_memfd_user(self, proc: Dict) -> bool:
        """Check if process is a known legitimate user of memfd"""
        comm = proc.get("comm", "").lower()
        exe = proc.get("exe", "").lower()
        
        if comm in self.LEGITIMATE_MEMFD_USERS:
            return True
        
        for legit_exe in self.LEGITIMATE_MEMFD_USERS:
            if legit_exe in exe:
                return True
        
        return False

    def _check_memfd_file_descriptors(self, processes: List[Dict]) -> List[Evidence]:
        """Detect memfd file descriptors in /proc/[pid]/fd/"""
        evidences = []

        for proc in processes:
            if self._is_legitimate_memfd_user(proc):
                continue

            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            fd_info = proc.get("fd_info", [])
            
            memfd_fds = []
            for fd in fd_info:
                fd_path = fd.get("path", "")
                match = self.MEMFD_PATTERN.search(fd_path)
                if match:
                    memfd_name = match.group(1)
                    memfd_fds.append({
                        "fd": fd.get("fd"),
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
                        severity=Severity.HIGH,
                        attack_id="T1620",
                        attack_tactic=get_attack_tactic_name("T1620"),
                        title=f"Memfd file descriptors detected in process {comm}",
                        description=f"Process {comm} (PID {pid}) has {len(memfd_fds)} memfd file descriptors",
                        confidence=0.80,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "memfd_count": len(memfd_fds),
                            "memfd_fds": memfd_fds[:10]
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Run comprehensive rootkit detection tools",
                        "Verify kernel module signatures and integrity",
                        "Check for hidden files, processes, and network connections",
                        "Consider system rebuild from known-good backup"
                    ]))

        return evidences

    def _check_memfd_execution(self, processes: List[Dict]) -> List[Evidence]:
        """Detect processes executing from memfd"""
        evidences = []

        for proc in processes:
            if self._is_legitimate_memfd_user(proc):
                continue

            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            exe = proc.get("exe", "")
            cmdline = proc.get("cmdline", "")
            
            if 'memfd:' in exe or 'memfd:' in cmdline:
                context = f"{comm} PID={pid} exe={exe}"
                if is_false_positive('memfd_fileless_analyzer', 'memfd_exec', context=context):
                    record_fp('memfd_fileless_analyzer', 'memfd_exec',
                             context=f'Suppressed: {context}')
                else:
                    evidences.append(self._create_evidence(
                        severity=Severity.CRITICAL,
                        attack_id="T1620",
                        attack_tactic=get_attack_tactic_name("T1620"),
                        title=f"Process executing from memfd: {comm}",
                        description=f"Process {comm} (PID {pid}) is executing from memfd memory region",
                        confidence=0.90,
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
                        "Run comprehensive rootkit detection tools",
                        "Verify kernel module signatures and integrity",
                        "Check for hidden files, processes, and network connections",
                        "Consider system rebuild from known-good backup"
                    ]))

        return evidences

    def _check_shm_c2(self, processes: List[Dict]) -> List[Evidence]:
        """Detect suspicious shared memory usage for C2 communication"""
        evidences = []
        
        shm_files = []
        try:
            if os.path.exists("/dev/shm"):
                for filename in os.listdir("/dev/shm"):
                    filepath = os.path.join("/dev/shm", filename)
                    if os.path.isfile(filepath):
                        shm_files.append({
                            "path": filepath,
                            "name": filename,
                            "executable": os.access(filepath, os.X_OK)
                        })
        except OSError as e:
            _get_logger().debug(f"Failed to list /dev/shm: {e}")
            return evidences

        suspicious_shm = []
        for shm_file in shm_files:
            filepath = shm_file["path"]
            
            for pattern in self.SUSPICIOUS_SHM_PATTERNS:
                if pattern.search(filepath):
                    suspicious_shm.append(shm_file)
                    break
            
            if shm_file.get("executable"):
                is_legitimate = False
                for legit in self.LEGITIMATE_SHM_FILES:
                    if filepath.startswith(legit):
                        is_legitimate = True
                        break
                
                if not is_legitimate:
                    if shm_file not in suspicious_shm:
                        suspicious_shm.append(shm_file)

        if suspicious_shm:
            for shm_file in suspicious_shm[:5]:
                context = f"shm_file={shm_file['path']}"
                if is_false_positive('memfd_fileless_analyzer', 'shm_c2', context=context):
                    record_fp('memfd_fileless_analyzer', 'shm_c2',
                             context=f'Suppressed: {context}')
                else:
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1055",
                        attack_tactic=get_attack_tactic_name("T1055"),
                        title=f"Suspicious shared memory file detected",
                        description=f"Suspicious file in /dev/shm: {shm_file['path']}",
                        confidence=0.75,
                        raw_data={
                            "path": shm_file["path"],
                            "name": shm_file["name"],
                            "executable": shm_file.get("executable", False)
                        },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Run comprehensive rootkit detection tools",
                        "Verify kernel module signatures and integrity",
                        "Check for hidden files, processes, and network connections",
                        "Consider system rebuild from known-good backup"
                    ]))

        for proc in processes:
            if self._is_legitimate_memfd_user(proc):
                continue

            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            cmdline = proc.get("cmdline", "")
            exe = proc.get("exe", "")
            
            for path_field in [exe, cmdline]:
                if '/dev/shm/' in path_field:
                    context = f"{comm} PID={pid} shm_path={path_field}"
                    if is_false_positive('memfd_fileless_analyzer', 'shm_execution', context=context):
                        record_fp('memfd_fileless_analyzer', 'shm_execution',
                                 context=f'Suppressed: {context}')
                    else:
                        evidences.append(self._create_evidence(
                            severity=Severity.CRITICAL,
                            attack_id="T1620",
                            attack_tactic=get_attack_tactic_name("T1620"),
                            title=f"Process executing from shared memory: {comm}",
                            description=f"Process {comm} (PID {pid}) executing from /dev/shm: {path_field[:200]}",
                            confidence=0.85,
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
                        "Run comprehensive rootkit detection tools",
                        "Verify kernel module signatures and integrity",
                        "Check for hidden files, processes, and network connections",
                        "Consider system rebuild from known-good backup"
                    ]))
                        break

        return evidences

    def _check_anonymous_exec_mappings(self, processes: List[Dict]) -> List[Evidence]:
        """Detect anonymous executable memory mappings"""
        evidences = []

        for proc in processes:
            if self._is_legitimate_memfd_user(proc):
                continue

            pid = proc.get("pid", 0)
            comm = proc.get("comm", "")
            maps_summary = proc.get("maps_summary", [])
            exe = proc.get("exe", "")
            
            anonymous_exec_mappings = []
            for mapping in maps_summary:
                if isinstance(mapping, str):
                    if 'memfd:' in mapping:
                        anonymous_exec_mappings.append(mapping)
                    elif self.ANONYMOUS_EXEC_MAPPING_PATTERN.search(mapping):
                        if '[heap]' not in mapping and '[stack]' not in mapping:
                            if exe and exe not in mapping:
                                anonymous_exec_mappings.append(mapping)
            
            if anonymous_exec_mappings:
                context = f"{comm} PID={pid} anon_exec_count={len(anonymous_exec_mappings)}"
                if is_false_positive('memfd_fileless_analyzer', 'anon_exec_mapping', context=context):
                    record_fp('memfd_fileless_analyzer', 'anon_exec_mapping',
                             context=f'Suppressed: {context}')
                else:
                    evidences.append(self._create_evidence(
                        severity=Severity.HIGH,
                        attack_id="T1055",
                        attack_tactic=get_attack_tactic_name("T1055"),
                        title=f"Anonymous executable memory mappings detected in {comm}",
                        description=f"Process {comm} (PID {pid}) has {len(anonymous_exec_mappings)} anonymous executable memory mappings",
                        confidence=0.70,
                        raw_data={
                            "pid": pid,
                            "comm": comm,
                            "mapping_count": len(anonymous_exec_mappings),
                            "mappings": anonymous_exec_mappings[:5]
                        },
                        evidence_details=EvidenceDetail(
                            pid=pid
                        ),
                        remediation_commands=[
                        "Run comprehensive rootkit detection tools",
                        "Verify kernel module signatures and integrity",
                        "Check for hidden files, processes, and network connections",
                        "Consider system rebuild from known-good backup"
                    ]))

        return evidences
