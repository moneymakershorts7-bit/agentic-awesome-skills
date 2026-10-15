"""MemoryForensicsAnalyzer core class - composes all detection capability mixins.

This module contains the main MemoryForensicsAnalyzer class that inherits from:
- InjectionDetectorMixin (memory injection, code segment, process maps)
- RWXScannerMixin (credential extraction, model integrity, GPU, shared memory, mmap)
- ProcessHollowingMixin (process hollowing, DLL injection)
- BackendScannerMixin (SQLite/Redis/JSON/vector DB backends, conversation state, vector anomalies)
- PoisoningDetectorMixin (memory poisoning, cross-session attacks, backup analysis)
- BaseAnalyzer (base class for all analyzers)

All class-level constants, thresholds, and patterns are defined in constants.py.
All lazy import helpers are defined in helpers.py.
"""
from typing import List, Dict

from ...reporter.evidence import Evidence
from ..base import BaseAnalyzer
from .constants import (
    MEMORY_FORENSICS_HEURISTICS,
    SEC_INSPECT_PATTERNS,
    MEMORY_BACKEND_PATTERNS,
    MEMORY_POISONING_ATTACKS,
)
from .injection_detector import InjectionDetectorMixin
from .rwx_scanner import RWXScannerMixin
from .process_hollowing import ProcessHollowingMixin
from .backend_scanner import BackendScannerMixin
from .poisoning_detector import PoisoningDetectorMixin


class MemoryForensicsAnalyzer(
    InjectionDetectorMixin,
    RWXScannerMixin,
    ProcessHollowingMixin,
    BackendScannerMixin,
    PoisoningDetectorMixin,
    BaseAnalyzer,
):
    """AI Agent Memory Forensics and Artifact Recovery Analyzer.

    Advanced memory forensics capabilities for AI agent systems:

    Detection capabilities (12+ heuristics):
    1. Memory-resident payload detection
    2. Injected code segment detection
    3. Credential pattern matching
    4. Prompt injection recovery
    5. Model weight anomaly detection
    6. GPU memory monitoring
    7. Shared memory analysis
    8. Memory-mapped file verification
    9. Process hollowing detection
    10. DLL injection detection
    11. Conversation state integrity
    12. Vector embedding anomaly detection

    ATT&CK Mapping: T1005, T1003, T1055, T1055.001, T1055.012, T1610, T1565.001, T1499
    OWASP ASI 2026: ASI01, ASI02, ASI03
    """

    name = "memory_forensics_analyzer"

    @property
    def timeout(self):
        return self._get_config("timeout", 120)

    required_collectors = ["process", "filesystem", "log"]

    # Sec-inspect self-protection whitelist - exclude scanner's own processes
    SEC_INSPECT_PATTERNS = SEC_INSPECT_PATTERNS

    # Memory backend patterns (used by backend scanner mixin)
    MEMORY_BACKEND_PATTERNS = MEMORY_BACKEND_PATTERNS

    # Memory poisoning attacks (used by poisoning detector mixin)
    MEMORY_POISONING_ATTACKS = MEMORY_POISONING_ATTACKS

    def __init__(self, workspace_dir: str = None):
        super().__init__(workspace_dir)
        self._compiled_patterns = {}
        self._compile_all_patterns()
        self._recovered_artifacts = []

    def _compile_all_patterns(self):
        """Pre-compile all regex patterns for performance."""
        for heuristic_name, heuristic_data in MEMORY_FORENSICS_HEURISTICS.items():
            self._compiled_patterns[heuristic_name] = []
            for pattern, description, severity in heuristic_data.get('patterns', []):
                self._compiled_patterns[heuristic_name].append({
                    'pattern': pattern,
                    'description': description,
                    'severity': severity
                })

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        if not self.proc_available():
            return True, "No /proc filesystem available"
        return False, ""

    def _get_safe_data(self, collected_data: Dict, key: str) -> Dict:
        """Safely get data from collected_data."""
        try:
            return self._get_data(collected_data, key)
        except (KeyError, TypeError):
            return {}

    def _is_sec_inspect_process(self, proc: dict, all_processes: list = None) -> bool:
        """Check if process is sec-userspace itself to avoid self-detection false positives.

        Detection strategies:
        1. Match process cmdline/comm against sec-userspace patterns
        2. Match process working directory (cwd) against sec-userspace workspace
        3. Trace parent process chain to detect sec-userspace spawned processes
        """
        cmdline = proc.get("cmdline", "") or ""
        comm = proc.get("comm", "") or ""
        cwd = proc.get("cwd", "") or ""

        for pattern in self.SEC_INSPECT_PATTERNS:
            if pattern.search(cmdline) or pattern.search(comm):
                return True

        if cwd and any(pattern.search(cwd) for pattern in self.SEC_INSPECT_PATTERNS):
            return True

        if all_processes:
            ppid = proc.get("ppid", 0)
            if ppid and ppid > 0:
                for parent_proc in all_processes:
                    if parent_proc.get("pid") == ppid:
                        if self._is_sec_inspect_process(parent_proc, all_processes):
                            return True
                        break

        return False

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute memory forensics analysis (quick or full mode)."""
        evidences = []

        # Get data sources safely
        process_data = self._get_safe_data(collected_data, "process")
        filesystem_data = self._get_safe_data(collected_data, "filesystem")
        log_data = self._get_safe_data(collected_data, "log")

        # Run all memory forensics checks
        # Original memory forensics capabilities (1-13)
        evidences.extend(self._analyze_process_memory_maps(process_data))
        evidences.extend(self._scan_memory_resident_payloads(process_data))
        evidences.extend(self._detect_injected_code_segments(process_data))
        evidences.extend(self._extract_credentials_from_artifacts(filesystem_data))
        evidences.extend(self._recover_prompt_injection_payloads(log_data))
        evidences.extend(self._verify_model_memory_integrity(filesystem_data))
        evidences.extend(self._monitor_gpu_memory(filesystem_data))
        evidences.extend(self._analyze_shared_memory(filesystem_data))
        evidences.extend(self._verify_memory_mapped_files(process_data))
        evidences.extend(self._detect_process_hollowing(process_data))
        evidences.extend(self._detect_dll_injection(process_data))
        evidences.extend(self._verify_conversation_state_integrity(filesystem_data))
        evidences.extend(self._detect_vector_embedding_anomalies(filesystem_data))

        # NEW: AI Agent Memory Storage Backend Detection (14-18)
        evidences.extend(self._scan_sqlite_memory_backend(filesystem_data))
        evidences.extend(self._scan_redis_memory_backend(filesystem_data))
        evidences.extend(self._scan_json_memory_backend(filesystem_data))
        evidences.extend(self._scan_vector_database_backends(filesystem_data))

        # NEW: Enhanced Memory Poisoning Detection (19+)
        evidences.extend(self._detect_memory_poisoning(filesystem_data))
        evidences.extend(self._detect_cross_session_attacks(log_data))

        # NEW: Memory Backup and Recovery Analysis
        evidences.extend(self._analyze_memory_backup_status(filesystem_data))

        return evidences
