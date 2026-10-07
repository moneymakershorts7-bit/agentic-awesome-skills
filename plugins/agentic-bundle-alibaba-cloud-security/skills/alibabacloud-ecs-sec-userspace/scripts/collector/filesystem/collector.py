"""File System Anomaly Collector - main class with mixin composition"""
import gc
import logging
import stat
import threading
import time

from ..base import BaseCollector
from .hash_calculator import HashCalculatorMixin
from .suid_finder import SuidFinderMixin
from .permission_checker import PermissionCheckerMixin
from .file_scanner import FileScannerMixin
from .webroot_scanner import WebrootScannerMixin
from .k8s_scanner import K8sScannerMixin

logger = logging.getLogger("sec-userspace")


class FilesystemCollector(
    BaseCollector,
    HashCalculatorMixin,
    SuidFinderMixin,
    PermissionCheckerMixin,
    FileScannerMixin,
    WebrootScannerMixin,
    K8sScannerMixin,
):
    """File System Anomaly Collector

    Uses mixin-based composition for:
    - HashCalculatorMixin: Binary hash computation and caching
    - SuidFinderMixin: SUID/SGID cache management
    - PermissionCheckerMixin: SUID/SGID file scanning
    - FileScannerMixin: Basic file scanning (tmp, hidden, recent, history, shell, skill)
    - WebrootScannerMixin: Web root recursive scanning
    - K8sScannerMixin: Kubernetes sensitive file scanning
    """
    name = "filesystem"

    def __init__(self):
        # Initialize base collector first
        BaseCollector.__init__(self)
        # Initialize mixins
        HashCalculatorMixin.__init__(self)
        SuidFinderMixin.__init__(self)
        # PermissionCheckerMixin has no __init__
        FileScannerMixin.__init__(self)

        self._partial_result = None
        self._lock = threading.Lock()
        self._scan_start_time = None

        self.timeout = self._get_collector_config("timeout", 180)
        self._max_files_per_dir = self._get_collector_config("max_files_per_dir", 100)

        # Override scan_paths from config for FileScannerMixin
        self._scan_paths = self._get_collector_config("scan_paths", [
            "/tmp", "/var/tmp", "/dev/shm"
        ])

        # Load cache on initialization
        self._load_cache()
        self._cache_initialized = True

    def _get_collector_config(self, key: str, default=None):
        """Get configuration value from collector config system."""
        try:
            return self._get_config(key, default)
        except AttributeError:
            return default

    def _calculate_completeness_internal(self, partial_result: dict) -> dict:
        """Calculate data completeness score for partial results (internal, no lock)

        Args:
            partial_result: Current partial result data

        Returns:
            dict with completeness metrics
        """
        if partial_result is None:
            return {
                "score": 0.0,
                "phases_completed": {},
                "data_sufficient": False,
                "warnings": ["No filesystem data collected"],
            }

        # Weight-based scoring (SUID/SGID/tmp_exec are most critical)
        phase_weights = {
            "suid_files": 0.20,
            "sgid_files": 0.10,
            "tmp_executables": 0.15,
            "hidden_files_suspicious": 0.10,
            "recent_modified": 0.05,
            "webroot_files": 0.05,
            "key_binary_hashes": 0.15,
            "history_files": 0.05,
            "shell_configs": 0.05,
            "skill_files": 0.05,
            "k8s_sensitive_files": 0.05,
        }

        # Calculate score based on which phases have non-empty data
        score = 0.0
        for data_key, weight in phase_weights.items():
            if data_key in partial_result:
                data = partial_result[data_key]
                # Check if data is non-empty (list with items or dict with keys)
                if isinstance(data, list) and len(data) > 0:
                    score += weight
                elif isinstance(data, dict) and len(data) > 0:
                    score += weight

        # Determine if data is sufficient for core detections
        has_suid = len(partial_result.get("suid_files", [])) > 0
        has_tmp_exec = len(partial_result.get("tmp_executables", [])) > 0
        has_hashes = len(partial_result.get("key_binary_hashes", {})) > 0
        data_sufficient = has_suid and has_tmp_exec

        # Generate warnings
        warnings = []
        if not has_suid:
            warnings.append("SUID files not scanned - privilege escalation detection unavailable")
        if not has_tmp_exec:
            warnings.append("Temporary executables not scanned - malware staging detection unavailable")
        if not has_hashes:
            warnings.append("Key binary hashes not computed - binary integrity check unavailable")
        if not partial_result.get("hidden_files_suspicious"):
            warnings.append("Hidden files not scanned - rootkit artifact detection unavailable")

        # Phase completion tracking (phase is complete if key exists and has data)
        phases = {
            "suid_scanned": len(partial_result.get("suid_files", [])) > 0,
            "sgid_scanned": len(partial_result.get("sgid_files", [])) > 0,
            "tmp_exec_scanned": len(partial_result.get("tmp_executables", [])) > 0,
            "hidden_files_scanned": len(partial_result.get("hidden_files_suspicious", [])) > 0,
            "recent_modified_scanned": len(partial_result.get("recent_modified", [])) > 0,
            "webroot_scanned": len(partial_result.get("webroot_files", [])) > 0,
            "binary_hashes_computed": len(partial_result.get("key_binary_hashes", {})) > 0,
            "history_files_collected": len(partial_result.get("history_files", {})) > 0,
            "shell_configs_collected": len(partial_result.get("shell_configs", {})) > 0,
            "skill_files_scanned": len(partial_result.get("skill_files", [])) > 0,
            "k8s_files_scanned": len(partial_result.get("k8s_sensitive_files", [])) > 0,
        }

        return {
            "score": round(score, 2),
            "phases_completed": phases,
            "data_sufficient": data_sufficient,
            "warnings": warnings,
        }

    def _calculate_completeness(self) -> dict:
        """Thread-safe wrapper around _calculate_completeness_internal."""
        with self._lock:
            return self._calculate_completeness_internal(self._partial_result)

    def _update_partial_result(self, **kwargs):
        """Update partial result with current collection progress"""
        with self._lock:
            if self._partial_result is None:
                self._partial_result = {
                    "suid_files": [],
                    "sgid_files": [],
                    "tmp_executables": [],
                    "hidden_files_suspicious": [],
                    "recent_modified": [],
                    "webroot_files": [],
                    "key_binary_hashes": {},
                    "history_files": {},
                    "shell_configs": {},
                    "skill_files": [],
                    "k8s_sensitive_files": [],
                    "_partial": False,
                }

            for key, value in kwargs.items():
                if key in self._partial_result:
                    self._partial_result[key] = value

    def get_partial_result(self) -> dict:
        """Return current partial result for timeout recovery"""
        with self._lock:
            if self._partial_result is None:
                return {}
            result = dict(self._partial_result)
            # Include completeness score in partial result (compute inline to avoid deadlock)
            result["_completeness"] = self._calculate_completeness_internal(self._partial_result)
            return result

    def _should_skip_due_to_timeout(self) -> bool:
        """Check if we should skip remaining collection due to approaching timeout"""
        if self._scan_start_time is None:
            return False
        elapsed = time.time() - self._scan_start_time

        # Use configured timeout
        effective_timeout = self.timeout
        soft_timeout = effective_timeout * 0.8
        return elapsed > soft_timeout

    def collect(self) -> dict:
        """Collect file system anomaly information with progressive results.

        Scans the filesystem for security-relevant artifacts including
        SUID/SGID files, temporary executables, suspicious hidden files,
        recently modified files, webroot content, and shell configurations.

        Returns:
            Dictionary with keys: suid_files, sgid_files, tmp_executables,
            hidden_files_suspicious, recent_modified, webroot_files,
            key_binary_hashes, history_files, shell_configs.
        """
        self._scan_start_time = time.time()

        # Pre-parse user list to avoid repeatedly reading /etc/passwd
        self._user_home_dirs = self._get_user_home_dirs()

        # Phase 1: SUID files (critical for privilege escalation detection)
        suid_files = self._scan_special_perm_files(stat.S_ISUID)
        self._update_partial_result(suid_files=suid_files)

        if self._should_skip_due_to_timeout():
            logger.warning("Filesystem collector: soft timeout reached after SUID scan")
            with self._lock:
                self._partial_result["_partial"] = True
            return self.get_partial_result()

        # Phase 2: SGID files
        sgid_files = self._scan_special_perm_files(stat.S_ISGID)
        self._update_partial_result(sgid_files=sgid_files)

        if self._should_skip_due_to_timeout():
            logger.warning("Filesystem collector: soft timeout reached after SGID scan")
            with self._lock:
                self._partial_result["_partial"] = True
            return self.get_partial_result()

        # Phase 3: Temporary executables
        tmp_executables = self._scan_tmp_executables()
        self._update_partial_result(tmp_executables=tmp_executables)

        if self._should_skip_due_to_timeout():
            logger.warning("Filesystem collector: soft timeout reached after tmp exec scan")
            with self._lock:
                self._partial_result["_partial"] = True
            return self.get_partial_result()

        # Phase 4: Hidden files
        hidden_files = self._scan_hidden_files()
        self._update_partial_result(hidden_files_suspicious=hidden_files)

        if self._should_skip_due_to_timeout():
            logger.warning("Filesystem collector: soft timeout reached after hidden files scan")
            with self._lock:
                self._partial_result["_partial"] = True
            return self.get_partial_result()

        # Phase 5: Recently modified files
        recent_files = self._scan_recent_modified()
        self._update_partial_result(recent_modified=recent_files)

        if self._should_skip_due_to_timeout():
            logger.warning("Filesystem collector: soft timeout reached after recent modified scan")
            with self._lock:
                self._partial_result["_partial"] = True
            return self.get_partial_result()

        # Phase 6: Webroot files (expensive recursive scan)
        webroot_files = self._scan_webroot_files()
        self._update_partial_result(webroot_files=webroot_files)

        if self._should_skip_due_to_timeout():
            logger.warning("Filesystem collector: soft timeout reached after webroot scan")
            with self._lock:
                self._partial_result["_partial"] = True
            return self.get_partial_result()

        # Phase 7: Key binary hashes
        binary_hashes = self._compute_key_binary_hashes()
        self._update_partial_result(key_binary_hashes=binary_hashes)

        # Phase 8: History files
        history_files = self._collect_history_files()
        self._update_partial_result(history_files=history_files)

        # Phase 9: Shell configs
        shell_configs = self._collect_shell_configs()
        self._update_partial_result(shell_configs=shell_configs)

        if self._should_skip_due_to_timeout():
            logger.warning("Filesystem collector: soft timeout reached, skipping skill/k8s scan")
            with self._lock:
                self._partial_result["_partial"] = True
            return self.get_partial_result()

        # Phase 10: Skill files
        skill_files = self._scan_skill_files()
        self._update_partial_result(skill_files=skill_files)

        # Phase 11: K8s sensitive files
        k8s_files = self._scan_k8s_sensitive_files()
        self._update_partial_result(k8s_sensitive_files=k8s_files)

        elapsed = time.time() - self._scan_start_time
        logger.debug(
            f"Filesystem collector: returning filesystem data "
            f"(SUID: {len(suid_files)}, SGID: {len(sgid_files)}, "
            f"Tmp: {len(tmp_executables)}, Hidden: {len(hidden_files)}, "
            f"Recent: {len(recent_files)}, Webroot: {len(webroot_files)}, "
            f"Binaries: {len(binary_hashes)}, History: {len(history_files)}, "
            f"Shell configs: {len(shell_configs)}, Skills: {len(skill_files)}, "
            f"K8s: {len(k8s_files)})"
        )

        # Truncate at collector layer to prevent analyzer processing huge lists
        def _truncate(data, label):
            if len(data) > self.max_items_limit:
                logger.warning(
                    f"[{self.name}] '{label}' exceeds limit: "
                    f"{len(data)} > {self.max_items_limit}, truncating"
                )
                if isinstance(data, dict):
                    return dict(list(data.items())[:self.max_items_limit])
                return data[:self.max_items_limit]
            return data

        suid_files = _truncate(suid_files, 'suid_files')
        sgid_files = _truncate(sgid_files, 'sgid_files')
        tmp_executables = _truncate(tmp_executables, 'tmp_executables')
        hidden_files = _truncate(hidden_files, 'hidden_files_suspicious')
        recent_files = _truncate(recent_files, 'recent_modified')
        webroot_files = _truncate(webroot_files, 'webroot_files')
        binary_hashes = _truncate(binary_hashes, 'key_binary_hashes')
        history_files = _truncate(history_files, 'history_files')
        shell_configs = _truncate(shell_configs, 'shell_configs')
        skill_files = _truncate(skill_files, 'skill_files')
        k8s_files = _truncate(k8s_files, 'k8s_sensitive_files')

        result = {
            "suid_files": suid_files,
            "sgid_files": sgid_files,
            "tmp_executables": tmp_executables,
            "hidden_files_suspicious": hidden_files,
            "recent_modified": recent_files,
            "webroot_files": webroot_files,
            "key_binary_hashes": binary_hashes,
            "history_files": history_files,
            "shell_configs": shell_configs,
            "skill_files": skill_files,
            "k8s_sensitive_files": k8s_files,
        }

        del suid_files, sgid_files, tmp_executables, hidden_files, recent_files
        del webroot_files, binary_hashes, history_files, shell_configs, skill_files, k8s_files

        gc.collect()

        return result
