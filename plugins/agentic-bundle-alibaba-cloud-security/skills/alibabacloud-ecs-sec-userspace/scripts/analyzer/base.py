"""Analyzer result and streaming data class"""
from abc import ABC, abstractmethod
import os
import threading
import time
from typing import List, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from ..reporter.severity import Severity
    from ..reporter.evidence import Evidence
    from ..collector.base import CollectResult

from .mixins import DataExtractionMixin, ThrottleMixin, StreamingMixin
from .mixins import caching as _caching_module
from .mixins.caching import _shared_analyzer_cache, _shared_cache_lock


# Lazy import helpers for heavy dependencies
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

_lazy_init_lock = threading.Lock()

_config_loader = None
def _get_config_loader():
    """Lazy load config_loader to avoid import at module level."""
    global _config_loader
    if _config_loader is None:
        with _lazy_init_lock:
            if _config_loader is None:
                from . import config_loader
                _config_loader = config_loader
    return _config_loader

_datetime = None
def _get_datetime():
    """Lazy datetime import to defer loading datetime and timezone."""
    global _datetime
    if _datetime is None:
        with _lazy_init_lock:
            if _datetime is None:
                from datetime import datetime, timezone
                _datetime = (datetime, timezone)
    return _datetime


# Default memory budget for analyzers (MB)
def _get_default_memory_budget():
    """Get default memory budget from config or fallback."""
    try:
        loader = _get_config_loader()
        return loader.get_global_memory_config().get("default_budget_mb", 200)
    except (ImportError, OSError, ValueError, KeyError, AttributeError):
        return 200

DEFAULT_MEMORY_BUDGET_MB = _get_default_memory_budget()

from .mixins.environment import (
    DEV_ENV_PATH_PATTERNS,
    DEV_ENV_HOSTNAME_PATTERNS,
    EXPENSIVE_ANALYZER_THRESHOLD,
    get_skip_expensive_flag,
)


class AnalyzeResult:
    """Analysis result class - using explicit __init__ to avoid field name obfuscation issues"""
    
    def __init__(self, status: str, module: str, evidences: List['Evidence'] = None, 
                 reason: str = "", duration: float = 0.0, execution_mode: str = "unknown"):
        self.status = status                    # "success" | "skipped" | "error"
        self.module = module                    # Analyzer name
        self.evidences = evidences or []        # List of evidence objects
        self.reason = reason                    # Reason for skipped/error
        self.duration = duration                # Execution duration (seconds)
        self.execution_mode = execution_mode    # "quick_check" | "full_analysis" | "skipped" | "unknown"


class BaseAnalyzer(DataExtractionMixin, ThrottleMixin, StreamingMixin, ABC):
    """Analyzer base class"""

    name: str = "base"           # Subclass override
    timeout: int = 60            # Module timeout in seconds (subclass overridable)
    
    @property
    def EXTREME_LOAD_TIMEOUT_THRESHOLD(self):
        return self._get_global_config("load_adaptive.extreme_load_timeout_threshold", 30.0)

    @property
    def EXTREME_LOAD_ANALYZER_TIMEOUT(self):
        return self._get_global_config("load_adaptive.extreme_load_analyzer_timeout", 3.0)

    @property
    def HIGH_LOAD_TIMEOUT_THRESHOLD(self):
        return self._get_global_config("load_adaptive.high_load_timeout_threshold", 15.0)

    @property
    def HIGH_LOAD_ANALYZER_TIMEOUT(self):
        return self._get_global_config("load_adaptive.high_load_analyzer_timeout", 5.0)
    
    # Smart scheduling attributes
    estimated_time: float = 1.0  # Estimated execution time in seconds
    analyzer_type: str = "routine"  # critical, important, routine, extended
    
    # Analyzer type constants
    CRITICAL = "critical"      # Must execute, < 10s
    IMPORTANT = "important"    # Priority execute, < 30s
    ROUTINE = "routine"        # On-demand execute, < 60s
    EXTENDED = "extended"      # Deferred execute, > 60s

    # Memory management attributes
    memory_budget_mb: float = DEFAULT_MEMORY_BUDGET_MB  # Memory budget in MB
    chunk_size: int = 10000    # Default chunk size for streaming
    
    # Feedback loop: confidence factor applied to evidence scoring
    confidence_factor: float = 1.0

    def __init__(self, workspace_dir: str = None):
        self._evidence_counter = 0
        self.workspace_dir = workspace_dir
        self._whitelist_manager = None
        self._whitelist_initialized = False
        self._cancel_flag = False  # Cooperative cancellation flag for timeout enforcement
        self._result_cache = {}
        self._cache_enabled = True

        self._config = self._load_analyzer_config()

    def _ensure_whitelist_manager(self):
        """Lazy initialization of whitelist manager.
        
        Defers expensive whitelist imports until first actual use,
        reducing per-analyzer instantiation overhead.
        """
        if self._whitelist_initialized:
            return
        
        self._whitelist_initialized = True
        
        if not self.workspace_dir:
            return

        try:
            from ..utils.hashed_whitelist import get_whitelist_manager
            self._whitelist_manager = get_whitelist_manager(self.workspace_dir)
        except ImportError as e:
            _get_logger().debug(f"Failed to import hashed whitelist manager: {e}")
        except (OSError, ValueError, KeyError) as e:
            _get_logger().debug(f"Failed to initialize hashed whitelist manager: {e}")
        
        if not self._whitelist_manager:
            try:
                from ..utils.whitelist import get_whitelist_manager
                self._whitelist_manager = get_whitelist_manager(self.workspace_dir)
            except ImportError as e:
                _get_logger().debug(f"Failed to import original whitelist manager: {e}")
            except (OSError, ValueError, KeyError) as e:
                _get_logger().debug(f"Failed to initialize original whitelist manager: {e}")

    # ── Environment detection helpers ──────────────────────────────────
    # These methods provide lightweight environment checks for should_skip().
    # They use direct OS checks (stdlib only) and never raise exceptions.

    def has_ebpf_support(self) -> bool:
        """Check if the system has eBPF support.
        
        Checks for /sys/fs/bpf mount and bpftool availability.
        Returns False on any detection failure.
        """
        try:
            if os.path.isdir('/sys/fs/bpf'):
                return True
            for path in ('/usr/sbin/bpftool', '/usr/bin/bpftool', '/sbin/bpftool'):
                if os.path.isfile(path):
                    return True
            return False
        except OSError:
            return False

    def has_ai_agents(self) -> bool:
        """Check if AI agent processes are running.
        
        Scans /proc for common AI agent frameworks and processes.
        Returns False if no agents detected or on any error.
        """
        try:
            ai_indicators = (
                'langchain', 'autogen', 'crewai', 'openai',
                'llamaindex', 'llama_index', 'mcp_server', 'mcp-server',
                'agent_executor', 'agentexecutor',
            )
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                try:
                    cmdline_path = f'/proc/{pid_dir}/cmdline'
                    with open(cmdline_path, 'rb') as f:
                        cmdline = f.read(4096).decode('utf-8', errors='ignore').lower()
                    if any(ind in cmdline for ind in ai_indicators):
                        return True
                except OSError:
                    continue
            return False
        except OSError:
            return False

    def has_k8s(self) -> bool:
        """Check if running in a Kubernetes environment.
        
        Checks for K8s service account, environment variables, and kubelet.
        Returns False if not in K8s or on any error.
        """
        try:
            # K8s injects this env var into every pod
            if os.environ.get('KUBERNETES_SERVICE_HOST'):
                return True
            # Service account mount
            if os.path.isdir('/var/run/secrets/kubernetes.io/serviceaccount'):
                return True
            # Check kubelet process via /proc
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                try:
                    cmdline_path = f'/proc/{pid_dir}/cmdline'
                    with open(cmdline_path, 'rb') as f:
                        cmdline = f.read(1024).decode('utf-8', errors='ignore')
                    if 'kubelet' in cmdline:
                        return True
                except OSError:
                    continue
            return False
        except OSError:
            return False

    def proc_available(self) -> bool:
        """Check if /proc filesystem is accessible and readable.
        
        Returns False if /proc is not mounted or not readable.
        """
        try:
            return os.path.isdir('/proc') and os.access('/proc', os.R_OK)
        except OSError:
            return False

    def is_container_env(self) -> bool:
        """Check if running inside a container (Docker, Podman, LXC, etc.).
        
        Checks for /.dockerenv, /run/.containerenv, and cgroup container markers.
        Returns False if not in a container or on any error.
        """
        try:
            if os.path.exists('/.dockerenv'):
                return True
            if os.path.exists('/run/.containerenv'):
                return True
            # Check cgroup for container markers
            try:
                with open('/proc/1/cgroup', 'r', encoding='utf-8') as f:
                    cgroup_content = f.read()
                if any(marker in cgroup_content for marker in ('docker', 'kubepods', 'containerd', 'lxc')):
                    return True
            except OSError:
                pass
            return False
        except (OSError, UnicodeDecodeError):
            return False

    def should_skip(self) -> tuple:
        """Check if this analyzer should be skipped
        
        Subclasses can override this method to define custom skip conditions.
        Default implementation returns (False, "") - no skip.
        Uses self.env_context for environment-aware skip decisions.
            
        Returns:
            tuple: (should_skip: bool, reason: str)
        """
        if get_skip_expensive_flag() and self.estimated_time >= EXPENSIVE_ANALYZER_THRESHOLD:
            return True, f"Skipping {self.name} - expensive analyzer (estimated_time={self.estimated_time:.1f}s >= {EXPENSIVE_ANALYZER_THRESHOLD:.1f}s threshold), --skip-expensive flag enabled"
        return False, ""

    def _is_development_environment(self) -> bool:
        """Detect if running in development environment.
        
        Checks multiple indicators to determine if this is a development
        environment where certain checks should be skipped.
        
        Returns:
            True if running in development environment
        """
        dev_indicators = []
        cwd = os.getcwd()
        for pattern in DEV_ENV_PATH_PATTERNS:
            if pattern in cwd:
                dev_indicators.append(f'CWD matches dev pattern: {pattern}')
                _get_logger().debug(f'[{self.name}] Development path indicator: {pattern} in {cwd}')
                break
        hostname = os.environ.get('HOSTNAME', '').lower()
        for pattern in DEV_ENV_HOSTNAME_PATTERNS:
            if pattern in hostname:
                dev_indicators.append(f'Hostname matches dev pattern: {pattern}')
                _get_logger().debug(f'[{self.name}] Development hostname indicator: {pattern} in {hostname}')
                break
        if not os.path.exists('/.dockerenv') and (not os.path.exists('/run/.containerenv')):
            dev_indicators.append('Not running in Docker/Podman container')
            _get_logger().debug(f'[{self.name}] Not in container environment')
        dev_artifacts = ['/.git', '/node_modules', '/venv', '/.venv', '/.idea', '/.vscode']
        for artifact in dev_artifacts:
            if os.path.exists(artifact) or os.path.exists(cwd + artifact):
                dev_indicators.append(f'Development artifact found: {artifact}')
                _get_logger().debug(f'[{self.name}] Development artifact: {artifact}')
                break
        is_dev = len(dev_indicators) >= 2
        if is_dev:
            _get_logger().info(f'[{self.name}] Development environment confirmed ({len(dev_indicators)} indicators)')
            for indicator in dev_indicators[:3]:
                _get_logger().debug(f'[{self.name}]   - {indicator}')
        return is_dev

    def _should_cancel(self) -> bool:
        """Check if analyzer should cancel execution due to timeout.
        
        Subclasses should check this method periodically during long-running
        operations to enable cooperative cancellation.
        
        Returns:
            bool: True if analyzer should abort execution
        """
        return self._cancel_flag

    def _check_and_cancel(self, operation: str = "operation") -> bool:
        """Check cancel flag and log if cancelled.
        
        Convenience method that checks _should_cancel() and logs the cancellation.
        Use this in long-running loops for periodic cancellation checks.
        
        Args:
            operation: Current operation name for logging
            
        Returns:
            bool: True if cancelled (should abort), False otherwise
        """
        if self._should_cancel():
            _get_logger().warning(
                f"[{self.name}] Cooperative cancellation triggered during {operation}"
            )
            return True
        return False

    def _reset_cancel_flag(self):
        """Reset the cancel flag for reuse of analyzer instance."""
        self._cancel_flag = False


    def _load_analyzer_config(self) -> dict:
        """Load configuration for this analyzer from analyzer.yaml.

        Returns:
            Merged config dict (analyzer-specific > defaults > code defaults)
        """
        try:
            loader = _get_config_loader()
            return loader.get_analyzer_config(self.name)
        except (ImportError, OSError, ValueError, KeyError) as e:
            if _logger:
                _get_logger().debug(f"[{self.name}] Config load failed: {e}")
            return {}

    def _get_config(self, key: str, default=None):
        """Get a configuration value for this analyzer.

        Falls back to the provided default if the key is not in the config.
        Subclasses use this to replace hardcoded values.

        Args:
            key: Configuration key (e.g., 'timeout', 'thresholds.max_package_checks')
            default: Default value if key not found

        Returns:
            Config value or default
        """
        if not self._config:
            return default

        # Support dotted key paths like 'thresholds.max_package_checks'
        if '.' in key:
            parts = key.split('.')
            value = self._config
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return default
            return value

        return self._config.get(key, default)

    def _get_global_config(self, key: str, default=None):
        """Get a global configuration value from analyzer.yaml.

        These are values from the top-level sections (cache, memory, load_adaptive, paths)
        that apply to all analyzers.

        Args:
            key: Configuration key with section prefix (e.g., 'cache.shared_cache_max_size')
            default: Default value if key not found

        Returns:
            Config value or default
        """
        try:
            loader = _get_config_loader()
            parts = key.split('.', 1)
            if len(parts) == 2:
                section, subkey = parts
                if section == 'cache':
                    cfg = loader.get_global_cache_config()
                elif section == 'memory':
                    cfg = loader.get_global_memory_config()
                elif section == 'load_adaptive':
                    cfg = loader.get_load_adaptive_config()
                elif section == 'paths':
                    cfg = loader.get_global_paths_config()
                else:
                    return default

                # Support nested dotted paths within section
                if '.' in subkey:
                    subparts = subkey.split('.')
                    value = cfg
                    for subpart in subparts:
                        if isinstance(value, dict) and subpart in value:
                            value = value[subpart]
                        else:
                            return default
                    return value
                return cfg.get(subkey, default)
            return default
        except (ImportError, OSError, ValueError, KeyError, AttributeError) as e:
            if _logger:
                _get_logger().debug(f"[{self.name}] Global config load failed: {e}")
            return default

    def safe_analyze(self, collected_data: Dict[str, 'CollectResult'],
                     is_high_load: bool = False,
                     is_deferred_analyzer: bool = False) -> AnalyzeResult:
        """Safe execution wrapper - sequential, no threading.

        Args:
            collected_data: Collected data from collectors
            is_high_load: Whether running under extreme system load
            is_deferred_analyzer: Whether this is a deferred analyzer

        Returns:
            AnalyzeResult with status, evidences, and duration
        """
        start_time = time.monotonic()

        try:
            # Reset cancel flag for reuse of analyzer instance
            self._reset_cancel_flag()
            self.is_high_load = is_high_load

            # Check if analyzer should be skipped
            try:
                skip_result = self.should_skip()
                if isinstance(skip_result, tuple) and len(skip_result) == 2:
                    should_skip_result, skip_reason = skip_result
                    if not isinstance(should_skip_result, bool):
                        should_skip_result = bool(should_skip_result)
                elif isinstance(skip_result, bool):
                    should_skip_result = skip_result
                    skip_reason = "" if not skip_result else "Skipped by should_skip()"
                else:
                    should_skip_result, skip_reason = False, ""
            except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError) as e:
                _get_logger().warning("[%s] should_skip() raised %s: %s", self.name, type(e).__name__, e)
                should_skip_result, skip_reason = False, ""

            if should_skip_result:
                duration = time.monotonic() - start_time
                _get_logger().info("[%s] %s", self.name, skip_reason)
                return AnalyzeResult(
                    status="skipped",
                    module=self.name,
                    reason=skip_reason,
                    duration=duration,
                    execution_mode="skipped"
                )

            # Check shared cache
            if self._cache_enabled:
                cache_key = "{}:{}".format(self.name, self._get_cache_key(collected_data))
                with _shared_cache_lock:
                    cache_hit = cache_key in _shared_analyzer_cache
                    cached_evidences = _shared_analyzer_cache.get(cache_key) if cache_hit else None
                if cache_hit:
                    duration = time.monotonic() - start_time
                    return AnalyzeResult(
                        status="success",
                        module=self.name,
                        evidences=cached_evidences,
                        duration=duration,
                        execution_mode="quick_check"
                    )

            # Execute analysis directly (no threading)
            evidences = self.analyze(collected_data)

            # Store in cache
            if self._cache_enabled:
                cache_key = "{}:{}".format(self.name, self._get_cache_key(collected_data))
                with _shared_cache_lock:
                    if len(_shared_analyzer_cache) >= _caching_module._shared_cache_max_size:
                        oldest_key = next(iter(_shared_analyzer_cache))
                        del _shared_analyzer_cache[oldest_key]
                    _shared_analyzer_cache[cache_key] = evidences

            duration = time.monotonic() - start_time
            _get_logger().info("[%s] Analysis complete (found %d evidences, %.1fs)", self.name, len(evidences), duration)

            return AnalyzeResult(
                status="success",
                module=self.name,
                evidences=evidences,
                duration=duration,
                execution_mode="full_analysis"
            )

        except KeyError as e:
            duration = time.monotonic() - start_time
            reason = "Required data not found: {}".format(str(e))
            _get_logger().warning("[%s] Analysis skipped: %s", self.name, reason)
            return AnalyzeResult(
                status="skipped",
                module=self.name,
                reason=reason,
                duration=duration
            )

        except (OSError, ValueError, TypeError, AttributeError) as e:
            duration = time.monotonic() - start_time
            reason = str(e)
            _get_logger().error("[%s] Analysis failed: %s", self.name, reason, exc_info=True)
            return AnalyzeResult(
                status="error",
                module=self.name,
                reason=reason,
                duration=duration
            )

        except (MemoryError, RecursionError):
            raise

        except Exception as e:
            duration = time.monotonic() - start_time
            reason = "{}: {}".format(type(e).__name__, e)
            _get_logger().error("[%s] Analysis failed (unexpected): %s", self.name, reason, exc_info=True)
            return AnalyzeResult(
                status="error",
                module=self.name,
                reason=reason,
                duration=duration
            )

    @abstractmethod
    def analyze(self, collected_data: Dict[str, 'CollectResult']) -> List['Evidence']:
        """Abstract method, subclasses implement specific analysis logic"""

    def _get_cache_key(self, collected_data: Dict) -> str:
        """Generate cache key from collected data."""
        import hashlib
        import json

        signature_parts = []
        content_hasher = hashlib.sha256()

        for key in sorted(collected_data.keys()):
            value = collected_data[key]
            if isinstance(value, list):
                signature_parts.append(f"{key}:list:{len(value)}")
                for item in value[:100]:
                    try:
                        content_hasher.update(json.dumps(item, sort_keys=True, default=str).encode())
                    except (TypeError, ValueError):
                        content_hasher.update(str(item).encode())
            elif isinstance(value, dict):
                signature_parts.append(f"{key}:dict:{len(value)}")
                try:
                    content_hasher.update(json.dumps(value, sort_keys=True, default=str).encode())
                except (TypeError, ValueError):
                    content_hasher.update(str(value).encode())
            else:
                signature_parts.append(f"{key}:{str(value)[:50]}")
                content_hasher.update(str(value).encode())

        signature = "|".join(signature_parts)
        content_digest = content_hasher.hexdigest()[:16]
        combined = f"{signature}:{content_digest}"
        return hashlib.md5(combined.encode(), usedforsecurity=False).hexdigest()

    def _create_evidence(
        self,
        title: str,
        description: str,
        severity: 'Severity',
        confidence: float,
        attack_id: str,
        attack_tactic: str = "",
        source_path: str = "",
        raw_data: dict = None,
        remediation: str = "",
        verified_status: str = "pending",
        owasp_asi: str = "",
        evidence_details=None,
        remediation_commands=None
    ) -> 'Evidence':
        """Simplified Evidence creation, auto-fills module and timestamp
        
        Args:
            title: Evidence title
            description: Evidence description
            severity: Severity level
            confidence: Confidence score (0-1)
            attack_id: MITRE ATT&CK technique ID
            attack_tactic: MITRE ATT&CK tactic name
            source_path: Source file or path
            raw_data: Raw detection data
            remediation: Human-readable remediation text
            verified_status: Verification status
            owasp_asi: OWASP ASI category
            evidence_details: Optional EvidenceDetail object with structured context
            remediation_commands: Optional list of remediation commands
        """
        from ..reporter.evidence import Evidence

        self._evidence_counter += 1
        datetime, timezone = _get_datetime()
        adjusted_confidence = max(0.0, min(1.0, confidence * self.confidence_factor))
        return Evidence(
            id=f"{self.name}-{self._evidence_counter}",
            module=self.name,
            title=title,
            description=description,
            severity=severity,
            confidence=adjusted_confidence,
            attack_id=attack_id,
            attack_tactic=attack_tactic,
            source_path=source_path,
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_data=raw_data or {},
            remediation=remediation,
            verified_status=verified_status,
            owasp_asi=owasp_asi,
            evidence_details=evidence_details,
            remediation_commands=remediation_commands or []
        )

    def _create_evidence_details(self, **kwargs) -> 'EvidenceDetail':
        """Create EvidenceDetail with automatic filtering of empty values.
        
        This helper ensures that only fields with meaningful data are populated,
        avoiding empty strings and zero values that reduce report quality.
        
        Args:
            **kwargs: Field name and value pairs for EvidenceDetail
            
        Returns:
            EvidenceDetail: Instance with only meaningful fields populated
            
        Example:
            self._create_evidence_details(
                pid=1234,
                cmdline='/usr/bin/test',
                file_path=''  # Will be filtered
            )
            # Returns EvidenceDetail(pid=1234, cmdline='/usr/bin/test')
        """
        from ..reporter.evidence import EvidenceDetail
        
        # Filter out None and empty strings; preserve 0, False, and []
        filtered_kwargs = {}
        for key, value in kwargs.items():
            if value is None:
                continue
            if isinstance(value, str) and value == '':
                continue
            filtered_kwargs[key] = value
        
        return EvidenceDetail(**filtered_kwargs)

    def _check_whitelist(self, evidence_value: str) -> bool:
        """Check if evidence matches whitelist

        Args:
            evidence_value: Evidence value to check

        Returns:
            bool: True if whitelisted
        """
        self._ensure_whitelist_manager()
        
        if not self._whitelist_manager:
            return False
        return self._whitelist_manager.is_whitelisted(self.name, evidence_value)

