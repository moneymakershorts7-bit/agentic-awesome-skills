"""Utils module for sec-userspace."""
import threading

# Lazy-load proc module to reduce import overhead at startup
# proc.py is 780+ lines and accounts for ~54% of utils import time
_proc_module = None
_proc_module_lock = threading.Lock()

def _load_proc_module():
    """Load proc module directly from file to avoid circular import."""
    global _proc_module
    if _proc_module is None:
        with _proc_module_lock:
            if _proc_module is None:
                import importlib.util
                import os
                proc_path = os.path.join(os.path.dirname(__file__), 'proc.py')
                spec = importlib.util.spec_from_file_location("_proc_actual", proc_path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                _proc_module = mod
    return _proc_module

# Proxy functions that lazy-load proc module on first call
def list_pids(*args, **kwargs):
    """Lazy wrapper for proc.list_pids."""
    return _load_proc_module().list_pids(*args, **kwargs)

def read_proc_file(*args, **kwargs):
    """Lazy wrapper for proc.read_proc_file."""
    return _load_proc_module().read_proc_file(*args, **kwargs)

def get_proc_stat(*args, **kwargs):
    """Lazy wrapper for proc.get_proc_stat."""
    return _load_proc_module().get_proc_stat(*args, **kwargs)

def get_proc_cmdline(*args, **kwargs):
    """Lazy wrapper for proc.get_proc_cmdline."""
    return _load_proc_module().get_proc_cmdline(*args, **kwargs)

def get_proc_exe(*args, **kwargs):
    """Lazy wrapper for proc.get_proc_exe."""
    return _load_proc_module().get_proc_exe(*args, **kwargs)

def get_proc_environ(*args, **kwargs):
    """Lazy wrapper for proc.get_proc_environ."""
    return _load_proc_module().get_proc_environ(*args, **kwargs)

def get_proc_fd_list(*args, **kwargs):
    """Lazy wrapper for proc.get_proc_fd_list."""
    return _load_proc_module().get_proc_fd_list(*args, **kwargs)

def get_proc_maps(*args, **kwargs):
    """Lazy wrapper for proc.get_proc_maps."""
    return _load_proc_module().get_proc_maps(*args, **kwargs)

def get_loadavg(*args, **kwargs):
    """Lazy wrapper for proc.get_loadavg."""
    return _load_proc_module().get_loadavg(*args, **kwargs)

def get_meminfo(*args, **kwargs):
    """Lazy wrapper for proc.get_meminfo."""
    return _load_proc_module().get_meminfo(*args, **kwargs)

def get_cpu_count(*args, **kwargs):
    """Lazy wrapper for proc.get_cpu_count."""
    return _load_proc_module().get_cpu_count(*args, **kwargs)

def get_self_status(*args, **kwargs):
    """Lazy wrapper for proc.get_self_status."""
    return _load_proc_module().get_self_status(*args, **kwargs)

def parse_proc_net_tcp(*args, **kwargs):
    """Lazy wrapper for proc.parse_proc_net_tcp."""
    return _load_proc_module().parse_proc_net_tcp(*args, **kwargs)

def parse_proc_net_udp(*args, **kwargs):
    """Lazy wrapper for proc.parse_proc_net_udp."""
    return _load_proc_module().parse_proc_net_udp(*args, **kwargs)

def get_process_list(*args, **kwargs):
    """Lazy wrapper for proc.get_process_list."""
    return _load_proc_module().get_process_list(*args, **kwargs)

# Provide module-level attribute access for `from ..utils import proc`
# This returns a lazy proxy that loads functions on demand
class _LazyProcModule:
    """Lazy loading proxy for proc module."""

    def __getattr__(self, name):
        return _load_proc_module().__getattr__(name) if hasattr(_load_proc_module(), '__getattr__') else getattr(_load_proc_module(), name)

    def __dir__(self):
        return dir(_load_proc_module())

# Create lazy proc module instance
proc = _LazyProcModule()

from .hash import file_sha256, string_sha256
from .safe_exec import safe_run

# Lazy-load fp_tracker to avoid I/O overhead at import time
def _lazy_import_fp_tracker():
    """Lazy-load FP tracker module."""
    from .fp_tracker import (
        FpTracker, FPRecord, get_tracker, record_fp, record_detection,
        is_false_positive, get_exception_context, DEFAULT_FP_EXCEPTIONS_PATHS
    )
    return FpTracker, FPRecord, get_tracker, record_fp, record_detection, is_false_positive, get_exception_context, DEFAULT_FP_EXCEPTIONS_PATHS

# Lazy-load fp_auto_learner to avoid I/O overhead at import time
def _lazy_import_fp_auto_learner():
    """Lazy-load FP auto-learner module."""
    from .fp_auto_learner import FPAutoLearner, get_fp_auto_learner, reset_fp_auto_learner
    return FPAutoLearner, get_fp_auto_learner, reset_fp_auto_learner

from .i18n import (
    CONCLUSION_MAP,
    SEVERITY_MAP,
    MODULE_MAP,
    TACTIC_MAP,
    ATTACK_ID_TO_TACTIC,
    translate_conclusion,
    translate_severity,
    translate_module,
    translate_tactic,
    localize_log_message,
    get_attack_tactic_name
)
from .redact import redact_credential, redact_in_text

# Lazy-load behavior_audit_logger to avoid import overhead
def _lazy_import_behavior_audit_logger():
    """Lazy-load behavior audit logger module."""
    from .behavior_audit_logger import (
        BehaviorAuditLogger,
        AuditLogQuery,
        AuditEvent,
        AuditSeverity,
        AuditQueryResult,
    )
    return BehaviorAuditLogger, AuditLogQuery, AuditEvent, AuditSeverity, AuditQueryResult

# Lazy-load security_config_generator to avoid import overhead
def _lazy_import_security_config_generator():
    """Lazy-load security config generator module."""
    from .security_config_generator import (
        SecurityConfigGenerator,
        SecurityLevel,
        AgentType,
        CloudProvider,
        ContainerConfig,
        NetworkConfig,
        EncryptionConfig,
        AuditConfig,
    )
    return SecurityConfigGenerator, SecurityLevel, AgentType, CloudProvider, ContainerConfig, NetworkConfig, EncryptionConfig, AuditConfig

# Lazy-import deduplicator to avoid import overhead
def _lazy_import_deduplicator():
    """Lazy-load deduplicator module."""
    from .deduplicator import (
        EvidenceDeduplicator,
        DeduplicationStrategy,
        DeduplicationResult,
        deduplicate_evidences,
    )
    return EvidenceDeduplicator, DeduplicationStrategy, DeduplicationResult, deduplicate_evidences

__all__ = [
    'list_pids', 'read_proc_file', 'get_proc_stat', 'get_proc_cmdline',
    'get_proc_exe', 'get_proc_environ', 'get_proc_fd_list', 'get_proc_maps',
    'get_loadavg', 'get_meminfo', 'get_cpu_count', 'get_self_status',
    'parse_proc_net_tcp', 'parse_proc_net_udp', 'get_process_list', 'file_sha256', 'string_sha256', 'safe_run',
    'proc',
    '_lazy_import_fp_tracker',
    '_lazy_import_fp_auto_learner',
    'CONCLUSION_MAP', 'SEVERITY_MAP', 'MODULE_MAP', 'TACTIC_MAP', 'ATTACK_ID_TO_TACTIC',
    'translate_conclusion', 'translate_severity', 'translate_module',
    'translate_tactic', 'localize_log_message', 'get_attack_tactic_name',
    'redact_credential', 'redact_in_text',
    '_lazy_import_behavior_audit_logger',
    '_lazy_import_security_config_generator',
    '_lazy_import_deduplicator',
]
