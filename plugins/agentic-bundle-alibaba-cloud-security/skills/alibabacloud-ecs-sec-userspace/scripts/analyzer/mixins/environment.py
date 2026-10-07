"""
EnvAwareMixin: Environment detection and awareness for analyzers.

Extracted from BaseAnalyzer to modularize environment detection functionality.
Methods: should_skip, _is_development_environment, proc_available,
         is_container_env, has_ebpf_support, has_ai_agents, has_k8s
"""
import os
import threading
from typing import Tuple


# Development environment detection patterns (shared across analyzers)
DEV_ENV_PATH_PATTERNS = ['/data/work', '/home/admin', '/Users/', '/workspace/', '/vscode/', '/projects/']
DEV_ENV_HOSTNAME_PATTERNS = ['development', 'dev-', '-dev', 'local', 'localhost']

_skip_expensive_flag = False


def set_skip_expensive_flag(value: bool):
    """Set the global skip expensive analyzers flag."""
    global _skip_expensive_flag
    _skip_expensive_flag = value


def get_skip_expensive_flag() -> bool:
    """Get the global skip expensive analyzers flag."""
    return _skip_expensive_flag


_lazy_init_lock = threading.Lock()

_config_loader = None
def _get_config_loader():
    """Lazy load config_loader to avoid import at module level."""
    global _config_loader
    if _config_loader is None:
        with _lazy_init_lock:
            if _config_loader is None:
                from .. import config_loader
                _config_loader = config_loader
    return _config_loader


def _get_expensive_analyzer_threshold():
    """Get expensive analyzer threshold from config or fallback."""
    try:
        loader = _get_config_loader()
        return loader.get_load_adaptive_config().get("expensive_analyzer_threshold", 10.0)
    except (ImportError, OSError, ValueError, KeyError, AttributeError):
        return 10.0


EXPENSIVE_ANALYZER_THRESHOLD = _get_expensive_analyzer_threshold()

_logger = None
def _get_logger():
    """Lazy logger initialization."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger


class EnvAwareMixin:
    """Mixin providing environment detection and awareness for analyzers."""

    def has_ebpf_support(self) -> bool:
        """Check if the system has eBPF support.

        Checks for /sys/fs/bpf mount and bpftool availability.
        Returns False on any detection failure.
        """
        try:
            if os.path.isdir('/sys/fs/bpf'):
                return True
            # Check for bpftool in common paths
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
        except OSError:
            return False

    def should_skip(self) -> Tuple[bool, str]:
        """Check if this analyzer should be skipped

        Subclasses can override this method to define custom skip conditions.
        Default implementation returns (False, "") - no skip.
        Uses self.env_context for environment-aware skip decisions.

        Returns:
            tuple: (should_skip: bool, reason: str)
        """
        if _skip_expensive_flag and self.estimated_time >= EXPENSIVE_ANALYZER_THRESHOLD:
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
