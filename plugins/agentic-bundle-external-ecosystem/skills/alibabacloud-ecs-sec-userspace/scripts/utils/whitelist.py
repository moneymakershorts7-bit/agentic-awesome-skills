"""Whitelist Management Module

Manages false positive whitelist. Supports auto-adding entries when 
Agent confirms false positives, and skips whitelisted alerts in subsequent scans.

Includes built-in false positive pattern library for common scenarios:
- Development tools (IDEs, compilers, debuggers)
- CI/CD pipelines (build scripts, deployment tools)
- Cloud services (monitoring agents, health checks)
- Container runtimes (Docker, Kubernetes)
- System administration (package managers, backups)
- AI development tools (Claude Code, Qoder, Cursor)
"""
import json
import os
import fnmatch
import logging
import re
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, List
from .datetime_compat import fromisoformat
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("sec-userspace")


# Built-in false positive patterns for common scenarios
# These are applied automatically based on environment detection
BUILTIN_FP_PATTERNS: Dict[str, Dict[str, List[str]]] = {
    "development_tools": {
        "description": "Development IDE, compilers, debuggers",
        "processes": [
            # JetBrains IDEs
            "idea", "pycharm", "webstorm", "goland", "clion", "rider",
            # VS Code and derivatives
            "code", "code-server", "cursor", "vscodium",
            # Other editors
            "vim", "nvim", "emacs", "sublime_text", "atom",
            # Compilers and build tools
            "gcc", "g++", "clang", "rustc", "javac", "tsc", "go",
            # Debuggers
            "gdb", "lldb", "dlv", "pdb",
            # Node.js development
            "node", "npm", "yarn", "pnpm", "npx",
            # Python development
            "python", "python3", "pip", "pip3", "pytest", "unittest",
            # Build systems
            "make", "cmake", "ninja", "bazel", "gradle", "maven",
        ],
        "paths": [
            "/opt/idea*", "/opt/pycharm*", "/opt/webstorm*",
            "/usr/share/idea*", "/usr/share/pycharm*",
            "/Applications/*.app/Contents/MacOS/*",
            "*/.local/share/JetBrains/**",
            "*/.config/JetBrains/**",
        ]
    },
    "ci_cd_tools": {
        "description": "CI/CD build and deployment tools",
        "processes": [
            # GitLab CI
            "gitlab-runner",
            # GitHub Actions
            "Runner.Listener", "Runner.Worker",
            # Jenkins
            "jenkins", "java",
            # Drone
            "drone-agent",
            # ArgoCD
            "argocd", "argocd-application-controller",
            # Common build/deploy scripts
            "terraform", "ansible", "puppet", "chef-client", "salt-minion",
        ],
        "paths": [
            "/home/gitlab-runner*", "/var/lib/jenkins*",
            "/opt/atlassian/pipeline-agent*",
        ]
    },
    "cloud_services": {
        "description": "Cloud provider monitoring and metadata services",
        "processes": [
            # AWS
            "amazon-cloudwatch-agent", "awslogs", "ssm-agent",
            # Azure
            "waagent", "azure-monitor-agent",
            # GCP
            "google-osconfig-agent", "stackdriver-agent",
            # Generic cloud tools
            "cloud-init", "cloud-init-local",
        ],
        "cmdline_patterns": [
            r".*metadata\.google\.internal.*",
            r".*169\.254\.169\.254.*",  # Cloud metadata IP
        ]
    },
    "container_runtimes": {
        "description": "Container runtime processes",
        "processes": [
            # Docker
            "dockerd", "docker-proxy", "com.docker.*",
            # containerd
            "containerd", "containerd-shim",
            # CRI-O
            "crio",
            # Kubernetes
            "kubelet", "kube-proxy", "coredns",
            # Podman
            "podman", "conmon",
        ],
        "paths": [
            "/var/run/docker.sock", "/var/run/containerd/*",
            "/var/lib/kubelet/*", "/etc/kubernetes/*",
        ]
    },
    "system_administration": {
        "description": "System maintenance tasks",
        "processes": [
            # Package managers
            "apt", "apt-get", "aptitude", "dpkg",
            "yum", "dnf", "rpm", "zypper",
            "pacman", "yay", "paru",
            # Backup tools
            "rsync", "tar", "restic", "borg", "duplicity",
            # Log rotation
            "logrotate",
            # System updates
            "unattended-upgr", "update-notifier",
            # Cron and scheduling
            "cron", "crond", "anacron", "at", "atd",
            # Time synchronization
            "ntpd", "chronyd", "systemd-timesyncd",
        ],
        "cmdline_patterns": [
            r"^(apt|apt-get|aptitude)\s+(update|upgrade|install).*$",
            r"^(yum|dnf)\s+(update|install).*$",
            r"^rsync\s+.*$",
            r"^tar\s+.*$",
        ]
    },
    "ai_development_tools": {
        "description": "AI development and coding tools",
        "processes": [
            # Claude Code
            "claude", "claude-code",
            # Qoder
            "qoder", "qoder-cli",
            # Cursor
            "cursor",
            # GitHub Copilot
            "copilot", "copilot-language-server",
            # Tabnine
            "tabnine", "tabnine-language-server",
            # Continue.dev
            "continue",
            # Codeium
            "codeium",
            # Sourcegraph Cody
            "cody",
            # Anthropic CLI tools
            "anthropic",
            # Node.js based AI tools
            "npx", "node",
        ],
        "paths": [
            "*/.claude-code/*",
            "*/.qoder/*",
            "*/.cursor/*",
            "*/.vscode/extensions/github.copilot-*",
            "*/.vscode/extensions/tabnine.*",
            # NPM global install paths (AI tools often installed here)
            "*/lib/node_modules/@anthropic-ai/*",
            "*/lib/node_modules/qoder*",
            "*/lib/node_modules/claude*",
            "*/lib/node_modules/cursor*",
            # Temporary extraction paths for AI tools
            "*/tmp/.claude-code-*/*",
            "*/tmp/.qoder-*/*",
            "*/tmp/.cursor-*/*",
        ],
        "cmdline_patterns": [
            # AI tool execution patterns
            r".*(claude|qoder|cursor|copilot|anthropic).*",
            # NPM/npx running AI tools
            r"^npx\s+(claude|qoder|cursor|anthropic|@anthropic-ai).*",
            r"^node\s+.*(claude|qoder|cursor|copilot|anthropic).*",
        ]
    },
    "network_monitoring": {
        "description": "Network monitoring and security tools",
        "processes": [
            # Security scanners
            "nmap", "masscan", "zmap",
            # Network diagnostics
            "tcpdump", "wireshark", "tshark",
            # Load balancers
            "nginx", "haproxy", "traefik", "envoy",
            # Reverse proxies
            "caddy", "apache2", "httpd",
        ],
        "paths": [
            "/usr/sbin/nmap", "/usr/bin/nmap",
            "/usr/sbin/tcpdump", "/usr/bin/tcpdump",
        ]
    },
}


@dataclass
class WhitelistEntry:
    """Whitelist entry"""
    id: str                    # Unique ID: whitelist-NNN
    module: str                # Analyzer name
    pattern: str               # Match pattern (exact or glob)
    reason: str                # Whitelist reason
    added_by: str = "agent"    # Added by: agent | system
    added_at: str = ""         # Addition timestamp (ISO format)
    expires: Optional[str] = None  # Expiration time (ISO format, null means never expires)
    environment: Optional[str] = None  # Environment context: development | production | ci | container
    enabled: bool = True       # Whether entry is enabled (soft delete support)
    tags: List[str] = field(default_factory=list)  # Tags for categorization
    
    def __post_init__(self):
        if not self.added_at:
            self.added_at = datetime.now(timezone.utc).isoformat()
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        if not self.expires:
            return False
        try:
            expires_dt = fromisoformat(self.expires)
            return datetime.now(timezone.utc) > expires_dt
        except (ValueError, TypeError):
            return False
    
    def matches(self, module: str, evidence_value: str, environment: Optional[str] = None) -> bool:
        """Check if matches specified module and evidence value
        
        Args:
            module: Analyzer name
            evidence_value: Evidence value (e.g., process path, IP, domain, credential value)
            environment: Current environment context (optional)
        
        Returns:
            bool: Whether it matches
        """
        # Skip disabled entries
        if not self.enabled:
            return False
        
        if self.module != module:
            return False
        
        # Check environment match if specified
        if self.environment and environment and self.environment != environment:
            return False
        
        # Exact match
        if self.pattern == evidence_value:
            return True
        
        # Regex pattern matching (for cmdline patterns) - check before glob
        if self.pattern.startswith('regex:'):
            regex_pattern = self.pattern[6:]
            try:
                return bool(re.match(regex_pattern, evidence_value))
            except re.error:
                return False
        
        # Glob pattern matching (supports * and ?)
        if '*' in self.pattern or '?' in self.pattern:
            return fnmatch.fnmatch(evidence_value, self.pattern)
        
        return False
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'WhitelistEntry':
        """Create from dictionary
        
        Only extracts known fields, ignores unknown fields for backwards compatibility.
        """
        known_fields = {'id', 'module', 'pattern', 'reason', 'added_by', 'added_at', 'expires', 'environment', 'enabled', 'tags'}
        filtered_data = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered_data)


class WhitelistManager:
    """Whitelist Manager"""
    
    def __init__(self, whitelist_path: str, environment: Optional[str] = None):
        """Initialize whitelist manager
        
        Args:
            whitelist_path: Whitelist file path
            environment: Environment context (development | production | ci | container)
        """
        self.path = whitelist_path
        self.environment = environment
        self.entries: List[WhitelistEntry] = []
        self._next_id = 1
        self._load()
    
    def _load(self) -> None:
        """Load whitelist file, create empty structure if not exists"""
        if not os.path.exists(self.path):
            # Create empty structure
            self._save()
            return
        
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.entries = [
                WhitelistEntry.from_dict(entry) 
                for entry in data.get("entries", [])
            ]
            
            # Calculate next ID
            if self.entries:
                # Filter entries with valid whitelist-NNN format IDs
                valid_ids = [
                    int(e.id.split('-')[1]) 
                    for e in self.entries 
                    if e.id.startswith('whitelist-')
                ]
                if valid_ids:
                    max_id = max(valid_ids)
                    self._next_id = max_id + 1
                else:
                    # No valid IDs found, start from 1
                    self._next_id = 1
            
        except (OSError, KeyError, ValueError) as e:
            # Log warning on parse failure and continue (graceful degradation)
            logger = logging.getLogger("sec-userspace")
            logger.warning(f"Whitelist file parse failed, using empty structure: {e}")
            self.entries = []
            self._save()
    
    def _save(self) -> None:
        """Save whitelist to file"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        
        data = {
            "version": "1.0",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "entries": [e.to_dict() for e in self.entries]
        }
        
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def is_whitelisted(self, module: str, evidence_value: str, check_builtin: bool = True) -> bool:
        """Check if evidence matches whitelist
        
        Args:
            module: Analyzer name
            evidence_value: Evidence value
            check_builtin: Whether to check built-in patterns
        
        Returns:
            bool: Whether it matches whitelist
        """
        # Check user-defined whitelist first
        for entry in self.entries:
            # Skip expired or disabled entries
            if entry.is_expired() or not entry.enabled:
                continue
            
            if entry.matches(module, evidence_value, self.environment):
                return True
        
        # Check built-in false positive patterns
        if check_builtin:
            if self._check_builtin_patterns(module, evidence_value):
                return True
        
        return False
    
    def _check_builtin_patterns(self, module: str, evidence_value: str) -> bool:
        """Check against built-in false positive patterns
        
        Args:
            module: Analyzer name
            evidence_value: Evidence value (process name, path, cmdline, etc.)
        
        Returns:
            bool: Whether it matches a built-in pattern
        """
        evidence_lower = evidence_value.lower()
        
        for category, patterns in BUILTIN_FP_PATTERNS.items():
            # Check process names
            if "processes" in patterns:
                # Exact match or starts with pattern (for patterns like com.docker.*)
                for proc_pattern in patterns["processes"]:
                    if proc_pattern.endswith('.*'):
                        # Prefix match for wildcard patterns
                        prefix = proc_pattern[:-2]  # Remove .*
                        if evidence_lower.startswith(prefix):
                            logger.debug(f"Builtin FP match: {category} - {proc_pattern}")
                            return True
                    elif evidence_lower == proc_pattern or evidence_lower.endswith('/' + proc_pattern):
                        logger.debug(f"Builtin FP match: {category} - {proc_pattern}")
                        return True
            
            # Check paths
            if "paths" in patterns:
                for path_pattern in patterns["paths"]:
                    if fnmatch.fnmatch(evidence_value, path_pattern):
                        logger.debug(f"Builtin FP path match: {category} - {path_pattern}")
                        return True
            
            # Check cmdline regex patterns
            if "cmdline_patterns" in patterns:
                for regex_pattern in patterns["cmdline_patterns"]:
                    try:
                        if re.match(regex_pattern, evidence_value, re.IGNORECASE):
                            logger.debug(f"Builtin FP cmdline match: {category} - {regex_pattern}")
                            return True
                    except re.error:
                        continue
        
        return False
    
    def get_builtin_fp_category(self, module: str, evidence_value: str) -> Optional[str]:
        """Get the built-in false positive category for an evidence
        
        Args:
            module: Analyzer name
            evidence_value: Evidence value
        
        Returns:
            Optional[str]: Category name if matched, None otherwise
        """
        evidence_lower = evidence_value.lower()
        
        for category, patterns in BUILTIN_FP_PATTERNS.items():
            if "processes" in patterns:
                for proc_pattern in patterns["processes"]:
                    if proc_pattern.endswith('.*'):
                        prefix = proc_pattern[:-2]
                        if evidence_lower.startswith(prefix):
                            return category
                    elif evidence_lower == proc_pattern or evidence_lower.endswith('/' + proc_pattern):
                        return category
            
            if "paths" in patterns:
                for path_pattern in patterns["paths"]:
                    if fnmatch.fnmatch(evidence_value, path_pattern):
                        return category
            
            if "cmdline_patterns" in patterns:
                for regex_pattern in patterns["cmdline_patterns"]:
                    try:
                        if re.match(regex_pattern, evidence_value, re.IGNORECASE):
                            return category
                    except re.error:
                        continue
        
        return None
    
    def add_entry(
        self, 
        module: str, 
        pattern: str, 
        reason: str,
        added_by: str = "agent",
        expires: Optional[str] = None,
        environment: Optional[str] = None
    ) -> WhitelistEntry:
        """Add whitelist entry
        
        Args:
            module: Analyzer name
            pattern: Match pattern
            reason: Whitelist reason
            added_by: Added by
            expires: Expiration time (ISO format)
            environment: Environment context (development | production | ci | container)
        
        Returns:
            WhitelistEntry: New entry
        """
        entry = WhitelistEntry(
            id=f"whitelist-{self._next_id:03d}",
            module=module,
            pattern=pattern,
            reason=reason,
            added_by=added_by,
            expires=expires,
            environment=environment
        )
        
        self.entries.append(entry)
        self._next_id += 1
        self._save()
        
        return entry
    
    def cleanup_expired(self) -> int:
        """Clean up expired entries
        
        Returns:
            int: Number of cleaned entries
        """
        original_count = len(self.entries)
        self.entries = [e for e in self.entries if not e.is_expired()]
        cleaned = original_count - len(self.entries)
        
        if cleaned > 0:
            self._save()
        
        return cleaned
    
    def get_stats(self) -> dict:
        """Get whitelist statistics
        
        Returns:
            dict: Statistics
        """
        active_count = sum(1 for e in self.entries if not e.is_expired())
        expired_count = len(self.entries) - active_count
        enabled_count = sum(1 for e in self.entries if e.enabled and not e.is_expired())
        disabled_count = sum(1 for e in self.entries if not e.enabled)
        
        by_module = {}
        for entry in self.entries:
            if not entry.is_expired() and entry.enabled:
                by_module[entry.module] = by_module.get(entry.module, 0) + 1
        
        # Add built-in FP stats
        builtin_categories = list(BUILTIN_FP_PATTERNS.keys())
        
        return {
            "total": len(self.entries),
            "active": active_count,
            "expired": expired_count,
            "enabled": enabled_count,
            "disabled": disabled_count,
            "by_module": by_module,
            "builtin_categories": builtin_categories,
            "environment": self.environment
        }
    
    def get_entries_for_module(self, module: str) -> List[WhitelistEntry]:
        """Get whitelist entries for specified module
        
        Args:
            module: Analyzer name
        
        Returns:
            list[WhitelistEntry]: List of whitelist entries
        """
        return [
            e for e in self.entries 
            if e.module == module and not e.is_expired() and e.enabled
        ]


# Global singleton (lazy initialization)
_whitelist_manager: Optional[WhitelistManager] = None
_whitelist_manager_lock = threading.Lock()


def get_whitelist_manager(workspace_dir: str, environment: Optional[str] = None) -> WhitelistManager:
    """Get whitelist manager singleton
    
    Args:
        workspace_dir: Workspace directory
        environment: Environment context (development | production | ci | container)
    
    Returns:
        WhitelistManager: Whitelist manager instance
    """
    global _whitelist_manager

    if _whitelist_manager is None:
        with _whitelist_manager_lock:
            if _whitelist_manager is None:
                whitelist_path = os.path.join(workspace_dir, "whitelist.json")
                _whitelist_manager = WhitelistManager(whitelist_path, environment)

    return _whitelist_manager


def check_whitelist(workspace_dir: str, module: str, evidence_value: str, environment: Optional[str] = None) -> bool:
    """Check if evidence matches whitelist
    
    Args:
        workspace_dir: Workspace directory
        module: Analyzer name
        evidence_value: Evidence value
        environment: Environment context
    
    Returns:
        bool: Whether it matches whitelist
    """
    manager = get_whitelist_manager(workspace_dir, environment)
    return manager.is_whitelisted(module, evidence_value)


def add_to_whitelist(
    workspace_dir: str,
    module: str,
    pattern: str,
    reason: str,
    expires: Optional[str] = None,
    environment: Optional[str] = None
) -> WhitelistEntry:
    """Add to whitelist
    
    Args:
        workspace_dir: Workspace directory
        module: Analyzer name
        pattern: Match pattern
        reason: Whitelist reason
        expires: Expiration time
        environment: Environment context
    
    Returns:
        WhitelistEntry: New entry
    """
    manager = get_whitelist_manager(workspace_dir, environment)
    return manager.add_entry(module, pattern, reason, expires=expires)


def get_whitelist_stats(workspace_dir: str) -> dict:
    """Get whitelist statistics
    
    Args:
        workspace_dir: Workspace directory
    
    Returns:
        dict: Statistics
    """
    manager = get_whitelist_manager(workspace_dir)
    return manager.get_stats()


def detect_environment() -> Optional[str]:
    """Detect current environment type

    Returns:
        Optional[str]: Environment type (development | ci | container | production)
    """
    import subprocess
    import shutil
    import glob as glob_module

    # Check for CI/CD environment
    ci_indicators = [
        'CI' in os.environ,
        'GITHUB_ACTIONS' in os.environ,
        'GITLAB_CI' in os.environ,
        'TRAVIS' in os.environ,
        'CIRCLECI' in os.environ,
        'JENKINS_URL' in os.environ,
        'BUILD_NUMBER' in os.environ,
    ]
    if any(ci_indicators):
        return 'ci'

    # Check for container environment
    container_indicators = [
        os.path.exists('/.dockerenv'),
        os.path.exists('/run/.containerenv'),
        'container=podman' in os.environ.get('container', ''),
        'KUBERNETES_SERVICE_HOST' in os.environ,
    ]
    if any(container_indicators):
        return 'container'

    # Check for development environment
    dev_indicators = 0

    # Check for /tmp development artifacts
    dev_tmp_patterns = [
        '/tmp/analyzer_backup',
        '/tmp/untracked_backup',
        '/tmp/go-build',
        '/tmp/pytest-',
        '/tmp/sec-userspace-mock-test-output',
        '/tmp/.pytest_cache',
    ]
    for pattern in dev_tmp_patterns:
        if glob_module.glob(pattern + '*'):
            dev_indicators += 1

    # Check for test processes
    try:
        result = subprocess.run(['pgrep', '-f', 'pytest|unittest'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
        if result.returncode == 0:
            dev_indicators += 1
    except (OSError, subprocess.SubprocessError):
        pass

    # Check for development tools
    dev_tools = ['node', 'go', 'cargo', 'npm', 'pytest']
    for tool in dev_tools:
        if shutil.which(tool):
            dev_indicators += 1

    # 3 or more indicators = development environment
    if dev_indicators >= 3:
        return 'development'

    # Check for explicit dev environment markers
    if 'DEV_MODE' in os.environ or 'DEBUG' in os.environ:
        return 'development'

    # Default to production
    return 'production'
