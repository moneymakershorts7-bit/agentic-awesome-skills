"""Server Environment Profile Data Model"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set


@dataclass
class EnvironmentContext:
    """Environment context for analyzer should_skip decisions.
    
    Provides a lightweight snapshot of the runtime environment so each
    analyzer can decide whether to skip execution without performing
    its own expensive environment detection.
    """
    runtime_env: 'RuntimeEnv' = None  # Will default to RuntimeEnv.BARE_METAL after class definition
    server_roles: set = field(default_factory=set)    # Set[ServerRole]
    has_ai_agents: bool = False       # Detected AI Agent processes
    has_k8s: bool = False             # Kubernetes environment
    is_container: bool = False        # Running inside a container
    is_wsl: bool = False              # WSL environment
    kernel_version: str = ""          # Kernel version string
    os_family: str = ""               # debian/rhel/alpine...
    detected_services: list = field(default_factory=list)  # Detected service names
    available_proc: bool = True       # /proc is accessible
    has_systemd: bool = False         # systemd is present
    has_docker: bool = False          # Docker environment
    has_ebpf: bool = False            # eBPF support available
    has_web_server: bool = False      # Web server detected
    has_database: bool = False        # Database service detected

    def __post_init__(self):
        if self.runtime_env is None:
            self.runtime_env = RuntimeEnv.BARE_METAL


class ServerRole(Enum):
    """Server Role Enumeration"""
    WEB_SERVER = "web_server"
    DATABASE = "database"
    CONTAINER_HOST = "container_host"
    KUBERNETES = "kubernetes"
    CI_CD = "ci_cd"
    AI_ML = "ai_ml"
    MCP_AGENT = "mcp_agent"
    MAIL_SERVER = "mail_server"
    DNS_SERVER = "dns_server"
    VIRTUALIZATION = "virtualization"
    FILE_SERVER = "file_server"


class RuntimeEnv(Enum):
    """Runtime Environment Enumeration"""
    BARE_METAL = "bare_metal"
    VM = "vm"
    DOCKER = "docker"
    PODMAN = "podman"
    KUBERNETES_POD = "kubernetes_pod"
    LXC = "lxc"
    WSL = "wsl"


@dataclass
class DetectedService:
    """Detected Service"""
    name: str               # Service name (nginx, mysqld)
    source: str             # Detection source (process, port, systemd, config)
    pid: int = 0            # Process PID (e.g., from process probe)
    port: int = 0           # Listening port (e.g., from port probe)
    detail: str = ""        # Additional details


@dataclass
class ServerProfile:
    """Server Environment Profile Result"""

    # Basic Environment
    os_family: str = ""                     # debian/rhel/alpine/arch/suse
    os_release: str = ""                    # Full distribution name
    runtime_env: RuntimeEnv = RuntimeEnv.BARE_METAL

    # Detected roles (a server can have multiple roles)
    roles: Set[ServerRole] = field(default_factory=set)

    # Role confidence (role -> 0.0~1.0), multiple signals increase confidence
    role_confidence: Dict[ServerRole, float] = field(default_factory=dict)

    # Hardware characteristics
    has_gpu: bool = False
    has_cuda: bool = False
    cpu_count: int = 1
    memory_total_mb: int = 0

    # List of detected services
    detected_services: List[DetectedService] = field(default_factory=list)

    # Final decision: list of analyzer names to run
    active_analyzers: List[str] = field(default_factory=list)
    # Skipped analyzers and reasons
    skipped_analyzers: List[Dict[str, str]] = field(default_factory=list)

    # Profiling duration
    profile_duration: float = 0.0

    def has_role(self, role: ServerRole) -> bool:
        return role in self.roles

    def add_role(self, role: ServerRole, confidence: float, source: str):
        """Add role, confidence takes the historical maximum"""
        self.roles.add(role)
        current = self.role_confidence.get(role, 0.0)
        self.role_confidence[role] = max(current, min(confidence, 1.0))

    def to_dict(self) -> dict:
        """Serialize to dictionary (for report output)"""
        return {
            "os_family": self.os_family,
            "os_release": self.os_release,
            "runtime_env": self.runtime_env.value,
            "roles": sorted(r.value for r in self.roles),
            "role_confidence": {r.value: round(c, 2) for r, c in self.role_confidence.items()},
            "has_gpu": self.has_gpu,
            "has_cuda": self.has_cuda,
            "cpu_count": self.cpu_count,
            "memory_total_mb": self.memory_total_mb,
            "detected_services": [
                {"name": s.name, "source": s.source, "pid": s.pid,
                 "port": s.port, "detail": s.detail}
                for s in self.detected_services
            ],
            "active_analyzers": self.active_analyzers,
            "skipped_analyzers": self.skipped_analyzers,
            "profile_duration": round(self.profile_duration, 3),
        }
