"""Environment Profiler Engine: Infer server roles and business characteristics from collected data

Design Principles:
- Reuse existing collected data (process/network/service/system/openclaw), zero additional I/O
- Multi-signal fusion (process + port + systemd + config files), multiple signals for the same role increase confidence
- Profiling phase < 0.5s, pure in-memory computation
"""
import logging
import os
import platform
import time
from typing import Dict

from .profile import ServerProfile, ServerRole, RuntimeEnv, DetectedService, EnvironmentContext

logger = logging.getLogger("sec-userspace")


# ============================================================================
# Signal mapping table (module-level constants)
# ============================================================================

# Process name -> role mapping
_PROCESS_ROLE_MAP: Dict[str, ServerRole] = {
    # Web Server
    "nginx": ServerRole.WEB_SERVER,
    "apache2": ServerRole.WEB_SERVER,
    "httpd": ServerRole.WEB_SERVER,
    "caddy": ServerRole.WEB_SERVER,
    "lighttpd": ServerRole.WEB_SERVER,
    "openresty": ServerRole.WEB_SERVER,
    "tengine": ServerRole.WEB_SERVER,
    # Database
    "mysqld": ServerRole.DATABASE,
    "mariadbd": ServerRole.DATABASE,
    "postgres": ServerRole.DATABASE,
    "mongod": ServerRole.DATABASE,
    "mongos": ServerRole.DATABASE,
    "redis-server": ServerRole.DATABASE,
    "redis-sentinel": ServerRole.DATABASE,
    "memcached": ServerRole.DATABASE,
    "clickhouse-server": ServerRole.DATABASE,
    "influxd": ServerRole.DATABASE,
    "tidb-server": ServerRole.DATABASE,
    # Container Runtime
    "dockerd": ServerRole.CONTAINER_HOST,
    "containerd": ServerRole.CONTAINER_HOST,
    "cri-o": ServerRole.CONTAINER_HOST,
    "podman": ServerRole.CONTAINER_HOST,
    # Kubernetes
    "kubelet": ServerRole.KUBERNETES,
    "kube-apiserver": ServerRole.KUBERNETES,
    "kube-scheduler": ServerRole.KUBERNETES,
    "kube-controller-manager": ServerRole.KUBERNETES,
    "etcd": ServerRole.KUBERNETES,
    "k3s": ServerRole.KUBERNETES,
    "k3s-agent": ServerRole.KUBERNETES,
    # CI/CD
    "jenkins": ServerRole.CI_CD,
    "gitlab-runner": ServerRole.CI_CD,
    "drone-server": ServerRole.CI_CD,
    # AI/ML
    "jupyter": ServerRole.AI_ML,
    "jupyter-notebook": ServerRole.AI_ML,
    "jupyter-lab": ServerRole.AI_ML,
    "tensorboard": ServerRole.AI_ML,
    # MCP/Agent
    "openclaw": ServerRole.MCP_AGENT,
    # Mail
    "postfix": ServerRole.MAIL_SERVER,
    "dovecot": ServerRole.MAIL_SERVER,
    "exim4": ServerRole.MAIL_SERVER,
    "sendmail": ServerRole.MAIL_SERVER,
    # DNS
    "named": ServerRole.DNS_SERVER,
    "dnsmasq": ServerRole.DNS_SERVER,
    "unbound": ServerRole.DNS_SERVER,
    "coredns": ServerRole.DNS_SERVER,
    # Virtualization
    "qemu": ServerRole.VIRTUALIZATION,
    "libvirtd": ServerRole.VIRTUALIZATION,
    # File Server
    "smbd": ServerRole.FILE_SERVER,
    "nmbd": ServerRole.FILE_SERVER,
    "vsftpd": ServerRole.FILE_SERVER,
    "proftpd": ServerRole.FILE_SERVER,
    "nfsd": ServerRole.FILE_SERVER,
    # ML Inference Servers
    "vllm": ServerRole.AI_ML,
    "ollama": ServerRole.AI_ML,
    "text-generation-inference": ServerRole.AI_ML,
    "tgi": ServerRole.AI_ML,
    "llama-server": ServerRole.AI_ML,
    # Vector Databases
    "milvus": ServerRole.AI_ML,
    "chroma": ServerRole.AI_ML,
    "qdrant": ServerRole.AI_ML,
    "weaviate": ServerRole.AI_ML,
    # Distributed Training
    "ray": ServerRole.AI_ML,
    "raylet": ServerRole.AI_ML,
}

# Listening port -> role mapping (may be ambiguous, needs process disambiguation)
_PORT_ROLE_MAP: Dict[int, ServerRole] = {
    # Web
    80: ServerRole.WEB_SERVER,
    443: ServerRole.WEB_SERVER,
    8443: ServerRole.WEB_SERVER,
    # Database
    3306: ServerRole.DATABASE,
    5432: ServerRole.DATABASE,
    27017: ServerRole.DATABASE,
    6379: ServerRole.DATABASE,
    11211: ServerRole.DATABASE,
    9042: ServerRole.DATABASE,
    # Container/K8s
    2375: ServerRole.CONTAINER_HOST,
    2376: ServerRole.CONTAINER_HOST,
    6443: ServerRole.KUBERNETES,
    10250: ServerRole.KUBERNETES,
    # Mail
    25: ServerRole.MAIL_SERVER,
    465: ServerRole.MAIL_SERVER,
    587: ServerRole.MAIL_SERVER,
    110: ServerRole.MAIL_SERVER,
    143: ServerRole.MAIL_SERVER,
    993: ServerRole.MAIL_SERVER,
    995: ServerRole.MAIL_SERVER,
    # DNS
    53: ServerRole.DNS_SERVER,
    # ML Inference Servers
    8000: ServerRole.AI_ML,  # Common for vLLM, TGI
    8080: ServerRole.AI_ML,  # Common for ML services
    11434: ServerRole.AI_ML,  # Ollama default port
    5000: ServerRole.AI_ML,  # Common for ML APIs
    8888: ServerRole.AI_ML,  # Jupyter notebook
    # Vector Databases
    19530: ServerRole.AI_ML,  # Milvus default port
    8001: ServerRole.AI_ML,  # ChromaDB default port
    6333: ServerRole.AI_ML,  # Qdrant default port
}

# systemd service name -> role mapping
_SERVICE_ROLE_MAP: Dict[str, ServerRole] = {
    "nginx.service": ServerRole.WEB_SERVER,
    "apache2.service": ServerRole.WEB_SERVER,
    "httpd.service": ServerRole.WEB_SERVER,
    "caddy.service": ServerRole.WEB_SERVER,
    "mysql.service": ServerRole.DATABASE,
    "mysqld.service": ServerRole.DATABASE,
    "mariadb.service": ServerRole.DATABASE,
    "postgresql.service": ServerRole.DATABASE,
    "mongod.service": ServerRole.DATABASE,
    "redis.service": ServerRole.DATABASE,
    "redis-server.service": ServerRole.DATABASE,
    "docker.service": ServerRole.CONTAINER_HOST,
    "containerd.service": ServerRole.CONTAINER_HOST,
    "kubelet.service": ServerRole.KUBERNETES,
    "k3s.service": ServerRole.KUBERNETES,
    "k3s-agent.service": ServerRole.KUBERNETES,
    "jenkins.service": ServerRole.CI_CD,
    "gitlab-runner.service": ServerRole.CI_CD,
    "postfix.service": ServerRole.MAIL_SERVER,
    "dovecot.service": ServerRole.MAIL_SERVER,
    "sendmail.service": ServerRole.MAIL_SERVER,
    "named.service": ServerRole.DNS_SERVER,
    "bind9.service": ServerRole.DNS_SERVER,
    "dnsmasq.service": ServerRole.DNS_SERVER,
    "unbound.service": ServerRole.DNS_SERVER,
    "libvirtd.service": ServerRole.VIRTUALIZATION,
    "smbd.service": ServerRole.FILE_SERVER,
    "vsftpd.service": ServerRole.FILE_SERVER,
    "nfs-server.service": ServerRole.FILE_SERVER,
    # ML/AI services
    "vllm.service": ServerRole.AI_ML,
    "ollama.service": ServerRole.AI_ML,
    "milvus.service": ServerRole.AI_ML,
    "chroma.service": ServerRole.AI_ML,
    "jupyter.service": ServerRole.AI_ML,
    "tensorboard.service": ServerRole.AI_ML,
}


# ============================================================================
# Environment Profiler Engine
# ============================================================================

class EnvironmentProfiler:
    """Environment Profiler Engine

    Infer server roles from collected data (process/network/service/system/openclaw),
    without executing any additional I/O or shell commands.
    """

    # Confidence weights: base confidence for each signal source
    _CONFIDENCE_PROCESS = 0.6      # Process match: confidence 0.6
    _CONFIDENCE_PORT = 0.3         # Port match: confidence 0.3
    _CONFIDENCE_SERVICE = 0.5      # systemd service match: confidence 0.5
    _CONFIDENCE_CONFIG = 0.4       # Config file match: confidence 0.4
    _CONFIDENCE_OPENCLAW = 0.9     # OpenClaw explicit detection: confidence 0.9

    def profile(self, collected_data: dict) -> ServerProfile:
        """Execute environment profiling, return ServerProfile"""
        start = time.monotonic()
        profile = ServerProfile()

        # 1. Basic environment detection
        self._detect_os_family(profile, collected_data)
        self._detect_runtime_env(profile, collected_data)
        self._detect_hardware(profile, collected_data)

        # 2. Multi-signal role inference
        self._probe_by_process(profile, collected_data)
        self._probe_by_port(profile, collected_data)
        self._probe_by_service(profile, collected_data)
        self._probe_by_config(profile, collected_data)
        self._probe_by_openclaw(profile, collected_data)

        # 3. Additional heuristic rules
        self._heuristic_rules(profile, collected_data)

        profile.profile_duration = time.monotonic() - start
        logger.info(
            f"[env_profiler] Profiling complete ({profile.profile_duration:.3f}s): "
            f"roles={[r.value for r in profile.roles]}, "
            f"environment={profile.runtime_env.value}, "
            f"services={len(profile.detected_services)}"
        )
        return profile

    # ------------------------------------------------------------------
    # Basic Environment Detection
    # ------------------------------------------------------------------

    def _detect_os_family(self, profile: ServerProfile, collected_data: dict):
        """Detect OS family"""
        system_data = self._safe_get(collected_data, "system")
        if not system_data:
            return

        profile.os_release = system_data.get("os_release", "")
        release_lower = profile.os_release.lower()

        if any(k in release_lower for k in ("ubuntu", "debian", "mint")):
            profile.os_family = "debian"
        elif any(k in release_lower for k in ("centos", "red hat", "rhel", "rocky", "alma", "oracle", "fedora")):
            profile.os_family = "rhel"
        elif "alpine" in release_lower:
            profile.os_family = "alpine"
        elif any(k in release_lower for k in ("suse", "sles", "opensuse")):
            profile.os_family = "suse"
        elif "arch" in release_lower:
            profile.os_family = "arch"
        else:
            profile.os_family = "unknown"

    def _detect_runtime_env(self, profile: ServerProfile, collected_data: dict):
        """Detect runtime environment (container/VM/bare-metal/WSL)"""
        system_data = self._safe_get(collected_data, "system")

        # WSL detection (via kernel version)
        if system_data:
            kernel = system_data.get("kernel_release", "")
            if "microsoft" in kernel.lower() or "wsl" in kernel.lower():
                profile.runtime_env = RuntimeEnv.WSL
                return

        # Container detection: via file characteristics
        if os.path.exists("/.dockerenv"):
            profile.runtime_env = RuntimeEnv.DOCKER
            return
        if os.path.exists("/run/.containerenv"):
            profile.runtime_env = RuntimeEnv.PODMAN
            return

        # Container detection via /proc/1/cgroup
        try:
            with open("/proc/1/cgroup", "r", errors="ignore", encoding='utf-8') as f:
                cgroup_content = f.read(8192)  # Limit 8KB
            if "docker" in cgroup_content or "kubepods" in cgroup_content:
                profile.runtime_env = RuntimeEnv.DOCKER
                return
            if "lxc" in cgroup_content:
                profile.runtime_env = RuntimeEnv.LXC
                return
        except (FileNotFoundError, PermissionError):
            pass

        # Kubernetes Pod detection
        try:
            with open("/proc/1/environ", "rb") as f:
                environ = f.read(1024 * 1024)  # Limit 1MB
            if b"KUBERNETES_SERVICE_HOST" in environ:
                profile.runtime_env = RuntimeEnv.KUBERNETES_POD
                return
        except (FileNotFoundError, PermissionError):
            pass

        # VM detection: via DMI/hypervisor
        vm_indicators = [
            "/sys/hypervisor/type",             # Xen
            "/sys/class/dmi/id/product_name",   # VMware/VirtualBox/KVM
        ]
        for indicator in vm_indicators:
            try:
                with open(indicator, "r", errors="ignore", encoding='utf-8') as f:
                    content = f.read(1024).lower()  # Limit 1KB
                if any(h in content for h in ("vmware", "virtualbox", "kvm", "qemu", "xen", "hyper-v")):
                    profile.runtime_env = RuntimeEnv.VM
                    return
            except (FileNotFoundError, PermissionError):
                continue

        profile.runtime_env = RuntimeEnv.BARE_METAL

    def _detect_hardware(self, profile: ServerProfile, collected_data: dict):
        """Detect hardware characteristics (GPU/CPU/Memory)"""
        system_data = self._safe_get(collected_data, "system")
        if system_data:
            profile.cpu_count = system_data.get("cpu_count", 1)
            profile.memory_total_mb = system_data.get("memory_total_mb", 0)

        # GPU detection (pure filesystem probe)
        gpu_indicators = [
            "/proc/driver/nvidia/gpus",
            "/dev/nvidia0",
        ]
        for ind in gpu_indicators:
            if os.path.exists(ind):
                profile.has_gpu = True
                break

        # CUDA detection
        if os.path.exists("/usr/local/cuda") or os.path.exists("/usr/local/cuda/version.txt"):
            profile.has_cuda = True

    # ------------------------------------------------------------------
    # Signal Probe: Process
    # ------------------------------------------------------------------

    def _probe_by_process(self, profile: ServerProfile, collected_data: dict):
        """Infer role from process data"""
        process_data = self._safe_get(collected_data, "process")
        if not process_data:
            return

        processes = process_data.get("processes", [])
        for proc_info in processes:
            comm = proc_info.get("comm", "")
            cmdline = proc_info.get("cmdline", "")
            pid = proc_info.get("pid", 0)

            # Exact match process name
            role = _PROCESS_ROLE_MAP.get(comm)
            if role:
                profile.add_role(role, self._CONFIDENCE_PROCESS, f"process:{comm}")
                profile.detected_services.append(
                    DetectedService(name=comm, source="process", pid=pid)
                )
                continue

            # cmdline fuzzy match (for services started by python/java)
            cmdline_lower = cmdline.lower() if cmdline else ""
            self._match_cmdline(profile, cmdline_lower, pid)

    def _match_cmdline(self, profile: ServerProfile, cmdline: str, pid: int):
        """Fuzzy match services via cmdline"""
        cmdline_patterns = {
            "jupyter": (ServerRole.AI_ML, "jupyter"),
            "tensorboard": (ServerRole.AI_ML, "tensorboard"),
            "gunicorn": (ServerRole.WEB_SERVER, "gunicorn"),
            "uvicorn": (ServerRole.WEB_SERVER, "uvicorn"),
            "uwsgi": (ServerRole.WEB_SERVER, "uwsgi"),
            "celery": (ServerRole.WEB_SERVER, "celery-worker"),
            "gitlab-runner": (ServerRole.CI_CD, "gitlab-runner"),
            "jenkins": (ServerRole.CI_CD, "jenkins"),
            "mcp-server": (ServerRole.MCP_AGENT, "mcp-server"),
            "openclaw": (ServerRole.MCP_AGENT, "openclaw"),
            "torch": (ServerRole.AI_ML, "pytorch"),
            "tensorflow": (ServerRole.AI_ML, "tensorflow"),
            # ML inference servers
            "vllm": (ServerRole.AI_ML, "vllm"),
            "ollama": (ServerRole.AI_ML, "ollama"),
            "text-generation-inference": (ServerRole.AI_ML, "tgi"),
            "llama-server": (ServerRole.AI_ML, "llama-cpp"),
            # Vector databases
            "milvus": (ServerRole.AI_ML, "milvus"),
            "chroma": (ServerRole.AI_ML, "chromadb"),
            "qdrant": (ServerRole.AI_ML, "qdrant"),
            "weaviate": (ServerRole.AI_ML, "weaviate"),
            # Distributed training
            "ray": (ServerRole.AI_ML, "ray"),
            "deepspeed": (ServerRole.AI_ML, "deepspeed"),
            # RAG frameworks
            "langchain": (ServerRole.AI_ML, "langchain"),
            "llamaindex": (ServerRole.AI_ML, "llama-index"),
            "haystack": (ServerRole.AI_ML, "haystack"),
        }
        for keyword, (role, svc_name) in cmdline_patterns.items():
            if keyword in cmdline:
                # cmdline match has slightly lower confidence
                profile.add_role(role, self._CONFIDENCE_PROCESS * 0.8, f"cmdline:{keyword}")
                profile.detected_services.append(
                    DetectedService(name=svc_name, source="cmdline", pid=pid, detail=keyword)
                )
                return  # Only match first for each process

    # ------------------------------------------------------------------
    # Signal Probe: Port
    # ------------------------------------------------------------------

    def _probe_by_port(self, profile: ServerProfile, collected_data: dict):
        """Infer role from listening ports"""
        network_data = self._safe_get(collected_data, "network")
        if not network_data:
            return

        listeners = network_data.get("listeners", [])
        for listener in listeners:
            port = listener.get("port", 0)
            role = _PORT_ROLE_MAP.get(port)
            if role:
                profile.add_role(role, self._CONFIDENCE_PORT, f"port:{port}")
                # Try to associate process name
                proc_name = listener.get("process", listener.get("program", ""))
                profile.detected_services.append(
                    DetectedService(name=proc_name or f"port-{port}", source="port",
                                    port=port, detail=f"LISTEN :{port}")
                )

    # ------------------------------------------------------------------
    # Signal Probe: systemd Service
    # ------------------------------------------------------------------

    def _probe_by_service(self, profile: ServerProfile, collected_data: dict):
        """Infer role from systemd/initd services"""
        service_data = self._safe_get(collected_data, "service")
        if not service_data:
            return

        # systemd services
        systemd_services = service_data.get("systemd_services", [])
        for svc in systemd_services:
            unit = svc.get("unit", "")
            role = _SERVICE_ROLE_MAP.get(unit)
            if role:
                state = svc.get("sub_state", svc.get("state", ""))
                confidence = self._CONFIDENCE_SERVICE if state == "running" else self._CONFIDENCE_SERVICE * 0.5
                profile.add_role(role, confidence, f"systemd:{unit}")
                profile.detected_services.append(
                    DetectedService(name=unit, source="systemd", detail=f"state={state}")
                )

    # ------------------------------------------------------------------
    # Signal Probe: Config File
    # ------------------------------------------------------------------

    _CONFIG_FILE_MAP = {
        "/etc/nginx/nginx.conf": ServerRole.WEB_SERVER,
        "/etc/apache2/apache2.conf": ServerRole.WEB_SERVER,
        "/etc/httpd/conf/httpd.conf": ServerRole.WEB_SERVER,
        "/etc/caddy/Caddyfile": ServerRole.WEB_SERVER,
        "/etc/mysql/my.cnf": ServerRole.DATABASE,
        "/etc/my.cnf": ServerRole.DATABASE,
        "/var/run/docker.sock": ServerRole.CONTAINER_HOST,
        "/var/run/containerd/containerd.sock": ServerRole.CONTAINER_HOST,
        "/etc/kubernetes/manifests": ServerRole.KUBERNETES,
        "/var/lib/kubelet": ServerRole.KUBERNETES,
        "/var/lib/jenkins": ServerRole.CI_CD,
        "/etc/gitlab-runner/config.toml": ServerRole.CI_CD,
        "/etc/postfix/main.cf": ServerRole.MAIL_SERVER,
        "/etc/dovecot/dovecot.conf": ServerRole.MAIL_SERVER,
        "/etc/bind/named.conf": ServerRole.DNS_SERVER,
        "/etc/named.conf": ServerRole.DNS_SERVER,
        "/etc/dnsmasq.conf": ServerRole.DNS_SERVER,
        "/etc/unbound/unbound.conf": ServerRole.DNS_SERVER,
        "/etc/libvirt": ServerRole.VIRTUALIZATION,
        "/etc/samba/smb.conf": ServerRole.FILE_SERVER,
        # ML/AI config files
        "/etc/vllm": ServerRole.AI_ML,
        "/etc/ollama": ServerRole.AI_ML,
        "/etc/milvus": ServerRole.AI_ML,
        "/var/lib/milvus": ServerRole.AI_ML,
        "/etc/chroma": ServerRole.AI_ML,
        "/var/lib/chroma": ServerRole.AI_ML,
        "/etc/ray": ServerRole.AI_ML,
    }

    def _probe_by_config(self, profile: ServerProfile, collected_data: dict):
        """Infer role from config file existence (pure os.path.exists, do not read content)"""
        for config_path, role in self._CONFIG_FILE_MAP.items():
            if os.path.exists(config_path):
                profile.add_role(role, self._CONFIDENCE_CONFIG, f"config:{config_path}")
                profile.detected_services.append(
                    DetectedService(name=os.path.basename(config_path),
                                    source="config", detail=config_path)
                )

    # ------------------------------------------------------------------
    # Signal Probe: OpenClaw/MCP Agent
    # ------------------------------------------------------------------

    def _probe_by_openclaw(self, profile: ServerProfile, collected_data: dict):
        """Detect MCP Agent environment"""
        openclaw_data = self._safe_get(collected_data, "openclaw")
        if not openclaw_data:
            return

        if openclaw_data.get("openclaw_installed"):
            profile.add_role(ServerRole.MCP_AGENT, self._CONFIDENCE_OPENCLAW, "openclaw:installed")
            skills = openclaw_data.get("skills", [])
            mcp_servers = openclaw_data.get("mcp_servers", [])
            profile.detected_services.append(
                DetectedService(
                    name="openclaw",
                    source="openclaw",
                    detail=f"skills={len(skills)}, mcp_servers={len(mcp_servers)}"
                )
            )

    # ------------------------------------------------------------------
    # Heuristic Rules
    # ------------------------------------------------------------------

    def _heuristic_rules(self, profile: ServerProfile, collected_data: dict):
        """Additional heuristic inference"""
        # GPU + high memory -> AI/ML possibility
        if profile.has_gpu and profile.memory_total_mb > 16 * 1024:
            profile.add_role(ServerRole.AI_ML, 0.4, "heuristic:gpu+high_memory")

        # CUDA installed -> AI/ML
        if profile.has_cuda:
            profile.add_role(ServerRole.AI_ML, 0.5, "heuristic:cuda_installed")

        # Running in Kubernetes Pod -> Kubernetes role
        if profile.runtime_env == RuntimeEnv.KUBERNETES_POD:
            profile.add_role(ServerRole.KUBERNETES, 0.3, "heuristic:k8s_pod")
        
        # ML log files detected -> AI/ML environment
        log_data = self._safe_get(collected_data, "log")
        ml_logs = log_data.get("ml_logs", []) if log_data else []
        if ml_logs and len(ml_logs) > 0:
            profile.add_role(ServerRole.AI_ML, 0.6, "heuristic:ml_logs_detected")
        
        # Check for ML-specific ports
        network_data = self._safe_get(collected_data, "network")
        if network_data:
            listeners = network_data.get("listeners", [])
            ml_ports = {8000, 8080, 11434, 5000, 8888, 19530, 8001, 6333}
            for listener in listeners:
                port = listener.get("port", 0)
                if port in ml_ports:
                    profile.add_role(ServerRole.AI_ML, 0.5, f"heuristic:ml_port_{port}")

    # ------------------------------------------------------------------
    # EnvironmentContext Builder
    # ------------------------------------------------------------------

    def build_environment_context(self, profile: ServerProfile) -> EnvironmentContext:
        """Build EnvironmentContext from a completed ServerProfile.

        This is a fast (<500ms) operation that distils the profiling result
        into a lightweight context object consumed by analyzer should_skip().

        Args:
            profile: A completed ServerProfile from self.profile()

        Returns:
            EnvironmentContext snapshot
        """
        ctx = EnvironmentContext(
            runtime_env=profile.runtime_env,
            server_roles=set(profile.roles),
            os_family=profile.os_family,
        )

        # Derived flags from roles / runtime_env
        ctx.has_k8s = ServerRole.KUBERNETES in profile.roles
        ctx.is_container = profile.runtime_env in (
            RuntimeEnv.DOCKER, RuntimeEnv.PODMAN,
            RuntimeEnv.KUBERNETES_POD, RuntimeEnv.LXC,
        )
        ctx.is_wsl = profile.runtime_env == RuntimeEnv.WSL
        ctx.has_ai_agents = (
            ServerRole.AI_ML in profile.roles
            or ServerRole.MCP_AGENT in profile.roles
        )
        ctx.has_docker = ServerRole.CONTAINER_HOST in profile.roles
        ctx.has_web_server = ServerRole.WEB_SERVER in profile.roles
        ctx.has_database = ServerRole.DATABASE in profile.roles

        # Quick filesystem probes (very cheap)
        ctx.available_proc = os.path.isdir('/proc')
        ctx.has_systemd = os.path.isdir('/run/systemd/system')

        # eBPF support detection
        ctx.has_ebpf = self._check_ebpf_support()

        # Kernel version
        try:
            ctx.kernel_version = platform.release()
        except OSError:
            ctx.kernel_version = ""

        # Detected service names
        ctx.detected_services = [s.name for s in profile.detected_services]

        return ctx

    @staticmethod
    def _check_ebpf_support() -> bool:
        """Check whether the running kernel supports eBPF (BTF).

        Fast check: look for /sys/kernel/btf/vmlinux (available on
        kernels >= 5.2 with BTF enabled) or fall back to a kernel
        version check (>= 5.8 heuristic).
        """
        # Primary: BTF vmlinux file
        if os.path.exists('/sys/kernel/btf/vmlinux'):
            return True

        # Fallback: kernel version >= 5.8
        try:
            release = platform.release()  # e.g. "5.15.0-100-generic"
            parts = release.split('.')
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            if (major, minor) >= (5, 8):
                return True
        except (ValueError, IndexError):
            pass

        return False

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_get(collected_data: dict, key: str) -> dict:
        """Safely get collected data, compatible with CollectResult and plain dict"""
        if key not in collected_data:
            return {}
        result = collected_data[key]
        if isinstance(result, dict):
            return result
        # CollectResult format
        if hasattr(result, "status") and result.status in ("success", "partial"):
            return result.data
        return {}
