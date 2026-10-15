"""Container Environment Detector

Centralized container environment detection with context awareness.
Provides unified container detection and standard behavior whitelists
to reduce false positives across all analyzers.

ATT&CK Mapping:
- T1611 - Escape to Host (context: legitimate container operations)
"""
import os
import threading
from typing import Dict, Set, Optional, Tuple


class ContainerEnvironmentDetector:
    """Centralized container environment detection with context awareness."""

    # Container detection indicators
    CONTAINER_INDICATORS = {
        'dockerenv': '/.dockerenv',
        'podmanenv': '/run/.containerenv',
        'cgroup_file': '/proc/1/cgroup',
    }

    # Container runtime identifiers
    RUNTIME_PATTERNS = [
        r'docker',
        r'containerd',
        r'kubepods',
        r'lxc',
        r'crio',
        r'podman',
    ]

    # Kubernetes environment indicators
    K8S_INDICATORS = [
        'KUBERNETES_SERVICE_HOST',
        'KUBERNETES_PORT',
        '/var/run/secrets/kubernetes.io',
    ]

    # Standard container mounts that should NOT trigger alerts
    STANDARD_CONTAINER_MOUNTS = {
        '/proc': {
            'required_by': ['kubelet', 'containerd', 'dockerd'],
            'description': 'Process information filesystem',
            'risk_if_missing': 'Container cannot monitor processes',
        },
        '/sys': {
            'required_by': ['kubelet', 'containerd'],
            'description': 'Sysfs filesystem for cgroup management',
            'risk_if_missing': 'Container resource management broken',
        },
        '/dev': {
            'required_by': ['kubelet', 'containerd', 'dockerd'],
            'description': 'Device filesystem',
            'risk_if_missing': 'Container device access broken',
        },
        '/dev/pts': {
            'required_by': ['kubelet'],
            'description': 'PTY device filesystem',
            'risk_if_missing': 'Container exec/attach broken',
        },
        '/dev/shm': {
            'required_by': ['containerd', 'dockerd'],
            'description': 'Shared memory for IPC',
            'risk_if_missing': 'Container IPC communication broken',
        },
    }

    # Standard container capabilities by workload type
    STANDARD_CAPABILITIES = {
        'kubelet': {'CAP_SYS_ADMIN', 'CAP_NET_ADMIN', 'CAP_SYS_PTRACE'},
        'cni_plugin': {'CAP_NET_ADMIN', 'CAP_NET_RAW'},
        'monitoring': {'CAP_SYS_PTRACE', 'CAP_DAC_READ_SEARCH'},
        'storage_driver': {'CAP_SYS_ADMIN', 'CAP_DAC_OVERRIDE'},
        'service_mesh': {'CAP_NET_ADMIN', 'CAP_NET_RAW'},
    }

    # Standard container processes that should not trigger alerts
    STANDARD_CONTAINER_PROCESSES = {
        # Infrastructure
        'kubelet', 'kube-proxy', 'kube-apiserver', 'kube-scheduler',
        'kube-controller-manager', 'etcd', 'k3s', 'k3s-agent',
        # CNI plugins
        'calico-node', 'cilium-agent', 'flannel', 'weave-net',
        'istio-cni', 'kube-router',
        # Monitoring
        'datadog-agent', 'node_exporter', 'kube-state-metrics',
        'cadvisor', 'fluent-bit', 'filebeat', 'metricbeat',
        # Service mesh
        'envoy', 'pilot-agent', 'linkerd2-proxy',
        # Storage
        'rbd', 'glusterfsd', 'longhorn-manager', 'csi-plugin',
        # Cloud providers
        'amazon-ssm-agent', 'awslogs-agent', 'WALinuxAgent',
    }

    def __init__(self):
        self._is_container = None
        self._is_k8s = None
        self._container_type = None
        self._detected_workloads = set()
        self._lock = threading.Lock()

    def is_container_environment(self) -> bool:
        """Check if running in a container environment."""
        if self._is_container is not None:
            return self._is_container
        with self._lock:
            if self._is_container is not None:
                return self._is_container
            self._is_container = self._detect_container()
            return self._is_container

    def is_kubernetes_environment(self) -> bool:
        """Check if running in a Kubernetes environment."""
        if self._is_k8s is not None:
            return self._is_k8s
        with self._lock:
            if self._is_k8s is not None:
                return self._is_k8s
            self._is_k8s = self._detect_kubernetes()
            return self._is_k8s

    def get_container_type(self) -> Optional[str]:
        """Get the type of container runtime (docker, podman, containerd, etc.)."""
        if self._container_type is not None:
            return self._container_type
        with self._lock:
            if self._container_type is not None:
                return self._container_type
            self._container_type = self._detect_container_type()
            return self._container_type

    def is_standard_mount(self, mount_path: str) -> Tuple[bool, Optional[Dict]]:
        """Check if a mount path is standard for containers.

        Args:
            mount_path: The mount path to check

        Returns:
            Tuple of (is_standard, mount_info)
        """
        if mount_path in self.STANDARD_CONTAINER_MOUNTS:
            return True, self.STANDARD_CONTAINER_MOUNTS[mount_path]
        return False, None

    def is_standard_capability(self, capability: str, workload: str = None) -> Tuple[bool, Optional[str]]:
        """Check if a capability is standard for the given workload.

        Args:
            capability: The capability to check (e.g., 'CAP_SYS_ADMIN')
            workload: The workload type (e.g., 'kubelet', 'cni_plugin')

        Returns:
            Tuple of (is_standard, workload_type)
        """
        if workload and workload in self.STANDARD_CAPABILITIES:
            if capability in self.STANDARD_CAPABILITIES[workload]:
                return True, workload

        # Check all workload types
        for workload_type, caps in self.STANDARD_CAPABILITIES.items():
            if capability in caps:
                return True, workload_type

        return False, None

    def is_standard_process(self, process_name: str) -> bool:
        """Check if a process is a standard container process.

        Args:
            process_name: The process name to check

        Returns:
            True if the process is a known standard container process
        """
        return process_name in self.STANDARD_CONTAINER_PROCESSES

    def detected_workloads(self) -> Set[str]:
        """Get detected workload types in the environment."""
        if not self._detected_workloads:
            self._detect_workloads()
        return self._detected_workloads

    def _detect_container(self) -> bool:
        """Detect if running in a container."""
        # Check /.dockerenv
        if os.path.exists('/.dockerenv'):
            return True

        # Check /run/.containerenv (Podman)
        if os.path.exists('/run/.containerenv'):
            return True

        # Check /proc/1/cgroup
        try:
            with open('/proc/1/cgroup', 'r', encoding='utf-8') as f:
                content = f.read(65536)
                if any(pattern in content.lower() for pattern in self.RUNTIME_PATTERNS):
                    return True
        except OSError:
            pass

        # Check environment variable
        if os.environ.get('container') == 'podman':
            return True

        return False

    def _detect_kubernetes(self) -> bool:
        """Detect if running in a Kubernetes environment."""
        # Check environment variables
        if os.environ.get('KUBERNETES_SERVICE_HOST'):
            return True

        # Check service account token
        if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount'):
            return True

        # Check for K8s processes
        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                try:
                    with open(f'/proc/{pid_dir}/cmdline', 'r', encoding='utf-8') as f:
                        cmdline = f.read(1024).replace('\x00', ' ')
                        if any(k8s_proc in cmdline for k8s_proc in [
                            'kubelet', 'kube-proxy', 'kube-apiserver'
                        ]):
                            return True
                except OSError:
                    continue
        except OSError:
            pass

        return False

    def _detect_container_type(self) -> Optional[str]:
        """Detect the container runtime type."""
        if os.path.exists('/.dockerenv'):
            return 'docker'

        if os.path.exists('/run/.containerenv'):
            return 'podman'

        # Check for containerd
        try:
            if os.path.exists('/run/containerd'):
                return 'containerd'
        except OSError:
            pass

        # Check cgroup for hints
        try:
            with open('/proc/1/cgroup', 'r', encoding='utf-8') as f:
                content = f.read(65536).lower()
                if 'docker' in content:
                    return 'docker'
                elif 'kubepods' in content:
                    return 'kubernetes'
                elif 'podman' in content:
                    return 'podman'
                elif 'lxc' in content:
                    return 'lxc'
        except OSError:
            pass

        return None

    def _detect_workloads(self) -> Set[str]:
        """Detect workload types running in the container."""
        workloads = set()

        # Scan processes to detect workload types
        try:
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue
                try:
                    with open(f'/proc/{pid_dir}/cmdline', 'r', encoding='utf-8') as f:
                        cmdline = f.read(1024).replace('\x00', ' ')
                        cmdline_lower = cmdline.lower()

                        # Detect workload types
                        if 'kubelet' in cmdline_lower:
                            workloads.add('kubelet')
                        if any(cni in cmdline_lower for cni in ['calico', 'cilium', 'flannel']):
                            workloads.add('cni_plugin')
                        if any(mon in cmdline_lower for mon in ['datadog', 'prometheus', 'node_exporter']):
                            workloads.add('monitoring')
                        if any(storage in cmdline_lower for storage in ['rbd', 'glusterfs', 'longhorn']):
                            workloads.add('storage_driver')
                        if any(mesh in cmdline_lower for mesh in ['envoy', 'istio', 'linkerd']):
                            workloads.add('service_mesh')
                except OSError:
                    continue
        except OSError:
            pass

        self._detected_workloads = workloads
        return workloads

    def get_context_info(self) -> Dict:
        """Get comprehensive container context information.

        Returns:
            Dictionary containing container environment context
        """
        return {
            'is_container': self.is_container_environment(),
            'is_kubernetes': self.is_kubernetes_environment(),
            'container_type': self.get_container_type(),
            'detected_workloads': self.detected_workloads(),
            'standard_mounts': list(self.STANDARD_CONTAINER_MOUNTS.keys()),
            'standard_capabilities': self.STANDARD_CAPABILITIES,
            'standard_processes': self.STANDARD_CONTAINER_PROCESSES,
        }


# Singleton instance for reuse across analyzers
_container_detector = None
_container_detector_lock = threading.Lock()


def get_container_detector() -> ContainerEnvironmentDetector:
    """Get the singleton container detector instance."""
    global _container_detector
    if _container_detector is None:
        with _container_detector_lock:
            if _container_detector is None:
                _container_detector = ContainerEnvironmentDetector()
    return _container_detector
