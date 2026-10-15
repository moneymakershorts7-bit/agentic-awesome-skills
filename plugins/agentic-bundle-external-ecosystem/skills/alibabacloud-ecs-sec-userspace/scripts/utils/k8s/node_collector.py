"""Kubernetes Node-level Security Data Collector

Collects security-related data from Kubernetes node perspective:
- Pod discovery from multiple sources (container runtime, kubelet, cgroup, /proc)
- Container information and configurations
- Network namespaces and connections
- Volume mounts and sensitive paths
"""
import json
import os
import re
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from ..collector.base import BaseCollector

logger = logging.getLogger("sec-userspace")


@dataclass
class ContainerInfo:
    """Container information"""
    id: str
    name: str
    image: str
    image_id: str
    pid: int
    pids: List[int] = field(default_factory=list)
    rootfs: Optional[Path] = None
    privileged: bool = False
    capabilities: List[str] = field(default_factory=list)
    volumes: List[Dict[str, Any]] = field(default_factory=list)
    network_mode: str = ""
    pid_mode: str = ""
    ipc_mode: str = ""


@dataclass
class PodInfo:
    """Pod information (Node perspective)"""
    uid: str
    name: str
    namespace: str
    containers: List[ContainerInfo] = field(default_factory=list)
    status: str = "Unknown"
    service_account: str = ""
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    kubelet_dir: Optional[Path] = None
    log_dir: Optional[Path] = None
    pod_ip: str = ""


class K8sNodeCollector(BaseCollector):
    """Kubernetes Node-level Security Data Collector
    
    Collects pod and container information from node perspective without
    requiring K8S API server access. Uses multiple data sources:
    - Container runtime (containerd/docker)
    - Kubelet data directories
    - Cgroup hierarchies
    - /proc filesystem
    """
    
    name = "k8s_node"
    timeout = 60
    
    # Container runtime paths
    RUNTIME_PATHS = {
        'containerd': {
            'socket': '/run/containerd/containerd.sock',
            'root': '/var/lib/containerd',
        },
        'docker': {
            'socket': '/var/run/docker.sock',
            'root': '/var/lib/docker',
        },
    }
    
    # Kubelet paths
    KUBELET_PATHS = {
        'pods_dir': '/var/lib/kubelet/pods',
        'pod_resources': '/var/lib/kubelet/pod-resources',
        'config': '/var/lib/kubelet/config.yaml',
    }
    
    # Sensitive mount paths
    SENSITIVE_MOUNTS = [
        '/etc/shadow',
        '/etc/passwd',
        '/etc/kubernetes',
        '/var/lib/kubelet',
        '/var/run/docker.sock',
        '/run/containerd/containerd.sock',
        '/etc/cni',
        '/var/lib/etcd',
        '/proc',
        '/sys',
        '/',
    ]
    
    def collect(self) -> Dict[str, Any]:
        """Collect Kubernetes node security data
        
        Returns:
            Dictionary containing pods, containers, and security issues
        """
        logger.info(f"[{self.name}] Starting K8S node security collection...")
        
        result = {
            'pods': [],
            'containers': [],
            'runtime': self._detect_runtime(),
            'security_issues': [],
        }
        
        # Discover pods from multiple sources
        try:
            pods = self.discover_pods()
            result['pods'] = [self._pod_to_dict(pod) for pod in pods]
            
            # Extract all containers from pods
            for pod in pods:
                for container in pod.containers:
                    result['containers'].append(self._container_to_dict(container))
            
            # Detect security issues
            result['security_issues'] = self._detect_security_issues(pods)
            
        except (OSError, ValueError, KeyError, TypeError) as e:
            logger.error(f"[{self.name}] Failed to collect K8S data: {e}")
        
        return result
    
    def _detect_runtime(self) -> str:
        """Detect container runtime"""
        if os.path.exists(self.RUNTIME_PATHS['containerd']['socket']):
            return 'containerd'
        elif os.path.exists(self.RUNTIME_PATHS['docker']['socket']):
            return 'docker'
        return 'unknown'
    
    def discover_pods(self) -> List[PodInfo]:
        """Discover pods using multi-source fusion
        
        Returns:
            List of discovered PodInfo objects
        """
        pods_dict: Dict[str, PodInfo] = {}
        
        # Source 1: Container runtime
        try:
            runtime_pods = self._discover_from_runtime()
            self._merge_pods(pods_dict, runtime_pods, source='runtime')
        except (OSError, ValueError, KeyError) as e:
            logger.debug(f"[{self.name}] Runtime discovery failed: {e}")
        
        # Source 2: Kubelet pods directory
        try:
            kubelet_pods = self._discover_from_kubelet()
            self._merge_pods(pods_dict, kubelet_pods, source='kubelet')
        except (OSError, ValueError, KeyError) as e:
            logger.debug(f"[{self.name}] Kubelet discovery failed: {e}")
        
        # Source 3: Cgroup hierarchy
        try:
            cgroup_pods = self._discover_from_cgroup()
            self._merge_pods(pods_dict, cgroup_pods, source='cgroup')
        except (OSError, ValueError) as e:
            logger.debug(f"[{self.name}] Cgroup discovery failed: {e}")
        
        # Source 4: /proc filesystem
        try:
            proc_pods = self._discover_from_proc()
            self._merge_pods(pods_dict, proc_pods, source='proc')
        except (OSError, ValueError) as e:
            logger.debug(f"[{self.name}] Proc discovery failed: {e}")
        
        return list(pods_dict.values())
    
    def _merge_pods(self, pods_dict: Dict[str, PodInfo], new_pods: List[PodInfo], source: str):
        """Merge newly discovered pods into existing dictionary
        
        Args:
            pods_dict: Existing pods dictionary
            new_pods: Newly discovered pods
            source: Discovery source name
        """
        for pod in new_pods:
            if pod.uid in pods_dict:
                # Merge with existing pod
                existing = pods_dict[pod.uid]
                
                # Update name/namespace if empty
                if not existing.name and pod.name:
                    existing.name = pod.name
                if not existing.namespace and pod.namespace:
                    existing.namespace = pod.namespace
                
                # Merge containers
                existing_container_ids = {c.id for c in existing.containers}
                for container in pod.containers:
                    if container.id and container.id not in existing_container_ids:
                        existing.containers.append(container)
            else:
                # Add new pod
                pods_dict[pod.uid] = pod
        
        logger.debug(f"[{self.name}] Merged {len(new_pods)} pods from {source}")
    
    def _discover_from_runtime(self) -> List[PodInfo]:
        """Discover pods from container runtime"""
        pods = []
        runtime = self._detect_runtime()
        
        if runtime == 'containerd':
            pods = self._crictl_pods()
        elif runtime == 'docker':
            pods = self._docker_pods()
        
        return pods
    
    def _crictl_pods(self) -> List[PodInfo]:
        """Get pods using crictl (containerd) with enhanced fallback mechanism
        
        Tries multiple methods in order:
        1. crictl CLI command
        2. containerd socket gRPC API
        3. containerd state files parsing
        
        Returns:
            List of discovered PodInfo objects
        """
        pods = []
        
        try:
            # Method 1: Try crictl CLI
            import subprocess
            cmd = ['crictl', 'pods', '-o', 'json']
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
            
            if result.returncode == 0:
                import json
                pod_data = json.loads(result.stdout)
                
                for pod in pod_data.get('items', []):
                    pod_info = self._parse_crictl_pod(pod)
                    if pod_info:
                        pods.append(pod_info)
                return pods
            
            # Method 2: Fallback to containerd socket gRPC
            if os.path.exists('/run/containerd/containerd.sock'):
                grpc_pods = self._containerd_grpc_pods()
                if grpc_pods:
                    return grpc_pods
                    
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            logger.debug(f"[{self.name}] crictl failed: {e}")
        
        # Method 3: Parse containerd state files
        return self._containerd_state_pods()
    
    def _parse_crictl_pod(self, pod: Dict) -> Optional[PodInfo]:
        """Parse crictl pod data into PodInfo object
        
        Args:
            pod: Raw pod data from crictl
            
        Returns:
            PodInfo object or None if parsing fails
        """
        try:
            metadata = pod.get('metadata', {})
            return PodInfo(
                uid=pod.get('id', ''),
                name=metadata.get('name', ''),
                namespace=metadata.get('namespace', ''),
                status=pod.get('state', 'Unknown'),
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
    
    def _containerd_grpc_pods(self) -> List[PodInfo]:
        """Query containerd via gRPC API for detailed pod information
        
        Returns:
            List of discovered PodInfo objects
        """
        pods = []
        
        try:
            # Try to import grpc and containerd modules
            import grpc
            from containerd.services.containers.v1.containers_pb2 import ListContainersRequest
            
            # Connect to containerd socket
            socket_path = '/run/containerd/containerd.sock'
            channel = grpc.insecure_channel(f'unix:///{socket_path}')
            
            # List containers
            containers_stub = grpc.unary_unary_rpc(
                channel,
                '/containerd.services.containers.v1.Containers/List',
                request_serializer=ListContainersRequest.SerializeToString,
                response_deserializer=lambda x: x,
            )
            
            response = containers_stub(ListContainersRequest())
            
            # Group by Pod UID
            pod_containers: Dict[str, List] = {}
            
            for container in response.containers:
                labels = container.labels
                pod_uid = labels.get('io.kubernetes.pod.uid', '')
                
                if pod_uid:
                    if pod_uid not in pod_containers:
                        pod_containers[pod_uid] = []
                    pod_containers[pod_uid].append(container)
            
            # Build PodInfo
            for pod_uid, containers in pod_containers.items():
                pod_info = self._build_pod_from_containerd_containers(pod_uid, containers)
                if pod_info:
                    pods.append(pod_info)
                    
        except ImportError:
            logger.debug("[{self.name}] containerd gRPC client not available")
        except (OSError, ValueError, RuntimeError, AttributeError) as e:
            logger.debug(f"[{self.name}] containerd gRPC failed: {e}")
        
        return pods
    
    def _build_pod_from_containerd_containers(self, pod_uid: str, containers: List) -> Optional[PodInfo]:
        """Build PodInfo from containerd container list
        
        Args:
            pod_uid: Pod unique identifier
            containers: List of containerd container objects
            
        Returns:
            PodInfo object or None
        """
        try:
            if not containers:
                return None
            
            # Get pod info from first container's labels
            first = containers[0]
            labels = first.labels
            
            pod_name = labels.get('io.kubernetes.pod.name', '')
            pod_namespace = labels.get('io.kubernetes.pod.namespace', '')
            
            # Build container list
            container_infos = []
            for container in containers:
                container_info = self._parse_containerd_container(container)
                if container_info:
                    container_infos.append(container_info)
            
            return PodInfo(
                uid=pod_uid,
                name=pod_name,
                namespace=pod_namespace,
                containers=container_infos,
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
    
    def _parse_containerd_container(self, container) -> Optional[ContainerInfo]:
        """Parse containerd container object
        
        Args:
            container: containerd container object
            
        Returns:
            ContainerInfo object or None
        """
        try:
            labels = container.labels
            
            # Extract security context
            privileged = labels.get('io.kubernetes.container.privileged', 'false') == 'true'
            
            return ContainerInfo(
                id=container.id,
                name=labels.get('io.kubernetes.container.name', ''),
                image=container.image,
                image_id='',
                pid=0,
                privileged=privileged,
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
    
    def _containerd_state_pods(self) -> List[PodInfo]:
        """Parse containerd state files to discover pods
        
        Reads container state from:
        - /var/lib/containerd/io.containerd.runtime.v2.task/k8s.io/*/spec.json
        - /var/lib/containerd/io.containerd.metadata.v1.meta/buckets/*/data
        
        Returns:
            List of discovered PodInfo objects
        """
        pods_dict: Dict[str, PodInfo] = {}
        
        try:
            # Path pattern for containerd k8s runtime state
            runtime_root = Path('/var/lib/containerd/io.containerd.runtime.v2.task/k8s.io')
            
            if not runtime_root.exists():
                return []
            
            for container_dir in runtime_root.iterdir():
                if not container_dir.is_dir():
                    continue
                
                container_id = container_dir.name
                spec_file = container_dir / 'spec.json'
                
                if not spec_file.exists():
                    continue
                
                try:
                    import json
                    spec_data = json.loads(spec_file.read_text(encoding='utf-8'))
                    
                    # Extract pod info from annotations
                    annotations = spec_data.get('annotations', {})
                    pod_uid = annotations.get('io.kubernetes.pod.uid', '')
                    pod_name = annotations.get('io.kubernetes.pod.name', '')
                    pod_namespace = annotations.get('io.kubernetes.pod.namespace', '')
                    
                    if not pod_uid:
                        continue
                    
                    # Get container info
                    container_info = ContainerInfo(
                        id=container_id,
                        name=annotations.get('io.kubernetes.container.name', ''),
                        image=spec_data.get('image', {}).get('image', ''),
                        image_id='',
                        pid=self._get_container_pid(container_id),
                    )
                    
                    # Add to pod
                    if pod_uid not in pods_dict:
                        pods_dict[pod_uid] = PodInfo(
                            uid=pod_uid,
                            name=pod_name,
                            namespace=pod_namespace,
                            containers=[],
                        )
                    
                    pods_dict[pod_uid].containers.append(container_info)
                    
                except (json.JSONDecodeError, KeyError, PermissionError):
                    continue
                    
        except (OSError, ValueError, KeyError) as e:
            logger.debug(f"[{self.name}] containerd state parsing failed: {e}")
        
        return list(pods_dict.values())
    
    def _docker_pods(self) -> List[PodInfo]:
        """Get pods using docker CLI with multi-container support
        
        Returns:
            List of discovered PodInfo objects
        """
        pods = []
        
        try:
            import subprocess
            import json
            
            # Get all containers with k8s labels
            ps_cmd = ['docker', 'ps', '--filter', 'label=io.kubernetes.pod.uid', '-q']
            ps_result = subprocess.run(ps_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
            
            if ps_result.returncode != 0 or not ps_result.stdout.strip():
                return []
            
            container_ids = ps_result.stdout.strip().split('\n')
            
            # Group containers by Pod UID
            pod_containers: Dict[str, List[Dict]] = {}
            
            for container_id in container_ids:
                if not container_id:
                    continue
                    
                inspect_cmd = ['docker', 'inspect', container_id]
                inspect_result = subprocess.run(inspect_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
                
                if inspect_result.returncode == 0:
                    containers = json.loads(inspect_result.stdout)
                    for container in containers:
                        labels = container.get('Config', {}).get('Labels', {})
                        pod_uid = labels.get('io.kubernetes.pod.uid', '')
                        
                        if pod_uid:
                            if pod_uid not in pod_containers:
                                pod_containers[pod_uid] = []
                            pod_containers[pod_uid].append(container)
            
            # Build PodInfo from grouped containers
            for pod_uid, containers in pod_containers.items():
                pod_info = self._build_pod_from_docker_containers(pod_uid, containers)
                if pod_info:
                    pods.append(pod_info)
                    
        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as e:
            logger.debug(f"[{self.name}] docker failed: {e}")
        
        return pods
    def _get_container_pid(self, container_id: str) -> int:
        """Get container main process PID by searching /proc
        
        Args:
            container_id: Container ID
            
        Returns:
            PID or 0 if not found
        """
        if not container_id:
            return 0
        
        try:
            for pid_str in os.listdir('/proc'):
                if not pid_str.isdigit():
                    continue
                
                try:
                    cgroup_file = Path(f'/proc/{pid_str}/cgroup')
                    if not cgroup_file.exists():
                        continue
                    
                    cgroup_content = cgroup_file.read_text(encoding='utf-8')
                    
                    # Check if this PID belongs to the container
                    if container_id in cgroup_content:
                        return int(pid_str)
                        
                except (PermissionError, FileNotFoundError):
                    continue
        except (OSError, KeyError, TypeError, ValueError):
            pass
        
        return 0
    
    def _build_pod_from_docker_containers(self, pod_uid: str, containers: List[Dict]) -> Optional[PodInfo]:
        """Build PodInfo from grouped Docker containers
        
        Args:
            pod_uid: Pod unique identifier
            containers: List of Docker container inspect results
            
        Returns:
            PodInfo object or None
        """
        try:
            if not containers:
                return None
            
            # Get pod info from first container's labels
            first = containers[0]
            config = first.get('Config', {})
            labels = config.get('Labels', {})
            
            pod_name = labels.get('io.kubernetes.pod.name', '')
            pod_namespace = labels.get('io.kubernetes.pod.namespace', '')
            
            # Build container list
            container_infos = []
            for container in containers:
                container_info = self._parse_docker_container(container)
                if container_info:
                    container_infos.append(container_info)
            
            return PodInfo(
                uid=pod_uid,
                name=pod_name,
                namespace=pod_namespace,
                containers=container_infos,
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
    
    def _parse_docker_container(self, container: Dict) -> Optional[ContainerInfo]:
        """Parse Docker container inspect result
        
        Args:
            container: Docker container inspect result
            
        Returns:
            ContainerInfo object or None
        """
        try:
            config = container.get('Config', {})
            config.get('Labels', {})
            host_config = container.get('HostConfig', {})
            container.get('GraphDriver', {})
            
            # Extract security context
            privileged = host_config.get('Privileged', False)
            
            # Extract capabilities
            cap_add = host_config.get('CapAdd', []) or []
            
            # Parse volumes
            volumes = []
            mounts = container.get('Mounts', []) or []
            for mount in mounts:
                volumes.append({
                    'host_path': mount.get('Source', ''),
                    'container_path': mount.get('Destination', ''),
                    'rw': mount.get('RW', True),
                })
            
            # Get rootfs path
            rootfs = self._get_container_rootfs(container)
            
            return ContainerInfo(
                id=container.get('Id', ''),
                name=config.get('Hostname', ''),
                image=config.get('Image', ''),
                image_id=container.get('Image', ''),
                pid=self._get_container_pid(container.get('Id', '')),
                privileged=privileged,
                capabilities=cap_add,
                volumes=volumes,
                rootfs=rootfs,
                network_mode=host_config.get('NetworkMode', ''),
                pid_mode=host_config.get('PidMode', ''),
                ipc_mode=host_config.get('IpcMode', ''),
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
    
    def _get_container_rootfs(self, container_info: Dict) -> Optional[Path]:
        """Get container root filesystem path
        
        Args:
            container_info: Container information dictionary
            
        Returns:
            Path to container rootfs or None
        """
        runtime = self._detect_runtime()
        container_id = container_info.get('Id', '')
        
        if not container_id:
            return None
        
        if runtime == 'containerd':
            # containerd overlay2 path pattern
            overlay2_root = Path('/var/lib/containerd/io.containerd.runtime.v2.task/k8s.io') / container_id / 'rootfs'
            
            try:
                if overlay2_root.exists():
                    return overlay2_root
            except OSError:
                pass
            
            # Alternative: snapshotter path
            snapshot_root = Path('/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots')
            try:
                if snapshot_root.exists():
                    # Try to find snapshot for this container
                    for snap_dir in snapshot_root.iterdir():
                        if snap_dir.is_dir():
                            # Check if this snapshot belongs to our container
                            spec_file = snap_dir / 'fs'
                            if spec_file.exists():
                                return spec_file
            except OSError:
                pass
        
        elif runtime == 'docker':
            # Docker overlay2 path
            graph_driver = container_info.get('GraphDriver', {})
            
            if graph_driver.get('Name') == 'overlay2':
                data = graph_driver.get('Data', {})
                merged_dir = data.get('MergedDir', '')
                
                if merged_dir:
                    try:
                        if Path(merged_dir).exists():
                            return Path(merged_dir)
                    except OSError:
                        pass
                
                # Fallback: construct from overlay structure
                upper_dir = data.get('UpperDir', '')
                if upper_dir:
                    return Path(upper_dir).parent
        
        return None
    
    def _discover_from_kubelet(self) -> List[PodInfo]:
        """Discover pods from /var/lib/kubelet/pods directory"""
        pods = []
        pods_dir = Path(self.KUBELET_PATHS['pods_dir'])
        
        if not pods_dir.exists():
            return pods
        
        try:
            for pod_dir in pods_dir.iterdir():
                if not pod_dir.is_dir():
                    continue
                
                pod_uid = pod_dir.name
                
                # Try to extract pod info from directory structure
                pod_info = self._parse_kubelet_pod(pod_dir, pod_uid)
                if pod_info:
                    pods.append(pod_info)
        except (OSError, ValueError) as e:
            logger.debug(f"[{self.name}] Kubelet parsing failed: {e}")
        
        return pods
    
    def _parse_kubelet_pod(self, pod_dir: Path, pod_uid: str) -> Optional[PodInfo]:
        """Parse kubelet pod directory"""
        try:
            # Look for pod metadata in various files
            pod_name = ''
            pod_namespace = ''
            
            # Check etc-hosts file for pod info
            etc_hosts = pod_dir / 'etc-hosts'
            if etc_hosts.exists():
                content = etc_hosts.read_text(encoding='utf-8')
                # Extract from hostname pattern
                match = re.search(r'(\S+)-(\S+)-([a-f0-9\-]+)', content)
                if match:
                    pod_namespace = match.group(1)
                    pod_name = match.group(2)
            
            # Check volumes directory
            volumes_dir = pod_dir / 'volumes'
            if volumes_dir.exists():
                # Look for kubernetes.io~serviceaccount
                sa_token_dir = volumes_dir / 'kubernetes.io~serviceaccount'
                if sa_token_dir.exists():
                    namespace_file = sa_token_dir / 'namespace'
                    if namespace_file.exists():
                        pod_namespace = namespace_file.read_text(encoding='utf-8').strip()
            
            return PodInfo(
                uid=pod_uid,
                name=pod_name,
                namespace=pod_namespace,
                kubelet_dir=pod_dir,
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
    
    def _discover_from_cgroup(self) -> List[PodInfo]:
        """Discover pods from cgroup hierarchy"""
        pods = []
        
        # Try cgroup v2 first
        cgroup_root = Path('/sys/fs/cgroup')
        kubepods = cgroup_root / 'kubepods.slice'
        
        if not kubepods.exists():
            # Try cgroup v1
            kubepods = cgroup_root / 'kubepods'
        
        if not kubepods.exists():
            return pods
        
        try:
            for pod_cgroup in kubepods.glob('*pod*'):
                if not pod_cgroup.is_dir():
                    continue
                
                # Extract pod UID from cgroup name
                pod_uid_match = re.search(r'pod([a-f0-9\-]+)', pod_cgroup.name)
                if pod_uid_match:
                    pod_uid = pod_uid_match.group(1).replace('_', '-')
                    
                    # Try to get more info from cgroup files
                    pod_info = self._parse_cgroup_pod(pod_cgroup, pod_uid)
                    if pod_info:
                        pods.append(pod_info)
        except (OSError, ValueError) as e:
            logger.debug(f"[{self.name}] Cgroup parsing failed: {e}")
        
        return pods
    
    def _parse_cgroup_pod(self, cgroup_dir: Path, pod_uid: str) -> Optional[PodInfo]:
        """Parse cgroup pod directory"""
        try:
            # Look for container subdirectories
            containers = []
            
            for item in cgroup_dir.iterdir():
                if not item.is_dir():
                    continue
                
                # Check if this is a container cgroup
                pids_file = item / 'cgroup.procs'
                if pids_file.exists():
                    pids_content = pids_file.read_text(encoding='utf-8').strip()
                    if pids_content:
                        pids = [int(pid) for pid in pids_content.split('\n') if pid.isdigit()]
                        
                        if pids:
                            containers.append(ContainerInfo(
                                id=item.name,
                                name='',
                                image='',
                                image_id='',
                                pid=pids[0],
                                pids=pids,
                            ))
            
            if containers:
                return PodInfo(
                    uid=pod_uid,
                    name='',
                    namespace='',
                    containers=containers,
                )
        except (OSError, KeyError, TypeError, ValueError):
            pass
        
        return None
    
    def _discover_from_proc(self) -> List[PodInfo]:
        """Discover containers from /proc filesystem"""
        containers_dict: Dict[str, List[int]] = {}
        
        try:
            for pid_str in os.listdir('/proc'):
                if not pid_str.isdigit():
                    continue
                
                pid = int(pid_str)
                
                try:
                    # Read cgroup to identify container
                    cgroup_file = Path(f'/proc/{pid}/cgroup')
                    if not cgroup_file.exists():
                        continue
                    
                    cgroup_content = cgroup_file.read_text(encoding='utf-8')
                    
                    # Extract container ID from cgroup
                    container_id = self._extract_container_id(cgroup_content)
                    pod_uid = self._extract_pod_uid(cgroup_content)
                    
                    if container_id and pod_uid:
                        if pod_uid not in containers_dict:
                            containers_dict[pod_uid] = []
                        containers_dict[pod_uid].append(pid)
                        
                except (PermissionError, FileNotFoundError):
                    continue
        except (OSError, KeyError, TypeError, ValueError):
            pass
        
        # Build pod info from containers
        pods = []
        for pod_uid, pids in containers_dict.items():
            if pids:
                pods.append(PodInfo(
                    uid=pod_uid,
                    name='',
                    namespace='',
                    containers=[ContainerInfo(
                        id='',
                        name='',
                        image='',
                        image_id='',
                        pid=pids[0],
                        pids=pids,
                    )],
                ))
        
        return pods
    
    def _extract_container_id(self, cgroup_content: str) -> Optional[str]:
        """Extract container ID from cgroup content"""
        # Container ID patterns (64-char hex or shorter docker IDs)
        patterns = [
            r'container/([a-f0-9]{64})',
            r'docker/([a-f0-9]{64})',
            r'docker/([a-f0-9]{12})',
            r'cri-containerd/[a-f0-9]{64}',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, cgroup_content)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_pod_uid(self, cgroup_content: str) -> Optional[str]:
        """Extract pod UID from cgroup content"""
        # Pod UID pattern in cgroup
        patterns = [
            r'pod([a-f0-9\-]{36})',
            r'kubepods.*pod([a-f0-9\-]{36})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, cgroup_content)
            if match:
                return match.group(1).replace('_', '-')
        
        return None
    
    def _detect_security_issues(self, pods: List[PodInfo]) -> List[Dict[str, Any]]:
        """Detect security issues in discovered pods
        
        Args:
            pods: List of discovered pods
            
        Returns:
            List of security issue dictionaries
        """
        issues = []
        
        for pod in pods:
            # Check for host namespaces
            if pod.host_network:
                issues.append({
                    'type': 'host_network',
                    'severity': 'HIGH',
                    'pod_uid': pod.uid,
                    'pod_name': pod.name,
                    'description': 'Pod uses host network namespace',
                })
            
            if pod.host_pid:
                issues.append({
                    'type': 'host_pid',
                    'severity': 'CRITICAL',
                    'pod_uid': pod.uid,
                    'pod_name': pod.name,
                    'description': 'Pod uses host PID namespace',
                })
            
            # Check containers
            for container in pod.containers:
                # Check for privileged mode
                if container.privileged:
                    issues.append({
                        'type': 'privileged_container',
                        'severity': 'CRITICAL',
                        'pod_uid': pod.uid,
                        'pod_name': pod.name,
                        'container': container.name,
                        'description': 'Container runs in privileged mode',
                    })
                
                # Check for dangerous capabilities
                dangerous_caps = {'SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'SYS_MODULE'}
                container_caps = set(container.capabilities)
                if container_caps & dangerous_caps:
                    issues.append({
                        'type': 'dangerous_capabilities',
                        'severity': 'HIGH',
                        'pod_uid': pod.uid,
                        'pod_name': pod.name,
                        'container': container.name,
                        'capabilities': list(container_caps & dangerous_caps),
                        'description': 'Container has dangerous capabilities',
                    })
                
                # Check for sensitive mounts
                for volume in container.volumes:
                    host_path = volume.get('host_path', '')
                    for sensitive in self.SENSITIVE_MOUNTS:
                        if host_path == sensitive or host_path.startswith(sensitive + '/'):
                            issues.append({
                                'type': 'sensitive_mount',
                                'severity': 'HIGH' if 'sock' not in host_path else 'CRITICAL',
                                'pod_uid': pod.uid,
                                'pod_name': pod.name,
                                'container': container.name,
                                'mount_path': host_path,
                                'description': f'Sensitive host path mounted: {host_path}',
                            })
        
        return issues
    
    def _pod_to_dict(self, pod: PodInfo) -> Dict[str, Any]:
        """Convert PodInfo to dictionary"""
        return {
            'uid': pod.uid,
            'name': pod.name,
            'namespace': pod.namespace,
            'status': pod.status,
            'service_account': pod.service_account,
            'host_network': pod.host_network,
            'host_pid': pod.host_pid,
            'host_ipc': pod.host_ipc,
            'containers': [self._container_to_dict(c) for c in pod.containers],
        }
    
    def _container_to_dict(self, container: ContainerInfo) -> Dict[str, Any]:
        """Convert ContainerInfo to dictionary"""
        return {
            'id': container.id,
            'name': container.name,
            'image': container.image,
            'image_id': container.image_id,
            'pid': container.pid,
            'pids': container.pids,
            'privileged': container.privileged,
            'capabilities': container.capabilities,
            'volumes': container.volumes,
            'network_mode': container.network_mode,
            'pid_mode': container.pid_mode,
            'ipc_mode': container.ipc_mode,
        }
