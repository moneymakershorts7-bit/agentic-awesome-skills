"""Pod Skill Deployer for AI Tool Security Detection

Deploys sec-userspace skill to AI tool pods in Kubernetes clusters.
Supports multiple AI tools: QoderCLI, Claude Code, OpenCode, OpenClaw, Cursor, Windsurf.
"""
import logging
import subprocess
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Any

logger = logging.getLogger("sec-userspace")


@dataclass
class AIPodInfo:
    """AI Pod information"""
    name: str
    namespace: str
    node: str
    ai_tools: List[str]
    status: str
    containers: List[str] = field(default_factory=list)


@dataclass
class DeployResult:
    """Deployment result for a single pod"""
    pod: str
    namespace: str
    success: bool = False
    deployed_tools: List[str] = field(default_factory=list)
    failed_tools: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class BatchDeployResult:
    """Batch deployment result"""
    total: int
    success: int = 0
    failed: int = 0
    discovered: List[AIPodInfo] = field(default_factory=list)
    results: List[DeployResult] = field(default_factory=list)
    dry_run: bool = False


class PodSkillDeployer:
    """
    Pod Skill Deployer for AI Tools
    
    Discovers AI tool pods and deploys sec-userspace skills to them.
    Supports: QoderCLI, Claude Code, OpenCode, OpenClaw, Cursor, Windsurf
    """
    
    # Supported AI tools and their configurations
    AI_TOOLS = {
        'qodercli': {
            'process_pattern': r'qodercli|qoder',
            'skill_dir': '.qoder/skills',
            'config_file': '.qoder/config.json',
            'display_name': 'QoderCLI',
        },
        'claude': {
            'process_pattern': r'claude|anthropic',
            'skill_dir': '.claude/skills',
            'config_file': '.claude/settings.json',
            'display_name': 'Claude Code',
        },
        'opencode': {
            'process_pattern': r'opencode',
            'skill_dir': '.opencode/skills',
            'config_file': '.opencode/config.yaml',
            'display_name': 'OpenCode',
        },
        'openclaw': {
            'process_pattern': r'openclaw|claw',
            'skill_dir': '.openclaw/skills',
            'config_file': '.openclaw/config.json',
            'display_name': 'OpenClaw',
        },
        'cursor': {
            'process_pattern': r'cursor',
            'skill_dir': '.cursor/skills',
            'config_file': '.cursor/settings.json',
            'display_name': 'Cursor',
        },
        'windsurf': {
            'process_pattern': r'windsurf',
            'skill_dir': '.windsurf/skills',
            'config_file': '.windsurf/config.json',
            'display_name': 'Windsurf',
        },
    }
    
    def __init__(self, kubeconfig: Optional[str] = None, context: Optional[str] = None):
        """Initialize Pod Skill Deployer
        
        Args:
            kubeconfig: Path to kubeconfig file (default: ~/.kube/config)
            context: Kubernetes context name
        """
        self.kubeconfig = kubeconfig
        self.context = context
        self.k8s_available = self._check_k8s_access()
        
        if not self.k8s_available:
            logger.warning("Kubernetes access not available, deployer will work in limited mode")
    
    def _check_k8s_access(self) -> bool:
        """Check if kubectl is available and can access the cluster"""
        try:
            cmd = ['kubectl']
            if self.kubeconfig:
                cmd.extend(['--kubeconfig', self.kubeconfig])
            if self.context:
                cmd.extend(['--context', self.context])
            cmd.extend(['cluster-info'])
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=10
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError) as e:
            logger.debug(f"K8s access check failed: {e}")
            return False
    
    def discover_ai_pods(self, namespace: Optional[str] = None) -> List[AIPodInfo]:
        """Discover AI tool pods in the cluster
        
        Args:
            namespace: Namespace to search (None for all namespaces)
            
        Returns:
            List of AI pod information
        """
        logger.info("Discovering AI tool pods...")
        ai_pods = []
        
        try:
            # Get all pods
            pods = self._list_pods(namespace)
            
            for pod in pods:
                # Detect AI tools in pod
                detected_tools = self._detect_ai_tools(pod)
                
                if detected_tools:
                    ai_pods.append(AIPodInfo(
                        name=pod['name'],
                        namespace=pod['namespace'],
                        node=pod.get('node', ''),
                        ai_tools=detected_tools,
                        status=pod.get('status', 'Unknown'),
                        containers=pod.get('containers', []),
                    ))
            
            logger.info(f"Discovered {len(ai_pods)} AI pods")
            
        except (OSError, subprocess.SubprocessError, KeyError, ValueError) as e:
            logger.error(f"Failed to discover AI pods: {e}")
        
        return ai_pods
    
    def _list_pods(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """List pods using kubectl
        
        Args:
            namespace: Namespace to list pods from
            
        Returns:
            List of pod dictionaries
        """
        cmd = ['kubectl', 'get', 'pods', '-o', 'jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.namespace}{"\t"}{.spec.nodeName}{"\t"}{.status.phase}{"\t"}{.spec.containers[*].name}{"\n"}']
        
        if namespace:
            cmd.extend(['-n', namespace])
        else:
            cmd.insert(2, '--all-namespaces')
        
        if self.kubeconfig:
            cmd.extend(['--kubeconfig', self.kubeconfig])
        if self.context:
            cmd.extend(['--context', self.context])
        
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
            if result.returncode != 0:
                logger.error(f"kubectl failed: {result.stderr}")
                return []
            
            pods = []
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) >= 4:
                    pods.append({
                        'name': parts[0],
                        'namespace': parts[1],
                        'node': parts[2],
                        'status': parts[3],
                        'containers': parts[4].split(' ') if len(parts) > 4 else [],
                    })
            
            return pods
            
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to list pods: {e}")
            return []
    
    def _detect_ai_tools(self, pod: Dict[str, Any]) -> List[str]:
        """Detect AI tools in a pod
        
        Args:
            pod: Pod information dictionary
            
        Returns:
            List of detected AI tool names
        """
        detected = set()
        
        # Check container names
        for container in pod.get('containers', []):
            container_lower = container.lower()
            for tool_name, tool_info in self.AI_TOOLS.items():
                if re.search(tool_info['process_pattern'], container_lower):
                    detected.add(tool_name)
        
        # Check pod name
        pod_name_lower = pod['name'].lower()
        for tool_name, tool_info in self.AI_TOOLS.items():
            if re.search(tool_info['process_pattern'], pod_name_lower):
                detected.add(tool_name)
        
        # If no tools detected via patterns, skip this pod
        # (We don't want to deploy to random pods)
        return list(detected)
    
    def deploy_skill_to_pod(
        self,
        pod_name: str,
        namespace: str,
        skill_package: Path,
        ai_tools: Optional[List[str]] = None,
        container: Optional[str] = None,
    ) -> DeployResult:
        """Deploy skill to a specific pod
        
        Args:
            pod_name: Name of the pod
            namespace: Namespace of the pod
            skill_package: Path to skill package zip file
            ai_tools: List of AI tools to deploy to (None for auto-detect)
            container: Container name (None for first container)
            
        Returns:
            Deployment result
        """
        result = DeployResult(pod=pod_name, namespace=namespace)
        
        if not self.k8s_available:
            result.error = "Kubernetes access not available"
            return result
        
        if not skill_package.exists():
            result.error = f"Skill package not found: {skill_package}"
            return result
        
        # Auto-detect AI tools if not specified
        if ai_tools is None:
            pods = self._list_pods(namespace)
            target_pod = next((p for p in pods if p['name'] == pod_name), None)
            if not target_pod:
                result.error = f"Pod {namespace}/{pod_name} not found"
                return result
            ai_tools = self._detect_ai_tools(target_pod)
        
        if not ai_tools:
            result.error = "No AI tools detected or specified"
            return result
        
        # Use first container if not specified
        if not container:
            pods = self._list_pods(namespace)
            target_pod = next((p for p in pods if p['name'] == pod_name), None)
            if target_pod and target_pod.get('containers'):
                container = target_pod['containers'][0]
        
        if not container:
            result.error = "No container specified or found"
            return result
        
        # Deploy to each AI tool
        for tool in ai_tools:
            tool_info = self.AI_TOOLS.get(tool)
            if not tool_info:
                result.failed_tools.append({
                    'tool': tool,
                    'error': f"Unknown AI tool: {tool}",
                })
                continue
            
            skill_dir = tool_info['skill_dir']
            
            try:
                logger.info(f"Deploying sec-userspace to {tool} in {namespace}/{pod_name}")
                
                # Step 1: Create skill directory
                self._exec_in_pod(
                    pod_name, namespace, container,
                    f"mkdir -p ~/{skill_dir}/sec-userspace"
                )
                
                # Step 2: Copy skill package to pod
                self._copy_to_pod(
                    pod_name, namespace, container,
                    skill_package,
                    f"/tmp/sec-userspace-skill.zip"
                )
                
                # Step 3: Unzip and configure
                self._exec_in_pod(
                    pod_name, namespace, container,
                    f"unzip -o /tmp/sec-userspace-skill.zip -d ~/{skill_dir}/sec-userspace/ && "
                    f"chmod +x ~/{skill_dir}/sec-userspace/*.sh 2>/dev/null || true && "
                    f"rm -f /tmp/sec-userspace-skill.zip"
                )
                
                result.deployed_tools.append(tool)
                logger.info(f"Successfully deployed to {tool} in {namespace}/{pod_name}")
                
            except (OSError, subprocess.SubprocessError) as e:
                logger.error(f"Failed to deploy to {tool}: {e}")
                result.failed_tools.append({
                    'tool': tool,
                    'error': str(e),
                })
        
        result.success = len(result.deployed_tools) > 0
        if not result.success:
            result.error = "All deployments failed"
        
        return result
    
    def deploy_to_all_ai_pods(
        self,
        skill_package: Path,
        namespace: Optional[str] = None,
        dry_run: bool = False,
    ) -> BatchDeployResult:
        """Deploy skill to all AI pods in batch
        
        Args:
            skill_package: Path to skill package zip file
            namespace: Namespace to search (None for all)
            dry_run: If True, only discover pods without deploying
            
        Returns:
            Batch deployment result
        """
        logger.info("Starting batch deployment to AI pods...")
        
        # Discover all AI pods
        ai_pods = self.discover_ai_pods(namespace)
        
        if not ai_pods:
            logger.warning("No AI pods discovered")
            return BatchDeployResult(total=0, discovered=[])
        
        logger.info(f"Discovered {len(ai_pods)} AI pods:")
        for pod in ai_pods:
            logger.info(f"  - {pod.namespace}/{pod.name}: {', '.join(pod.ai_tools)}")
        
        if dry_run:
            logger.info("Dry run mode - skipping deployment")
            return BatchDeployResult(
                total=len(ai_pods),
                discovered=ai_pods,
                dry_run=True,
            )
        
        # Deploy to each pod
        results = []
        success_count = 0
        
        for pod in ai_pods:
            result = self.deploy_skill_to_pod(
                pod.name,
                pod.namespace,
                skill_package,
                pod.ai_tools,
            )
            results.append(result)
            
            if result.success:
                success_count += 1
        
        return BatchDeployResult(
            total=len(ai_pods),
            success=success_count,
            failed=len(ai_pods) - success_count,
            discovered=ai_pods,
            results=results,
        )
    
    def _exec_in_pod(
        self,
        pod: str,
        namespace: str,
        container: str,
        command: str,
    ) -> str:
        """Execute command in pod
        
        Args:
            pod: Pod name
            namespace: Namespace
            container: Container name
            command: Command to execute
            
        Returns:
            Command output
        """
        cmd = ['kubectl', 'exec', pod, '-n', namespace, '-c', container, '--', 'sh', '-c', command]
        
        if self.kubeconfig:
            cmd.extend(['--kubeconfig', self.kubeconfig])
        if self.context:
            cmd.extend(['--context', self.context])
        
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
            if result.returncode != 0:
                raise RuntimeError(f"kubectl exec failed: {result.stderr}")
            return result.stdout
            
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Command execution timed out")
    
    def _copy_to_pod(
        self,
        pod: str,
        namespace: str,
        container: str,
        local_path: Path,
        remote_path: str,
    ):
        """Copy file to pod
        
        Args:
            pod: Pod name
            namespace: Namespace
            container: Container name
            local_path: Local file path
            remote_path: Remote path in pod
        """
        cmd = ['kubectl', 'cp', str(local_path), f'{namespace}/{pod}:{remote_path}', '-c', container]
        
        if self.kubeconfig:
            cmd.extend(['--kubeconfig', self.kubeconfig])
        if self.context:
            cmd.extend(['--context', self.context])
        
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=120)
            if result.returncode != 0:
                raise RuntimeError(f"kubectl cp failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"File copy timed out")
    
    def verify_deployment(
        self,
        namespace: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify skill deployment in AI pods
        
        Args:
            namespace: Namespace to verify
            
        Returns:
            Verification results
        """
        logger.info("Verifying skill deployment...")
        
        ai_pods = self.discover_ai_pods(namespace)
        verification_results = {
            'total_pods': len(ai_pods),
            'verified': 0,
            'failed': 0,
            'details': [],
        }
        
        for pod in ai_pods:
            for tool in pod.ai_tools:
                tool_info = self.AI_TOOLS.get(tool)
                if not tool_info:
                    continue
                
                skill_dir = tool_info['skill_dir']
                container = pod.containers[0] if pod.containers else None
                
                if not container:
                    verification_results['failed'] += 1
                    verification_results['details'].append({
                        'pod': f"{pod.namespace}/{pod.name}",
                        'tool': tool,
                        'status': 'FAILED',
                        'error': 'No container found',
                    })
                    continue
                
                # Check if skill directory exists
                try:
                    self._exec_in_pod(
                        pod.name, pod.namespace, container,
                        f"test -d ~/{skill_dir}/sec-userspace && echo 'EXISTS' || echo 'NOT_FOUND'"
                    )
                    
                    verification_results['verified'] += 1
                    verification_results['details'].append({
                        'pod': f"{pod.namespace}/{pod.name}",
                        'tool': tool,
                        'status': 'OK',
                    })
                    
                except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError) as e:
                    verification_results['failed'] += 1
                    verification_results['details'].append({
                        'pod': f"{pod.namespace}/{pod.name}",
                        'tool': tool,
                        'status': 'FAILED',
                        'error': str(e),
                    })
        
        return verification_results
