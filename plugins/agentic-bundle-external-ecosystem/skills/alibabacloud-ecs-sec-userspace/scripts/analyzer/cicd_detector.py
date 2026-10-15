"""Unified CI/CD Context Detection Module

Provides shared CI/CD detection logic for all Kubernetes analyzers to reduce
false positives in CI/CD environments (Jenkins, GitLab Runner, ArgoCD, Flux, etc.).

This module extracts and centralizes the CI/CD detection logic from
k8s_escape_lateral_movement_analyzer.py so all K8s analyzers can reuse it.

Usage:
    from .cicd_detector import CICDDetector

    detector = CICDDetector()
    if detector.is_ci_cd_context(process_data, pid):
        # Reduce confidence or skip detection
        confidence -= 0.15
"""
import threading
from typing import Dict, Any, Set

_lazy_init_lock = threading.Lock()

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

class CICDDetector:
    """Detects if processes are running in CI/CD context.
    
    CI/CD systems legitimately execute K8s commands like kubectl exec,
    kubectl apply, helm install, etc. These should have reduced confidence
    or be excluded from certain detections.
    """
    
    # CI/CD system processes that legitimately run K8s commands
    CI_CD_PROCESSES: Set[str] = {
        'jenkins', 'jenkins-agent', 'gitlab-runner', 'gitlab-runner-helper',
        'argocd-application-controller', 'argocd-repo-server', 'argocd-server',
        'argocd-dex-server', 'argocd-notifications-controller',
        'flux', 'helm-controller', 'kustomize-controller', 'source-controller',
        'tekton-pipeline-controller', 'tekton-triggers-controller',
        'circleci', 'github-runner', 'actions-runner',
        'drone', 'concourse-worker', 'spinnaker',
        'rancher', 'rancher-agent',
    }
    
    # Legitimate CI/CD namespace names
    CI_CD_NAMESPACES: Set[str] = {
        'ci-cd', 'cicd', 'pipeline', 'build',
        'jenkins', 'gitlab-runner', 'argocd', 'flux-system',
        'tekton-pipelines', 'tekton-pipelines-resolvers',
    }
    
    # Trusted parent processes for K8s commands
    TRUSTED_PARENT_PROCESSES: Set[str] = {
        'jenkins', 'gitlab-runner', 'argocd', 'flux', 'tekton',
        'circleci', 'github-actions', 'drone', 'concourse',
        'cron', 'systemd', 'supervisord',
    }
    
    # CI/CD environment variables that indicate CI/CD context
    CI_CD_ENV_VARS: Set[str] = {
        'CI', 'CI_PIPELINE_ID', 'CI_JOB_ID', 'GITLAB_CI',
        'JENKINS_URL', 'JENKINS_HOME', 'BUILD_NUMBER',
        'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'CIRCLECI',
        'ARGOCD_APP_NAME', 'ARGOCD_APP_NAMESPACE',
        'FLUX_GROUP', 'FLUX_CONTROLLER',
        'TEKTON_PIPELINE_NAME', 'TEKTON_TASK_NAME',
        'CONCOURSE', 'DRONE', 'SPINNAKER_USER',
    }
    
    # Confidence reduction for CI/CD context
    CONFIDENCE_REDUCTION: float = 0.15
    
    def is_ci_cd_context(self, process_data: Dict[str, Any], pid: int) -> bool:
        """Check if process is running in CI/CD context.
        
        CI/CD systems legitimately execute K8s commands like kubectl exec,
        kubectl apply, helm install, etc. These should have reduced confidence.
        
        Args:
            process_data: Process collector data
            pid: Process ID to check
            
        Returns:
            True if process appears to be CI/CD initiated
        """
        processes = process_data.get("processes", []) if isinstance(process_data, dict) else []
        
        # Build process lookup by PID
        proc_map = {p.get("pid"): p for p in processes if isinstance(p, dict)}
        target_proc = proc_map.get(pid, {})
        
        # Check if current process is a CI/CD system
        cmdline = target_proc.get("cmdline", "").lower()
        comm = target_proc.get("comm", "").lower()
        
        for ci_proc in self.CI_CD_PROCESSES:
            if ci_proc in cmdline or ci_proc in comm:
                _get_logger().debug(f"[CICDDetector] CI/CD process detected: {ci_proc} in PID {pid}")
                return True
        
        # Check parent process (PPID)
        ppid = target_proc.get("ppid", 0)
        if ppid and ppid in proc_map:
            parent = proc_map[ppid]
            parent_cmdline = parent.get("cmdline", "").lower()
            parent_comm = parent.get("comm", "").lower()
            
            for trusted_proc in self.TRUSTED_PARENT_PROCESSES:
                if trusted_proc in parent_cmdline or trusted_proc in parent_comm:
                    _get_logger().debug(f"[CICDDetector] Trusted parent detected: {trusted_proc}")
                    return True
        
        # Check environment variables for CI/CD indicators
        env_vars = target_proc.get("environ", {})
        if isinstance(env_vars, dict):
            for var in self.CI_CD_ENV_VARS:
                if var in env_vars:
                    _get_logger().debug(f"[CICDDetector] CI/CD env var detected: {var}")
                    return True
        
        return False
    
    def is_ci_cd_namespace(self, cmdline: str) -> bool:
        """Check if kubectl command targets a CI/CD namespace.
        
        Args:
            cmdline: Process command line
            
        Returns:
            True if command targets a CI/CD namespace
        """
        if not cmdline:
            return False
        
        import re
        ns_match = re.search(r'(?:-n|--namespace)\s+(\S+)', cmdline)
        if ns_match:
            ns = ns_match.group(1).lower()
            return ns in self.CI_CD_NAMESPACES
        
        return False
    
    def adjust_confidence(self, base_confidence: float, is_ci_cd: bool) -> float:
        """Adjust detection confidence based on CI/CD context.
        
        Args:
            base_confidence: Base confidence from pattern match
            is_ci_cd: Whether process is in CI/CD context
            
        Returns:
            Adjusted confidence value (0.0-0.99)
        """
        if is_ci_cd:
            adjusted = base_confidence - self.CONFIDENCE_REDUCTION
            _get_logger().debug(f"[CICDDetector] CI/CD context, reducing confidence from {base_confidence:.2f} to {adjusted:.2f}")
            return max(0.3, min(adjusted, 0.99))
        return base_confidence
