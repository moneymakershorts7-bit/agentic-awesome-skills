"""Analyzer Dispatcher: Decides which analyzers to run based on environment profile.

Three-layer scheduling model:
  Layer 1 - Universal: General security detection, always runs (process/network/auth/persistence/rootkit/file/log/credential/threat intel)
  Layer 2 - Environment: Environment-specific detection, runs when role matches (webshell/mining/ransomware/malware)
  Layer 3 - Business: Business-specific detection, runs when business load matches (MCP security/Skill analysis/RAT)

Degradation strategy: Fallback to full scan when profiling fails or role set is empty.
"""
import logging
from typing import Dict, List, Tuple, Type

from .profile import ServerProfile, ServerRole

logger = logging.getLogger("sec-userspace")


# ============================================================================
# Three-layer analyzer classification
# ============================================================================

# Layer 1: Universal security detection (always runs)
UNIVERSAL_ANALYZERS = frozenset([
    "process_analyzer",
    "network_analyzer",
    "cloud_storage_execution_analyzer",  # T1204.005 - Cloud storage execution detection
    "cloud_exfiltration_analyzer",  # T1537 - Cloud data exfiltration detection (AWS S3, GCP Storage, Azure Blob, Alibaba OSS)
    "auth_analyzer",
    "persistence_analyzer",
    "rootkit_analyzer",
    "pam_backdoor_analyzer",  # T1556.003, T1078 - PAM backdoor detection
    "file_analyzer",
    # log_analyzer disabled (confidence < 0.95)
    "threat_intel_analyzer",
    "malware_analyzer",
])

# Layer 2: Environment-specific detection (role -> extra analyzers to activate)
ENVIRONMENT_ANALYZER_MAP: Dict[ServerRole, List[str]] = {
    ServerRole.WEB_SERVER:      ["webshell_analyzer"],
    ServerRole.DATABASE:        ["ransomware_analyzer"],
    ServerRole.CONTAINER_HOST:  ["container_syscall_monitor"],  # Container security
    ServerRole.KUBERNETES:      ["kubernetes_analyzer", "k8s_lateral_movement_analyzer", "cilium_runtime_security_analyzer"],  # K8s security + Cilium runtime security
    ServerRole.CI_CD:           [],
    ServerRole.AI_ML:           ["mining_analyzer"],
    ServerRole.MAIL_SERVER:     [],             # Reserved for mail_analyzer
    ServerRole.DNS_SERVER:      [],             # Reserved for dns_analyzer
    ServerRole.VIRTUALIZATION:  [],
    ServerRole.FILE_SERVER:     ["ransomware_analyzer"],
}

# Layer 3: Business-specific detection (role -> extra analyzers to activate)
BUSINESS_ANALYZER_MAP: Dict[ServerRole, List[str]] = {
}



class AnalyzerDispatcher:
    """Analyzer dispatcher: Decides analyzer execution plan based on profile results."""

    def dispatch(
        self,
        profile: ServerProfile,
        all_analyzers: List[Tuple[str, Type]],
    ) -> Tuple[List[Tuple[str, Type]], ServerProfile]:
        """Decide which analyzers to run based on profile.

        Args:
            profile: Environment profile results
            all_analyzers: Complete analyzer registry [(name, class), ...]

        Returns:
            (filtered_analyzers, updated_profile)
            filtered_analyzers: Filtered analyzer list
            updated_profile: Profile with active/skipped info updated
        """
        # Degradation check: Fallback to full scan when profiling fails
        if not profile.roles and profile.os_family == "":
            logger.warning("[dispatcher] Profiling data insufficient, falling back to full scan")
            profile.active_analyzers = [name for name, _ in all_analyzers]
            return all_analyzers, profile

        # Build active set
        active_set = set(UNIVERSAL_ANALYZERS)

        # Layer 2: Environment-specific
        for role in profile.roles:
            extra = ENVIRONMENT_ANALYZER_MAP.get(role, [])
            active_set.update(extra)

        # Layer 3: Business-specific
        for role in profile.roles:
            extra = BUSINESS_ANALYZER_MAP.get(role, [])
            active_set.update(extra)

        # Special rule: GPU/CUDA -> mining_analyzer
        if profile.has_gpu or profile.has_cuda:
            active_set.add("mining_analyzer")

        # Filter while preserving original order
        filtered = []
        for name, cls in all_analyzers:
            if name in active_set:
                filtered.append((name, cls))
            else:
                profile.skipped_analyzers.append({
                    "name": name,
                    "reason": self._skip_reason(name, profile),
                })

        profile.active_analyzers = [name for name, _ in filtered]

        skipped_names = [s["name"] for s in profile.skipped_analyzers]
        logger.info(
            f"[dispatcher] Dispatch complete: "
            f"active={len(filtered)}/{len(all_analyzers)}, "
            f"skipped={skipped_names if skipped_names else 'none'}"
        )

        return filtered, profile

    @staticmethod
    def _skip_reason(analyzer_name: str, profile: ServerProfile) -> str:
        """Generate skip reason explanation."""
        reasons = {
            "webshell_analyzer": "No web server environment detected",
            "mining_analyzer": "No GPU/CUDA or AI/ML workload detected",
            "ransomware_analyzer": "No database or file server detected",
            "rat_analyzer": "No remote administration tool signatures matched",
            "ebpf_analyzer": "Current environment does not support eBPF detection (not in this release)",
            "ebpf_rootkit_detector": "Current environment does not support eBPF detection (not in this release)",
            "advanced_ebpf_rootkit_analyzer": "eBPF analyzer not included in this release",
            "ebpf_advanced_exploit_detector": "eBPF analyzer not included in this release",
            "kubernetes_analyzer": "No Kubernetes environment detected",
            "k8s_lateral_movement_analyzer": "No Kubernetes environment detected for lateral movement detection",
            "cilium_runtime_security_analyzer": "No Kubernetes/Cilium environment detected for eBPF runtime security check",
        }
        return reasons.get(analyzer_name, f"Current environment roles {[r.value for r in profile.roles]} do not match")
