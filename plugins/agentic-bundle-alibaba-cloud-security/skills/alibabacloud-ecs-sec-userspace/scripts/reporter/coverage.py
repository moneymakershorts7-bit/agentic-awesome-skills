"""Detection Coverage Calculator - Compute security coverage metrics for scan reports.

This module calculates which security categories and ATT&CK tactics are covered
or skipped in different scan modes (quick vs full), providing transparency into
detection capabilities.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from ..analyzer.analyzer_registry import ANALYZER_REGISTRY


# Security category mapping for analyzers
# Maps analyzer names to security categories
SECURITY_CATEGORIES = {
    # Process and System
    "process_analyzer": "进程检测",
    "process_tree_analyzer": "进程检测",
    "network_analyzer": "网络检测",
    "network_behavior_analyzer": "网络检测",
    "auth_analyzer": "认证安全",
    "credential_analyzer": "凭证安全",
    "data_encryption_analyzer": "凭证安全",
    "identity_abuse_analyzer": "凭证安全",
    "persistence_analyzer": "持久化检测",
    "pam_backdoor_analyzer": "后门检测",
    "library_injection_analyzer": "注入检测",
    "systemd_timer_analyzer": "持久化检测",

    # Rootkit and Kernel
    "rootkit_analyzer": "Rootkit检测",
    "kernel_taint_analyzer": "内核安全",
    "kernel_module_monitor": "内核安全",
    "io_uring_rootkit_analyzer": "Rootkit检测",
    "kernel_integrity_checker": "内核安全",
    "proc_integrity_validator": "内核安全",

    # Cloud Security
    "cloud_storage_execution_analyzer": "云安全",
    "cloud_storage_discovery_analyzer": "云安全",
    "cloud_exfiltration_analyzer": "云安全",
    "cloud_metadata_analyzer": "云安全",
    "cloud_storage_analyzer": "云安全",
    "cloud_iam_analyzer": "云安全",
    "cloud_logging_evasion_analyzer": "云安全",

    # Threat Intelligence
    "threat_intel_analyzer": "威胁情报",
    "dga_detection_analyzer": "威胁情报",
    "malware_analyzer": "恶意软件",
    "mining_analyzer": "恶意软件",
    "ransomware_analyzer": "恶意软件",
    "rat_analyzer": "恶意软件",
    "file_analyzer": "文件系统",
    "file_behavior_analyzer": "文件系统",
    "log_analyzer": "日志分析",
    "history_analyzer": "日志分析",
    "webshell_analyzer": "Web安全",
    "fileless_malware_analyzer": "恶意软件",
    "web_exploit_analyzer": "Web安全",
    "dns_tunnel_analyzer": "网络检测",
    "remote_service_analyzer": "网络检测",
    "pubsub_abuse_analyzer": "命令执行",
    "mta_analyzer": "网络检测",

    # Container and Kubernetes
    "container_analyzer": "容器安全",
    "container_image_supply_chain_analyzer": "供应链安全",
    "container_syscall_monitor": "容器安全",
    "container_registry_analyzer": "容器安全",
    "kubernetes_analyzer": "Kubernetes",
    "k8s_lateral_movement_analyzer": "横向移动",
    "k8s_escape_lateral_movement_analyzer": "横向移动",
    "k8s_workload_identity_analyzer": "Kubernetes",
    "k8s_runtime_behavior_analyzer": "Kubernetes",
    "cilium_runtime_security_analyzer": "容器安全",
    "cilium_evasion_detector": "容器安全",
    "service_mesh_analyzer": "容器安全",
    "serverless_analyzer": "云安全",

    # Memory Forensics
    "memory_forensics_analyzer": "内存取证",
    "memory_inspection_analyzer": "内存取证",
    "memory_integrity_verifier": "内存取证",
    "memory_poisoning_detector": "内存取证",
    "memory_version_control_analyzer": "内存取证",
    "memory_poison_analyzer": "内存取证",

    # Lateral Movement
    "lateral_movement_analyzer": "横向移动",
    "lateral_movement_correlator": "横向移动",

    # Reconnaissance
    "reconnaissance_analyzer": "侦察检测",

    # Vulnerability
    "vulnerability_db_analyzer": "漏洞库",

    # Fileless and Advanced
    "memfd_fileless_analyzer": "Rootkit检测",
    "runtime_code_injection_analyzer": "注入检测",
    "defense_evasion_analyzer": "防御规避",

    # Security Tool Integrity
    "security_tool_integrity_analyzer": "安全工具",
    "openclaw_skill_integrity": "安全工具",
    "side_channel_analyzer": "侧信道",
    "t1562_aggregator": "防御规避",
}


# ATT&CK tactic coverage mapping
# Maps analyzer names to ATT&CK tactics
ATTACK_TACTIC_MAP = {
    # Process and Execution
    "process_analyzer": "Execution",
    "process_tree_analyzer": "Execution",
    "network_analyzer": "Lateral Movement",
    "network_behavior_analyzer": "Lateral Movement",
    "auth_analyzer": "Credential Access",
    "credential_analyzer": "Lateral Movement",
    "data_encryption_analyzer": "Credential Access",
    "identity_abuse_analyzer": "Credential Access",
    "persistence_analyzer": "Persistence",
    "pam_backdoor_analyzer": "Persistence",
    "systemd_timer_analyzer": "Persistence",
    "library_injection_analyzer": "Defense Evasion",

    # Rootkit and Kernel
    "rootkit_analyzer": "Defense Evasion",
    "kernel_taint_analyzer": "Persistence",
    "kernel_module_monitor": "Persistence",
    "kernel_integrity_checker": "Defense Evasion",
    "io_uring_rootkit_analyzer": "Defense Evasion",
    "proc_integrity_validator": "Defense Evasion",
    "defense_evasion_analyzer": "Defense Evasion",

    # File and Memory
    "file_analyzer": "Execution",
    "file_behavior_analyzer": "Execution",
    "log_analyzer": "Defense Evasion",
    "history_analyzer": "Defense Evasion",
    "memory_forensics_analyzer": "Defense Evasion",
    "memory_inspection_analyzer": "Impact",
    "memory_integrity_verifier": "Defense Evasion",
    "memory_poisoning_detector": "Data Manipulation",
    "memory_version_control_analyzer": "Defense Evasion",
    "memory_poison_analyzer": "Data Manipulation",
    "fileless_malware_analyzer": "Defense Evasion",
    "memfd_fileless_analyzer": "Defense Evasion",
    "runtime_code_injection_analyzer": "Defense Evasion",

    # Threat Intelligence and Malware
    "threat_intel_analyzer": "Command and Control",
    "dga_detection_analyzer": "Command and Control",
    "malware_analyzer": "Impact",
    "mining_analyzer": "Impact",
    "ransomware_analyzer": "Impact",
    "rat_analyzer": "Command and Control",
    "webshell_analyzer": "Initial Access",
    "web_exploit_analyzer": "Initial Access",
    "dns_tunnel_analyzer": "Command and Control",
    "remote_service_analyzer": "Lateral Movement",
    "pubsub_abuse_analyzer": "Execution",
    "mta_analyzer": "Command and Control",

    # Cloud Security
    "cloud_storage_execution_analyzer": "Execution",
    "cloud_storage_discovery_analyzer": "Discovery",
    "cloud_exfiltration_analyzer": "Exfiltration",
    "cloud_metadata_analyzer": "Discovery",
    "cloud_storage_analyzer": "Exfiltration",
    "cloud_iam_analyzer": "Privilege Escalation",
    "cloud_logging_evasion_analyzer": "Defense Evasion",

    # Container and Kubernetes
    "container_analyzer": "Lateral Movement",
    "container_image_supply_chain_analyzer": "Initial Access",
    "container_syscall_monitor": "Defense Evasion",
    "container_registry_analyzer": "Execution",
    "kubernetes_analyzer": "Privilege Escalation",
    "k8s_lateral_movement_analyzer": "Lateral Movement",
    "k8s_workload_identity_analyzer": "Credential Access",
    "k8s_runtime_behavior_analyzer": "Lateral Movement",
    "cilium_runtime_security_analyzer": "Defense Evasion",
    "cilium_evasion_detector": "Execution",
    "k8s_escape_lateral_movement_analyzer": "Lateral Movement",
    "service_mesh_analyzer": "Command and Control",
    "serverless_analyzer": "Execution",

    # Lateral Movement
    "lateral_movement_analyzer": "Lateral Movement",
    "lateral_movement_correlator": "Lateral Movement",

    # Reconnaissance
    "reconnaissance_analyzer": "Reconnaissance",

    # Vulnerability
    "vulnerability_db_analyzer": "Discovery",

    # Security Tool Integrity
    "security_tool_integrity_analyzer": "Defense Evasion",
    "openclaw_skill_integrity": "Supply Chain Compromise",
    "side_channel_analyzer": "Discovery",

    # T1562 Aggregator
    "t1562_aggregator": "Defense Evasion",
}


@dataclass
class CoverageMetrics:
    """Detection coverage metrics for a scan."""
    total_registered_analyzers: int = 0
    loaded_analyzers: int = 0
    executed_analyzers: int = 0
    skipped_analyzers: int = 0
    failed_analyzers: int = 0
    
    # Overall coverage percentage (computed)
    overall_coverage_pct: float = 0.0

    # Intentional skip tracking (dev environment, etc.)
    skipped_intentional: int = 0
    intentional_skip_reasons: Dict[str, int] = field(default_factory=dict)

    # Category coverage
    category_coverage: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # ATT&CK tactic coverage
    attack_tactic_coverage: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Quick mode specific
    skipped_categories: List[str] = field(default_factory=list)
    partially_covered_categories: List[str] = field(default_factory=list)

    # Effectiveness tracking
    effectiveness_rating: str = ""
    effectiveness_recommendation: str = ""
    coverage_gap_warnings: List[Dict[str, Any]] = field(default_factory=list)

    # Skipped analyzers with reasons (for intentional skip detection in warnings)
    skipped_analyzers_detail: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "total_registered_analyzers": self.total_registered_analyzers,
            "loaded_analyzers": self.loaded_analyzers,
            "executed_analyzers": self.executed_analyzers,
            "skipped_analyzers": self.skipped_analyzers,
            "failed_analyzers": self.failed_analyzers,
            "overall_coverage_pct": self.overall_coverage_pct,
            "skipped_intentional": self.skipped_intentional,
            "intentional_skip_reasons": self.intentional_skip_reasons,
            "category_coverage": self.category_coverage,
            "attack_tactic_coverage": self.attack_tactic_coverage,
            "skipped_categories": self.skipped_categories,
            "partially_covered_categories": self.partially_covered_categories,
        }

        result["skipped_analyzers_detail"] = self.skipped_analyzers_detail
        result["effectiveness"] = {
            "rating": self.effectiveness_rating,
            "recommendation": self.effectiveness_recommendation,
        }
        result["coverage_gap_warnings"] = self.coverage_gap_warnings

        return result


class DetectionCoverageCalculator:
    """Calculate detection coverage for scan reports."""

    def compute_coverage(
        self,
        executed_analyzers: List[str],
        skipped_analyzers: List[Dict[str, str]],
        failed_analyzers: List[str],
        total_registered: Optional[int] = None,
    ) -> CoverageMetrics:
        """Compute detection coverage metrics.

        Args:
            executed_analyzers: List of successfully executed analyzer names
            skipped_analyzers: List of dicts with 'name' and 'reason' for skipped analyzers
            failed_analyzers: List of failed analyzer names
            total_registered: Total registered analyzers (optional, computed if None)

        Returns:
            CoverageMetrics object with coverage data
        """

        # Get all registered analyzers count
        if total_registered is None:
            total_registered = len(ANALYZER_REGISTRY)

        # Build sets for computation
        executed_set = set(executed_analyzers)
        skipped_set = {s["name"] for s in skipped_analyzers}
        failed_set = set(failed_analyzers)

        # Count intentional skips (dev environment, etc.)
        skipped_intentional = 0
        intentional_skip_reasons = {}
        dev_skip_patterns = [
            "dev environment", "development environment", "in development",
            "dev_skip", "dev_mode", "skipping in development",
        ]
        for skip_info in skipped_analyzers:
            reason = skip_info.get("reason", "").lower()
            if any(pattern in reason for pattern in dev_skip_patterns):
                skipped_intentional += 1
                reason_key = skip_info.get("reason", "unknown")
                intentional_skip_reasons[reason_key] = intentional_skip_reasons.get(reason_key, 0) + 1

        # Compute category coverage
        category_coverage = self._compute_category_coverage(
            executed_set, skipped_set, failed_set
        )

        # Compute ATT&CK tactic coverage
        attack_tactic_coverage = self._compute_attack_tactic_coverage(
            executed_set, skipped_set, failed_set
        )

        # Identify skipped and partially covered categories
        skipped_categories = [
            cat for cat, cov in category_coverage.items()
            if cov["coverage_pct"] == 0.0
        ]
        partially_covered = [
            cat for cat, cov in category_coverage.items()
            if 0.0 < cov["coverage_pct"] < 100.0
        ]

        # Compute overall coverage percentage
        if total_registered > 0:
            overall_coverage_pct = round((len(executed_set) / total_registered) * 100, 1)
        else:
            overall_coverage_pct = 0.0
        
        # Create metrics object
        metrics = CoverageMetrics(
            total_registered_analyzers=total_registered,
            loaded_analyzers=len(executed_set | skipped_set | failed_set),
            executed_analyzers=len(executed_set),
            skipped_analyzers=len(skipped_set),
            failed_analyzers=len(failed_set),
            overall_coverage_pct=overall_coverage_pct,
            skipped_intentional=skipped_intentional,
            intentional_skip_reasons=intentional_skip_reasons,
            category_coverage=category_coverage,
            attack_tactic_coverage=attack_tactic_coverage,
            skipped_categories=sorted(skipped_categories),
            partially_covered_categories=sorted(partially_covered),
            skipped_analyzers_detail=skipped_analyzers,
        )

        # Compute effectiveness rating and gap warnings
        effectiveness = self.get_effectiveness_rating(metrics)
        metrics.effectiveness_rating = effectiveness["rating"]
        metrics.effectiveness_recommendation = effectiveness["recommendation"]
        metrics.coverage_gap_warnings = self.generate_coverage_gap_warnings(metrics)

        return metrics

    def _compute_category_coverage(
        self,
        executed: set,
        skipped: set,
        failed: set,
    ) -> Dict[str, Dict[str, Any]]:
        """Compute coverage percentage per security category."""
        # Build category -> analyzers mapping
        category_analyzers = {}
        for analyzer_name, category in SECURITY_CATEGORIES.items():
            if analyzer_name not in ANALYZER_REGISTRY:
                continue
            if category not in category_analyzers:
                category_analyzers[category] = {"total": 0, "analyzers": set()}
            category_analyzers[category]["total"] += 1
            category_analyzers[category]["analyzers"].add(analyzer_name)

        # Compute coverage for each category
        coverage = {}
        for category, info in category_analyzers.items():
            total = info["total"]
            analyzers = info["analyzers"]
            executed_count = len(analyzers & executed)
            skipped_count = len(analyzers & skipped)
            failed_count = len(analyzers & failed)

            coverage[category] = {
                "total_analyzers": total,
                "executed": executed_count,
                "skipped": skipped_count,
                "failed": failed_count,
                "coverage_pct": round((executed_count / total) * 100, 1) if total > 0 else 0.0,
                "analyzers": sorted(list(analyzers)),
            }

        return coverage

    def _compute_attack_tactic_coverage(
        self,
        executed: set,
        skipped: set,
        failed: set,
    ) -> Dict[str, Dict[str, Any]]:
        """Compute coverage percentage per ATT&CK tactic."""
        # Build tactic -> analyzers mapping
        tactic_analyzers = {}
        for analyzer_name, tactic in ATTACK_TACTIC_MAP.items():
            if analyzer_name not in ANALYZER_REGISTRY:
                continue
            if tactic not in tactic_analyzers:
                tactic_analyzers[tactic] = {"total": 0, "analyzers": set()}
            tactic_analyzers[tactic]["total"] += 1
            tactic_analyzers[tactic]["analyzers"].add(analyzer_name)

        # Compute coverage for each tactic
        coverage = {}
        for tactic, info in tactic_analyzers.items():
            total = info["total"]
            analyzers = info["analyzers"]
            executed_count = len(analyzers & executed)
            skipped_count = len(analyzers & skipped)
            failed_count = len(analyzers & failed)

            coverage[tactic] = {
                "total_analyzers": total,
                "executed": executed_count,
                "skipped": skipped_count,
                "failed": failed_count,
                "coverage_pct": round((executed_count / total) * 100, 1) if total > 0 else 0.0,
                "analyzers": sorted(list(analyzers)),
            }

        return coverage

    def generate_recommendation(self, coverage: CoverageMetrics) -> str:
        """Generate recommendation text based on coverage."""
        if coverage.skipped_categories:
            categories_str = "、".join(coverage.skipped_categories[:5])
            if len(coverage.skipped_categories) > 5:
                categories_str += f" 等{len(coverage.skipped_categories)}个类别"

            return (
                f"**检测覆盖度提示**: 当前扫描跳过了 {len(coverage.skipped_categories)} 个安全类别 "
                f"({categories_str})。建议定期进行全面检测。"
            )

        return ""

    def get_effectiveness_rating(self, coverage: CoverageMetrics) -> Dict[str, str]:
        """Get effectiveness rating based on coverage score."""
        coverage_score = coverage.overall_coverage_pct
        is_dev_env = coverage.skipped_intentional > 0

        if coverage_score >= 80:
            if is_dev_env:
                return {
                    "rating": "HIGH",
                    "recommendation": "开发环境检测覆盖优秀，生产环境建议定期全面检测",
                }
            return {
                "rating": "HIGH",
                "recommendation": "检测覆盖优秀，适合日常巡检",
            }
        elif coverage_score >= 60:
            if is_dev_env:
                return {
                    "rating": "MEDIUM",
                    "recommendation": "开发环境检测覆盖良好，生产环境建议全面扫描",
                }
            return {
                "rating": "MEDIUM",
                "recommendation": "检测覆盖中等，建议进行全面扫描",
            }
        elif coverage_score >= 40:
            if is_dev_env:
                return {
                    "rating": "MEDIUM",
                    "recommendation": "开发环境检测覆盖可接受，部分分析器已安全跳过",
                }
            return {
                "rating": "LOW",
                "recommendation": "检测覆盖较低，建议进行全面扫描",
            }
        else:
            return {
                "rating": "MINIMAL",
                "recommendation": "检测覆盖不足，建议立即进行全面扫描",
            }

    def generate_coverage_gap_warnings(self, coverage: CoverageMetrics) -> List[Dict[str, Any]]:
        """Generate coverage gap warnings when coverage is below threshold."""
        warnings = []
        is_dev_env = coverage.skipped_intentional > 0

        intentional_skip_names = set()
        dev_skip_patterns = [
            "dev environment", "development environment", "in development",
            "dev_skip", "dev_mode", "skipping in development",
        ]

        for skip_info in coverage.skipped_analyzers_detail:
            reason = skip_info.get("reason", "").lower()
            if any(pattern in reason for pattern in dev_skip_patterns):
                intentional_skip_names.add(skip_info["name"])

        for tactic, info in coverage.attack_tactic_coverage.items():
            coverage_pct = info.get("coverage_pct", 0)
            tactic_analyzers = set(info.get("analyzers", []))

            if coverage_pct == 0:
                intentionally_skipped = tactic_analyzers & intentional_skip_names
                all_intentional = (
                    is_dev_env and
                    len(intentionally_skipped) > 0 and
                    len(intentionally_skipped) == len(tactic_analyzers)
                )

                warnings.append({
                    "type": "tactic_missing",
                    "tactic": tactic,
                    "severity": "INFO" if all_intentional else "HIGH",
                    "message": f"ATT&CK 战术 '{tactic}' 完全未覆盖 (0%)",
                    "analyzers_skipped": info.get("analyzers", []),
                    "intentional_skip": all_intentional,
                    "skip_reason": "开发环境安全跳过" if all_intentional else None,
                })
            elif coverage_pct < 50:
                warnings.append({
                    "type": "tactic_partial",
                    "tactic": tactic,
                    "severity": "MEDIUM",
                    "message": f"ATT&CK 战术 '{tactic}' 覆盖不足 ({coverage_pct}%)",
                    "analyzers_skipped": info.get("analyzers", []),
                })

        for category, info in coverage.category_coverage.items():
            coverage_pct = info.get("coverage_pct", 0)
            category_analyzers = set(info.get("analyzers", []))

            if coverage_pct == 0:
                intentionally_skipped = category_analyzers & intentional_skip_names
                all_intentional = (
                    is_dev_env and
                    len(intentionally_skipped) > 0 and
                    len(intentionally_skipped) == len(category_analyzers)
                )

                warnings.append({
                    "type": "category_missing",
                    "category": category,
                    "severity": "INFO" if all_intentional else "MEDIUM",
                    "message": f"安全类别 '{category}' 完全未覆盖",
                    "analyzers_skipped": info.get("analyzers", []),
                    "intentional_skip": all_intentional,
                    "skip_reason": "开发环境安全跳过" if all_intentional else None,
                })

        severity_order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2, "LOW": 3}
        warnings.sort(key=lambda w: severity_order.get(w["severity"], 4))

        return warnings


def compute_detection_coverage(
    module_stats: List[Dict[str, Any]],
) -> CoverageMetrics:
    """Convenience function to compute detection coverage from module stats.

    Args:
        module_stats: List of module execution statistics from main.py

    Returns:
        CoverageMetrics object
    """
    calculator = DetectionCoverageCalculator()

    executed = []
    skipped = []
    failed = []

    for module in module_stats:
        name = module.get("name", "")
        status = module.get("status", "unknown")

        if status == "success":
            executed.append(name)
        elif status == "skipped":
            skipped.append({
                "name": name,
                "reason": module.get("skip_reason", "unknown"),
            })
        elif status == "failed":
            failed.append(name)

    return calculator.compute_coverage(
        executed_analyzers=executed,
        skipped_analyzers=skipped,
        failed_analyzers=failed,
    )
