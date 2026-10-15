"""Detection Coverage Module - Maps analyzers to security categories and computes coverage"""
from typing import Dict, List, Set, Any
from dataclasses import dataclass


# Security category definitions with descriptions and ATT&CK tactics
SECURITY_CATEGORIES = {
    "process_security": {
        "name": "Process Security",
        "name_cn": "进程安全",
        "description": "Process anomaly detection, hidden processes, deleted binaries",
        "description_cn": "进程异常检测、隐藏进程、已删除二进制",
        "attck_tactics": ["Execution", "Privilege Escalation", "Defense Evasion"],
        "analyzers": [
            "process_analyzer",
            "process_tree_analyzer",
            "memfd_fileless_analyzer",
        ],
    },
    "network_security": {
        "name": "Network Security",
        "name_cn": "网络安全",
        "description": "Network connections, C2 communication, DGA domains",
        "description_cn": "网络连接、C2 通信、DGA 域名",
        "attck_tactics": ["Command and Control", "Exfiltration"],
        "analyzers": [
            "network_analyzer",
            "threat_intel_analyzer",
            "dga_detection_analyzer",
            "pubsub_abuse_analyzer",
        ],
    },
    "authentication_security": {
        "name": "Authentication Security",
        "name_cn": "认证安全",
        "description": "SSH keys, brute force, UID 0 accounts, PAM backdoors",
        "description_cn": "SSH 密钥、暴力破解、UID 0 账号、PAM 后门",
        "attck_tactics": ["Credential Access", "Persistence", "Lateral Movement"],
        "analyzers": [
            "auth_analyzer",
            "credential_analyzer",
            "pam_backdoor_analyzer",
        ],
    },
    "persistence_detection": {
        "name": "Persistence Detection",
        "name_cn": "持久化检测",
        "description": "Cronjobs, systemd timers, init scripts, backdoors",
        "description_cn": "Cronjob、systemd 定时器、启动脚本、后门",
        "attck_tactics": ["Persistence"],
        "analyzers": [
            "persistence_analyzer",
            "systemd_timer_analyzer",
        ],
    },
    "rootkit_detection": {
        "name": "Rootkit Detection",
        "name_cn": "Rootkit 检测",
        "description": "io_uring abuse, kernel module tampering",
        "description_cn": "io_uring 滥用、内核模块篹改",
        "attck_tactics": ["Defense Evasion", "Privilege Escalation"],
        "analyzers": [
            "io_uring_rootkit_analyzer",
            "kernel_taint_analyzer",
        ],
    },

    "cloud_security": {
        "name": "Cloud Security",
        "name_cn": "云安全",
        "description": "Cloud storage execution, metadata API access, exfiltration",
        "description_cn": "云存储执行、元数据 API 访问、数据外泄",
        "attck_tactics": ["Discovery", "Exfiltration", "Initial Access"],
        "analyzers": [
            "cloud_storage_execution_analyzer",
            "cloud_metadata_analyzer",
            "cloud_storage_discovery_analyzer",
            "cloud_exfiltration_analyzer",
        ],
    },
    "reconnaissance_detection": {
        "name": "Reconnaissance Detection",
        "name_cn": "侦察检测",
        "description": "Attack reconnaissance, environment fingerprinting",
        "description_cn": "攻击侦察、环境指纹识别",
        "attck_tactics": ["Reconnaissance", "Discovery"],
        "analyzers": [
            "reconnaissance_analyzer",
        ],
    },

    "file_integrity": {
        "name": "File Integrity",
        "name_cn": "文件完整性",
        "description": "SUID binaries, webshells, file tampering",
        "description_cn": "SUID 二进制、Webshell、文件篡改",
        "attck_tactics": ["Privilege Escalation", "Defense Evasion"],
        "analyzers": [
            "file_analyzer",
        ],
    },
    "log_security": {
        "name": "Log Security",
        "name_cn": "日志安全",
        "description": "Log tampering, clearing, timestamp manipulation",
        "description_cn": "日志篡改、清除、时间戳操纵",
        "attck_tactics": ["Defense Evasion"],
        "analyzers": [
            # log_analyzer disabled (confidence < 0.95)
        ],
    },
}


@dataclass
class CategoryCoverage:
    """Coverage status for a security category"""
    category_id: str
    category_name: str
    category_name_cn: str
    description: str
    description_cn: str
    attck_tactics: List[str]
    total_analyzers: int
    executed_analyzers: int
    skipped_analyzers: List[str]
    executed_analyzer_names: List[str]
    coverage_pct: float
    status: str  # "full", "partial", "none"


@dataclass
class DetectionCoverageReport:
    """Complete detection coverage report"""
    scan_mode: str
    total_categories: int
    covered_categories: int
    partial_categories: int
    uncovered_categories: int
    category_details: List[CategoryCoverage]
    overall_coverage_pct: float
    recommendation: str
    recommendation_cn: str


def build_coverage_report(
    scan_mode: str,
    executed_analyzers: Set[str],
    skipped_analyzers: Dict[str, str],  # analyzer_name -> reason
    all_registered_analyzers: Set[str],
) -> DetectionCoverageReport:
    """Build detection coverage report
    
    Args:
        scan_mode: Current scan mode (legacy, always 'adaptive')
        executed_analyzers: Set of analyzer names that were executed
        skipped_analyzers: Dict of analyzer names that were skipped with reasons
        all_registered_analyzers: Set of all registered analyzer names
    
    Returns:
        DetectionCoverageReport with coverage statistics
    """
    category_details = []
    covered = 0
    partial = 0
    uncovered = 0
    
    for cat_id, cat_info in SECURITY_CATEGORIES.items():
        cat_analyzers = set(cat_info["analyzers"])
        
        # Filter to only registered analyzers
        registered_cat_analyzers = cat_analyzers.intersection(all_registered_analyzers)
        
        if not registered_cat_analyzers:
            continue
        
        # Count executed vs skipped
        executed_in_cat = registered_cat_analyzers.intersection(executed_analyzers)
        skipped_in_cat = registered_cat_analyzers.intersection(set(skipped_analyzers.keys()))
        
        total = len(registered_cat_analyzers)
        executed_count = len(executed_in_cat)
        skipped_list = list(skipped_in_cat)
        
        coverage_pct = (executed_count / total * 100) if total > 0 else 0
        
        if coverage_pct >= 100:
            status = "full"
            covered += 1
        elif coverage_pct > 0:
            status = "partial"
            partial += 1
        else:
            status = "none"
            uncovered += 1
        
        category_details.append(CategoryCoverage(
            category_id=cat_id,
            category_name=cat_info["name"],
            category_name_cn=cat_info["name_cn"],
            description=cat_info["description"],
            description_cn=cat_info["description_cn"],
            attck_tactics=cat_info["attck_tactics"],
            total_analyzers=total,
            executed_analyzers=executed_count,
            skipped_analyzers=skipped_list,
            executed_analyzer_names=list(executed_in_cat),
            coverage_pct=coverage_pct,
            status=status,
        ))
    
    total_categories = covered + partial + uncovered
    overall_pct = (covered / total_categories * 100) if total_categories > 0 else 0
    
    # Generate recommendation
    if uncovered > 0:
        recommendation = f"{uncovered} security category/categories not covered. Review scan configuration."
        recommendation_cn = f"有 {uncovered} 个安全类别未被覆盖。请检查扫描配置。"
    else:
        recommendation = "All security categories covered."
        recommendation_cn = "所有安全类别均已覆盖。"
    
    return DetectionCoverageReport(
        scan_mode=scan_mode,
        total_categories=total_categories,
        covered_categories=covered,
        partial_categories=partial,
        uncovered_categories=uncovered,
        category_details=category_details,
        overall_coverage_pct=overall_pct,
        recommendation=recommendation,
        recommendation_cn=recommendation_cn,
    )


def coverage_to_dict(report: DetectionCoverageReport) -> Dict[str, Any]:
    """Convert coverage report to dictionary for JSON output"""
    return {
        "scan_mode": report.scan_mode,
        "total_categories": report.total_categories,
        "covered_categories": report.covered_categories,
        "partial_categories": report.partial_categories,
        "uncovered_categories": report.uncovered_categories,
        "overall_coverage_pct": round(report.overall_coverage_pct, 1),
        "recommendation": report.recommendation,
        "recommendation_cn": report.recommendation_cn,
        "category_details": [
            {
                "category_id": c.category_id,
                "category_name": c.category_name,
                "category_name_cn": c.category_name_cn,
                "description": c.description,
                "description_cn": c.description_cn,
                "attck_tactics": c.attck_tactics,
                "total_analyzers": c.total_analyzers,
                "executed_analyzers": c.executed_analyzers,
                "skipped_analyzers": c.skipped_analyzers,
                "coverage_pct": round(c.coverage_pct, 1),
                "status": c.status,
            }
            for c in report.category_details
        ],
    }


def coverage_to_markdown(report: DetectionCoverageReport) -> str:
    """Convert coverage report to Markdown section"""
    lines = [
        "",
        "## 检测覆盖度分析",
        "",
        "### 覆盖概览",
        "",
        f"- **扫描模式**: {report.scan_mode.upper()}",
        f"- **安全类别总数**: {report.total_categories}",
        f"- **完全覆盖**: {report.covered_categories} 个",
        f"- **部分覆盖**: {report.partial_categories} 个",
        f"- **未覆盖**: {report.uncovered_categories} 个",
        f"- **整体覆盖率**: {report.overall_coverage_pct:.1f}%",
        "",
    ]
    
    # Add detection gap warning if uncovered categories exist
    uncovered_cats = [c for c in report.category_details if c.status == "none"]
    partial_cats = [c for c in report.category_details if c.status == "partial"]
    
    if uncovered_cats or partial_cats:
        lines.extend([
            "### ⚠️ 检测覆盖度警告",
            "",
            "以下安全类别未被完全覆盖:",
            "",
        ])
        
        # Show uncovered categories first
        for cat in uncovered_cats[:3]:
            lines.append(f"- **❌ {cat.category_name_cn}**: 完全未覆盖，跳过了 {len(cat.skipped_analyzers)} 个检测器")
        
        # Show partially covered categories
        for cat in partial_cats[:3]:
            lines.append(f"- **⚠️ {cat.category_name_cn}**: 部分覆盖，{cat.coverage_pct:.0f}% 的检测器被跳过")
    
    # Add general recommendation
    lines.append(f"> **建议**: {report.recommendation_cn}")
    lines.append("")
    
    lines.extend([
        "### 类别详情",
        "",
        "| 安全类别 | 状态 | 覆盖率 | 已执行/总数 |",
        "|----------|------|--------|-------------|",
    ])
    
    # Sort by status (none -> partial -> full) for better visibility
    status_order = {"none": 0, "partial": 1, "full": 2}
    sorted_details = sorted(report.category_details, key=lambda c: status_order.get(c.status, 3))
    
    for cat in sorted_details:
        status_icon = {"full": "✅", "partial": "⚠️", "none": "❌"}.get(cat.status, "?")
        lines.append(
            f"| {status_icon} {cat.category_name_cn} | {cat.status.upper()} | {cat.coverage_pct:.0f}% | {cat.executed_analyzers}/{cat.total_analyzers} |"
        )
    
    # Add uncovered categories detail
    uncovered_cats = [c for c in report.category_details if c.status == "none"]
    if uncovered_cats:
        lines.extend([
            "",
            "### 未覆盖类别详情",
            "",
            "以下安全类别在当前扫描模式下未被检测:",
            "",
        ])
        
        for cat in uncovered_cats:
            lines.extend([
                f"#### ❌ {cat.category_name_cn} ({cat.category_name})",
                "",
                f"- **描述**: {cat.description_cn}",
                f"- **ATT&CK 战术**: {', '.join(cat.attck_tactics)}",
                f"- **跳过的 Analyzer**: {', '.join(cat.skipped_analyzers)}",
                "",
            ])
    
    return "\n".join(lines)
