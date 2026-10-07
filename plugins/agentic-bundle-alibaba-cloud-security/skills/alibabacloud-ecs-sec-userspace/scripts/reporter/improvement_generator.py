"""Improvement Plan Generator: Generates improvement suggestions based on scan results"""
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from .evidence import Evidence
from .severity import Severity


@dataclass
class ImprovementSuggestion:
    """Represents a single improvement suggestion"""
    id: str
    category: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    evidence_ref: Optional[str] = None
    impact: Optional[str] = None
    fix_priority: str = "medium"  # critical, high, medium, low
    policy: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence_ref": self.evidence_ref,
            "impact": self.impact,
            "fix_priority": self.fix_priority,
            "policy": self.policy,
        }


@dataclass
class ImprovementPlan:
    """Represents the complete improvement plan"""
    version: str = "1.0"
    generated_at: str = ""
    scan_mode: str = "adaptive"
    total_suggestions: int = 0
    suggestions: List[ImprovementSuggestion] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "scan_summary": self.summary,
            "suggestions_count": self.total_suggestions,
            "suggestions": [s.to_dict() for s in self.suggestions],
        }


# Category-based policy configuration
IMPROVEMENT_POLICY_CONFIG = {
    "authentication": {
        "default_anonymize": True,
        "default_reportable": True,
        "sensitive_fields": ["password_hash", "private_key", "token", "credential"],
    },
    "network": {
        "default_anonymize": True,
        "default_reportable": True,
        "sensitive_fields": ["ip_address", "domain", "port", "destination"],
    },
    "system_hardening": {
        "default_anonymize": False,
        "default_reportable": True,
        "sensitive_fields": [],
    },
    "malware": {
        "default_anonymize": True,
        "default_reportable": True,
        "sensitive_fields": ["file_path", "file_hash", "process_cmdline"],
    },
    "ai_security": {
        "default_anonymize": True,
        "default_reportable": True,
        "sensitive_fields": ["prompt_content", "api_key", "model_name"],
    },
    "persistence": {
        "default_anonymize": True,
        "default_reportable": True,
        "sensitive_fields": ["file_path", "command", "script_content"],
    },
    "credential": {
        "default_anonymize": True,
        "default_reportable": True,
        "sensitive_fields": ["password", "secret", "token", "private_key"],
    },
    "rootkit": {
        "default_anonymize": True,
        "default_reportable": True,
        "sensitive_fields": ["file_path", "module_name", "hidden_process"],
    },
}

# Mapping from analyzer module to category
MODULE_TO_CATEGORY = {
    "auth_analyzer": "authentication",
    "credential_analyzer": "credential",
    "network_analyzer": "network",
    "threat_intel_analyzer": "network",
    "dns_tunnel_analyzer": "network",
    "file_analyzer": "system_hardening",
    "persistence_analyzer": "persistence",
    "webshell_analyzer": "malware",
    "malware_analyzer": "malware",
    "ransomware_analyzer": "malware",
    "rat_analyzer": "malware",
    "mining_analyzer": "malware",
    "rootkit_analyzer": "rootkit",
    # log_analyzer disabled (confidence < 0.95)
}

# Suggestion templates based on evidence patterns
SUGGESTION_TEMPLATES = {
    "weak_credential": {
        "title": "发现弱密码配置",
        "description": "系统存在使用弱密码或过时哈希算法的凭据",
        "recommendation": "升级到 SHA-512 或更强的哈希算法，并强制使用复杂密码策略",
        "impact": "密码可能被彩虹表或暴力破解攻击",
        "fix_priority": "high",
    },
    "suspicious_connection": {
        "title": "发现可疑外连",
        "description": "进程连接到未知或可疑的外部地址",
        "recommendation": "检查进程配置，确认是否为合法连接，必要时阻断网络连接",
        "impact": "可能存在 C2 通信或数据外泄风险",
        "fix_priority": "high",
    },
    "kernel_tuning": {
        "title": "内核参数可优化",
        "description": "部分安全相关的内核参数未启用或非最优配置",
        "recommendation": "根据安全基线调整内核参数配置",
        "impact": "降低对特定攻击的防御能力",
        "fix_priority": "medium",
    },
    "suspicious_file": {
        "title": "发现可疑文件",
        "description": "检测到与已知恶意软件特征匹配的文件",
        "recommendation": "隔离并分析文件样本，确认后立即删除并溯源",
        "impact": "系统可能已被植入恶意软件",
        "fix_priority": "critical",
    },
    "privilege_escalation": {
        "title": "提权风险检测",
        "description": "发现可能被利用进行提权的配置或漏洞",
        "recommendation": "修复 SUID/SGID 文件权限，更新存在漏洞的软件",
        "impact": "攻击者可能获取更高权限",
        "fix_priority": "high",
    },
    "persistence_mechanism": {
        "title": "发现持久化机制",
        "description": "检测到可疑的自启动项或定时任务",
        "recommendation": "审查并移除不必要的持久化配置",
        "impact": "恶意程序可能在系统重启后继续运行",
        "fix_priority": "high",
    },
    "log_anomaly": {
        "title": "日志异常检测",
        "description": "系统日志中存在异常或删除痕迹",
        "recommendation": "检查日志配置，确保关键事件被完整记录",
        "impact": "影响安全事件的追溯和取证",
        "fix_priority": "medium",
    },
}


class ImprovementGenerator:
    """Generates improvement suggestions based on scan results"""
    
    def __init__(self):
        self.policy_config = IMPROVEMENT_POLICY_CONFIG
    
    def generate(self, evidences: List[Evidence], scan_mode: str, 
                 system_info: Dict[str, Any]) -> ImprovementPlan:
        """
        Generate improvement plan from scan results
        
        Args:
            evidences: List of detected evidence items
            system_info: System information
            
        Returns:
            ImprovementPlan object
        """
        suggestions: List[ImprovementSuggestion] = []
        
        # Group evidences by module and type
        evidence_groups: Dict[str, List[Evidence]] = {}
        for e in evidences:
            key = f"{e.module}:{e.title}"
            if key not in evidence_groups:
                evidence_groups[key] = []
            evidence_groups[key].append(e)
        
        # Generate suggestions for each group
        for key, group_evidences in evidence_groups.items():
            module = group_evidences[0].module
            category = MODULE_TO_CATEGORY.get(module, "system_hardening")
            
            # Get representative evidence (highest weighted_score)
            rep_evidence = max(group_evidences, key=lambda e: e.weighted_score if not (math.isnan(e.weighted_score) or math.isinf(e.weighted_score)) else 0.0)
            
            # Generate suggestion based on evidence pattern
            suggestion = self._generate_suggestion(
                module=module,
                category=category,
                evidence=rep_evidence,
                all_evidences=group_evidences
            )
            
            if suggestion:
                suggestions.append(suggestion)
        
        # Sort by severity and fix priority
        suggestions.sort(key=lambda s: (-s.severity.score, 
                                        -{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s.fix_priority, 0)))
        
        # Create summary
        summary = {
            "total_suggestions": len(suggestions),
            "critical": sum(1 for s in suggestions if s.severity.name == "CRITICAL"),
            "high": sum(1 for s in suggestions if s.severity.name == "HIGH"),
            "medium": sum(1 for s in suggestions if s.severity.name == "MEDIUM"),
            "low": sum(1 for s in suggestions if s.severity.name == "LOW"),
        }
        
        return ImprovementPlan(
            version="1.0",
            generated_at=datetime.now(timezone.utc).isoformat(),
            scan_mode=scan_mode,
            total_suggestions=len(suggestions),
            suggestions=suggestions,
            summary=summary,
        )
    
    def _generate_suggestion(self, module: str, category: str, 
                            evidence: Evidence, all_evidences: List[Evidence]) -> Optional[ImprovementSuggestion]:
        """Generate a single improvement suggestion from evidence"""
        
        # Determine fix priority based on severity
        fix_priority_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }
        fix_priority = fix_priority_map.get(evidence.severity.name, "medium")
        
        # Get policy for this category
        policy = self._get_policy_for_category(category)
        
        # Try to match evidence to known patterns
        template = self._match_evidence_pattern(evidence, module)
        
        if template:
            # Use template-based suggestion
            return ImprovementSuggestion(
                id=f"IMP-{uuid.uuid4().hex[:8].upper()}",
                category=category,
                severity=evidence.severity,
                title=template["title"],
                description=template["description"],
                recommendation=template["recommendation"],
                evidence_ref=evidence.id,
                impact=template.get("impact"),
                fix_priority=fix_priority,
                policy=policy,
            )
        else:
            # Generic suggestion based on evidence
            return ImprovementSuggestion(
                id=f"IMP-{uuid.uuid4().hex[:8].upper()}",
                category=category,
                severity=evidence.severity,
                title=evidence.title,
                description=evidence.description,
                recommendation=evidence.remediation or "Review and address the identified issue",
                evidence_ref=evidence.id,
                impact=None,
                fix_priority=fix_priority,
                policy=policy,
            )
    
    def _get_policy_for_category(self, category: str) -> Dict[str, Any]:
        """Get policy configuration for a category"""
        config = self.policy_config.get(category, {
            "default_anonymize": True,
            "default_reportable": True,
            "sensitive_fields": [],
        })
        
        return {
            "anonymize": config["default_anonymize"],
            "reportable": config["default_reportable"],
            "data_fields": config["sensitive_fields"],
        }
    
    def _match_evidence_pattern(self, evidence: Evidence, module: str) -> Optional[Dict[str, str]]:
        """Match evidence to known suggestion templates"""
        desc_lower = evidence.description.lower()
        title_lower = evidence.title.lower()
        
        # Check for weak credentials
        if any(kw in desc_lower or kw in title_lower for kw in 
               ["weak password", "md5 hash", "weak credential", "弱密码", "md5"]):
            return SUGGESTION_TEMPLATES["weak_credential"]
        
        # Check for suspicious connections
        if any(kw in desc_lower or kw in title_lower for kw in 
               ["suspicious connection", "c2", "reverse shell", "外连", "可疑连接"]):
            return SUGGESTION_TEMPLATES["suspicious_connection"]
        
        # Check for malware
        if any(kw in desc_lower or kw in title_lower for kw in 
               ["malware", "trojan", "virus", "挖矿", "恶意软件", "勒索软件"]):
            return SUGGESTION_TEMPLATES["suspicious_file"]
        
        # Check for privilege escalation
        if any(kw in desc_lower or kw in title_lower for kw in 
               ["privilege escalation", "suid", "sgid", "提权", "权限"]):
            return SUGGESTION_TEMPLATES["privilege_escalation"]
        
        # Check for persistence
        if any(kw in desc_lower or kw in title_lower for kw in 
               ["persistence", "cron", "startup", "持久化", "自启动"]):
            return SUGGESTION_TEMPLATES["persistence_mechanism"]
        
        # Check for log anomalies
        if any(kw in desc_lower or kw in title_lower for kw in 
               ["log anomaly", "log deletion", "日志异常", "日志删除"]):
            return SUGGESTION_TEMPLATES["log_anomaly"]
        
        return None
