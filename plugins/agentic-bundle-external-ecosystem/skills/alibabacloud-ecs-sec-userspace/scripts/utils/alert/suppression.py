"""Alert Suppression Engine

Suppresses false positive alerts based on configurable rules.
"""
import os
import fnmatch
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

import logging
logger = logging.getLogger("sec-userspace")


@dataclass
class SuppressionRule:
    """Suppression Rule
    
    Attributes:
        id: Rule unique ID
        analyzer: Match specific analyzer name
        rule: Match specific rule name
        path_pattern: Glob pattern for source path matching
        target_pattern: Glob pattern for target matching
        tags: Match any of these tags
        enabled: Whether rule is enabled
        reason: Reason for suppression
        priority: Rule priority (lower number = higher priority)
    """
    
    id: str = ""
    analyzer: str = ""
    rule: str = ""
    path_pattern: str = ""
    target_pattern: str = ""
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    reason: str = ""
    priority: int = 100
    
    def __post_init__(self):
        """Generate ID if not provided"""
        if not self.id:
            import hashlib
            content = f"{self.analyzer}:{self.rule}:{self.path_pattern}:{self.target_pattern}"
            self.id = hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:8]
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "analyzer": self.analyzer,
            "rule": self.rule,
            "path_pattern": self.path_pattern,
            "target_pattern": self.target_pattern,
            "tags": self.tags,
            "enabled": self.enabled,
            "reason": self.reason,
            "priority": self.priority
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "SuppressionRule":
        """Create rule from dictionary"""
        return cls(
            id=data.get("id", ""),
            analyzer=data.get("analyzer", ""),
            rule=data.get("rule", ""),
            path_pattern=data.get("path_pattern", ""),
            target_pattern=data.get("target_pattern", ""),
            tags=data.get("tags", []),
            enabled=data.get("enabled", True),
            reason=data.get("reason", ""),
            priority=data.get("priority", 100)
        )


@dataclass
class SuppressionConfig:
    """Suppression Configuration
    
    Attributes:
        version: Config version
        enabled: Whether suppression is enabled globally
        rules: List of suppression rules
        show_suppressed_count: Whether to show suppressed count in reports
        log_suppressed_details: Whether to log suppressed alert details
        max_suppression_rules: Maximum number of suppression rules
    """
    
    version: str = "1.0"
    enabled: bool = True
    rules: List[SuppressionRule] = field(default_factory=list)
    show_suppressed_count: bool = True
    log_suppressed_details: bool = False
    max_suppression_rules: int = 100
    
    @classmethod
    def from_dict(cls, data: dict) -> "SuppressionConfig":
        """Create config from dictionary"""
        rules = []
        for rule_data in data.get("rules", []):
            rules.append(SuppressionRule.from_dict(rule_data))
        
        # Handle nested settings dict
        settings = data.get("settings", {})
        
        return cls(
            version=data.get("version", "1.0"),
            enabled=data.get("enabled", True),
            rules=rules,
            show_suppressed_count=settings.get("show_suppressed_count", data.get("show_suppressed_count", True)),
            log_suppressed_details=settings.get("log_suppressed_details", data.get("log_suppressed_details", False)),
            max_suppression_rules=settings.get("max_suppression_rules", data.get("max_suppression_rules", 100))
        )


class AlertSuppressionEngine:
    """Alert Suppression Engine
    
    Evaluates alerts against suppression rules and determines
    which alerts should be suppressed.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize suppression engine
        
        Args:
            config_path: Path to suppression config file (YAML)
        """
        self.config = SuppressionConfig()
        self.suppressed_count = 0
        self.suppressed_alerts: List[Dict[str, Any]] = []
        
        # Load config if path provided
        if config_path:
            self.load_config(config_path)
    
    def load_config(self, config_path: str) -> bool:
        """Load suppression config from file
        
        Args:
            config_path: Path to YAML config file
            
        Returns:
            bool: True if loaded successfully
        """
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML not installed, please run: pip install pyyaml")
            return False
        
        path = Path(config_path)
        if not path.exists():
            logger.debug(f"Suppression config not found: {config_path}")
            return False
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if data:
                self.config = SuppressionConfig.from_dict(data)
                logger.info(f"Loaded {len(self.config.rules)} suppression rules from {config_path}")
                return True
            
            return False
            
        except (OSError, ValueError, KeyError, TypeError) as e:
            logger.error(f"Failed to load suppression config: {e}")
            return False
        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in suppression config: {e}")
            return False
    
    def should_suppress(self, alert: Any) -> bool:
        """Check if alert should be suppressed
        
        Args:
            alert: Alert object to check
            
        Returns:
            bool: True if alert should be suppressed
        """
        if not self.config.enabled:
            return False
        
        # Check max rules limit
        if len(self.config.rules) > self.config.max_suppression_rules:
            logger.warning(
                f"Too many suppression rules ({len(self.config.rules)} > "
                f"{self.config.max_suppression_rules}), ignoring all"
            )
            return False
        
        # Sort rules by priority
        sorted_rules = sorted(self.config.rules, key=lambda r: r.priority)
        
        for rule in sorted_rules:
            if not rule.enabled:
                continue
            
            if self._matches_rule(alert, rule):
                self.suppressed_count += 1
                self.suppressed_alerts.append({
                    "alert_id": alert.id,
                    "rule_id": rule.id,
                    "rule": rule.to_dict(),
                    "reason": rule.reason
                })
                
                if self.config.log_suppressed_details:
                    logger.debug(
                        f"Suppressed alert {alert.id} (rule: {rule.id}, "
                        f"reason: {rule.reason})"
                    )
                
                return True
        
        return False
    
    def _matches_rule(self, alert: Any, rule: SuppressionRule) -> bool:
        """Check if alert matches suppression rule
        
        Uses AND logic - all specified conditions must match.
        
        Args:
            alert: Alert object
            rule: Suppression rule
            
        Returns:
            bool: True if alert matches rule
        """
        matches = []
        
        # Analyzer match
        if rule.analyzer:
            matches.append(alert.analyzer == rule.analyzer)
        
        # Rule match
        if rule.rule:
            matches.append(alert.rule == rule.rule)
        
        # Path pattern match (supports wildcards)
        if rule.path_pattern:
            matches.append(fnmatch.fnmatch(alert.target, rule.path_pattern))
        
        # Target pattern match (supports wildcards)
        if rule.target_pattern:
            matches.append(fnmatch.fnmatch(alert.target, rule.target_pattern))
        
        # Tags match (any tag in list)
        if rule.tags:
            matches.append(any(tag in alert.tags for tag in rule.tags))
        
        # All specified conditions must match (AND logic)
        return all(matches) if matches else False
    
    def get_suppression_report(self) -> dict:
        """Get suppression statistics report
        
        Returns:
            dict: Suppression report
        """
        return {
            "total_suppressed": self.suppressed_count,
            "suppressed_alerts": self.suppressed_alerts[:10],  # Max 10 details
            "rules_count": len(self.config.rules),
            "enabled_rules": sum(1 for r in self.config.rules if r.enabled)
        }
    
    def reset_stats(self):
        """Reset suppression statistics"""
        self.suppressed_count = 0
        self.suppressed_alerts = []


def get_default_config_paths() -> List[str]:
    """Get default suppression config file paths
    
    Returns:
        List[str]: List of config paths to check
    """
    paths = []
    
    # User-level config
    home = Path.home()
    paths.append(str(home / ".sec-userspace" / "alert-suppression.yaml"))
    
    # Workspace-level config
    workspace = Path("/data/sec-userspace/workspace")
    if workspace.exists():
        paths.append(str(workspace / "alert-suppression.yaml"))
    
    # Current directory config
    cwd = Path.cwd()
    paths.append(str(cwd / "alert-suppression.yaml"))
    
    return paths


def load_suppression_engine(config_path: Optional[str] = None) -> AlertSuppressionEngine:
    """Load suppression engine with config
    
    Args:
        config_path: Explicit config path (optional)
        
    Returns:
        AlertSuppressionEngine: Configured engine
    """
    engine = AlertSuppressionEngine()
    
    if config_path:
        # Use explicit path
        engine.load_config(config_path)
    else:
        # Try default paths in order
        for path in get_default_config_paths():
            if os.path.exists(path):
                engine.load_config(path)
                break
    
    return engine
