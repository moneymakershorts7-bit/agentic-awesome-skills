#!/usr/bin/env python3
"""Policy Manager - Security detection policy management"""

import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class PolicyConfig:
    """Security detection policy configuration"""
    # Basic settings
    name: str = "default"
    version: str = "1.0"
    description: str = "Default security detection policy"
    
    # Detection settings
    enabled_analyzers: List[str] = field(default_factory=list)
    disabled_analyzers: List[str] = field(default_factory=list)
    
    # Severity thresholds
    min_severity_to_report: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    auto_respond_threshold: str = "HIGH"  # Auto-respond for HIGH and above
    
    # Resource limits
    max_memory_mb: int = 2048
    max_cpu_percent: int = 80
    max_scan_duration_sec: int = 600
    
    # Whitelist settings
    whitelist_enabled: bool = True
    whitelist_path: Optional[str] = None
    
    # FP suppression
    fp_suppression_enabled: bool = True
    auto_fp_detection: bool = True
    
    # Reporting settings
    report_format: List[str] = field(default_factory=lambda: ["markdown", "json"])
    attack_chain_enabled: bool = True
    trend_analysis_enabled: bool = False
    trend_lookback_days: int = 7
    
    # Notification settings
    notify_on_critical: bool = True
    notify_on_high: bool = False
    notification_channels: List[str] = field(default_factory=list)
    
    # Compliance settings
    compliance_mode: bool = False
    compliance_frameworks: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyConfig":
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})


class PolicyManager:
    """
    Policy manager for security detection configurations.
    
    Responsibilities:
    - Load/save policy configurations
    - Validate policy settings
    - Apply policies to orchestrator
    - Manage multiple policy profiles
    """
    
    DEFAULT_POLICY_NAME = "default"
    
    def __init__(self, workspace_dir: Optional[str] = None):
        """
        Initialize policy manager.
        
        Args:
            workspace_dir: Workspace directory for storing policies
        """
        self.logger = logging.getLogger(__name__)
        self.workspace_dir = workspace_dir
        self.policies: Dict[str, PolicyConfig] = {}
        self.active_policy_name: str = self.DEFAULT_POLICY_NAME
        
        # Create policies directory
        if workspace_dir:
            self.policies_dir = Path(workspace_dir) / "policies"
            self.policies_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.policies_dir = None
        
        # Load default policy
        self._load_default_policy()
    
    def _load_default_policy(self) -> None:
        """Load default policy"""
        default_policy = PolicyConfig()
        self.policies[self.DEFAULT_POLICY_NAME] = default_policy
        self.active_policy_name = self.DEFAULT_POLICY_NAME
        self.logger.debug("Default policy loaded")
    
    def create_policy(self, name: str, config: Optional[PolicyConfig] = None) -> bool:
        """
        Create a new policy.
        
        Args:
            name: Policy name
            config: Policy configuration (uses default if None)
            
        Returns:
            True if policy created successfully
        """
        if name in self.policies:
            self.logger.warning(f"Policy '{name}' already exists")
            return False
        
        policy = config or PolicyConfig(name=name)
        self.policies[name] = policy
        self.logger.info(f"Policy '{name}' created")
        return True
    
    def get_policy(self, name: str) -> Optional[PolicyConfig]:
        """Get policy by name"""
        return self.policies.get(name)
    
    def set_active_policy(self, name: str) -> bool:
        """
        Set active policy.
        
        Args:
            name: Policy name
            
        Returns:
            True if policy set successfully
        """
        if name not in self.policies:
            self.logger.error(f"Policy '{name}' not found")
            return False
        
        self.active_policy_name = name
        self.logger.info(f"Active policy set to '{name}'")
        return True
    
    def get_active_policy(self) -> PolicyConfig:
        """Get current active policy"""
        return self.policies.get(self.active_policy_name, self.policies[self.DEFAULT_POLICY_NAME])
    
    def update_policy(self, name: str, updates: Dict[str, Any]) -> bool:
        """
        Update policy configuration.
        
        Args:
            name: Policy name
            updates: Dictionary of fields to update
            
        Returns:
            True if policy updated successfully
        """
        policy = self.policies.get(name)
        if not policy:
            self.logger.error(f"Policy '{name}' not found")
            return False
        
        for key, value in updates.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
            else:
                self.logger.warning(f"Unknown policy field: {key}")
        
        self.logger.info(f"Policy '{name}' updated")
        return True
    
    def list_policies(self) -> List[str]:
        """List all available policy names"""
        return list(self.policies.keys())
    
    def delete_policy(self, name: str) -> bool:
        """
        Delete a policy.
        
        Args:
            name: Policy name
            
        Returns:
            True if policy deleted successfully
        """
        if name == self.DEFAULT_POLICY_NAME:
            self.logger.error("Cannot delete default policy")
            return False
        
        if name not in self.policies:
            self.logger.error(f"Policy '{name}' not found")
            return False
        
        del self.policies[name]
        self.logger.info(f"Policy '{name}' deleted")
        return True
    
    def save_policy(self, name: str) -> bool:
        """
        Save policy to disk.
        
        Args:
            name: Policy name
            
        Returns:
            True if policy saved successfully
        """
        if not self.policies_dir:
            self.logger.warning("No policies directory configured")
            return False
        
        policy = self.policies.get(name)
        if not policy:
            self.logger.error(f"Policy '{name}' not found")
            return False
        
        try:
            policy_file = self.policies_dir / f"{name}.json"
            with open(policy_file, 'w', encoding='utf-8') as f:
                json.dump(policy.to_dict(), f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Policy '{name}' saved to {policy_file}")
            return True
        except (OSError, TypeError, ValueError) as e:
            self.logger.error(f"Failed to save policy: {e}")
            return False
    
    def load_policy(self, name: str) -> bool:
        """
        Load policy from disk.
        
        Args:
            name: Policy name
            
        Returns:
            True if policy loaded successfully
        """
        if not self.policies_dir:
            return False
        
        policy_file = self.policies_dir / f"{name}.json"
        if not policy_file.exists():
            self.logger.error(f"Policy file not found: {policy_file}")
            return False
        
        try:
            with open(policy_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            policy = PolicyConfig.from_dict(data)
            self.policies[name] = policy
            self.logger.info(f"Policy '{name}' loaded from {policy_file}")
            return True
        except (OSError, KeyError, TypeError, ValueError) as e:
            self.logger.error(f"Failed to load policy: {e}")
            return False
    
    def save_all_policies(self) -> bool:
        """Save all policies to disk"""
        success = True
        for name in self.policies:
            if not self.save_policy(name):
                success = False
        return success
    
    def load_all_policies(self) -> int:
        """
        Load all policies from disk.
        
        Returns:
            Number of policies loaded
        """
        if not self.policies_dir or not self.policies_dir.exists():
            return 0
        
        count = 0
        for policy_file in self.policies_dir.glob("*.json"):
            name = policy_file.stem
            if self.load_policy(name):
                count += 1
        
        self.logger.info(f"Loaded {count} policies from {self.policies_dir}")
        return count
    
    def validate_policy(self, name: str) -> List[str]:
        """
        Validate policy configuration.
        
        Args:
            name: Policy name
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        policy = self.policies.get(name)
        
        if not policy:
            return [f"Policy '{name}' not found"]
        
        # Validate severity thresholds
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if policy.min_severity_to_report not in valid_severities:
            errors.append(f"Invalid min_severity_to_report: {policy.min_severity_to_report}")
        if policy.auto_respond_threshold not in valid_severities:
            errors.append(f"Invalid auto_respond_threshold: {policy.auto_respond_threshold}")
        
        # Validate resource limits
        if policy.max_memory_mb < 256 or policy.max_memory_mb > 8192:
            errors.append(f"max_memory_mb out of range: {policy.max_memory_mb}")
        if policy.max_cpu_percent < 10 or policy.max_cpu_percent > 100:
            errors.append(f"max_cpu_percent out of range: {policy.max_cpu_percent}")
        if policy.max_scan_duration_sec < 60 or policy.max_scan_duration_sec > 7200:
            errors.append(f"max_scan_duration_sec out of range: {policy.max_scan_duration_sec}")
        
        # Validate report formats
        valid_formats = {"markdown", "json", "html"}
        for fmt in policy.report_format:
            if fmt not in valid_formats:
                errors.append(f"Invalid report format: {fmt}")
        
        return errors
    
    def export_policy(self, name: str, output_path: str) -> bool:
        """
        Export policy to a file.
        
        Args:
            name: Policy name
            output_path: Output file path
            
        Returns:
            True if export successful
        """
        policy = self.policies.get(name)
        if not policy:
            return False
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(policy.to_dict(), f, indent=2, ensure_ascii=False)
            self.logger.info(f"Policy '{name}' exported to {output_path}")
            return True
        except (OSError, TypeError, ValueError) as e:
            self.logger.error(f"Failed to export policy: {e}")
            return False
    
    def import_policy(self, name: str, input_path: str) -> bool:
        """
        Import policy from a file.
        
        Args:
            name: Policy name
            input_path: Input file path
            
        Returns:
            True if import successful
        """
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            policy = PolicyConfig.from_dict(data)
            policy.name = name
            self.policies[name] = policy
            self.logger.info(f"Policy '{name}' imported from {input_path}")
            return True
        except (OSError, KeyError, TypeError, ValueError) as e:
            self.logger.error(f"Failed to import policy: {e}")
            return False
