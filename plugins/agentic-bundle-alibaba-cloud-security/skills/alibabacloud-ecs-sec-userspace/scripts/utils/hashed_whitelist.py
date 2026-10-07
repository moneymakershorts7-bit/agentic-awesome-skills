"""Hashed Whitelist Management Module

Provides hashed whitelist management for false positive suppression.
Uses SHA256+HMAC to store rules securely without exposing patterns.

This module provides a compatibility layer with the original whitelist.py API,
allowing existing analyzers to use hashed whitelists without code changes.
"""

import json
import os
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("sec-userspace")


class HashedWhitelistManager:
    """Hashed Whitelist Manager - compatible with original WhitelistManager API"""
    
    def __init__(self, workspace_dir: str, environment: Optional[str] = None):
        """Initialize hashed whitelist manager
        
        Args:
            workspace_dir: Workspace directory for database storage
            environment: Environment context (development | production | ci | container)
        """
        self.workspace_dir = workspace_dir
        self.environment = environment
        self._manager = None
        self._matcher = None
        self._hmac_key = None
        self._db_path = None
        
        # Try to initialize with HMAC key
        try:
            self._initialize()
        except (ImportError, OSError, ValueError, KeyError) as e:
            logger.warning(f"Failed to initialize hashed whitelist: {e}")
    
    def _initialize(self) -> bool:
        """Initialize the hashed whitelist manager"""
        try:
            from ..threat_intel import create_whitelist_manager, WhitelistMatcher
        except ImportError:
            logger.warning("Whitelist manager not available after threat_intel refactor")
            return False
        
        # Load or generate HMAC key
        self._hmac_key = self._load_or_generate_hmac_key()
        
        if not self._hmac_key:
            logger.error("Failed to load HMAC key")
            return False
        
        # Database path
        self._db_path = os.path.join(self.workspace_dir, "whitelist.db")
        
        # Check if migration is needed
        db_exists = os.path.exists(self._db_path)
        from .path_resolver import get_scripts_dir
        fp_exceptions_path = os.path.join(get_scripts_dir(), "utils", "fp-exceptions.json")
        fp_exceptions_exists = os.path.exists(fp_exceptions_path)
        
        # Auto-migrate if: fp-exceptions.json exists AND whitelist.db doesn't exist
        if fp_exceptions_exists and not db_exists:
            logger.info("Detected fp-exceptions.json, auto-migrating to hashed whitelist...")
            self._migrate_fp_exceptions(fp_exceptions_path)
        
        # Create and initialize manager
        self._manager = create_whitelist_manager(self._db_path, self._hmac_key)
        self._matcher = WhitelistMatcher(self._manager)
        
        logger.info(f"Hashed whitelist manager initialized: {self._db_path}")
        return True
    
    def _migrate_fp_exceptions(self, fp_exceptions_path: str) -> None:
        """Migrate fp-exceptions.json to hashed whitelist database
        
        Args:
            fp_exceptions_path: Path to fp-exceptions.json
        """
        try:
            import sys

            # Add scripts directory to path for importing migrate_whitelist
            from .path_resolver import get_scripts_dir
            scripts_dir = get_scripts_dir()
            if scripts_dir not in sys.path:
                sys.path.insert(0, scripts_dir)
            
            from migrate_whitelist import WhitelistMigrator
            
            migrator = WhitelistMigrator(
                json_path=fp_exceptions_path,
                db_path=self._db_path,
                hmac_key=self._hmac_key
            )
            
            result = migrator.migrate()
            
            logger.info(
                f"Migration complete: {result.migrated} rules migrated, "
                f"{result.failed} failed, {result.skipped} skipped"
            )
            
            # Rename fp-exceptions.json to .deprecated after successful migration
            if result.failed == 0:
                deprecated_path = fp_exceptions_path + ".deprecated"
                os.rename(fp_exceptions_path, deprecated_path)
                logger.info(f"fp-exceptions.json renamed to {deprecated_path}")
            else:
                logger.warning(f"Migration completed with {result.failed} failures, "
                             f"fp-exceptions.json preserved")
                
        except (ImportError, OSError, ValueError, KeyError) as e:
            logger.error(f"Auto-migration failed: {e}")
            # Migration failure doesn't block initialization
    
    def _load_or_generate_hmac_key(self) -> str:
        """Generate HMAC key or load from workspace cache."""
        import secrets
        
        # Try to load from workspace cache
        try:
            key_file = os.path.join(self.workspace_dir, "hmac.key")
            if os.path.exists(key_file):
                with open(key_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    key = data.get("hmac_key")
                    if key:
                        return key
        except (OSError, KeyError, ValueError) as e:
            logger.debug(f"Failed to load HMAC key from workspace: {e}")
        
        # Generate new key
        new_key = secrets.token_hex(32)
        
        # Save to workspace
        try:
            key_file = os.path.join(self.workspace_dir, "hmac.key")
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "hmac_key": new_key,
                    "created": datetime.now(timezone.utc).isoformat()
                }, f, indent=2)
            return new_key
        except OSError as e:
            logger.error(f"Failed to save HMAC key: {e}")
            return new_key
    
    def is_whitelisted(self, module: str, evidence_value: str, check_builtin: bool = True) -> bool:
        """Check if evidence matches whitelist
        
        Args:
            module: Analyzer name
            evidence_value: Evidence value
            check_builtin: Whether to check built-in patterns (not implemented for hashed version)
        
        Returns:
            bool: Whether it matches whitelist
        """
        if not self._manager:
            return False
        
        try:
            # Use matcher to check against hashed rules
            try:
                from ..threat_intel import AlertContext
            except ImportError:
                return False
            
            alert = AlertContext(
                analyzer_name=module,
                signature=evidence_value,
                severity="medium",
                raw_data={"value": evidence_value}
            )
            
            result = self._matcher.match(alert)
            return result.matched
            
        except (OSError, ValueError, KeyError, AttributeError) as e:
            logger.debug(f"Whitelist check failed: {e}")
            return False
    
    def add_entry(
        self, 
        module: str, 
        pattern: str, 
        reason: str,
        added_by: str = "agent",
        expires: Optional[str] = None,
        environment: Optional[str] = None
    ):
        """Add whitelist entry (stored as hash)
        
        Args:
            module: Analyzer name
            pattern: Match pattern
            reason: Whitelist reason
            added_by: Added by
            expires: Expiration time (ISO format)
            environment: Environment context
        
        Returns:
            dict: Entry info (hash-based, no plaintext returned)
        """
        if not self._manager:
            return None
        
        try:
            try:
                from ..threat_intel import WhitelistRule
            except ImportError:
                return None
            
            rule = WhitelistRule(
                analyzer=module,
                rule_type="pattern",
                pattern=pattern,
                reason=reason,
                severity_filter=["critical", "high", "medium", "low"],
                tags=[added_by] + ([environment] if environment else [])
            )
            
            success = self._manager.add_rule(rule)
            
            if success:
                logger.debug(f"Added hashed whitelist entry for {module}")
                return {"status": "added", "module": module}
            else:
                logger.error(f"Failed to add hashed whitelist entry for {module}")
                return None
                
        except (OSError, ValueError, KeyError, TypeError) as e:
            logger.error(f"Failed to add whitelist entry: {e}")
            return None
    
    def get_stats(self) -> dict:
        """Get whitelist statistics
        
        Returns:
            dict: Statistics
        """
        if not self._manager:
            return {
                "total": 0,
                "active": 0,
                "expired": 0,
                "by_module": {},
                "type": "hashed"
            }
        
        try:
            stats = self._manager.get_statistics()
            return {
                "total": stats.get("total_rules", 0),
                "active": stats.get("total_rules", 0),  # All rules in hashed DB are active
                "expired": 0,
                "by_module": stats.get("by_analyzer", {}),
                "type": "hashed"
            }
        except (OSError, ValueError, KeyError, AttributeError) as e:
            logger.debug(f"Failed to get stats: {e}")
            return {"total": 0, "active": 0, "expired": 0, "by_module": {}, "type": "hashed"}
    
    def get_entries_for_module(self, module: str) -> list:
        """Get whitelist entries for specified module
        
        Note: Returns hashed entries only (patterns not visible)
        
        Args:
            module: Analyzer name
        
        Returns:
            list: List of entry info dictionaries (hashed)
        """
        if not self._manager:
            return []
        
        try:
            rules = self._manager.list_rules(module)
            return rules
        except (OSError, ValueError, KeyError, AttributeError) as e:
            logger.debug(f"Failed to get entries for module: {e}")
            return []
    
    def cleanup_expired(self) -> int:
        """Clean up expired entries (no-op for hashed version)
        
        Returns:
            int: Number of cleaned entries (always 0)
        """
        return 0
    
    def close(self) -> None:
        """Close the whitelist manager"""
        if self._manager:
            self._manager.close()
            self._manager = None
            self._matcher = None


# Global singleton (lazy initialization)
_hashed_whitelist_manager: Optional[HashedWhitelistManager] = None
_hashed_whitelist_lock = threading.Lock()


def get_whitelist_manager(workspace_dir: str, environment: Optional[str] = None) -> HashedWhitelistManager:
    """Get hashed whitelist manager singleton
    
    Args:
        workspace_dir: Workspace directory
        environment: Environment context (development | production | ci | container)
    
    Returns:
        HashedWhitelistManager: Hashed whitelist manager instance
    """
    global _hashed_whitelist_manager

    if _hashed_whitelist_manager is None:
        with _hashed_whitelist_lock:
            if _hashed_whitelist_manager is None:
                _hashed_whitelist_manager = HashedWhitelistManager(workspace_dir, environment)

    return _hashed_whitelist_manager


def check_whitelist(workspace_dir: str, module: str, evidence_value: str, environment: Optional[str] = None) -> bool:
    """Check if evidence matches whitelist
    
    Args:
        workspace_dir: Workspace directory
        module: Analyzer name
        evidence_value: Evidence value
        environment: Environment context
    
    Returns:
        bool: Whether it matches whitelist
    """
    manager = get_whitelist_manager(workspace_dir, environment)
    return manager.is_whitelisted(module, evidence_value)


def add_to_whitelist(
    workspace_dir: str,
    module: str,
    pattern: str,
    reason: str,
    expires: Optional[str] = None,
    environment: Optional[str] = None
) -> Optional[dict]:
    """Add to whitelist (stored as hash)
    
    Args:
        workspace_dir: Workspace directory
        module: Analyzer name
        pattern: Match pattern
        reason: Whitelist reason
        expires: Expiration time
        environment: Environment context
    
    Returns:
        dict: Entry info or None on failure
    """
    manager = get_whitelist_manager(workspace_dir, environment)
    return manager.add_entry(module, pattern, reason, added_by="agent", expires=expires, environment=environment)


def get_whitelist_stats(workspace_dir: str) -> dict:
    """Get whitelist statistics
    
    Args:
        workspace_dir: Workspace directory
    
    Returns:
        dict: Statistics
    """
    manager = get_whitelist_manager(workspace_dir)
    return manager.get_stats()


# Re-export environment detection from original module
def detect_environment() -> Optional[str]:
    """Detect current environment type
    
    Returns:
        Optional[str]: Environment type (development | ci | container | production)
    """
    # Check for CI/CD environment
    ci_indicators = [
        'CI' in os.environ,
        'GITHUB_ACTIONS' in os.environ,
        'GITLAB_CI' in os.environ,
        'TRAVIS' in os.environ,
        'CIRCLECI' in os.environ,
        'JENKINS_URL' in os.environ,
        'BUILD_NUMBER' in os.environ,
    ]
    if any(ci_indicators):
        return 'ci'
    
    # Check for container environment
    container_indicators = [
        os.path.exists('/.dockerenv'),
        os.path.exists('/run/.containerenv'),
        'container=podman' in os.environ.get('container', ''),
        'KUBERNETES_SERVICE_HOST' in os.environ,
    ]
    if any(container_indicators):
        return 'container'
    
    # Check for explicit dev environment markers
    if 'DEV_MODE' in os.environ or 'DEBUG' in os.environ:
        return 'development'
    
    # Default to production
    return 'production'
