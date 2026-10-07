"""
Generic PoC Verifier - JSON-driven PoC orchestration

Supports three-phase verification with configurable handlers from JSON
"""
import logging
from typing import Optional, Dict, Any
from pathlib import Path

from .base import BasePoCVerifier
from ..core.result import PoCResult
from ..core.kernel_info import KernelInfo

logger = logging.getLogger(__name__)


class GenericPoCVerifier(BasePoCVerifier):
    """
    Generic PoC verifier (JSON-driven)
    
    Eliminates need for per-CVE PoC verifier classes by:
    - Loading PoC metadata from JSON
    - Dynamically loading prepare/post handlers
    - Standard pre-check flow (version + modules)
    """
    
    def __init__(self, cve_id: str, poc_bin: str, timeout: int = 10,
                 prepare_handler_name: Optional[str] = None,
                 post_handler_name: Optional[str] = None,
                 metadata: Optional[Dict[str, Any]] = None):
        """
        Initialize generic PoC verifier
        
        Args:
            cve_id: CVE identifier
            poc_bin: PoC binary path (relative to project root)
            timeout: Execution timeout
            prepare_handler_name: Prepare handler class name (or None)
            post_handler_name: Post handler class name (or None)
            metadata: CVE metadata dict (optional, for optimization)
        """
        self.cve_id = cve_id
        self.poc_bin = poc_bin
        self.timeout = timeout
        self._prepare_handler_name = prepare_handler_name
        self._post_handler_name = post_handler_name
        self._metadata = metadata
    
    def get_prepare_handler(self):
        """Get prepare handler (dynamic loading)"""
        if not self._prepare_handler_name:
            return None
        
        # Import handlers module
        from ..detector.handlers import get_prepare_handler
        return get_prepare_handler(self._prepare_handler_name, self.cve_id)
    
    def get_post_handler(self):
        """Get post handler (dynamic loading)"""
        if not self._post_handler_name:
            return None
        
        from ..detector.handlers import get_post_handler
        return get_post_handler(self._post_handler_name, self.cve_id)
    
    def pre_check(self, kernel_info: KernelInfo) -> Optional[PoCResult]:
        """
        Standard pre-check (JSON-driven):
        
        1. Version range check
        2. Required modules check
        """
        # Load metadata if not provided
        if self._metadata is None:
            from ..cve_db.loader import CVEDatabase
            self._metadata = CVEDatabase.get(self.cve_id)
        
        if self._metadata is None:
            return PoCResult(
                status="ERROR",
                error_message=f"CVE metadata not found: {self.cve_id}"
            )
        
        # Version check
        version_range = self._metadata["affected_versions"]["generic"]
        from ..utils.version_compare import version_in_range
        
        if not version_in_range(
            kernel_info.version,
            version_range["min"],
            fixed_version=version_range.get("fixed")
        ):
            return PoCResult(
                status="NOT_EXPLOITABLE",
                confidence=0.9,
                error_message=(
                    f"Kernel {kernel_info.version} not in affected range "
                    f"[{version_range['min']}, {version_range.get('fixed')})"
                )
            )
        
        # Modules check
        from ..utils.safe_check import check_config_enabled
        
        modules = self._metadata["detection"].get("modules", [])
        for module_name in modules:
            if module_name not in kernel_info.loaded_modules:
                configs = self._metadata["detection"].get("configs", [])
                module_config_ok = any(
                    check_config_enabled(cfg, kernel_info.config)
                    for cfg in configs
                )
                if not module_config_ok:
                    return PoCResult(
                        status="NOT_EXPLOITABLE",
                        confidence=0.8,
                        error_message=f"Module {module_name} not available"
                    )
        
        return None  # Pre-check passed
    
    def get_extra_env(self, kernel_info: KernelInfo) -> Dict[str, str]:
        """Pass kernel version to PoC"""
        return {
            "KERNEL_VERSION": kernel_info.version,
            "KERNEL_ARCH": kernel_info.arch,
        }