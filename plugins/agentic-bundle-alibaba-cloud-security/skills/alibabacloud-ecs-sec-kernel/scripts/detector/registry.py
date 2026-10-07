"""
Detector dynamic registration and auto-discovery

Auto-scan cve_*.py files in detector/ directory,
import and register all BaseDetector subclasses.
"""
import os
import threading
import importlib
import pkgutil
import logging
from typing import List, Dict, Optional
from .base import BaseDetector

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """CVE Detector Registry"""

    def __init__(self):
        self._detectors: Dict[str, BaseDetector] = {}
        self._loaded: bool = False
        self._lock = threading.Lock()

    def discover_and_register(self) -> None:
        """AutoDiscover and register All Detectors (compatible with plain and zipapp mode)"""
        if self._loaded:
            return

        with self._lock:
            if self._loaded:
                return

            # Use pkgutil.iter_modules for zipapp compatibility (no filesystem dependency)
            package = importlib.import_module(__package__)
            for importer, module_name, is_pkg in pkgutil.iter_modules(
                package.__path__, prefix=f"{__package__}."
            ):
                short_name = module_name.rsplit('.', 1)[-1]
                if not short_name.startswith("cve_"):
                    continue

                try:
                    module = importlib.import_module(module_name)
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and
                            issubclass(attr, BaseDetector) and
                            attr is not BaseDetector and
                            attr.cve_id):
                            self.register(attr())
                            logger.debug(f"Registered detector: {attr.cve_id}")
                except Exception as e:
                    logger.warning(f"Failed to load detector module {short_name}: {e}")

            self._loaded = True
            logger.info(f"Discovered {len(self._detectors)} detector(s)")

    def register(self, detector: BaseDetector) -> None:
        """Register a detector instance"""
        if not detector.cve_id:
            raise ValueError("Detector must have a cve_id")
        if detector.cve_id in self._detectors:
            logger.warning(f"Detector {detector.cve_id} already registered, skipping")
            return
        self._detectors[detector.cve_id] = detector

    def get_all(self) -> List[BaseDetector]:
        """Get all registered detectors"""
        self.discover_and_register()
        return list(self._detectors.values())

    def get_by_cve_id(self, cve_id: str) -> Optional[BaseDetector]:
        """Get detector by CVE ID"""
        self.discover_and_register()
        return self._detectors.get(cve_id)

    def get_by_severity(self, severity: str) -> List[BaseDetector]:
        """Filter detectors by severity level"""
        self.discover_and_register()
        return [d for d in self._detectors.values() if d.severity == severity]

    def list_cve_ids(self) -> List[str]:
        """List all registered CVE IDs"""
        self.discover_and_register()
        return sorted(self._detectors.keys())

    @property
    def count(self) -> int:
        """Number of registered detectors"""
        self.discover_and_register()
        return len(self._detectors)

    def reset(self) -> None:
        """Reset the registry (useful for test cleanup)"""
        with self._lock:
            self._detectors.clear()
            self._loaded = False


# Global singleton
_registry = DetectorRegistry()


def get_registry() -> DetectorRegistry:
    """Get global detector registry"""
    return _registry
