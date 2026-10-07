#!/usr/bin/env python3
"""
CVE Database Loader - YAML-driven
"""
import os
import yaml
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class CVEDatabase:
    """YAML-based CVE database loader (class method design)"""
    
    _db_path: Optional[Path] = None
    _data: Optional[Dict[str, Any]] = None
    
    @classmethod
    def initialize(cls, db_path: Path = None):
        """Initialize CVE database from YAML
        
        YAML is now in configs/ directory (separated from scripts/ for better design)
        - Plain mode: configs/kernel_cves.yaml relative to project root
        - Zipapp mode: configs/kernel_cves.yaml relative to .pyz file
        """
        if db_path is None:
            # Auto-detect based on __file__ location
            abs_file = Path(__file__).resolve()
            
            if '.pyz' in str(abs_file):
                # Zipapp mode: configs is outside .pyz (user editable)
                # __file__ = /path/sec-kernel/scripts/main.pyz/scripts/cve_db/loader.pyc
                # configs = /path/sec-kernel/configs/kernel_cves.yaml
                pyz_path = str(abs_file).split('.pyz')[0] + '.pyz'
                pyz_dir = Path(pyz_path).parent.parent  # Go up 2 levels: scripts → sec-kernel
                db_path = pyz_dir / 'configs' / 'kernel_cves.yaml'
            else:
                # Plain mode: configs is at project root
                # __file__ = /path/sec-kernel/scripts/cve_db/loader.py
                # configs = /path/sec-kernel/configs/kernel_cves.yaml
                project_root = abs_file.parent.parent.parent  # Go up 3 levels: cve_db → scripts → sec-kernel
                db_path = project_root / 'configs' / 'kernel_cves.yaml'
        
        cls._db_path = db_path
        
        if not db_path.exists():
            logger.warning(f"CVE database not found: {db_path}")
            cls._data = {'cves': []}
            return
        
        try:
            with open(db_path, 'r', encoding='utf-8') as f:
                cls._data = yaml.safe_load(f) or {'cves': []}
            
            logger.info(f"CVE database loaded: {len(cls._data.get('cves', []))} CVE entries")
            
        except (yaml.YAMLError, OSError) as e:
            logger.error(f"Failed to load CVE database: {e}")
            cls._data = {'cves': []}
    
    @classmethod
    def get(cls, cve_id: str, enabled_only: bool = True) -> Optional[Dict[str, Any]]:
        """Get CVE metadata by CVE ID"""
        if cls._data is None:
            cls.initialize()
        
        # Search in cves array
        for cve in cls._data.get('cves', []):
            if cve.get('cve_id') == cve_id:
                if enabled_only and not cve.get('enabled', True):
                    logger.debug(f"CVE {cve_id} is disabled")
                    return None
                return cve
        
        return None
    
    @classmethod
    def list_all(cls, enabled_only: bool = True) -> List[Dict[str, Any]]:
        """Get all CVE entries"""
        if cls._data is None:
            cls.initialize()
        
        cves = cls._data.get('cves', [])
        if enabled_only:
            return [c for c in cves if c.get('enabled', True)]
        return cves
    
    @classmethod
    def list_disabled(cls) -> List[str]:
        """Get list of disabled CVE IDs"""
        return [c['cve_id'] for c in cls.list_all(enabled_only=False) if not c.get('enabled', True)]
    
    @classmethod
    def reload(cls):
        """Reload CVE database from disk"""
        cls._data = None
        cls.initialize(cls._db_path)
    
    @classmethod
    def get_version(cls) -> str:
        """Get database version"""
        if cls._data is None:
            cls.initialize()
        return cls._data.get('version', 'unknown')


def load_cve_database(db_path: Optional[str] = None) -> CVEDatabase:
    """Factory function to load CVE database"""
    CVEDatabase.initialize(Path(db_path) if db_path else None)
    return CVEDatabase
