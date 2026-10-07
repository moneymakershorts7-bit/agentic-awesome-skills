"""Cold start mode manager

Manages offline/cold start mode when network is unreachable.
Provides access to locally cached assets.
"""
import json
import os
import logging
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime, timezone

logger = logging.getLogger("sec-userspace")


class ColdStartManager:
    """Cold start mode manager"""
    
    COLD_START_FLAG_FILE = "/tmp/sec-userspace-cold-start.flag"
    
    @classmethod
    def enter_cold_start(cls, reason: str = "network_unreachable") -> None:
        """Enter cold start mode
        
        Args:
            reason: Reason for entering cold start mode
        """
        try:
            flag_data = {
                "mode": "cold_start",
                "reason": reason,
                "entered_at": datetime.now(timezone.utc).isoformat()
            }
            with open(cls.COLD_START_FLAG_FILE, 'w', encoding='utf-8') as f:
                json.dump(flag_data, f)
            logger.warning(f"Entered cold start mode: {reason}")
        except OSError as e:
            logger.error(f"Failed to enter cold start mode: {e}")
    
    @classmethod
    def exit_cold_start(cls) -> None:
        """Exit cold start mode"""
        try:
            if os.path.exists(cls.COLD_START_FLAG_FILE):
                os.remove(cls.COLD_START_FLAG_FILE)
                logger.info("Exited cold start mode")
        except OSError as e:
            logger.error(f"Failed to exit cold start mode: {e}")
    
    @classmethod
    def is_cold_start(cls) -> bool:
        """Check if in cold start mode
        
        Returns:
            True if in cold start mode
        """
        return os.path.exists(cls.COLD_START_FLAG_FILE)
    
    @classmethod
    def get_cold_start_info(cls) -> Dict:
        """Get cold start mode information
        
        Returns:
            Dict with cold start info, empty dict if not in cold start
        """
        if not cls.is_cold_start():
            return {}
        
        try:
            with open(cls.COLD_START_FLAG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read cold start flag: {e}")
            return {}
    
    @classmethod
    def get_local_assets(cls, asset_type: str) -> Optional[Dict]:
        """Get locally cached assets (used in cold start mode)
        
        Args:
            asset_type: Asset type ('whitelist', 'ioc', 'rules')
            
        Returns:
            Locally cached asset data, or None if no cache
        """
        cache_paths = {
            'whitelist': [
                Path.home() / '.cache' / 'sec-userspace' / 'cloud_whitelist.json',
                Path("/data/sec-userspace/workspace/cache/ebpf-whitelist-cache.json"),
                Path.cwd() / "sec-userspace/workspace/cache/ebpf-whitelist-cache.json",
            ],
            'ioc': [
                Path.home() / '.cache' / 'sec-userspace' / 'ioc_data.json',
            ],
            'rules': [
                Path.home() / '.cache' / 'sec-userspace' / 'detection_rules.json',
            ],
        }
        
        for path in cache_paths.get(asset_type, []):
            if path.exists():
                try:
                    logger.info(f"Using cached {asset_type} from {path}")
                    with open(path, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning(f"Failed to load cached {asset_type} from {path}: {e}")
                    continue
        
        return None
    
    @classmethod
    def save_local_cache(cls, asset_type: str, data: Dict) -> bool:
        """Save data to local cache for cold start mode
        
        Args:
            asset_type: Asset type ('whitelist', 'ioc', 'rules', 'report')
            data: Data to cache
            
        Returns:
            True if saved successfully
        """
        cache_paths = {
            'whitelist': Path.home() / '.cache' / 'sec-userspace' / 'cloud_whitelist.json',
            'ioc': Path.home() / '.cache' / 'sec-userspace' / 'ioc_data.json',
            'rules': Path.home() / '.cache' / 'sec-userspace' / 'detection_rules.json',
            'report': Path.home() / '.cache' / 'sec-userspace' / 'pending_uploads',
        }
        
        cache_path = cache_paths.get(asset_type)
        if not cache_path:
            logger.warning(f"Unknown asset type for caching: {asset_type}")
            return False
        
        try:
            if asset_type == 'report':
                cache_path.mkdir(parents=True, exist_ok=True)
                cache_file = cache_path / f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
            else:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_file = cache_path
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            
            logger.info(f"Cached {asset_type} to {cache_file}")
            return True
            
        except OSError as e:
            logger.error(f"Failed to cache {asset_type}: {e}")
            return False
