"""Network connectivity prober

Provides server reachability detection before attempting network requests.
Supports caching to avoid redundant probes.
"""
import time
import logging
import threading
from typing import Tuple, Dict
from urllib.parse import urlparse

from .network_config import NetworkTimeout

logger = logging.getLogger("sec-userspace")


class NetworkProber:
    """Network connectivity probe"""

    # Probe result cache: url -> (is_reachable, latency, timestamp)
    _probe_cache: Dict[str, Tuple[bool, float, float]] = {}
    _cache_lock = threading.Lock()
    
    @classmethod
    def probe_server(cls, url: str, timeout: float = None) -> Tuple[bool, float]:
        """Probe server reachability
        
        Args:
            url: Target server URL
            timeout: Timeout in seconds, default 3s
            
        Returns:
            Tuple[is_reachable, latency]:
            - is_reachable: Whether server is reachable
            - latency: Response latency in ms, -1 if unreachable
        """
        timeout = timeout or NetworkTimeout.get_config('CONNECTION_TIMEOUT_SECONDS')

        # Check cache
        parsed = urlparse(url)
        cache_key = parsed.netloc
        if not cache_key:
            logger.warning(f"Server probe skipped: invalid URL {url}")
            return False, -1

        with cls._cache_lock:
            if cache_key in cls._probe_cache:
                is_reachable, latency, timestamp = cls._probe_cache[cache_key]
                if time.time() - timestamp < NetworkTimeout.get_config('PROBE_CACHE_TTL_SECONDS'):
                    return is_reachable, latency

        # Execute probe
        start_time = time.time()
        try:
            import urllib.request

            scheme = parsed.scheme or "https"
            probe_url = f"{scheme}://{cache_key}"
            req = urllib.request.Request(probe_url, method='HEAD')

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                latency = (time.time() - start_time) * 1000
                is_reachable = resp.status < 500
                with cls._cache_lock:
                    cls._probe_cache[cache_key] = (is_reachable, latency, time.time())
                logger.debug(f"Server probe success: {url} - {latency:.0f}ms")
                return is_reachable, latency

        except (OSError, ValueError, TypeError) as e:
            latency = (time.time() - start_time) * 1000
            with cls._cache_lock:
                cls._probe_cache[cache_key] = (False, -1, time.time())
            logger.warning(f"Server probe failed: {url} - {e}")
            return False, -1
    
    @classmethod
    def should_use_cold_start(cls, endpoints: list) -> bool:
        """Check if cold start mode should be used
        
        Args:
            endpoints: List of endpoint URLs to probe
            
        Returns:
            True if all endpoints are unreachable (cold start needed)
        """
        if not endpoints:
            return False
            
        for endpoint in endpoints:
            is_reachable, _ = cls.probe_server(endpoint)
            if is_reachable:
                return False
        return True
    
    @classmethod
    def clear_cache(cls):
        """Clear probe cache"""
        with cls._cache_lock:
            cls._probe_cache.clear()
        logger.debug("Network probe cache cleared")
