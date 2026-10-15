"""Resilient HTTP client with timeout and retry control

Provides fault-tolerant HTTP requests with:
- Pre-request connectivity probing
- Configurable timeouts
- Automatic retry with backoff
- Graceful degradation on failure
"""
import asyncio
import logging
from typing import Optional, Dict

from .network_config import NetworkTimeout
from .network_prober import NetworkProber
from .cold_start_manager import ColdStartManager

logger = logging.getLogger("sec-userspace")


class ResilientHttpClient:
    """Resilient HTTP client with timeout and retry"""
    
    def __init__(
        self,
        connect_timeout: float = None,
        read_timeout: float = None,
        max_retries: int = None
    ):
        """Initialize resilient HTTP client
        
        Args:
            connect_timeout: Connection timeout in seconds
            read_timeout: Total request timeout in seconds
            max_retries: Maximum retry attempts
        """
        self.connect_timeout = connect_timeout or NetworkTimeout.get_config('CONNECTION_TIMEOUT_SECONDS')
        self.read_timeout = read_timeout or NetworkTimeout.get_config('SINGLE_REQUEST_TIMEOUT_SECONDS')
        self.max_retries = max_retries or NetworkTimeout.get_config('MAX_RETRY_COUNT')
    
    async def get(self, url: str, **kwargs) -> Optional[Dict]:
        """GET request with timeout and retry
        
        Args:
            url: Target URL
            **kwargs: Additional arguments passed to HTTP client
            
        Returns:
            Response data dict, or None on failure
        """
        # Probe connectivity first
        is_reachable, latency = NetworkProber.probe_server(url)
        if not is_reachable:
            logger.warning(f"Server unreachable, skipping request: {url}")
            return None
        
        # Execute request with retry
        retry_interval = NetworkTimeout.get_config('RETRY_INTERVAL_SECONDS')
        
        for attempt in range(self.max_retries):
            try:
                result = await self._do_get(url, **kwargs)
                if result is not None:
                    return result
            except asyncio.TimeoutError:
                logger.warning(f"Request timeout (attempt {attempt + 1}/{self.max_retries}): {url}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(retry_interval)
            except (OSError, ValueError, RuntimeError) as e:
                logger.error(f"HTTP request error: {e}")
                break
        
        return None
    
    async def post(self, url: str, data: Dict = None, **kwargs) -> Optional[Dict]:
        """POST request with timeout and retry
        
        Args:
            url: Target URL
            data: Request body data
            **kwargs: Additional arguments passed to HTTP client
            
        Returns:
            Response data dict, or None on failure
        """
        # Probe connectivity first
        is_reachable, latency = NetworkProber.probe_server(url)
        if not is_reachable:
            logger.warning(f"Server unreachable, skipping request: {url}")
            ColdStartManager.save_local_cache('report', data)
            return None
        
        # Execute request with retry
        retry_interval = NetworkTimeout.get_config('RETRY_INTERVAL_SECONDS')
        
        for attempt in range(self.max_retries):
            try:
                result = await self._do_post(url, data, **kwargs)
                if result is not None:
                    return result
            except asyncio.TimeoutError:
                logger.warning(f"Request timeout (attempt {attempt + 1}/{self.max_retries}): {url}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(retry_interval)
            except (OSError, ValueError, RuntimeError) as e:
                logger.error(f"HTTP request error: {e}")
                break
        
        # Save to local cache on failure
        if data:
            ColdStartManager.save_local_cache('report', data)
        
        return None
    
    @staticmethod
    def _sanitize_kwargs(kwargs: dict) -> dict:
        """Remove dangerous keys from kwargs before passing to aiohttp."""
        for key in ('ssl', 'proxy', 'proxy_auth'):
            kwargs.pop(key, None)
        return kwargs

    async def _do_get(self, url: str, **kwargs) -> Optional[Dict]:
        """Execute GET request

        Args:
            url: Target URL
            **kwargs: Additional arguments

        Returns:
            Response data or None
        """
        try:
            import aiohttp
        except ImportError:
            logger.error("aiohttp not available, cannot make HTTP requests")
            return None

        self._sanitize_kwargs(kwargs)
        timeout = aiohttp.ClientTimeout(
            connect=self.connect_timeout,
            total=self.read_timeout
        )

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, timeout=timeout, **kwargs) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        logger.error(f"HTTP {resp.status} from {url}")
                        return None
        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error: {e}")
            return None
    
    async def _do_post(self, url: str, data: Dict = None, **kwargs) -> Optional[Dict]:
        """Execute POST request
        
        Args:
            url: Target URL
            data: Request body
            **kwargs: Additional arguments
            
        Returns:
            Response data or None
        """
        try:
            import aiohttp
        except ImportError:
            logger.error("aiohttp not available, cannot make HTTP requests")
            return None
        
        self._sanitize_kwargs(kwargs)
        timeout = aiohttp.ClientTimeout(
            connect=self.connect_timeout,
            total=self.read_timeout
        )

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    url,
                    json=data,
                    timeout=timeout,
                    **kwargs
                ) as resp:
                    if resp.status in (200, 201, 202):
                        return await resp.json()
                    else:
                        logger.error(f"HTTP {resp.status} from {url}")
                        return None
        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error: {e}")
            return None


def get_resilient_client(
    connect_timeout: float = None,
    read_timeout: float = None,
    max_retries: int = None
) -> ResilientHttpClient:
    """Get resilient HTTP client instance
    
    Args:
        connect_timeout: Connection timeout
        read_timeout: Read timeout
        max_retries: Max retry count
        
    Returns:
        ResilientHttpClient instance
    """
    return ResilientHttpClient(
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        max_retries=max_retries
    )
