"""Network timeout configuration constants

Defines standard timeout values for all network operations in sec-userspace.
"""


class NetworkTimeout:
    """Network access timeout configuration"""
    
    # Connection timeout (establish TCP connection)
    CONNECTION_TIMEOUT_SECONDS = 3
    
    # IoC download total timeout
    IOC_DOWNLOAD_TIMEOUT_SECONDS = 10 * 60  # 10 minutes
    
    # Report upload total timeout
    REPORT_UPLOAD_TIMEOUT_SECONDS = 60  # 1 minute
    
    # Whitelist sync timeout
    WHITELIST_SYNC_TIMEOUT_SECONDS = 30
    
    # Single request timeout (read/write)
    SINGLE_REQUEST_TIMEOUT_SECONDS = 10
    
    # Retry count
    MAX_RETRY_COUNT = 2
    
    # Retry interval (seconds)
    RETRY_INTERVAL_SECONDS = 1
    
    # Probe cache TTL (seconds)
    PROBE_CACHE_TTL_SECONDS = 60
    
    @classmethod
    def get_config(cls, key: str, default=None):
        """Get timeout configuration by key
        
        Supports environment variable override:
        SEC_INSPECT_CONNECT_TIMEOUT
        SEC_INSPECT_IOC_DOWNLOAD_TIMEOUT
        SEC_INSPECT_REPORT_UPLOAD_TIMEOUT
        SEC_INSPECT_WHITELIST_SYNC_TIMEOUT
        SEC_INSPECT_SINGLE_REQUEST_TIMEOUT
        SEC_INSPECT_MAX_RETRY_COUNT
        SEC_INSPECT_RETRY_INTERVAL
        SEC_INSPECT_PROBE_CACHE_TTL
        
        Args:
            key: Configuration key name
            default: Default value if not found
            
        Returns:
            Configuration value
        """
        import os
        
        env_var_map = {
            'CONNECTION_TIMEOUT_SECONDS': 'SEC_INSPECT_CONNECT_TIMEOUT',
            'IOC_DOWNLOAD_TIMEOUT_SECONDS': 'SEC_INSPECT_IOC_DOWNLOAD_TIMEOUT',
            'REPORT_UPLOAD_TIMEOUT_SECONDS': 'SEC_INSPECT_REPORT_UPLOAD_TIMEOUT',
            'WHITELIST_SYNC_TIMEOUT_SECONDS': 'SEC_INSPECT_WHITELIST_SYNC_TIMEOUT',
            'SINGLE_REQUEST_TIMEOUT_SECONDS': 'SEC_INSPECT_SINGLE_REQUEST_TIMEOUT',
            'MAX_RETRY_COUNT': 'SEC_INSPECT_MAX_RETRY_COUNT',
            'RETRY_INTERVAL_SECONDS': 'SEC_INSPECT_RETRY_INTERVAL',
            'PROBE_CACHE_TTL_SECONDS': 'SEC_INSPECT_PROBE_CACHE_TTL',
        }
        
        env_var = env_var_map.get(key)
        if env_var:
            env_value = os.environ.get(env_var)
            if env_value:
                try:
                    return int(env_value)
                except ValueError:
                    pass
        
        return getattr(cls, key, default)
