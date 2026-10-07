"""Lazy import helpers and module-level caches for network analyzer.

Provides deferred module loading to reduce import overhead under high load.
All caches are module-level singletons shared across the network analyzer package.
"""
import ipaddress
import threading

_logger = None
_lazy_init_lock = threading.Lock()

# =============================================================================
# Lazy Module Import Helpers
# =============================================================================

_os_cache: dict = {}

def _get_os_module():
    if 'os' not in _os_cache:
        with _lazy_init_lock:
            if 'os' not in _os_cache:
                import os as _os
                _os_cache['os'] = _os
    return _os_cache['os']


_time_cache: dict = {}

def _get_time_module():
    if 'time' not in _time_cache:
        with _lazy_init_lock:
            if 'time' not in _time_cache:
                import time as _time
                _time_cache['time'] = _time
    return _time_cache['time']


_collections_cache: dict = {}

def _get_defaultdict():
    if 'defaultdict' not in _collections_cache:
        with _lazy_init_lock:
            if 'defaultdict' not in _collections_cache:
                from collections import defaultdict as _dd
                _collections_cache['defaultdict'] = _dd
    return _collections_cache['defaultdict']


_subprocess_cache: dict = {}

def _get_subprocess_module():
    if 'subprocess' not in _subprocess_cache:
        with _lazy_init_lock:
            if 'subprocess' not in _subprocess_cache:
                import subprocess as _subprocess
                _subprocess_cache['subprocess'] = _subprocess
    return _subprocess_cache['subprocess']


# =============================================================================
# Logger
# =============================================================================

def _get_logger():
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger


# =============================================================================
# I18n Lazy Import
# =============================================================================

_lazy_i18n_cache: dict = {}

def _get_attack_tactic_name(attack_id: str) -> str:
    if 'gatn' not in _lazy_i18n_cache:
        with _lazy_init_lock:
            if 'gatn' not in _lazy_i18n_cache:
                from ...utils.i18n import get_attack_tactic_name as _gatn
                _lazy_i18n_cache['gatn'] = _gatn
    return _lazy_i18n_cache['gatn'](attack_id)


# =============================================================================
# IoCLoader Lazy Import
# =============================================================================

_ioc_loader_cache = None

def _get_ioc_loader():
    global _ioc_loader_cache
    if _ioc_loader_cache is None:
        with _lazy_init_lock:
            if _ioc_loader_cache is None:
                from ...threat_intel.ioc_loader import get_loader
                _ioc_loader_cache = get_loader()
    return _ioc_loader_cache


def _is_cloud_metadata_ip(ip: str) -> bool:
    """Check if IP is cloud provider metadata using IoCLoader."""
    return _get_ioc_loader().is_cloud_metadata_ip(ip)


def _is_container_network_ip(ip: str) -> bool:
    """Check if IP belongs to container networks using IoCLoader + standard library."""
    from .constants import CONTAINER_NETWORK_RANGES

    loader = _get_ioc_loader()
    # Use IoCLoader's cloud metadata check as part of container detection
    if loader.is_cloud_metadata_ip(ip):
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in CONTAINER_NETWORK_RANGES:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
        return False
    except (ValueError, TypeError):
        return False


def _is_service_mesh_port(port: int) -> tuple:
    """Check if port is a service mesh port using IoCLoader's C2 port check."""
    from .constants import SERVICE_MESH_PORTS

    loader = _get_ioc_loader()
    c2_desc = loader.lookup_c2_port(port)
    if c2_desc:
        return True, c2_desc
    # Known service mesh ports not in IoCLoader
    if port in SERVICE_MESH_PORTS:
        return True, SERVICE_MESH_PORTS[port]
    return False, ""


# =============================================================================
# Security DB Lazy Import
# =============================================================================

_security_db_cache = None

def _get_security_db():
    global _security_db_cache
    if _security_db_cache is None:
        with _lazy_init_lock:
            if _security_db_cache is None:
                from ...utils.security_db import get_security_db_manager, decode_domain
                _security_db_cache = (get_security_db_manager, decode_domain)
    return _security_db_cache


# =============================================================================
# Cloud Whitelist Lazy Import
# =============================================================================

_cloud_whitelist_cache = None

def _get_cloud_whitelist():
    global _cloud_whitelist_cache
    if _cloud_whitelist_cache is None:
        with _lazy_init_lock:
            if _cloud_whitelist_cache is None:
                from ..cloud_service_whitelist import is_cloud_service_endpoint
                _cloud_whitelist_cache = is_cloud_service_endpoint
    return _cloud_whitelist_cache


# =============================================================================
# FP Tracker Lazy Import
# =============================================================================

_fp_tracker_cache: dict = {}

def _get_fp_tracker():
    if 'fp_tracker' not in _fp_tracker_cache:
        with _lazy_init_lock:
            if 'fp_tracker' not in _fp_tracker_cache:
                from ...utils.fp_tracker import get_tracker, is_false_positive, record_fp
                _fp_tracker_cache['fp_tracker'] = (get_tracker, is_false_positive, record_fp)
    return _fp_tracker_cache['fp_tracker']
