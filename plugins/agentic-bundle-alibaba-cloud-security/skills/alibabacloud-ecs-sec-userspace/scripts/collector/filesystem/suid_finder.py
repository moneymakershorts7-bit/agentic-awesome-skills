"""SUID/SGID cache management mixin for FilesystemCollector"""
import json
import logging
import os
import stat
import time

logger = logging.getLogger("sec-userspace")

_SUID_SGID_CACHE_TTL = 3600  # 1 hour cache TTL for SUID/SGID results
_CACHE_DIR = "/data/sec-userspace/workspace/cache"


class SuidFinderMixin:
    """Mixin providing SUID/SGID cache loading and retrieval."""

    def __init__(self):
        self._suid_cache = {}
        self._sgid_cache = {}
        self._cache_dir = _CACHE_DIR
        self._cache_loaded = False
        self._cache_initialized = False

    def _ensure_cache_loaded(self):
        """Lazy load cache on first access"""
        if not self._cache_initialized:
            self._load_cache()
            self._cache_initialized = True

    def _load_cache(self):
        """Load SUID/SGID and binary hash cache from disk if available and not expired"""
        try:
            os.makedirs(self._cache_dir, exist_ok=True)

            # Load SUID/SGID cache
            suid_cache_file = os.path.join(self._cache_dir, "suid_sgid_cache.json")
            if os.path.exists(suid_cache_file):
                cache_age = time.time() - os.path.getmtime(suid_cache_file)
                if cache_age <= _SUID_SGID_CACHE_TTL:
                    with open(suid_cache_file, "r", encoding="utf-8") as f:
                        cache_data = json.load(f)
                    self._suid_cache = cache_data.get("suid", {})
                    self._sgid_cache = cache_data.get("sgid", {})
                    logger.debug(
                        f"Filesystem collector: loaded SUID/SGID cache with {len(self._suid_cache)} SUID, "
                        f"{len(self._sgid_cache)} SGID entries (age: {cache_age:.0f}s)"
                    )

            self._cache_loaded = True

        except (OSError, json.JSONDecodeError, KeyError) as e:
            logger.debug(f"Filesystem collector: failed to load cache: {e}")
            self._suid_cache = {}
            self._sgid_cache = {}

    def _get_cached_special_files(self, perm_flag: int) -> tuple:
        """Get cached SUID/SGID files if cache is valid

        Returns:
            (cached_files, cache_valid) tuple
        """
        self._ensure_cache_loaded()
        if not self._cache_loaded:
            return [], False

        cache = self._suid_cache if perm_flag == stat.S_ISUID else self._sgid_cache

        if not cache:
            return [], True

        cached_files = list(cache.values())
        return cached_files, True
