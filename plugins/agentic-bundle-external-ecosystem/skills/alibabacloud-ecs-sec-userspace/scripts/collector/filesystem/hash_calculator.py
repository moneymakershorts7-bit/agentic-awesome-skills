"""Binary hash calculation mixin for FilesystemCollector"""
import logging
import os
import time

from ...utils import hash as hash_utils

logger = logging.getLogger("sec-userspace")

_BINARY_HASH_CACHE_TTL = 86400  # 24 hour cache TTL for binary hashes


class HashCalculatorMixin:
    """Mixin providing binary hash calculation and caching."""

    def __init__(self):
        self._binary_hash_cache = {}
        self._cache_dir = "/data/sec-userspace/workspace/cache"

    def _save_binary_hash_cache(self, hashes: dict):
        """Save binary hash results to disk cache"""
        try:
            os.makedirs(self._cache_dir, exist_ok=True)
            cache_file = os.path.join(self._cache_dir, "binary_hash_cache.json")

            cache_data = {
                "timestamp": time.time(),
                "hashes": hashes,
            }

            temp_file = cache_file + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                import json
                json.dump(cache_data, f)
            os.replace(temp_file, cache_file)

            logger.debug(
                f"Filesystem collector: saved binary hash cache with {len(hashes)} entries"
            )
        except OSError as e:
            logger.warning(f"Filesystem collector: failed to save binary hash cache: {e}")

    def _get_cached_binary_hash(self, binary_path: str) -> str:
        """Get cached binary hash if available and not expired

        Returns:
            Cached hash or empty string if not found/expired
        """
        if not self._binary_hash_cache:
            return ""

        entry = self._binary_hash_cache.get(binary_path)
        if entry and isinstance(entry, dict):
            cached_time = entry.get("timestamp", 0)
            if time.time() - cached_time <= _BINARY_HASH_CACHE_TTL:
                return entry.get("hash", "")

        return ""

    def _update_cached_binary_hash(self, binary_path: str, hash_value: str):
        """Update in-memory binary hash cache"""
        self._binary_hash_cache[binary_path] = {
            "hash": hash_value,
            "timestamp": time.time(),
        }

    def _compute_key_binary_hashes(self) -> dict:
        """Compute SHA256 hashes of critical system binaries"""
        key_binaries = [
            "/bin/ls", "/bin/ps", "/bin/netstat", "/usr/bin/ssh",
            "/usr/bin/sudo", "/bin/bash", "/usr/bin/passwd", "/bin/su",
            "/usr/bin/find", "/usr/bin/wget", "/usr/bin/curl",
            "/usr/sbin/sshd", "/bin/cat", "/usr/bin/top", "/bin/sh",
            "/usr/bin/id", "/bin/chmod", "/bin/chown", "/usr/bin/which",
        ]

        hashes = {}
        cache_hits = 0
        cache_misses = 0

        for binary in key_binaries:
            if hasattr(self, '_should_skip_due_to_timeout') and self._should_skip_due_to_timeout():
                logger.warning("Filesystem collector: timeout during binary hash computation")
                return hashes

            # Try cache first
            cached_hash = self._get_cached_binary_hash(binary)
            if cached_hash:
                hashes[binary] = cached_hash
                cache_hits += 1
                continue

            # Compute hash
            if os.path.isfile(binary):
                hash_value = hash_utils.file_sha256(binary)
                hashes[binary] = hash_value
                self._update_cached_binary_hash(binary, hash_value)
                cache_misses += 1
            else:
                hashes[binary] = ""

        # Save cache after computing all hashes
        if cache_misses > 0:
            self._save_binary_hash_cache(self._binary_hash_cache)
            logger.debug(
                f"Filesystem collector: binary hash cache updated "
                f"({cache_hits} hits, {cache_misses} misses)"
            )

        return hashes
