"""Module-level constants for process collection."""

# Standard library path prefixes
_STANDARD_LIB_PREFIXES = ("/lib", "/usr/lib", "/lib64", "/usr/lib64")
# Critical environment variables
_CRITICAL_ENV_VARS = ("LD_PRELOAD", "LD_LIBRARY_PATH", "PATH")
# Socket/pipe types
_SOCKET_PIPE_TYPES = ("socket", "pipe")

# Minimum user processes guarantee
# Before soft timeout returns, ensure at least this many user processes are collected
_MIN_USER_PROCESS_GUARANTEE = 8

# Hard timeout for process collection (seconds)
_PROCESS_COLLECTION_HARD_TIMEOUT = 10.0
