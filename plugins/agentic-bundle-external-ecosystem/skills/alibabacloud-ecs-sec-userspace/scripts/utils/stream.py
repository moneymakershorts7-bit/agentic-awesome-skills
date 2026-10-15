"""Stream Output Utility Module"""
import sys
import time
import logging
import hashlib
import re


class StreamOutput:
    """Stream output manager, outputs detection progress to stderr
    
    Design principle: All output is unified through logger handlers to avoid duplicate output.
    Logger is configured with stderr handler and file handler, automatically dispatching to terminal and file.
    
    Note: If logger has no handlers configured (e.g., test environment), falls back to direct stderr output.
    """

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.logger = logging.getLogger("sec-userspace")
        # Check whether logger has handler configuration
        self._has_handler = len(self.logger.handlers) > 0
        # Deduplication cache: {content_hash: last_output_time}
        self._dedup_cache = {}
        self._dedup_window = 10.0  # 10-second deduplication window - increased to reduce duplicate output

    def _get_timestamp(self) -> str:
        """Get current timestamp in HH:MM:SS format"""
        return time.strftime("%H:%M:%S")

    def _write_stderr(self, message: str):
        """Internal method, writes messages to stderr (only used when no handler)"""
        if not self.quiet:
            sys.stderr.write(message + "\n")
            sys.stderr.flush()

    def info(self, message: str):
        """Output INFO level message"""
        timestamp = self._get_timestamp()
        formatted = f"[{timestamp}] [INFO] {message}"
        if self._has_handler:
            self.logger.info(formatted)
        else:
            self._write_stderr(formatted)

    def warn(self, message: str):
        """Output WARN level message"""
        timestamp = self._get_timestamp()
        formatted = f"[{timestamp}] [WARN] {message}"
        if self._has_handler:
            self.logger.warning(formatted)
        else:
            self._write_stderr(formatted)

    def warning(self, message: str):
        """Output WARN level message (alias for warn)."""
        self.warn(message)

    def critical(self, message: str):
        """Output CRITICAL level message"""
        timestamp = self._get_timestamp()
        formatted = f"[{timestamp}] [CRITICAL] {message}"
        if self._has_handler:
            self.logger.critical(formatted)
        else:
            self._write_stderr(formatted)

    def error(self, message: str):
        """Output ERROR level message"""
        timestamp = self._get_timestamp()
        formatted = f"[{timestamp}] [ERROR] {message}"
        if self._has_handler:
            self.logger.error(formatted)
        else:
            self._write_stderr(formatted)

    def progress(self, step: int, total: int, module_name: str, status: str, detail: str = ""):
        """Progress output
        Format: [HH:MM:SS] [INFO] [1/8] Collecting process info... complete (collected 156 processes, 0.3s)
        """
        timestamp = self._get_timestamp()
        if detail:
            formatted = f"[{timestamp}] [INFO] [{step}/{total}] {module_name}... {status} ({detail})"
        else:
            formatted = f"[{timestamp}] [INFO] [{step}/{total}] {module_name}... {status}"
        if self._has_handler:
            self.logger.info(formatted)
        else:
            self._write_stderr(formatted)

    def _normalize_message(self, message: str) -> str:
        """Normalize message content for deduplication comparison
        
        Removes variable parts (such as specific values, paths), preserving core semantics.
        Examples:
        - "/home/user/.ssh/id_rsa" -> "~/.ssh/id_rsa"  
        - "entropy 4.52" -> "entropy X"
        - "process 12345" -> "process PID"
        
        Enhanced deduplication: removes more variable parts that may cause duplicates
        """
        normalized = message
        
        # Replace username in specific file paths
        normalized = re.sub(r'/home/[^/]+/', '~/ ', normalized)
        
        # Replace other user directory paths
        normalized = re.sub(r'/root/', '~/root/', normalized)
        normalized = re.sub(r'/var/log/[^/\s]+', '/var/log/SERVICE', normalized)
        
        # Replace specific numbers (entropy values, ports, etc.)
        normalized = re.sub(r'\b\d+\.\d+\b', 'X', normalized)  # decimal
        normalized = re.sub(r'\b\d{2,}\b', 'N', normalized)  # multi-digit integers
        
        # Replace specific PIDs
        normalized = re.sub(r'进程 \d+', '进程 PID', normalized)
        normalized = re.sub(r'PID[=:\s]+\d+', 'PID=N', normalized, flags=re.IGNORECASE)
        
        # Replace specific IP addresses
        normalized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'X.X.X.X', normalized)
        
        # Replace timestamps and dates
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}', 'DATE', normalized)
        normalized = re.sub(r'\d{2}:\d{2}:\d{2}', 'TIME', normalized)
        
        # Replace hash values and tokens (long character strings)
        normalized = re.sub(r'[a-f0-9]{32,}', 'HASH', normalized, flags=re.IGNORECASE)
        
        # Replace credential values (asterisk or masked parts)
        normalized = re.sub(r'[A-Za-z0-9_-]{20,}', 'CREDENTIAL', normalized)
        
        return normalized

    def _get_content_hash(self, content: str) -> str:
        """Compute content hash for deduplication"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]

    def finding(self, severity: str, message: str):
        """Discovery output
        Format: [HH:MM:SS] [severity] [Finding] message
        
        Note: Output is unified through logger, dispatched to stderr and file by handlers.
        Deduplication mechanism:
        1. Normalize message content (remove variable parts like paths, values)
        2. Same content is output only once within the deduplication window
        3. Clean up expired cache entries (older than 10 seconds)
        """
        # normalize message for dedup comparison
        normalized_msg = self._normalize_message(message)
        content_hash = self._get_content_hash(f"{severity}:{normalized_msg}")
        current_time = time.monotonic()
        
        # Clean up expired cache entries (older than 30 seconds) - increased window for better dedup
        expired_keys = [k for k, v in self._dedup_cache.items() 
                       if current_time - v > 30.0]
        for k in expired_keys:
            del self._dedup_cache[k]
        
        if content_hash in self._dedup_cache:
            last_output = self._dedup_cache[content_hash]
            if current_time - last_output < self._dedup_window:
                # Within deduplication window, skip output
                return
        
        # update cache and output
        self._dedup_cache[content_hash] = current_time
        
        timestamp = self._get_timestamp()
        formatted = f"[{timestamp}] [{severity}] [发现] {message}"
        if self._has_handler:
            self.logger.info(formatted)
        else:
            self._write_stderr(formatted)
