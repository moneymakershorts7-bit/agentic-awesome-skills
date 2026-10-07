"""FileVerifier - Verify file-related alerts

Verifies:
- File existence and hash validation
- Package manager ownership
- Known legitimate file patterns
- Whitelist matching
"""
import os
import logging
from typing import Dict, Optional, Set

from ..evidence import Evidence

logger = logging.getLogger("sec-userspace")


class FileVerifier:
    """Verify file-related security alerts"""
    
    def __init__(self, collected_data: Optional[Dict] = None):
        """Initialize file verifier
        
        Args:
            collected_data: Collected data from collectors
        """
        self.collected_data = collected_data or {}
        self.whitelist_hashes = self._load_whitelist_hashes()
        self.legitimate_paths = self._get_legitimate_paths()
    
    def _load_whitelist_hashes(self) -> Set[str]:
        """Load known good file hashes
        
        Returns:
            Set of known good file hashes
        """
        # In production, this would load from threat intel database
        # For now, return empty set
        return set()
    
    def _get_legitimate_paths(self) -> Dict[str, list]:
        """Get known legitimate file paths by type
        
        Returns:
            Dict mapping file type to list of path patterns
        """
        return {
            'system_binaries': [
                '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/',
                '/lib/', '/lib64/', '/usr/lib/', '/usr/lib64/',
            ],
            'config_files': [
                '/etc/',
            ],
            'python_packages': [
                '/usr/lib/python3/', '/usr/local/lib/python3/',
                '/home/*/.local/lib/python3/',
            ],
            'node_modules': [
                '/usr/lib/node_modules/', '/home/*/node_modules/',
            ],
            'logs': [
                '/var/log/',
            ],
            'tmp': [
                '/tmp/', '/var/tmp/',
            ],
        }
    
    def verify(self, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify file-related evidence
        
        Args:
            evidence: Evidence to verify
            
        Returns:
            VerifyCheckResult: Verification result
        """
        from .process_verifier import VerifyCheckResult
        
        raw_data = evidence.raw_data or {}
        
        # Check by file path
        path = raw_data.get('path') or raw_data.get('file') or raw_data.get('filename')
        if path:
            return self._verify_by_path(path, evidence)
        
        # Check by file hash
        file_hash = raw_data.get('hash') or raw_data.get('sha256') or raw_data.get('md5')
        if file_hash:
            return self._verify_by_hash(file_hash, evidence)
        
        # No file indicators found
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason="No file indicators to verify"
        )
    
    def _verify_by_path(self, path: str, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify by file path
        
        Args:
            path: File path to check
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        # Check if file exists
        file_exists = os.path.isfile(path)
        
        if not file_exists:
            # File doesn't exist - could be cleaned up or historical
            return VerifyCheckResult(
                is_false_positive=False,
                is_confirmed_threat=False,
                reason=f"File {path} no longer exists"
            )
        
        # Check against legitimate path patterns
        for file_type, prefixes in self.legitimate_paths.items():
            if any(path.startswith(prefix) for prefix in prefixes):
                # File is in legitimate location
                if file_type in ['system_binaries', 'config_files']:
                    # Check if owned by package manager
                    if self._is_package_owned(path):
                        return VerifyCheckResult(
                            is_false_positive=True,
                            is_confirmed_threat=False,
                            reason=f"File {path} is owned by system package manager"
                        )
                
                # Check file permissions
                if self._has_suspicious_permissions(path):
                    return VerifyCheckResult(
                        is_false_positive=False,
                        is_confirmed_threat=True,
                        reason=f"File {path} has suspicious permissions"
                    )
                
                return VerifyCheckResult(
                    is_false_positive=False,
                    is_confirmed_threat=False,
                    reason=f"File {path} in legitimate location ({file_type})"
                )
        
        # File in suspicious location (e.g., /tmp, hidden directory)
        suspicious_locations = ['/tmp/', '/var/tmp/', '/dev/shm/', '/._', '/home/./._']
        for susp_loc in suspicious_locations:
            if susp_loc in path or '_tmp' in path.lower():
                # Check if executable
                if os.access(path, os.X_OK):
                    return VerifyCheckResult(
                        is_false_positive=False,
                        is_confirmed_threat=True,
                        reason=f"Executable file in suspicious location: {path}"
                    )
        
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"File {path} requires manual review"
        )
    
    def _verify_by_hash(self, file_hash: str, evidence: Evidence) -> 'VerifyCheckResult':
        """Verify by file hash
        
        Args:
            file_hash: File hash to check
            evidence: Related evidence
            
        Returns:
            VerifyCheckResult: Verification result
        """
        hash_lower = file_hash.lower()
        
        # Check against whitelist
        if hash_lower in self.whitelist_hashes:
            return VerifyCheckResult(
                is_false_positive=True,
                is_confirmed_threat=False,
                reason=f"File hash {file_hash} matches known good whitelist"
            )
        
        # Check against malware databases (would integrate with threat intel in production)
        # For now, just note that hash is unknown
        return VerifyCheckResult(
            is_false_positive=False,
            is_confirmed_threat=False,
            reason=f"File hash {file_hash} unknown (not in whitelist)"
        )
    
    def _is_package_owned(self, path: str) -> bool:
        """Check if file is owned by a package manager
        
        Args:
            path: File path
            
        Returns:
            bool: Whether file is package-owned
        """
        import subprocess
        
        try:
            # Try dpkg (Debian/Ubuntu)
            result = subprocess.run(
                ['dpkg', '-S', path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5
            )
            if result.returncode == 0 and ':' in result.stdout:
                return True
            
            # Try rpm (RHEL/CentOS)
            result = subprocess.run(
                ['rpm', '-qf', path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                timeout=5
            )
            if result.returncode == 0 and 'not owned' not in result.stdout.lower():
                return True
            
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug(f"Package check failed for {path}: {e}")
        
        return False
    
    def _has_suspicious_permissions(self, path: str) -> bool:
        """Check if file has suspicious permissions
        
        Args:
            path: File path
            
        Returns:
            bool: Whether permissions are suspicious
        """
        try:
            stat_info = os.stat(path)
            mode = stat_info.st_mode
            
            # World-writable
            if mode & 0o002:
                return True
            
            # SUID bit on non-standard binary
            if mode & 0o4000:
                # SUID in non-system location is suspicious
                if not any(path.startswith(p) for p in self.legitimate_paths['system_binaries']):
                    return True
            
            # SGID bit
            if mode & 0o2000:
                if not any(path.startswith(p) for p in self.legitimate_paths['system_binaries']):
                    return True
            
        except OSError:
            pass
        
        return False
