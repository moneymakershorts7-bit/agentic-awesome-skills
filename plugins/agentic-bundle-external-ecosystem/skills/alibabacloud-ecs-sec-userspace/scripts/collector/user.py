"""User and Authentication Information Collector"""
import hashlib
import os
import stat
from .base import BaseCollector
import threading
_lazy_init_lock = threading.Lock()

_logger = None


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

def _hash_sensitive(value: str) -> str:
    """SHA256 hash a sensitive value (retain first 16 characters)"""
    if not value:
        return ""
    return hashlib.sha256(value.encode()).hexdigest()[:16]

class UserCollector(BaseCollector):
    """User and Authentication Information Collector"""
    name = "user"

    def __init__(self):
        """Initialize user collector with config-driven settings"""
        super().__init__()
        
        self._sudoers_limit = self._get_config("max_sudoers", 100)
        self._scan_sudoers_d = True
        
        self._max_auth_keys_file_size = self._get_config("max_auth_keys_file_size", 1048576)
        self._max_sshd_config_size = self._get_config("max_sshd_config_size", 1048576)
        self._max_shadow_size = self._get_config("max_shadow_size", 1048576)
        
        self._paths = self._get_config("paths", {})
        
        self.timeout = self._get_config("timeout", 30)

    def collect(self) -> dict:
        """Collect user and authentication information"""
        result = {
            "users": [],
            "uid0_users": [],
            "nologin_bypass": [],
            "ssh_authorized_keys": [],
            "sshd_config": {},
            "sudoers_entries": [],
            "shadow_permissions": "",
        }
        
        # 1.1 Parse /etc/passwd
        result["users"] = self._parse_passwd()
        
        # 1.2 Check users with UID=0
        result["uid0_users"] = [u["username"] for u in result["users"] if u["uid"] == 0]
        
        # 1.3 Check nologin bypass
        result["nologin_bypass"] = [
            u["username"] for u in result["users"]
            if u["uid"] < 1000 and u["shell"] not in ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]
        ]
        
        # 1.4 Collect SSH authorized_keys (reuse parsed user data to avoid re-reading /etc/passwd)
        result["ssh_authorized_keys"] = self._collect_ssh_keys(result["users"])
        
        # 1.5 Parse sshd_config
        result["sshd_config"] = self._parse_sshd_config()
        
        # 1.6 Collect sudoers entries (limited in quick mode)
        result["sudoers_entries"] = self._collect_sudoers()
        
        # 1.7 Check shadow file permissions
        try:
            shadow_stat = os.stat("/etc/shadow")
            result["shadow_permissions"] = oct(stat.S_IMODE(shadow_stat.st_mode))
        except (FileNotFoundError, PermissionError):
            result["shadow_permissions"] = ""
        
        return result

    def _parse_passwd(self) -> list:
        """Parse /etc/passwd file"""
        users = []
        try:
            with open("/etc/passwd", "r", errors='replace', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) == 7:
                        users.append({
                            "username": parts[0],
                            "uid": int(parts[2]),
                            "gid": int(parts[3]),
                            "home": parts[5],
                            "shell": parts[6],
                        })
        except (FileNotFoundError, PermissionError):
            pass
        return users

    def _collect_ssh_keys(self, users: list) -> list:
        """Collect SSH authorized_keys (reuse parsed user data)"""
        ssh_keys = []
        for user_info in users:
            home = user_info.get("home", "")
            username = user_info.get("username", "")
            if not home or not username:
                continue
            auth_keys_path = os.path.join(home, ".ssh", "authorized_keys")
            
            if os.path.exists(auth_keys_path):
                try:
                    # Check file size to prevent OOM
                    file_size = os.path.getsize(auth_keys_path)
                    if file_size > self._max_auth_keys_file_size:
                        _get_logger().debug(f"authorized_keys file too large ({file_size}B), skipping: {auth_keys_path}")
                        continue
                    
                    with open(auth_keys_path, "r", errors='replace', encoding='utf-8') as key_file:
                        keys = []
                        for key_line in key_file:
                            key_line = key_line.strip()
                            if key_line and not key_line.startswith("#"):
                                raw_line = key_line
                                key_parts = key_line.split(None, 2)
                                key_type = ""
                                comment = ""
                                if len(key_parts) >= 2:
                                    key_type = key_parts[0]
                                    comment = key_parts[2] if len(key_parts) > 2 else ""
                                keys.append({
                                    "type": key_type,
                                    "fingerprint": _hash_sensitive(raw_line) if raw_line else "",
                                    "comment": comment,
                                    "raw_line_truncated": raw_line[:50] if raw_line else "",
                                })
                        
                        ssh_keys.append({
                            "user": username,
                            "path": auth_keys_path,
                            "key_count": len(keys),
                            "keys": keys,
                        })
                except (PermissionError, FileNotFoundError):
                    pass
        return ssh_keys

    def _parse_sshd_config(self) -> dict:
        """Parse sshd_config"""
        config_path = self._paths.get("sshd_config", "/etc/ssh/sshd_config")
        config = {}
        
        try:
            with open(config_path, "r", errors='replace', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        config[key.lower()] = value
        except (FileNotFoundError, PermissionError):
            pass
        
        return {
            "permit_root_login": config.get("permitrootlogin", ""),
            "password_authentication": config.get("passwordauthentication", ""),
            "pubkey_authentication": config.get("pubkeyauthentication", ""),
            "port": config.get("port", ""),
            "allow_tcp_forwarding": config.get("allowtcpforwarding", ""),
            "gateway_ports": config.get("gatewayports", ""),
            "permit_tunnel": config.get("permittunnel", ""),
            "raw_path": config_path,
        }

    def _collect_sudoers(self) -> list:
        """Collect sudoers entries"""
        entries = []
        
        # Read /etc/sudoers
        sudoers_path = self._paths.get("sudoers", "/etc/sudoers")
        try:
            with open(sudoers_path, "r", errors='replace', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("Defaults"):
                        entries.append(line)
                        # Apply limit
                        if len(entries) >= self._sudoers_limit:
                            _get_logger().debug(
                                f"User collector: sudoers limit reached ({self._sudoers_limit})"
                            )
                            break
        except (FileNotFoundError, PermissionError):
            pass
        
        # Read /etc/sudoers.d/*
        sudoers_d = self._paths.get("sudoers_d", "/etc/sudoers.d")
        try:
            if os.path.isdir(sudoers_d):
                for filename in os.listdir(sudoers_d):
                    filepath = os.path.join(sudoers_d, filename)
                    if os.path.isfile(filepath):
                        try:
                            with open(filepath, "r", errors='replace', encoding='utf-8') as f:
                                for line in f:
                                    line = line.strip()
                                    if line and not line.startswith("#"):
                                        entries.append(line)
                                        # Apply limit
                                        if len(entries) >= self._sudoers_limit:
                                            _get_logger().debug(
                                                f"User collector: sudoers limit reached ({self._sudoers_limit})"
                                            )
                                            break
                        except (PermissionError, FileNotFoundError):
                            pass
                    if len(entries) >= self._sudoers_limit:
                        break
        except (PermissionError, FileNotFoundError):
            pass
        
        return entries
