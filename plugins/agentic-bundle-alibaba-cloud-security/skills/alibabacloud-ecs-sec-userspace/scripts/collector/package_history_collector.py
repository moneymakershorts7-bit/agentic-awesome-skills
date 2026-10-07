"""Package history collector"""
import gc
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any

from .base import BaseCollector, safe_run_command
from ..utils.hook_detector import get_hook_detector
import threading
_lazy_init_lock = threading.Lock()

_logger = None

_PACKAGE_HISTORY_BATCH_GC_THRESHOLD_DEFAULT = 10


def _get_logger():
    """Lazy logger initialization to avoid importing logging at module load."""
    global _logger
    if _logger is None:
        with _lazy_init_lock:
            if _logger is None:
                import logging
                _logger = logging.getLogger("sec-userspace")
    return _logger

class PackageHistoryCollector(BaseCollector):
    """Collect installed package history and metadata
    
    Supports:
    - npm: npm list, package.json
    - pip: pip list, pip freeze
    - apt: dpkg-query, apt list
    - yum/rpm: rpm -qa
    - go: go list
    - cargo: cargo tree
    """
    
    name = "package_history"
    
    def __init__(self):
        """Initialize package history collector"""
        super().__init__()
        self.hook_detector = get_hook_detector()
        
        self.timeout = self._get_config("timeout", 120)
        self._batch_gc_interval = self._get_config("batch_gc_interval", _PACKAGE_HISTORY_BATCH_GC_THRESHOLD_DEFAULT)
        self._package_managers = self._get_config("package_managers", ["dpkg", "rpm", "pip", "npm", "gem", "cargo"])
    
    def collect(self) -> Dict[str, Any]:
        """Collect package installation history
        
        Returns:
            Dict with:
            {
                "installed_packages": [...],
                "recent_installs": [...],
                "install_hooks": {...},
                "package_managers_detected": [...]
            }
        """
        result = {
            "installed_packages": [],
            "recent_installs": [],
            "install_hooks": {},
            "package_managers_detected": [],
            "collection_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Collect from npm
        try:
            npm_packages = self._collect_npm_packages()
            if npm_packages:
                result["package_managers_detected"].append("npm")
                result["installed_packages"].extend(npm_packages)
            del npm_packages  # P3-2026-04-22: Explicit memory release
            gc.collect()  # P3-2026-04-22: Batch GC
        except (OSError, ValueError) as e:
            _get_logger().debug(f"Failed to collect npm packages: {e}")
        
        # Collect from pip
        try:
            pip_packages = self._collect_pip_packages()
            if pip_packages:
                result["package_managers_detected"].append("pip")
                result["installed_packages"].extend(pip_packages)
            del pip_packages  # P3-2026-04-22: Explicit memory release
            gc.collect()  # P3-2026-04-22: Batch GC
        except (OSError, ValueError) as e:
            _get_logger().debug(f"Failed to collect pip packages: {e}")
        
        # Collect from apt
        try:
            apt_packages = self._collect_apt_packages()
            if apt_packages:
                result["package_managers_detected"].append("apt")
                result["installed_packages"].extend(apt_packages)
            del apt_packages  # P3-2026-04-22: Explicit memory release
            gc.collect()  # P3-2026-04-22: Batch GC
        except (OSError, ValueError) as e:
            _get_logger().debug(f"Failed to collect apt packages: {e}")
        
        # Collect from yum/rpm
        try:
            rpm_packages = self._collect_rpm_packages()
            if rpm_packages:
                result["package_managers_detected"].append("rpm")
                result["installed_packages"].extend(rpm_packages)
            del rpm_packages  # P3-2026-04-22: Explicit memory release
            gc.collect()  # P3-2026-04-22: Batch GC
        except (OSError, ValueError) as e:
            _get_logger().debug(f"Failed to collect rpm packages: {e}")
        
        # Collect from go modules
        try:
            go_packages = self._collect_go_modules()
            if go_packages:
                result["package_managers_detected"].append("go")
                result["installed_packages"].extend(go_packages)
            del go_packages  # P3-2026-04-22: Explicit memory release
            gc.collect()  # P3-2026-04-22: Batch GC
        except (OSError, ValueError) as e:
            _get_logger().debug(f"Failed to collect go modules: {e}")
        
        # Detect recent installs (last 7 days)
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        result["recent_installs"] = [
            pkg for pkg in result["installed_packages"]
            if self._is_recent_install(pkg, seven_days_ago)
        ]
        
        # Scan for install hooks in common locations
        result["install_hooks"] = self._scan_for_hooks()
        
        _get_logger().info(f"Collected {len(result['installed_packages'])} packages from {len(result['package_managers_detected'])} package managers")
        
        gc.collect()
        
        return result
    
    def _collect_npm_packages(self) -> List[Dict[str, Any]]:
        """Collect npm packages
        
        Returns:
            List of npm package info
        """
        packages = []
        
        # Try global npm list
        try:
            cmd = ["npm", "list", "-g", "--json"]
            proc = safe_run_command(cmd, timeout=30)
            if proc and proc.returncode == 0:
                data = json.loads(proc.stdout)
                packages.extend(self._parse_npm_list(data, is_global=True))
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        
        # Try local npm list in common directories
        common_dirs = ["/var/www", "/opt", "/home"]
        for base_dir in common_dirs:
            try:
                p = Path(base_dir)
                for package_json in p.rglob("package.json"):
                    if "node_modules" not in str(package_json):
                        continue
                    
                    try:
                        with open(package_json, 'r', encoding='utf-8') as f:
                            pkg_data = json.load(f)
                        
                        packages.append({
                            "name": pkg_data.get("name", "unknown"),
                            "version": pkg_data.get("version", "unknown"),
                            "package_manager": "npm",
                            "location": str(package_json.parent),
                            "metadata": {
                                "description": pkg_data.get("description", ""),
                                "author": pkg_data.get("author", ""),
                                "repository": pkg_data.get("repository", "")
                            },
                            "source": "local"
                        })
                    except (json.JSONDecodeError, OSError):
                        pass
            except OSError:
                pass
        
        return packages
    
    def _parse_npm_list(self, data: Dict, is_global: bool = False) -> List[Dict[str, Any]]:
        """Parse npm list output
        
        Args:
            data: Parsed npm list JSON
            is_global: Whether this is global packages
            
        Returns:
            List of package info
        """
        packages = []
        
        if "dependencies" in data:
            for name, info in data["dependencies"].items():
                if isinstance(info, dict):
                    packages.append({
                        "name": name,
                        "version": info.get("version", "unknown"),
                        "package_manager": "npm",
                        "location": "global" if is_global else "local",
                        "metadata": {},
                        "source": "official"
                    })
                    
                    # Recurse into nested dependencies
                    if "dependencies" in info:
                        packages.extend(self._parse_npm_list(
                            {"dependencies": info["dependencies"]},
                            is_global=is_global
                        ))
        
        return packages
    
    def _collect_pip_packages(self) -> List[Dict[str, Any]]:
        """Collect pip packages
        
        Returns:
            List of pip package info
        """
        packages = []
        
        try:
            # Use pip list with JSON output
            cmd = ["pip", "list", "--format=json"]
            proc = safe_run_command(cmd, timeout=30)
            if proc and proc.returncode == 0:
                data = json.loads(proc.stdout)
                for pkg in data:
                    packages.append({
                        "name": pkg.get("name", "unknown"),
                        "version": pkg.get("version", "unknown"),
                        "package_manager": "pip",
                        "location": "system",
                        "metadata": {},
                        "source": "official"
                    })
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        
        # Also try pip freeze for additional info
        try:
            cmd = ["pip", "freeze"]
            proc = safe_run_command(cmd, timeout=30)
            if proc and proc.returncode == 0:
                # Parse freeze output
                for line in proc.stdout.strip().split('\n'):
                    if '==' in line:
                        name, version = line.split('==', 1)
                        # Update existing or add new
                        for pkg in packages:
                            if pkg["name"] == name:
                                pkg["version"] = version
                                break
        except FileNotFoundError:
            pass
        
        return packages
    
    def _collect_apt_packages(self) -> List[Dict[str, Any]]:
        """Collect apt/dpkg packages
        
        Returns:
            List of apt package info
        """
        packages = []
        
        try:
            # Use dpkg-query for installed packages
            cmd = ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"]
            proc = safe_run_command(cmd, timeout=60)
            if proc and proc.returncode == 0:
                for line in proc.stdout.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 3 and "install ok installed" in parts[2]:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "package_manager": "apt",
                            "location": "system",
                            "metadata": {},
                            "source": "official"
                        })
        except (FileNotFoundError, PermissionError):
            pass
        
        return packages
    
    def _collect_rpm_packages(self) -> List[Dict[str, Any]]:
        """Collect rpm packages
        
        Returns:
            List of rpm package info
        """
        packages = []
        
        try:
            cmd = ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"]
            proc = safe_run_command(cmd, timeout=60)
            if proc and proc.returncode == 0:
                for line in proc.stdout.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        packages.append({
                            "name": parts[0],
                            "version": parts[1],
                            "package_manager": "rpm",
                            "location": "system",
                            "metadata": {},
                            "source": "official"
                        })
        except (FileNotFoundError, PermissionError):
            pass
        
        return packages
    
    def _collect_go_modules(self) -> List[Dict[str, Any]]:
        """Collect go modules
        
        Returns:
            List of go module info
        """
        packages = []
        
        # Check common go project locations
        go_dirs = [
            Path("/opt/go"),
            Path("/home").expanduser() / "go",
            Path.cwd()
        ]
        
        for go_dir in go_dirs:
            go_mod = go_dir / "go.mod"
            if go_mod.exists():
                try:
                    cmd = ["go", "list", "-m", "-json", "all"]
                    proc = safe_run_command(cmd, timeout=60, cwd=go_dir)
                    if proc and proc.returncode == 0:
                        # Parse JSON stream
                        for block in proc.stdout.strip().split('\n\n'):
                            if block.strip():
                                try:
                                    mod = json.loads(block)
                                    packages.append({
                                        "name": mod.get("Path", "unknown"),
                                        "version": mod.get("Version", "unknown"),
                                        "package_manager": "go",
                                        "location": str(go_dir),
                                        "metadata": {
                                            "indirect": mod.get("Indirect", False)
                                        },
                                        "source": "official"
                                    })
                                except json.JSONDecodeError:
                                    pass
                except FileNotFoundError:
                    pass
        
        return packages
    
    def _is_recent_install(self, pkg: Dict[str, Any], since: datetime) -> bool:
        """Check if package was installed recently
        
        Args:
            pkg: Package info
            since: Datetime threshold
            
        Returns:
            True if recently installed
        """
        # For now, consider all packages as potentially recent
        # In production, would check install timestamps
        return True
    
    def _scan_for_hooks(self) -> Dict[str, Any]:
        """Scan for installation hooks in common locations
        
        Returns:
            Dict with hook detection results
        """
        hooks = {}
        
        # Scan npm packages for hooks
        npm_dirs = [
            Path("/var/www/node_modules"),
            Path("/opt/node_modules"),
        ]
        
        for base_dir in npm_dirs:
            if base_dir.exists():
                try:
                    for package_json in base_dir.rglob("package.json"):
                        if "node_modules" in str(package_json):
                            hook_result = self.hook_detector.detect_npm_hooks(str(package_json))
                            if hook_result.get("hooks_found"):
                                pkg_name = package_json.parent.name
                                hooks[pkg_name] = hook_result
                except OSError:
                    pass
        
        return hooks

# Export for use
def create_collector() -> PackageHistoryCollector:
    """Create package history collector instance
    
    Returns:
        PackageHistoryCollector instance
    """
    return PackageHistoryCollector()
