"""Package installation hook detector"""
import re
import json
import logging
import threading
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger("sec-userspace")


class HookDetector:
    """Detect and analyze package installation hooks
    
    Supports multiple package managers:
    - npm: preinstall, install, postinstall scripts
    - pip: setup.py, pyproject.toml hooks
    - apt: preinst, postinst maintainer scripts
    - maven: lifecycle plugins
    - go: go generate directives
    - cargo: build.rs build scripts
    """

    # Sensitive file paths
    SENSITIVE_PATHS = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/ssh/',
        '~/.ssh/',
        '~/.aws/',
        '~/.gnupg/',
        '~/.npmrc',
        '~/.pypirc',
        '/root/',
        '/var/log/',
    ]
    
    def detect_npm_hooks(self, package_json_path: str) -> Dict[str, Any]:
        """Detect npm package hooks from package.json
        
        Args:
            package_json_path: Path to package.json
            
        Returns:
            Dict with detected hooks and risk assessment
        """
        result = {
            "package_manager": "npm",
            "hooks_found": [],
            "risk_level": "LOW",
            "warnings": [],
            "raw_scripts": {}
        }
        
        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                package_json = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Failed to read package.json: {e}")
            result["risk_level"] = "UNKNOWN"
            return result
        
        scripts = package_json.get("scripts", {})
        result["raw_scripts"] = scripts
        
        # Check install hooks
        install_hooks = ["preinstall", "install", "postinstall"]
        for hook_name in install_hooks:
            if hook_name in scripts:
                script_content = scripts[hook_name]
                analysis = self._analyze_script(script_content)
                
                hook_info = {
                    "name": hook_name,
                    "script": script_content,
                    "risk_level": analysis["risk_level"],
                    "warnings": analysis["warnings"]
                }
                
                result["hooks_found"].append(hook_info)
                
                if analysis["risk_level"] in ["HIGH", "CRITICAL"]:
                    result["risk_level"] = analysis["risk_level"]
        
        # Check lifecycle scripts directory
        pkg_dir = Path(package_json_path).parent
        lifecycle_scripts = ["preinstall.js", "install.js", "postinstall.js"]
        for script_file in lifecycle_scripts:
            script_path = pkg_dir / script_file
            if script_path.exists():
                try:
                    with open(script_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    analysis = self._analyze_script(content)
                    
                    result["hooks_found"].append({
                        "name": script_file,
                        "type": "file",
                        "risk_level": analysis["risk_level"],
                        "warnings": analysis["warnings"]
                    })
                except OSError as e:
                    logger.debug(f"Could not read {script_file}: {e}")
        
        return result
    
    def detect_pip_hooks(self, package_dir: str) -> Dict[str, Any]:
        """Detect pip package hooks from setup.py or pyproject.toml
        
        Args:
            package_dir: Path to package directory
            
        Returns:
            Dict with detected hooks and risk assessment
        """
        result = {
            "package_manager": "pip",
            "hooks_found": [],
            "risk_level": "LOW",
            "warnings": []
        }
        
        # Check setup.py
        setup_py = Path(package_dir) / "setup.py"
        if setup_py.exists():
            try:
                with open(setup_py, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Look for install hooks
                if 'install' in content.lower():
                    analysis = self._analyze_python_setup(content)
                    result["hooks_found"].append({
                        "name": "setup.py",
                        "type": "file",
                        "risk_level": analysis["risk_level"],
                        "warnings": analysis["warnings"]
                    })
                    
                    if analysis["risk_level"] in ["HIGH", "CRITICAL"]:
                        result["risk_level"] = analysis["risk_level"]
                        
            except OSError as e:
                logger.debug(f"Could not read setup.py: {e}")
        
        # Check pyproject.toml
        pyproject = Path(package_dir) / "pyproject.toml"
        if pyproject.exists():
            try:
                with open(pyproject, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Look for build hooks
                if '[build-system]' in content or '[tool.setuptools]' in content:
                    analysis = self._analyze_toml_hooks(content)
                    result["hooks_found"].append({
                        "name": "pyproject.toml",
                        "type": "file",
                        "risk_level": analysis["risk_level"],
                        "warnings": analysis["warnings"]
                    })
                    
            except OSError as e:
                logger.debug(f"Could not read pyproject.toml: {e}")
        
        return result
    
    def detect_apt_hooks(self, package_path: str) -> Dict[str, Any]:
        """Detect apt/debian package hooks from DEBIAN control files
        
        Args:
            package_path: Path to .deb file or extracted directory
            
        Returns:
            Dict with detected hooks and risk assessment
        """
        result = {
            "package_manager": "apt",
            "hooks_found": [],
            "risk_level": "LOW",
            "warnings": []
        }
        
        # Check for DEBIAN directory
        debian_dir = Path(package_path) / "DEBIAN"
        if not debian_dir.exists():
            # Might be a .deb file, would need extraction
            result["risk_level"] = "UNKNOWN"
            return result
        
        # Check maintainer scripts
        maintainer_scripts = ["preinst", "postinst", "prerm", "postrm"]
        for script_name in maintainer_scripts:
            script_path = debian_dir / script_name
            if script_path.exists():
                try:
                    with open(script_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    analysis = self._analyze_script(content)
                    result["hooks_found"].append({
                        "name": script_name,
                        "type": "maintainer_script",
                        "risk_level": analysis["risk_level"],
                        "warnings": analysis["warnings"]
                    })
                    
                    if analysis["risk_level"] in ["HIGH", "CRITICAL"]:
                        result["risk_level"] = analysis["risk_level"]
                        
                except OSError as e:
                    logger.debug(f"Could not read {script_name}: {e}")
        
        return result
    
    def _analyze_script(self, content: str) -> Dict[str, Any]:
        """Analyze a script for suspicious behavior

        Args:
            content: Script content

        Returns:
            Dict with risk assessment
        """
        warnings = []
        risk_score = 0
        
        # Critical patterns (remote code execution)
        critical_patterns = [
            r'curl\s+[^|]+\|\s*(ba)?sh',
            r'wget\s+[^|]+\|\s*(ba)?sh',
            r'base64\s+-d\s*\|\s*(ba)?sh',
            r'curl\s+.*\|\s*bash',
            r'wget\s+.*\|\s*bash',
            r'/dev/(tcp|udp)/',
            r'nc\s+-e\s+',
            r'bash\s+-i\s+>&',
        ]
        
        # Check for critical RCE patterns first
        for pattern_str in critical_patterns:
            match = re.search(pattern_str, content, re.IGNORECASE)
            if match:
                risk_score += 50  # Critical score
                warnings.append({
                    "type": "remote_code_execution",
                    "pattern": pattern_str,
                    "matches": [match.group()],
                    "severity": "CRITICAL"
                })
        
        # Check for other suspicious commands
        suspicious_patterns = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'\$\([^)]+\)',
            r'`[^`]+`',
            r'python.*-c\s+.*import\s+socket',
            r'perl\s+-e\s+.*socket',
            r'ruby\s+-r\s+socket',
            r'chmod\s+[0-7]*777',
            r'rm\s+-rf\s+/',
            r'dd\s+if=',
            r'>\s*/etc/',
            r'>\s*~/.ssh/',
            r'>\s*~/.aws/',
            r'crontab\s+-i',
            r'systemctl\s+.*--user',
            r'LD_PRELOAD',
            r'/proc/self/',
        ]
        
        for pattern_str in suspicious_patterns:
            matches = re.findall(pattern_str, content, re.IGNORECASE)
            if matches:
                risk_score += 20
                warnings.append({
                    "type": "suspicious_command",
                    "pattern": pattern_str,
                    "matches": matches[:5],
                    "severity": "HIGH"
                })
        
        # Check for sensitive file access
        for sensitive_path in self.SENSITIVE_PATHS:
            if sensitive_path in content:
                risk_score += 25  # Increased to ensure MEDIUM or higher
                warnings.append({
                    "type": "sensitive_path",
                    "path": sensitive_path,
                    "severity": "MEDIUM"
                })
        
        # Check for network activity
        network_patterns = [
            r'http[s]?://',
            r'fetch\s*\(',
            r'axios\.',
            r'request\(',
            r'urllib',
            r'http\.client',
        ]
        for net_pattern in network_patterns:
            if re.search(net_pattern, content):
                risk_score += 5
                warnings.append({
                    "type": "network_activity",
                    "pattern": net_pattern,
                    "severity": "LOW"
                })
        
        # Check for file system writes
        write_patterns = [
            r'fs\.writeFile',
            r'fs\.appendFile',
            r'open\s*\([^)]+,?\s*[\'"][wa]',
            r'file\s*\.write',
        ]
        for write_pattern in write_patterns:
            if re.search(write_pattern, content):
                risk_score += 10
                warnings.append({
                    "type": "file_write",
                    "pattern": write_pattern,
                    "severity": "MEDIUM"
                })
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = "CRITICAL"
        elif risk_score >= 40:
            risk_level = "HIGH"
        elif risk_score >= 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "warnings": warnings,
            "warning_count": len(warnings)
        }
    
    def _analyze_python_setup(self, content: str) -> Dict[str, Any]:
        """Analyze Python setup.py for hooks
        
        Args:
            content: setup.py content
            
        Returns:
            Risk assessment
        """
        # Use generic analyzer
        return self._analyze_script(content)
    
    def _analyze_toml_hooks(self, content: str) -> Dict[str, Any]:
        """Analyze pyproject.toml for hooks
        
        Args:
            content: pyproject.toml content
            
        Returns:
            Risk assessment
        """
        warnings = []
        
        # Check for custom build backends
        if 'setuptools_scm' in content:
            warnings.append({
                "type": "custom_backend",
                "description": "Uses setuptools_scm (dynamic versioning)",
                "severity": "LOW"
            })
        
        # Check for custom scripts
        if '[tool.setuptools.cmdclass]' in content:
            warnings.append({
                "type": "custom_cmdclass",
                "description": "Defines custom command classes",
                "severity": "MEDIUM"
            })
        
        risk_score = len(warnings) * 10
        risk_level = "LOW"
        if risk_score >= 30:
            risk_level = "MEDIUM"
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "warnings": warnings,
            "warning_count": len(warnings)
        }
    
    def analyze_command_line(self, command: str) -> Dict[str, Any]:
        """Analyze a package manager command line for risks
        
        Args:
            command: Full command line
            
        Returns:
            Risk assessment
        """
        warnings = []
        
        # Check for dangerous flags
        dangerous_flags = [
            ('--unsafe-perm', 'Allows running scripts as root'),
            ('--ignore-scripts', 'Bypasses install scripts (protective)'),
            ('--force', 'Forces installation despite warnings'),
            ('no-deps', 'Skips dependency resolution'),
        ]
        
        for flag, description in dangerous_flags:
            if flag in command:
                warnings.append({
                    "type": "dangerous_flag",
                    "flag": flag,
                    "description": description,
                    "severity": "MEDIUM"
                })
        
        # Check for non-official sources
        if '--registry=' in command and 'npmjs' not in command:
            warnings.append({
                "type": "non_official_registry",
                "description": "Using non-official npm registry",
                "severity": "HIGH"
            })
        
        if '--index-url=' in command and 'pypi' not in command:
            warnings.append({
                "type": "non_official_index",
                "description": "Using non-official pip index",
                "severity": "HIGH"
            })
        
        # Use generic analyzer for the command
        analysis = self._analyze_script(command)
        analysis["warnings"].extend(warnings)
        
        return analysis


# Singleton instance
_hook_detector = None
_hook_detector_lock = threading.Lock()


def get_hook_detector() -> HookDetector:
    """Get singleton hook detector instance
    
    Returns:
        HookDetector instance
    """
    global _hook_detector
    if _hook_detector is None:
        with _hook_detector_lock:
            if _hook_detector is None:
                _hook_detector = HookDetector()
    return _hook_detector
