"""PAM Backdoor Detection Analyzer"""
import os
import re
import subprocess
from typing import List, Dict, Optional
from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from .base import BaseAnalyzer
from ..utils.i18n import get_attack_tactic_name
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

class PAMBackdoorAnalyzer(BaseAnalyzer):
    """PAM Backdoor Detection Analyzer
    
    Detects PAM (Pluggable Authentication Modules) backdoors including:
    - Module integrity violations
    - Suspicious PAM configurations
    - Hardcoded credentials in PAM modules
    - PAM environment tampering
    
    ATT&CK: T1556.003 (Pluggable Authentication Modules), T1078 (Valid Accounts)
    """
    name = "pam_backdoor_analyzer"
    timeout = 45
    required_collectors = ["filesystem"]
    
    estimated_time = 0.2  # Quick mode: ~0.2s, Full mode: ~1.0s
    analyzer_type = BaseAnalyzer.CRITICAL
    
    PAM_CONFIG_DIR = "/etc/pam.d"
    PAM_MODULE_DIRS = ["/lib64/security", "/lib/security", "/usr/lib64/security", "/usr/lib/security"]
    
    SUSPICIOUS_PAM_PATTERNS = [
        (re.compile(r'sufficient\s+pam_permit\.so', re.IGNORECASE), 
         "pam_permit_sufficient", 
         "pam_permit.so configured as sufficient - can bypass authentication"),
        # NOTE: pam_deny.so as required is legitimate - used to deny access after other checks fail
        # (re.compile(r'required\s+pam_deny\.so', re.IGNORECASE),
        #  "pam_deny_required",
        #  "pam_deny.so configured as required - may block legitimate access"), 
        (re.compile(r'auth\s+sufficient\s+pam_succeed_if\.so\s+.*user\s+in\s+', re.IGNORECASE),
         "pam_succeed_if_user_backdoor",
         "pam_succeed_if.so with user list - possible backdoor user bypass"),
        (re.compile(r'(?:pam_exec\.so|pam_script\.so).*?/dev/null', re.IGNORECASE),
         "pam_dev_null_redirect",
         "PAM exec/script module output redirected to /dev/null - evidence suppression"),
    ]
    
    HARDCODED_CRED_PATTERNS = [
        (re.compile(rb'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
         "hardcoded_password_string",
         "Hardcoded password string detected"),
        (re.compile(rb'(?:root|admin|backdoor)\s*:\s*\$[0-9a-z]+\$.{20,}', re.IGNORECASE),
         "hardcoded_password_hash",
         "Hardcoded password hash detected"),
        (re.compile(rb'pam_sm_authenticate.*(?:return\s+PAM_SUCCESS|return\s+0)', re.IGNORECASE),
         "always_authenticate_success",
         "Authentication always returns success - possible backdoor"),
    ]
    
    SUSPICIOUS_ENV_VARS = {
        'LD_PRELOAD': 'Dynamic library preloading - possible injection',
        'LD_LIBRARY_PATH': 'Library path override - possible hijack',
        'PAM_ENV_DEBUG': 'PAM debug mode enabled - may leak credentials',
        'PAM_DEBUG': 'PAM debug mode enabled',
    }
    
    KNOWN_PAM_MODULES_RPM = {
        'pam_unix.so', 'pam_permit.so', 'pam_deny.so', 'pam_env.so',
        'pam_warn.so', 'pam_limits.so', 'pam_nologin.so', 'pam_selinux.so',
        'pam_sepermit.so', 'pam_pwquality.so', 'pam_cracklib.so',
        'pam_succeed_if.so', 'pam_access.so', 'pam_lastlog.so',
        'pam_faillock.so', 'pam_fprintd.so', 'pam_ecryptfs.so',
        'pam_gnome_keyring.so', 'pam_krb5.so', 'pam_ldap.so',
        'pam_localuser.so', 'pam_systemd.so', 'pam_rootok.so',
        'pam_securetty.so', 'pam_console.so', 'pam_umask.so',
        'pam_loginuid.so', 'pam_namespace.so', 'pam_keyinit.so',
        'pam_mkhomedir.so', 'pam_rhosts.so', 'pam_ssh_agent_auth.so',
        'pam_time.so', 'pam_userdb.so', 'pam_winbind.so',
        'pam_oddjob_mkhomedir.so', 'pam_pkcs11.so',
        'pam_cap.so', 'pam_chroot.so', 'pam_debug.so', 'pam_echo.so',
        'pam_exec.so', 'pam_faildelay.so', 'pam_filter.so', 'pam_ftp.so',
        'pam_group.so', 'pam_issue.so', 'pam_listfile.so', 'pam_mail.so',
        'pam_motd.so', 'pam_postgresok.so', 'pam_pwhistory.so',
        'pam_selinux_permit.so', 'pam_shells.so', 'pam_sss.so',
        'pam_sss_gss.so', 'pam_stress.so', 'pam_timestamp.so',
        'pam_tty_audit.so', 'pam_unix_acct.so', 'pam_unix_auth.so',
        'pam_unix_passwd.so', 'pam_unix_session.so', 'pam_usertype.so',
        'pam_wheel.so', 'pam_xauth.so',
    }
    
    KNOWN_PAM_MODULES_DPKG = {
        'pam_unix.so', 'pam_permit.so', 'pam_deny.so', 'pam_env.so',
        'pam_warn.so', 'pam_limits.so', 'pam_nologin.so', 'pam_selinux.so',
        'pam_pwquality.so', 'pam_cracklib.so', 'pam_succeed_if.so',
        'pam_access.so', 'pam_lastlog.so', 'pam_faillock.so',
        'pam_fprintd.so', 'pam_gnome_keyring.so', 'pam_krb5.so',
        'pam_ldap.so', 'pam_localuser.so', 'pam_systemd.so',
        'pam_rootok.so', 'pam_securetty.so', 'pam_umask.so',
        'pam_loginuid.so', 'pam_mkhomedir.so', 'pam_ssh_agent_auth.so',
        'pam_time.so', 'pam_userdb.so', 'pam_winbind.so',
        'pam_pkcs11.so', 'pam_extrausers.so',
        'pam_cap.so', 'pam_chroot.so', 'pam_debug.so', 'pam_echo.so',
        'pam_exec.so', 'pam_faildelay.so', 'pam_filter.so', 'pam_ftp.so',
        'pam_group.so', 'pam_issue.so', 'pam_listfile.so', 'pam_mail.so',
        'pam_motd.so', 'pam_postgresok.so', 'pam_pwhistory.so',
        'pam_selinux_permit.so', 'pam_shells.so', 'pam_sss.so',
        'pam_sss_gss.so', 'pam_stress.so', 'pam_timestamp.so',
        'pam_tty_audit.so', 'pam_unix_acct.so', 'pam_unix_auth.so',
        'pam_unix_passwd.so', 'pam_unix_session.so', 'pam_usertype.so',
        'pam_wheel.so', 'pam_xauth.so',
    }
    
    # Configuration files that are expected to be modified by administrators
    # These are excluded from RPM/DPKG verification alerts
    PAM_CONFIG_FILE_WHITELIST = {
        '/etc/pam.d/fingerprint-auth',
        '/etc/pam.d/password-auth',
        '/etc/pam.d/postlogin',
        '/etc/pam.d/smartcard-auth',
        '/etc/pam.d/system-auth',
        '/etc/pam.d/other',
        '/etc/security/limits.conf',
        '/etc/security/opasswd',
        '/usr/sbin/unix_update',
    }
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute PAM backdoor analysis"""
        evidences = []
        
        file_data = self._get_data(collected_data, "filesystem")
        
        # Full integrity checks + credential scanning
        evidences.extend(self._check_pam_module_integrity())
        evidences.extend(self._check_pam_config_suspicious())
        evidences.extend(self._check_hardcoded_credentials())
        evidences.extend(self._check_pam_environment_tampering(file_data))
        
        return evidences
    
    def _check_pam_module_integrity(self) -> List[Evidence]:
        """Check PAM module integrity against package manager records"""
        evidences = []
        
        try:
            rpm_modified = self._verify_rpm_packages()
            for module, details in rpm_modified.items():
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1556.003",
                    attack_tactic=get_attack_tactic_name("T1556.003"),
                    title=f"PAM Module Modified: {module}",
                    description=f"PAM module {module} has been modified from original package: {details}",
                    confidence=0.85,
                    raw_data={"module": module, "details": details, "source": "rpm"},
                        evidence_details=EvidenceDetail(
                            content="PAM Module Modified: {...}"
                        ),
                        remediation_commands=[
                        "Review the alert details and investigate related system artifacts",
                        "Review related system logs and configuration",
                        "Check for additional indicators of compromise",
                        "Apply appropriate remediation and monitor"
                    ]))
        except (OSError, ValueError, KeyError) as e:
            _get_logger().debug(f"[{self.name}] RPM verification failed: {e}")
        
        try:
            dpkg_modified = self._verify_dpkg_packages()
            for module, details in dpkg_modified.items():
                evidences.append(self._create_evidence(
                    severity=Severity.HIGH,
                    attack_id="T1556.003",
                    attack_tactic=get_attack_tactic_name("T1556.003"),
                    title=f"PAM Module Modified: {module}",
                    description=f"PAM module {module} has been modified from original package: {details}",
                    confidence=0.85,
                    raw_data={"module": module, "details": details, "source": "dpkg"},
                        evidence_details=EvidenceDetail(
                            content="PAM Module Modified: {...}"
                        ),
                        remediation_commands=[
                        "Review the alert details and investigate related system artifacts",
                        "Review related system logs and configuration",
                        "Check for additional indicators of compromise",
                        "Apply appropriate remediation and monitor"
                    ]))
        except (OSError, ValueError, KeyError) as e:
            _get_logger().debug(f"[{self.name}] DPKG verification failed: {e}")
        
        try:
            unknown_modules = self._detect_unknown_modules()
            for module_path in unknown_modules:
                evidences.append(self._create_evidence(
                    severity=Severity.MEDIUM,
                    attack_id="T1556.003",
                    attack_tactic=get_attack_tactic_name("T1556.003"),
                    title=f"Unknown PAM Module: {os.path.basename(module_path)}",
                    description=f"Unknown PAM module found: {module_path}",
                    confidence=0.6,
                    raw_data={"module_path": module_path},
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Audit PAM configuration files for backdoors",
                        "Verify PAM module signatures and remove unauthorized modules",
                        "Review authentication logs for suspicious activity",
                        "Restore PAM configuration from known-good backup"
                    ]))
        except (OSError, ValueError, KeyError) as e:
            _get_logger().debug(f"[{self.name}] Unknown module detection failed: {e}")
        
        return evidences
    
    def _verify_rpm_packages(self) -> Dict[str, str]:
        """Verify PAM packages using rpm -V"""
        modified = {}
        
        try:
            result = subprocess.run(
                ['rpm', '-V', 'pam'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )
            
            if result.returncode != 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    
                    verify_flags = parts[0]
                    module = parts[-1]
                    
                    if module in self.PAM_CONFIG_FILE_WHITELIST:
                        continue
                    
                    # Only alert on binary modifications (S=Size, M=Mode, 5=MD5, T=mtime)
                    # Config files (marked with 'c') are expected to change
                    if 'c' in verify_flags:
                        continue
                    
                    details = verify_flags if verify_flags != '........' else "unknown"
                    modified[module] = f"rpm verify: {details}"
        except (subprocess.TimeoutExpired, OSError):
            pass

        return modified

    def _verify_dpkg_packages(self) -> Dict[str, str]:
        """Verify PAM packages using dpkg --verify"""
        modified = {}

        try:
            result = subprocess.run(
                ['dpkg', '--verify', 'libpam-modules'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10
            )

            if result.returncode != 0 and result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            module = parts[-1]
                            if module in self.PAM_CONFIG_FILE_WHITELIST:
                                continue
                            details = parts[0] if len(parts) > 1 else "unknown"
                            modified[module] = f"dpkg verify: {details}"
        except (subprocess.TimeoutExpired, OSError):
            pass
        
        return modified
    
    def _detect_unknown_modules(self) -> List[str]:
        """Detect PAM modules not in known whitelist"""
        unknown = []
        
        for pam_dir in self.PAM_MODULE_DIRS:
            if not os.path.exists(pam_dir):
                continue
            
            try:
                for entry in os.listdir(pam_dir):
                    if entry.endswith('.so'):
                        module_path = os.path.join(pam_dir, entry)
                        if os.path.isfile(module_path):
                            is_known = (
                                entry in self.KNOWN_PAM_MODULES_RPM or 
                                entry in self.KNOWN_PAM_MODULES_DPKG
                            )
                            if not is_known:
                                unknown.append(module_path)
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Cannot list {pam_dir}: {e}")
        
        return unknown
    
    def _check_pam_config_suspicious(self) -> List[Evidence]:
        """Check for suspicious PAM configurations
        
        In quick mode, limits scanning to first 5 config files for performance.
        """
        evidences = []
        
        if not os.path.exists(self.PAM_CONFIG_DIR):
            return evidences
        
        try:
            config_files = os.listdir(self.PAM_CONFIG_DIR)
            
            # In quick mode, limit to first 5 files for performance
            for config_file in config_files:
                config_path = os.path.join(self.PAM_CONFIG_DIR, config_file)
                if not os.path.isfile(config_path):
                    continue
                
                try:
                    with open(config_path, 'r', errors='ignore', encoding='utf-8') as f:
                        content = f.read()
                    
                    for pattern, check_id, description in self.SUSPICIOUS_PAM_PATTERNS:
                        if pattern.search(content):
                            evidences.append(self._create_evidence(
                                severity=Severity.HIGH,
                                attack_id="T1556.003",
                                attack_tactic=get_attack_tactic_name("T1556.003"),
                                title=f"Suspicious PAM Config: {config_file}",
                                description=f"{description} in {config_path}",
                                confidence=0.8,
                                raw_data={
                                    "config_file": config_path,
                                    "check_id": check_id,
                                    "description": description
                                },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Audit PAM configuration files for backdoors",
                        "Verify PAM module signatures and remove unauthorized modules",
                        "Review authentication logs for suspicious activity",
                        "Restore PAM configuration from known-good backup"
                    ]))
                except OSError as e:
                    _get_logger().debug(f"[{self.name}] Cannot read {config_path}: {e}")
        except OSError as e:
            _get_logger().debug(f"[{self.name}] Cannot list {self.PAM_CONFIG_DIR}: {e}")
        
        return evidences
    
    def _extract_strings_from_binary(self, filepath: str, max_size: int = 1024 * 1024, min_length: int = 8) -> str:
        """Extract printable ASCII strings from binary file
        
        Args:
            filepath: Path to binary file
            max_size: Maximum bytes to read (default 1MB)
            min_length: Minimum string length to extract (default 8)
            
        Returns:
            Extracted strings joined with newlines
        """
        try:
            with open(filepath, 'rb') as f:
                data = f.read(max_size)
            
            # Extract only printable ASCII strings >= min_length
            pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
            strings = re.findall(pattern, data)
            return b'\n'.join(strings).decode('ascii', errors='ignore')
        except OSError as e:
            _get_logger().debug(f"[{self.name}] Failed to extract strings from {filepath}: {e}")
            return ""
    
    def _check_hardcoded_credentials(self) -> List[Evidence]:
        """Scan PAM modules for hardcoded credentials"""
        evidences = []
        
        for pam_dir in self.PAM_MODULE_DIRS:
            if not os.path.exists(pam_dir):
                continue
            
            try:
                for entry in os.listdir(pam_dir):
                    if not entry.endswith('.so'):
                        continue
                    
                    module_path = os.path.join(pam_dir, entry)
                    if not os.path.isfile(module_path):
                        continue
                    
                    # Skip very large binaries (>10MB)
                    try:
                        if os.path.getsize(module_path) > 10 * 1024 * 1024:
                            _get_logger().debug(f"[{self.name}] Skipping large binary {module_path}")
                            continue
                    except OSError:
                        continue
                    
                    try:
                        # Extract printable strings only
                        content = self._extract_strings_from_binary(module_path)
                        if not content:
                            continue
                        
                        for pattern, check_id, description in self.HARDCODED_CRED_PATTERNS:
                            if pattern.search(content.encode('ascii', errors='ignore')):
                                evidences.append(self._create_evidence(
                                    severity=Severity.CRITICAL,
                                    attack_id="T1078",
                                    attack_tactic=get_attack_tactic_name("T1078"),
                                    title=f"Hardcoded Credential in PAM Module: {entry}",
                                    description=f"{description} found in {module_path}",
                                    confidence=0.75,
                                    raw_data={
                                        "module": module_path,
                                        "check_id": check_id,
                                        "description": description
                                    },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Audit PAM configuration files for backdoors",
                        "Verify PAM module signatures and remove unauthorized modules",
                        "Review authentication logs for suspicious activity",
                        "Restore PAM configuration from known-good backup"
                    ]))
                    except OSError as e:
                        _get_logger().debug(f"[{self.name}] Cannot read {module_path}: {e}")
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Cannot list {pam_dir}: {e}")
        
        return evidences
    
    def _check_pam_environment_tampering(self, file_data: Optional[Dict]) -> List[Evidence]:
        """Check for PAM environment tampering"""
        evidences = []
        
        if file_data and isinstance(file_data, dict):
            env_files = file_data.get('pam_env_files', {})
            for env_file, details in env_files.items():
                if not details.get('exists', False):
                    continue
                
                content = details.get('content', '')
                for var, description in self.SUSPICIOUS_ENV_VARS.items():
                    if var in content:
                        evidences.append(self._create_evidence(
                            severity=Severity.HIGH,
                            attack_id="T1556.003",
                            attack_tactic=get_attack_tactic_name("T1556.003"),
                            title=f"Suspicious PAM Environment Variable: {var}",
                            description=f"{description} found in {env_file}",
                            confidence=0.7,
                            raw_data={
                                "env_file": env_file,
                                "variable": var,
                                "description": description
                            },
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Audit PAM configuration files for backdoors",
                        "Verify PAM module signatures and remove unauthorized modules",
                        "Review authentication logs for suspicious activity",
                        "Restore PAM configuration from known-good backup"
                    ]))
        
        return evidences
