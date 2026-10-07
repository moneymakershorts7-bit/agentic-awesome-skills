"""Data Encryption Status Analyzer

Detects if AI agent sensitive data (config files, memory, credentials) are encrypted.

ATT&CK mapping:
- T1552.001 - Credentials in Files
- T1552.004 - Private Keys
"""
import os
import re
import logging
from typing import Dict, List, Optional

from ..reporter.evidence import Evidence, EvidenceDetail
from ..reporter.severity import Severity
from .base import BaseAnalyzer

logger = logging.getLogger("sec-userspace")


class DataEncryptionAnalyzer(BaseAnalyzer):
    """Data Encryption Status Analyzer"""

    name = "data_encryption_analyzer"
    timeout = 60

    # Sensitive file patterns and their expected encryption
    ENCRYPTION_CHECKS = {
        'config_files': {
            'patterns': [
                '**/.openclaw/config.json',
                '**/.openclaw/config.yaml',
                '**/.openclaw/settings.yml',
                '**/openclaw/config.*',
                '**/.claude-code/config.json',
                '**/claude-code/config.*',
            ],
            'description': 'Configuration files',
            'check_encryption': True,
        },
        'memory_files': {
            'patterns': [
                '**/.openclaw/memory.db',
                '**/.openclaw/memory.sqlite',
                '**/.openclaw/knowledge_base/**',
                '**/openclaw/memory/**',
                '**/.claude-code/memory.db',
                '**/claude-code/memory/**',
            ],
            'description': 'Agent memory / knowledge base files',
            'check_encryption': True,
        },
        'credential_files': {
            'patterns': [
                '**/.openclaw/credentials.json',
                '**/.openclaw/.env',
                '**/.openclaw/secrets.*',
                '**/openclaw/credentials/**',
                '**/.claude-code/credentials.json',
                '**/.claude-code/.env',
            ],
            'description': 'Credential and secret files',
            'check_encryption': True,
            'critical': True,
        },
    }

    # Patterns indicating plaintext sensitive data
    PLAINTEXT_PATTERNS = [
        (re.compile(r'api[_-]?key\s*[=:]\s*["\']?[a-zA-Z0-9_-]{20,}', re.IGNORECASE), 'API Key'),
        (re.compile(r'secret[_-]?key\s*[=:]\s*["\']?[a-zA-Z0-9_-]{16,}', re.IGNORECASE), 'Secret Key'),
        (re.compile(r'password\s*[=:]\s*["\']?[^\s"\']{8,}', re.IGNORECASE), 'Password'),
        (re.compile(r'token\s*[=:]\s*["\']?[a-zA-Z0-9_-]{20,}', re.IGNORECASE), 'Token'),
        (re.compile(r'private[_-]?key\s*[=:]\s*["\']?-----BEGIN', re.IGNORECASE), 'Private Key'),
        (re.compile(r'Bearer\s+[a-zA-Z0-9_-]{20,}', re.IGNORECASE), 'Bearer Token'),
        (re.compile(r'sk-[a-zA-Z0-9]{48}', re.IGNORECASE), 'OpenAI API Key'),
        (re.compile(r'sk-ant-[a-zA-Z0-9_-]{20,}', re.IGNORECASE), 'Anthropic API Key'),
    ]

    # Encryption indicators
    ENCRYPTION_INDICATORS = [
        b'-----BEGIN ENCRYPTED PRIVATE KEY-----',
        b'-----BEGIN PGP MESSAGE-----',
        b'Salted__',  # OpenSSL salted encryption
        b'AES256',
        b'encrypted:',
    ]

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute data encryption analysis"""
        evidences = []

        # Get filesystem data
        try:
            file_data = self._get_data(collected_data, "file")
        except KeyError:
            return evidences

        if not file_data:
            return evidences

        # Check for sensitive files
        files_scanned = file_data.get("files", [])
        
        for file_info in files_scanned:
            file_path = file_info.get("path", "")
            file_name = os.path.basename(file_path)
            
            # Determine file category
            category = self._categorize_file(file_path)
            if not category:
                continue
            
            # Check encryption status
            is_encrypted = file_info.get("is_encrypted", False)
            content_preview = file_info.get("content_preview", "")
            
            # Check for plaintext sensitive data
            has_plaintext_secrets = self._check_plaintext_secrets(content_preview)
            
            if has_plaintext_secrets:
                severity = Severity.CRITICAL if category == 'credential_files' else Severity.HIGH
                evidences.append(self._create_evidence(
                    title=f"Plaintext sensitive data found in {category}: {file_name}",
                    description=f"File {file_path} contains plaintext {has_plaintext_secrets} without encryption",
                    severity=severity,
                    confidence=0.85,
                    attack_id="T1552.001",
                    attack_tactic="Credential Access",
                    source_path=file_path,
                    raw_data={
                        "file_category": category,
                        "plaintext_type": has_plaintext_secrets,
                        "is_encrypted": False,
                    },
                    remediation="Encrypt sensitive files using AES-256-GCM or use a secrets manager",
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Review encryption configurations and key management",
                        "Audit data encryption status and coverage",
                        "Implement strong encryption algorithms and key rotation",
                        "Monitor for encryption policy violations"
                    ]
                ))
            elif not is_encrypted and category in ['credential_files', 'memory_files']:
                # Even if no obvious plaintext patterns, check if should be encrypted
                evidences.append(self._create_evidence(
                    title=f"Sensitive file not encrypted: {file_name}",
                    description=f"{category.replace('_', ' ').title()} {file_path} is not encrypted",
                    severity=Severity.HIGH if category == 'credential_files' else Severity.MEDIUM,
                    confidence=0.7,
                    attack_id="T1552.001",
                    attack_tactic="Credential Access",
                    source_path=file_path,
                    raw_data={
                        "file_category": category,
                        "is_encrypted": False,
                    },
                    remediation="Enable encryption for this sensitive file",
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Review encryption configurations and key management",
                        "Audit data encryption status and coverage",
                        "Implement strong encryption algorithms and key rotation",
                        "Monitor for encryption policy violations"
                    ]
                ))

        # Check for OpenClaw specific data
        try:
            openclaw_data = self._get_data(collected_data, "openclaw")
            if openclaw_data and openclaw_data.get("openclaw_installed"):
                evidences.extend(self._check_openclaw_encryption(openclaw_data))
        except KeyError:
            pass

        return evidences

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def _categorize_file(self, file_path: str) -> Optional[str]:
        """Categorize file based on path patterns"""
        path_lower = file_path.lower()
        
        for category, config in self.ENCRYPTION_CHECKS.items():
            for pattern in config['patterns']:
                pattern_regex = pattern.replace('**/', '.*').replace('*', '[^/]*')
                if re.search(pattern_regex, path_lower):
                    return category
        
        return None

    def _check_plaintext_secrets(self, content: str) -> Optional[str]:
        """Check if content contains plaintext secrets"""
        if not content:
            return None
        
        # First check for encryption indicators
        content_bytes = content.encode('utf-8', errors='ignore')
        for indicator in self.ENCRYPTION_INDICATORS:
            if indicator in content_bytes:
                return None  # File appears encrypted
        
        # Check for plaintext patterns
        for compiled_re, secret_type in self.PLAINTEXT_PATTERNS:
            if compiled_re.search(content):
                return secret_type
        
        return None

    def _check_openclaw_encryption(self, openclaw_data: Dict) -> List[Evidence]:
        """Check OpenClaw specific encryption settings"""
        evidences = []
        
        config = openclaw_data.get("config", {})
        
        # Check if encryption is enabled in config
        encryption_config = config.get("encryption", {})
        if not encryption_config.get("enabled", False):
            evidences.append(self._create_evidence(
                title="OpenClaw encryption not enabled",
                description="OpenClaw configuration does not have encryption enabled for sensitive data",
                severity=Severity.HIGH,
                confidence=0.9,
                attack_id="T1552.001",
                attack_tactic="Credential Access",
                source_path=openclaw_data.get("config_path", ""),
                raw_data={
                    "encryption_enabled": False,
                },
                remediation="Enable encryption in OpenClaw configuration",
                        evidence_details=EvidenceDetail(
                            content="OpenClaw encryption not enabled"
                        ),
                        remediation_commands=[
                        "Review the alert details and investigate related system artifacts",
                        "Review related system logs and configuration",
                        "Check for additional indicators of compromise",
                        "Apply appropriate remediation and monitor"
                    ]
            ))
        
        # Check encryption algorithm
        algorithm = encryption_config.get("algorithm", "")
        weak_algorithms = ['DES', 'RC4', 'MD5', 'SHA1']
        if algorithm and any(weak in algorithm.upper() for weak in weak_algorithms):
            evidences.append(self._create_evidence(
                title=f"Weak encryption algorithm configured: {algorithm}",
                description=f"OpenClaw uses weak encryption algorithm {algorithm}",
                severity=Severity.MEDIUM,
                confidence=0.85,
                attack_id="T1552.001",
                attack_tactic="Credential Access",
                source_path=openclaw_data.get("config_path", ""),
                raw_data={
                    "algorithm": algorithm,
                },
                remediation="Use AES-256-GCM or ChaCha20-Poly1305 for encryption",
                        evidence_details=EvidenceDetail(
                            content="Weak encryption algorithm configured: {...}"
                        ),
                        remediation_commands=[
                        "Review the alert details and investigate related system artifacts",
                        "Review related system logs and configuration",
                        "Check for additional indicators of compromise",
                        "Apply appropriate remediation and monitor"
                    ]
            ))
        
        return evidences
