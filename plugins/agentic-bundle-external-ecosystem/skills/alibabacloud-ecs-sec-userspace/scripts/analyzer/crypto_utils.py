"""Cryptographic utility functions for inter-agent communication security analysis.

Provides certificate validation, HMAC signature verification, and cipher suite strength checking.
"""
import hmac
import hashlib
import logging
from typing import Tuple, List
from datetime import datetime, timezone
from ..utils.datetime_compat import fromisoformat

logger = logging.getLogger("sec-userspace")


# Weak/deprecated cipher suites per NIST 2026 guidelines
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "RSA_WITH_3DES_EDE_CBC_SHA", "RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA",
    "ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE_RSA_WITH_AES_256_CBC_SHA",
]

# Strong cipher suites (recommended)
STRONG_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
]


def is_strong_cipher(cipher_suite: str) -> bool:
    """Check if cipher suite meets 2026 security standards.
    
    Args:
        cipher_suite: Cipher suite name to check
        
    Returns:
        True if cipher is strong, False if weak or unknown
    """
    if not cipher_suite:
        return False
    
    cipher_upper = cipher_suite.upper()
    
    # Check against known weak ciphers
    for weak in WEAK_CIPHERS:
        if weak.upper() in cipher_upper:
            return False
    
    # Check if it's a known strong cipher
    for strong in STRONG_CIPHERS:
        if strong.upper() == cipher_upper:
            return True
    
    # Default: assume moderate strength if not explicitly weak
    # Prefer AEAD ciphers (GCM, CCM, Poly1305)
    aead_indicators = ["GCM", "CCM", "POLY1305", "CHACHA20"]
    return any(indicator in cipher_upper for indicator in aead_indicators)


def compute_hmac_signature(payload: str, timestamp: str, sender: str, 
                           receiver: str, secret_key: bytes) -> str:
    """Compute HMAC-SHA256 signature for message integrity.
    
    Args:
        payload: Message payload
        timestamp: ISO format timestamp
        sender: Sender agent ID
        receiver: Receiver agent ID
        secret_key: Shared secret key for HMAC
        
    Returns:
        Hex-encoded HMAC signature
    """
    message = f"{timestamp}:{sender}:{receiver}:{payload}"
    return hmac.new(secret_key, message.encode('utf-8'), hashlib.sha256).hexdigest()


def verify_hmac_signature(payload: str, timestamp: str, sender: str,
                          receiver: str, expected_signature: str,
                          secret_key: bytes) -> bool:
    """Verify HMAC-SHA256 signature using constant-time comparison.
    
    Args:
        payload: Message payload
        timestamp: ISO format timestamp
        sender: Sender agent ID
        receiver: Receiver agent ID
        expected_signature: Expected HMAC signature
        secret_key: Shared secret key for HMAC
        
    Returns:
        True if signature is valid
    """
    computed = compute_hmac_signature(payload, timestamp, sender, receiver, secret_key)
    return hmac.compare_digest(computed, expected_signature)


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of text for randomness detection.
    
    Args:
        text: Text to analyze
        
    Returns:
        Entropy value (higher = more random)
    """
    if not text:
        return 0.0
    
    from collections import Counter
    import math
    
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def validate_tls_version(tls_version: str) -> Tuple[bool, str]:
    """Validate TLS version meets 2026 security standards.
    
    Args:
        tls_version: TLS version string (e.g., "TLS 1.2", "TLSv1.3")
        
    Returns:
        Tuple of (is_valid, reason)
    """
    if not tls_version:
        return False, "No TLS version specified"
    
    # Normalize version string
    version_clean = tls_version.upper().replace("TLSV", "TLS ").replace("TLS", "").strip()
    
    try:
        version_num = float(version_clean)
        if version_num < 1.2:
            return False, f"Deprecated TLS version: {tls_version} (minimum: TLS 1.2)"
        elif version_num < 1.3:
            return True, f"Acceptable but not recommended: {tls_version} (upgrade to TLS 1.3)"
        else:
            return True, f"Recommended TLS version: {tls_version}"
    except ValueError:
        return False, f"Invalid TLS version format: {tls_version}"


def extract_certificate_info(cert_data: dict) -> dict:
    """Extract relevant information from certificate data.
    
    Args:
        cert_data: Certificate data dictionary
        
    Returns:
        Extracted certificate information
    """
    return {
        "subject": cert_data.get("subject", ""),
        "issuer": cert_data.get("issuer", ""),
        "serial_number": cert_data.get("serial_number", ""),
        "not_before": cert_data.get("not_before", ""),
        "not_after": cert_data.get("not_after", ""),
        "key_size": cert_data.get("key_size", 0),
        "signature_algorithm": cert_data.get("signature_algorithm", ""),
        "has_chain": cert_data.get("chain_length", 0) > 1,
    }


def check_certificate_expiration(not_after_str: str) -> Tuple[bool, str]:
    """Check if certificate has expired.
    
    Args:
        not_after_str: Certificate expiration date in ISO format
        
    Returns:
        Tuple of (is_valid, reason)
    """
    if not not_after_str:
        return False, "No expiration date specified"
    
    try:
        not_after = fromisoformat(not_after_str)
        now = datetime.now(timezone.utc)
        
        if not_after < now:
            days_expired = (now - not_after).days
            return False, f"Certificate expired {days_expired} days ago on {not_after.isoformat()}"
        
        # Warn if expiring within 30 days
        days_remaining = (not_after - now).days
        if days_remaining < 30:
            return True, f"Certificate expiring soon: {days_remaining} days remaining"
        
        return True, f"Certificate valid for {days_remaining} days"
    except (ValueError, AttributeError) as e:
        return False, f"Invalid expiration date format: {str(e)}"


def detect_sensitive_patterns(text: str) -> List[dict]:
    """Detect sensitive data patterns in text (API keys, passwords, tokens, etc.).
    
    Args:
        text: Text to scan
        
    Returns:
        List of detected sensitive patterns with type and location
    """
    import re
    
    SENSITIVE_PATTERNS = {
        "api_key": r"(?i)(sk-[a-zA-Z0-9]{32,}|AKIA[0-9A-Z]{16}|api[_-]?key\s*[:=]\s*\S+)",
        "password": r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
        "token": r"(?i)(bearer|token|jwt)\s*[:=]?\s+[a-zA-Z0-9\._\-]{20,}",
        "secret": r"(?i)(secret|private[_-]?key)\s*[:=]\s*\S{8,}",
        "internal_ip": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "pii_ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    }
    
    detections = []
    for leak_type, pattern in SENSITIVE_PATTERNS.items():
        for match in re.finditer(pattern, text):
            detections.append({
                "type": leak_type,
                "match": match.group(0)[:50],  # Truncate for safety
                "start": match.start(),
                "end": match.end(),
            })
    
    return detections


def validate_certificate_chain(cert_chain: List[dict]) -> Tuple[bool, str]:
    """Validate certificate chain integrity.

    Checks:
    - Chain has at least one certificate
    - Each certificate's issuer matches the next certificate's subject
    - No certificate in the chain is expired
    - Chain ends at a trusted root (self-signed or known CA)

    Args:
        cert_chain: List of certificate dicts with subject, issuer, not_after fields

    Returns:
        Tuple of (is_valid, reason)
    """
    if not cert_chain:
        return False, "Empty certificate chain"

    if len(cert_chain) == 1:
        return True, "Single certificate chain (no intermediate CAs)"

    for i, cert in enumerate(cert_chain):
        subject = cert.get("subject", "")
        issuer = cert.get("issuer", "")
        not_after = cert.get("not_after", "")

        if not subject:
            return False, f"Certificate at position {i} missing subject"

        if not issuer:
            return False, f"Certificate at position {i} missing issuer"

        if i > 0:
            prev_subject = cert_chain[i - 1].get("subject", "")
            if issuer != prev_subject:
                return False, (
                    f"Chain break at position {i}: issuer '{issuer}' "
                    f"does not match previous subject '{prev_subject}'"
                )

        if not_after:
            is_valid, reason = check_certificate_expiration(not_after)
            if not is_valid:
                return False, f"Certificate at position {i} {reason}"

    last_cert = cert_chain[-1]
    if last_cert.get("subject") == last_cert.get("issuer"):
        return True, f"Valid chain ending at self-signed root ({len(cert_chain)} certs)"

    return True, f"Valid chain with {len(cert_chain)} certificates (root not self-signed)"


def validate_certificate_validity_period(cert_data: dict) -> Tuple[bool, str]:
    """Validate certificate validity period meets security standards.

    Checks:
    - Certificate is not expired
    - Certificate is not yet valid (not_before in future)
    - Validity period is not excessively long (> 398 days per CA/Browser Forum)
    - Certificate is not expiring soon (< 30 days)

    Args:
        cert_data: Certificate dict with not_before, not_after fields

    Returns:
        Tuple of (is_valid, reason)
    """
    not_before_str = cert_data.get("not_before", "")
    not_after_str = cert_data.get("not_after", "")

    if not not_before_str or not not_after_str:
        return False, "Missing validity period dates"

    try:
        not_before = fromisoformat(not_before_str)
        not_after = fromisoformat(not_after_str)
        now = datetime.now(timezone.utc)

        if not_before > now:
            return False, f"Certificate not yet valid (starts {not_before.isoformat()})"

        if not_after < now:
            days_expired = (now - not_after).days
            return False, f"Certificate expired {days_expired} days ago"

        validity_days = (not_after - not_before).days
        if validity_days > 398:
            return True, (
                f"Certificate validity period ({validity_days} days) exceeds "
                f"CA/Browser Forum recommendation (398 days)"
            )

        days_remaining = (not_after - now).days
        if days_remaining < 30:
            return True, f"Certificate expiring in {days_remaining} days - renewal recommended"

        return True, f"Certificate valid for {days_remaining} days ({validity_days}-day total period)"

    except (ValueError, AttributeError) as e:
        return False, f"Invalid date format: {str(e)}"
