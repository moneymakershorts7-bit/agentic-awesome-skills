"""Credential redaction utilities for secure reporting."""
import hashlib
import re
from typing import Any, Dict, List


def redact_credential(value: str, visible_chars: int = 4) -> str:
    """Redact a credential value for safe display in reports.
    
    Shows only first and last few characters, replacing middle with asterisks.
    
    Args:
        value: The credential value to redact
        visible_chars: Number of characters to show at start and end
        
    Returns:
        Redacted string in format: "AKIA****MPLE" or "[REDACTED]" for short values
        
    Examples:
        >>> redact_credential("AKIAIOSFODNN7EXAMPLE")
        'AKIA****MPLE'
        >>> redact_credential("short")
        '[REDACTED]'
        >>> redact_credential("")
        '[REDACTED]'
        >>> redact_credential(None)
        '[REDACTED]'
    """
    if not value or not isinstance(value, str):
        return '[REDACTED]'
    
    # Remove whitespace
    value = value.strip()
    
    if not value:
        return '[REDACTED]'
    
    # If value is too short, fully redact
    if len(value) <= (visible_chars * 2):
        return '[REDACTED]'
    
    # Show first and last N characters
    return f"{value[:visible_chars]}****{value[-visible_chars:]}"


def redact_in_text(text: str, patterns: list = None, visible_chars: int = 4) -> str:
    """Redact credential-like values in a text string.
    
    Identifies and redacts potential credential values based on common patterns.
    
    Args:
        text: The text containing potential credentials
        patterns: List of regex patterns to identify credential keys (default: common patterns)
        visible_chars: Number of characters to show at start and end
        
    Returns:
        Text with credential values redacted
    """
    
    if not text:
        return text
    
    # Default patterns for common credential formats
    if patterns is None:
        patterns = [
            # API keys and tokens: key=value or key: value
            r'((?:api[_-]?key|token|secret|password|passwd|pwd|credential|access[_-]?key|access[_-]?token|private[_-]?key)\s*[=:]\s*)(["\']?)([A-Za-z0-9+/=_-]{8,})(["\']?)',
            # AWS-style keys
            r'((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{12,})',
            # Long alphanumeric strings that look like tokens
            r'([A-Za-z0-9]{32,})',
        ]
    
    result = text
    for pattern in patterns:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            
            def replace_match(match):
                # Group 3 is typically the actual credential value
                if len(match.groups()) >= 3 and match.group(3):
                    prefix = match.group(1) + match.group(2)
                    suffix = match.group(4) if len(match.groups()) >= 4 else ""
                    redacted = redact_credential(match.group(3), visible_chars)
                    return f"{prefix}{redacted}{suffix}"
                elif len(match.groups()) >= 1 and match.group(1):
                    # Single group patterns (like AWS keys)
                    return redact_credential(match.group(1), visible_chars)
                return match.group(0)
            
            result = regex.sub(replace_match, result)
        except re.error:
            # Skip invalid patterns
            continue
    
    return result


def anonymize_field(value: Any, method: str = "mask", visible_chars: int = 4) -> str:
    """Anonymize a field value using specified method.
    
    Args:
        value: The field value to anonymize
        method: Anonymization method ("mask", "hash", "redact")
        visible_chars: Number of characters to show (for mask method)
        
    Returns:
        Anonymized string
        
    Examples:
        >>> anonymize_field("192.168.1.100", "mask")
        '192.****100'
        >>> anonymize_field("password123", "hash")
        'HASH:a1b2c3d4...'
        >>> anonymize_field("secret", "redact")
        '[REDACTED]'
    """
    if value is None:
        return "[REDACTED]"
    
    str_value = str(value)
    
    if not str_value:
        return "[REDACTED]"
    
    if method == "mask":
        # Mask with first and last N characters visible
        if len(str_value) <= (visible_chars * 2):
            return "[REDACTED]"
        return f"{str_value[:visible_chars]}****{str_value[-visible_chars:]}"
    
    elif method == "hash":
        # Show hash prefix for reference without revealing actual value
        hash_value = hashlib.sha256(str_value.encode()).hexdigest()[:12]
        return f"HASH:{hash_value}..."
    
    elif method == "redact":
        # Fully redact
        return "[REDACTED]"
    
    else:
        # Default to masking
        return anonymize_field(value, "mask", visible_chars)


def anonymize_ip_address(ip: str) -> str:
    """Anonymize IP address by masking last octets.
    
    Args:
        ip: IP address to anonymize
        
    Returns:
        Anonymized IP address
        
    Examples:
        >>> anonymize_ip_address("192.168.1.100")
        '192.168.1.***'
        >>> anonymize_ip_address("10.0.0.1")
        '10.0.0.***'
    """
    if not ip or not isinstance(ip, str):
        return "[REDACTED]"
    
    parts = ip.split(".")
    if len(parts) != 4:
        return anonymize_field(ip, "mask")
    
    # Keep first 3 octets, mask last one
    parts[3] = "***"
    return ".".join(parts)


def anonymize_domain(domain: str) -> str:
    """Anonymize domain by keeping only TLD.
    
    Args:
        domain: Domain to anonymize
        
    Returns:
        Anonymized domain
        
    Examples:
        >>> anonymize_domain("malicious.example.com")
        '*.example.com'
        >>> anonymize_domain("sub.domain.co.uk")
        '*.*.co.uk'
    """
    if not domain or not isinstance(domain, str):
        return "[REDACTED]"
    
    parts = domain.split(".")
    if len(parts) <= 2:
        return anonymize_field(domain, "mask")
    
    # Replace all but last two parts with wildcard
    if len(parts) > 2:
        parts[:-2] = ["*"] * (len(parts) - 2)
    
    return ".".join(parts)


def anonymize_data(data: Dict[str, Any], fields: List[str], 
                   method: str = "mask") -> Dict[str, Any]:
    """Anonymize specific fields in a data dictionary.
    
    Args:
        data: Dictionary containing data to anonymize
        fields: List of field names to anonymize
        method: Anonymization method ("mask", "hash", "redact")
        
    Returns:
        New dictionary with specified fields anonymized
        
    Examples:
        >>> data = {"ip": "192.168.1.100", "port": 443, "domain": "evil.example.com"}
        >>> anonymize_data(data, ["ip", "domain"], "mask")
        {'ip': '192.****100', 'port': 443, 'domain': 'e****m'}
    """
    if not data or not fields:
        return data.copy() if data else {}
    
    result = data.copy()
    
    for field in fields:
        if field in result:
            value = result[field]
            
            # Special handling for IP addresses
            if field in ["ip", "ip_address", "src_ip", "dst_ip", "destination_ip"]:
                result[field] = anonymize_ip_address(str(value))
            # Special handling for domains
            elif field in ["domain", "hostname", "dns_name"]:
                result[field] = anonymize_domain(str(value))
            # General field anonymization
            elif isinstance(value, dict):
                result[field] = anonymize_data(value, list(value.keys()), method)
            elif isinstance(value, list):
                result[field] = [
                    anonymize_field(item, method) if isinstance(item, str) else item
                    for item in value
                ]
            elif isinstance(value, str):
                result[field] = anonymize_field(value, method)
            else:
                result[field] = anonymize_field(str(value), method)
    
    return result


def apply_policy_anonymization(data: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    """Apply policy-based anonymization to data.
    
    Args:
        data: Data dictionary to anonymize
        policy: Policy dictionary with keys:
            - anonymize: bool - Whether to anonymize
            - data_fields: List[str] - Fields to anonymize
            
    Returns:
        Anonymized data dictionary
        
    Examples:
        >>> data = {"ip_address": "10.0.0.1", "process_name": "nginx"}
        >>> policy = {"anonymize": True, "data_fields": ["ip_address"]}
        >>> apply_policy_anonymization(data, policy)
        {'ip_address': '10.0.0.***', 'process_name': 'nginx'}
    """
    if not data:
        return {}
    
    if not policy or not policy.get("anonymize", False):
        return data.copy()
    
    fields_to_anonymize = policy.get("data_fields", [])
    
    if not fields_to_anonymize:
        return data.copy()
    
    return anonymize_data(data, fields_to_anonymize, method="mask")
