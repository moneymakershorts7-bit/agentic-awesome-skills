"""File Hash Calculation Tool - Uses only hashlib standard library"""
import hashlib
import logging

logger = logging.getLogger("sec-userspace")


def file_sha256(filepath: str) -> str:
    """Calculate SHA256 hash of file (streaming read)
    
    Args:
        filepath: File path
        
    Returns:
        Lowercase hexadecimal string, return empty string if file is unreadable
    """
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            # Streaming read, 8192 bytes at a time
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except OSError as e:
        logger.warning(f"Unable to calculate file hash {filepath}: {e}")
        return ""
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        logger.error(f"Failed to calculate file hash {filepath}: {e}", exc_info=True)
        return ""


def string_sha256(content: str) -> str:
    """Calculate SHA256 hash of string
    
    Args:
        content: String content
        
    Returns:
        Lowercase hexadecimal string
    """
    try:
        sha256_hash = hashlib.sha256()
        sha256_hash.update(content.encode("utf-8"))
        return sha256_hash.hexdigest()
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        logger.error(f"Failed to calculate string hash: {e}", exc_info=True)
        return ""
