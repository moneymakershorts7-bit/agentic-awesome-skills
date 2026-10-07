"""Security Database Management Module

Provides unified interfaces for loading, querying, and managing security databases:
- Malicious domain database (IOC format)
- Malicious hash database (MD5/SHA1/SHA256)
- Vulnerability database (CVE)

All databases are stored in assets/ioc/ directory.
"""
import json
import os
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl


# IOC Format: Use [.] instead of . to avoid interception
# Example: evil-c2.example.com -> evil-c2[.]example[.]com
def encode_domain(domain: str) -> str:
    """Encode domain to IOC format (enhanced readability)
    
    Args:
        domain: Original domain string
        
    Returns:
        Domain in IOC format with [.] replacing .
        
    Example:
        >>> encode_domain("evil-c2.example.com")
        'evil-c2[.]example[.]com'
    """
    return domain.replace(".", "[.]")


def decode_domain(encoded: str) -> str:
    """Decode domain from IOC format
    
    Args:
        encoded: Domain in IOC format
        
    Returns:
        Original domain string
        
    Example:
        >>> decode_domain("evil-c2[.]example[.]com")
        'evil-c2.example.com'
    """
    return encoded.replace("[.]", ".")


@dataclass
class ThreatDomain:
    """Malicious domain record
    
    Attributes:
        domain: Domain name in IOC format (e.g., evil[.]com)
        threat_type: Type of threat: c2, malware, phishing, dga
        confidence: Confidence score 0-1
        source: Data source identifier
        first_seen: First discovery date (ISO format)
        last_updated: Last update time (ISO format)
    """
    domain: str           # IOC format: evil[.]com
    threat_type: str      # c2, malware, phishing, dga
    confidence: float     # 0-1
    source: str           # Data source
    first_seen: str       # ISO date
    last_updated: str     # ISO datetime
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "domain": self.domain,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_updated": self.last_updated
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ThreatDomain":
        """Create from dictionary"""
        return cls(
            domain=data.get("domain", ""),
            threat_type=data.get("threat_type", "unknown"),
            confidence=float(data.get("confidence", 0.0)),
            source=data.get("source", "unknown"),
            first_seen=data.get("first_seen", ""),
            last_updated=data.get("last_updated", "")
        )


@dataclass
class MaliciousHash:
    """Malicious file hash record
    
    Attributes:
        md5: MD5 hash (optional)
        sha1: SHA1 hash (optional)
        sha256: SHA256 hash (optional)
        malware_family: Malware family name
        malware_type: Type: ransomware, miner, rat, trojan
        source: Data source
        first_seen: First discovery date
    """
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    malware_family: str   # Malware family
    malware_type: str     # ransomware, miner, rat, trojan
    source: str
    first_seen: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "malware_family": self.malware_family,
            "malware_type": self.malware_type,
            "source": self.source,
            "first_seen": self.first_seen
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "MaliciousHash":
        """Create from dictionary"""
        return cls(
            md5=data.get("md5"),
            sha1=data.get("sha1"),
            sha256=data.get("sha256"),
            malware_family=data.get("malware_family", "unknown"),
            malware_type=data.get("malware_type", "unknown"),
            source=data.get("source", "unknown"),
            first_seen=data.get("first_seen", "")
        )


@dataclass
class Vulnerability:
    """Vulnerability record
    
    Attributes:
        cve_id: CVE identifier (e.g., CVE-2024-0001)
        cvss_score: CVSS severity score
        affected_products: List of affected products
        description: Vulnerability description
        remediation: Remediation steps
        references: List of reference URLs
    """
    cve_id: str
    cvss_score: float
    affected_products: List[str]
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "affected_products": self.affected_products,
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Vulnerability":
        """Create from dictionary"""
        return cls(
            cve_id=data.get("cve_id", ""),
            cvss_score=float(data.get("cvss_score", 0.0)),
            affected_products=data.get("affected_products", []),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            references=data.get("references", [])
        )


@dataclass
class DatabaseMetadata:
    """Database metadata for tracking updates

    Attributes:
        last_updated: Last update timestamp (ISO format)
        etag: ETag from HTTP response for incremental updates
        last_modified: Last-Modified header from HTTP response
        source_url: URL of the remote source
        entry_count: Number of entries in the database
    """
    last_updated: str = ""
    etag: str = ""
    last_modified: str = ""
    source_url: str = ""
    entry_count: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "last_updated": self.last_updated,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "source_url": self.source_url,
            "entry_count": self.entry_count
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DatabaseMetadata":
        """Create from dictionary"""
        return cls(
            last_updated=data.get("last_updated", ""),
            etag=data.get("etag", ""),
            last_modified=data.get("last_modified", ""),
            source_url=data.get("source_url", ""),
            entry_count=data.get("entry_count", 0)
        )


class SecurityDBManager:
    """Security Database Manager

    Manages loading, querying, and caching of security databases.
    Supports malicious domains, hashes, and vulnerabilities.

    Usage:
        manager = SecurityDBManager("/path/to/assets")
        stats = manager.load_all()

        if manager.is_malicious_domain("evil.example.com"):
            print("Malicious domain detected!")

        if manager.is_malicious_hash(file_hash):
            print("Malicious file detected!")
    """

    # Default request timeout in seconds
    DEFAULT_TIMEOUT = 30
    # Default User-Agent for HTTP requests
    DEFAULT_USER_AGENT = "sec-userspace-threat-intel/1.0"

    def __init__(self, assets_dir: str):
        """Initialize security database manager

        Args:
            assets_dir: Path to assets directory containing ioc/
        """
        self.assets_dir = assets_dir
        self.security_db_dir = os.path.join(assets_dir, "ioc")
        self.metadata_dir = os.path.join(self.security_db_dir, ".metadata")
        self._cache_lock = threading.Lock()

        # In-memory caches
        self._domain_db: Set[str] = set()  # Decoded domains for fast lookup
        self._domain_map: Dict[str, ThreatDomain] = {}  # domain -> ThreatDomain
        self._hash_db: Dict[str, MaliciousHash] = {}  # hash -> MaliciousHash
        self._vuln_db: Dict[str, Vulnerability] = {}  # cve_id -> Vulnerability

        # Metadata cache
        self._metadata: Dict[str, DatabaseMetadata] = {}

        self._loaded = False
        self._stats: Dict[str, int] = {}

        # Ensure metadata directory exists
        os.makedirs(self.metadata_dir, exist_ok=True)

        # Logger
        self.logger = logging.getLogger("sec-userspace")
    
    def load_all(self) -> dict:
        """Load all security databases
        
        Returns:
            Dictionary with load statistics
        """
        stats = {
            "domains": 0,
            "hashes": 0,
            "vulnerabilities": 0,
            "loaded": False
        }
        
        try:
            stats["domains"] = self.load_domains()
            stats["hashes"] = self.load_hashes()
            stats["vulnerabilities"] = self.load_vulnerabilities()
            stats["loaded"] = True
            self._loaded = True
            self._stats = stats
        except (OSError, ValueError, KeyError) as e:
            logger = logging.getLogger("sec-userspace")
            logger.error(f"Failed to load security databases: {e}")
        
        return stats
    
    def load_domains(self) -> int:
        """Load malicious domain database

        Returns:
            Number of domains loaded
        """
        domains_file = os.path.join(self.security_db_dir, "domains.json")

        if not os.path.exists(domains_file):
            return 0

        try:
            with open(domains_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            new_domain_db: set = set()
            new_domain_map: dict = {}
            entries = data.get("entries", [])
            for entry in entries:
                threat_domain = ThreatDomain.from_dict(entry)
                decoded = decode_domain(threat_domain.domain)
                new_domain_db.add(decoded)
                new_domain_map[decoded] = threat_domain

            with self._cache_lock:
                self._domain_db = new_domain_db
                self._domain_map = new_domain_map

            return len(new_domain_db)

        except (json.JSONDecodeError, OSError) as e:
            logger = logging.getLogger("sec-userspace")
            logger.warning(f"Failed to load domains.json: {e}")

        return 0

    def load_hashes(self) -> int:
        """Load malicious hash database

        Returns:
            Number of hashes loaded
        """
        hashes_file = os.path.join(self.security_db_dir, "hashes.json")

        if not os.path.exists(hashes_file):
            return 0

        try:
            with open(hashes_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            new_hash_db: dict = {}
            count = 0
            entries = data.get("entries", [])
            for entry in entries:
                mal_hash = MaliciousHash.from_dict(entry)
                for hash_val in [mal_hash.md5, mal_hash.sha1, mal_hash.sha256]:
                    if hash_val:
                        new_hash_db[hash_val.lower()] = mal_hash
                        count += 1

            with self._cache_lock:
                self._hash_db = new_hash_db

            return count

        except (json.JSONDecodeError, OSError) as e:
            logger = logging.getLogger("sec-userspace")
            logger.warning(f"Failed to load hashes.json: {e}")

        return 0

    def load_vulnerabilities(self) -> int:
        """Load vulnerability database

        Returns:
            Number of vulnerabilities loaded
        """
        vulns_file = os.path.join(self.security_db_dir, "vulnerabilities.json")

        if not os.path.exists(vulns_file):
            return 0

        try:
            with open(vulns_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            new_vuln_db: dict = {}
            entries = data.get("entries", [])
            for entry in entries:
                vuln = Vulnerability.from_dict(entry)
                new_vuln_db[vuln.cve_id] = vuln

            with self._cache_lock:
                self._vuln_db = new_vuln_db

            return len(new_vuln_db)

        except (json.JSONDecodeError, OSError) as e:
            logger = logging.getLogger("sec-userspace")
            logger.warning(f"Failed to load vulnerabilities.json: {e}")

        return 0
    
    def is_malicious_domain(self, domain: str) -> Optional[ThreatDomain]:
        """Check if domain is malicious

        Args:
            domain: Domain to check (will be decoded if in IOC format)

        Returns:
            ThreatDomain if malicious, None otherwise
        """
        if not domain:
            return None

        decoded = decode_domain(domain) if "[" in domain else domain

        with self._cache_lock:
            domain_db = self._domain_db
            domain_map = self._domain_map

        if decoded in domain_db:
            return domain_map.get(decoded)

        parts = decoded.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in domain_db:
                return domain_map.get(parent)

        return None

    def is_malicious_hash(self, file_hash: str) -> Optional[MaliciousHash]:
        """Check if file hash is malicious

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            MaliciousHash if malicious, None otherwise
        """
        if not file_hash:
            return None

        with self._cache_lock:
            hash_db = self._hash_db

        return hash_db.get(file_hash.lower())
    
    def check_vulnerability(
        self,
        cve_id: Optional[str] = None,
        product: Optional[str] = None
    ) -> List[Vulnerability]:
        """Query vulnerability information

        Args:
            cve_id: CVE identifier to look up
            product: Product name to search for affected vulnerabilities

        Returns:
            List of matching vulnerabilities
        """
        with self._cache_lock:
            vuln_db = self._vuln_db

        results = []

        if cve_id:
            vuln = vuln_db.get(cve_id)
            if vuln:
                results.append(vuln)

        if product:
            product_lower = product.lower()
            for vuln in vuln_db.values():
                for affected in vuln.affected_products:
                    if product_lower in affected.lower():
                        results.append(vuln)
                        break

        return results
    
    def get_stats(self) -> dict:
        """Get database statistics

        Returns:
            Dictionary with database statistics
        """
        with self._cache_lock:
            return {
                "domains": len(self._domain_db),
                "hashes": len(self._hash_db),
                "vulnerabilities": len(self._vuln_db),
                "loaded": self._loaded
            }

    def update_remote_database(
        self,
        source_type: str,
        source_url: str,
        timeout: int = None,
        verify_ssl: bool = True
    ) -> dict:
        """Fetch and merge remote threat intelligence data

        Args:
            source_type: Type of database to update (domains, hashes, vulnerabilities)
            source_url: URL to fetch updates from
            timeout: Request timeout in seconds (default: 30)
            verify_ssl: Whether to verify SSL certificates (default: True)

        Returns:
            dict: {
                "updated": bool,
                "entries_added": int,
                "entries_updated": int,
                "entries_removed": int,
                "error": str (optional)
            }

        Raises:
            ValueError: If source_type is invalid
            URLError: If remote fetch fails
        """
        if timeout is None:
            timeout = self.DEFAULT_TIMEOUT

        # Validate source type
        valid_types = {"domains", "hashes", "vulnerabilities"}
        if source_type not in valid_types:
            return {
                "updated": False,
                "error": f"Invalid source_type. Must be one of: {valid_types}"
            }

        try:
            # Step 1: Load existing data and user whitelist
            existing_entries, user_whitelist = self._load_existing_data(source_type)

            # Step 2: Fetch remote data with etag/last-modified caching
            remote_data = self._fetch_remote_data(source_url, source_type, timeout, verify_ssl)

            if not remote_data.get("updated"):
                return remote_data  # Not modified (304)

            # Step 3: Merge data (preserve user whitelist)
            merge_result = self._merge_data(
                source_type,
                existing_entries,
                user_whitelist,
                remote_data.get("entries", [])
            )

            # Step 4: Save updated database
            self._save_database(source_type, merge_result["merged_entries"])

            # Step 5: Update metadata
            self._update_metadata(source_type, source_url, remote_data)

            # Update in-memory cache
            self._refresh_cache(source_type, merge_result["merged_entries"])

            return {
                "updated": True,
                "entries_added": merge_result["entries_added"],
                "entries_updated": merge_result["entries_updated"],
                "entries_removed": merge_result["entries_removed"],
                "source_url": source_url,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        except HTTPError as e:
            self.logger.error(f"HTTP error fetching {source_type}: {e.code} {e.reason}")
            return {"updated": False, "error": f"HTTP error: {e.code} {e.reason}"}
        except URLError as e:
            self.logger.error(f"URL error fetching {source_type}: {e.reason}")
            return {"updated": False, "error": f"URL error: {e.reason}"}
        except (OSError, ValueError, TypeError, KeyError) as e:
            self.logger.error(f"Unexpected error updating {source_type}: {e}", exc_info=True)
            return {"updated": False, "error": str(e)}

    def _load_existing_data(self, source_type: str) -> tuple:
        """Load existing database entries and user whitelist

        Args:
            source_type: Type of database (domains, hashes, vulnerabilities)

        Returns:
            Tuple of (existing_entries_dict, user_whitelist_set)
        """
        file_map = {
            "domains": ("domains.json", lambda e: e.get("domain", "")),
            "hashes": ("hashes.json", lambda e: e.get("sha256") or e.get("sha1") or e.get("md5", "")),
            "vulnerabilities": ("vulnerabilities.json", lambda e: e.get("cve_id", ""))
        }

        filename, key_func = file_map[source_type]
        filepath = os.path.join(self.security_db_dir, filename)

        existing = {}
        user_whitelist = set()

        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                for entry in data.get("entries", []):
                    key = key_func(entry)
                    if key:
                        existing[key] = entry
                        # Track user-added entries (source starts with "user-" or "local-")
                        source = entry.get("source", "")
                        if source.startswith(("user-", "local-", "manual-")):
                            user_whitelist.add(key)

            except (json.JSONDecodeError, OSError) as e:
                self.logger.warning(f"Failed to load existing {source_type}: {e}")

        return existing, user_whitelist

    def _fetch_remote_data(
        self,
        url: str,
        source_type: str,
        timeout: int,
        verify_ssl: bool
    ) -> dict:
        """Fetch remote threat intelligence data with caching

        Uses etag and last-modified headers for incremental updates.

        Args:
            url: Remote URL to fetch
            source_type: Type of data being fetched
            timeout: Request timeout
            verify_ssl: Whether to verify SSL

        Returns:
            dict: {"updated": bool, "entries": list, "etag": str, "last_modified": str}
        """
        # Load cached metadata
        metadata = self._load_metadata(source_type)

        # Build request with caching headers
        headers = {
            "User-Agent": self.DEFAULT_USER_AGENT,
            "Accept": "application/json"
        }

        if metadata.etag:
            headers["If-None-Match"] = metadata.etag
        if metadata.last_modified:
            headers["If-Modified-Since"] = metadata.last_modified

        req = Request(url, headers=headers)

        # Create SSL context
        if verify_ssl:
            context = ssl.create_default_context()
        else:
            context = ssl.create_unverified_context()

        try:
            with urlopen(req, timeout=timeout, context=context) as response:
                # Check for 304 Not Modified
                if response.status == 304:
                    return {"updated": False, "entries": []}

                # Parse response
                content_type = response.headers.get("Content-Type", "")
                if "application/json" not in content_type:
                    self.logger.warning(f"Unexpected content type: {content_type}")

                data = json.loads(response.read().decode('utf-8'))

                # Extract etag and last-modified
                new_etag = response.headers.get("ETag", "")
                new_last_modified = response.headers.get("Last-Modified", "")

                # Validate data format
                entries = self._validate_remote_data(data, source_type)

                return {
                    "updated": True,
                    "entries": entries,
                    "etag": new_etag,
                    "last_modified": new_last_modified
                }

        except HTTPError as e:
            if e.code == 304:
                return {"updated": False, "entries": []}
            raise

    def _validate_remote_data(self, data: dict, source_type: str) -> List[dict]:
        """Validate remote data format

        Args:
            data: Parsed JSON data
            source_type: Expected data type

        Returns:
            List of validated entry dictionaries
        """
        entries = data.get("entries", [])

        if not isinstance(entries, list):
            raise ValueError("Remote data must contain 'entries' array")

        validated = []
        for entry in entries:
            if not isinstance(entry, dict):
                self.logger.warning(f"Skipping non-dict entry: {entry}")
                continue

            # Basic validation based on source type
            if source_type == "domains":
                if not entry.get("domain"):
                    self.logger.warning(f"Skipping domain entry without domain: {entry}")
                    continue
            elif source_type == "hashes":
                if not (entry.get("md5") or entry.get("sha1") or entry.get("sha256")):
                    self.logger.warning(f"Skipping hash entry without hash: {entry}")
                    continue
            elif source_type == "vulnerabilities":
                if not entry.get("cve_id"):
                    self.logger.warning(f"Skipping vulnerability entry without cve_id: {entry}")
                    continue

            # Add source tracking
            if "source" not in entry:
                entry["source"] = "remote-feed"

            validated.append(entry)

        return validated

    def _merge_data(
        self,
        source_type: str,
        existing: dict,
        user_whitelist: set,
        remote_entries: list
    ) -> dict:
        """Merge remote data with existing data, preserving user whitelist

        Args:
            source_type: Type of database
            existing: Existing entries keyed by primary key
            user_whitelist: Set of keys that are user-added (must be preserved)
            remote_entries: New entries from remote source

        Returns:
            dict: {"merged_entries": list, "entries_added": int, "entries_updated": int}
        """
        merged = {}
        entries_added = 0
        entries_updated = 0

        # Get key function
        key_func = {
            "domains": lambda e: e.get("domain", ""),
            "hashes": lambda e: e.get("sha256") or e.get("sha1") or e.get("md5", ""),
            "vulnerabilities": lambda e: e.get("cve_id", "")
        }[source_type]

        # First, preserve all user whitelist entries
        for key in user_whitelist:
            if key in existing:
                merged[key] = existing[key]

        # Merge remote entries
        remote_keys = set()
        for entry in remote_entries:
            key = key_func(entry)
            if not key:
                continue

            remote_keys.add(key)

            if key in merged:
                # Update existing entry with newer data
                existing_entry = merged[key]
                if self._is_entry_newer(entry, existing_entry):
                    merged[key] = self._merge_entry(entry, existing_entry)
                    entries_updated += 1
            else:
                # New entry
                merged[key] = entry
                entries_added += 1

        # Keep non-whitelisted existing entries that weren't updated
        for key, entry in existing.items():
            if key not in merged and key not in user_whitelist:
                # Entry was removed from remote, check if we should keep it
                # Keep entries from local sources
                source = entry.get("source", "")
                if source.startswith(("local-", "generated-")):
                    merged[key] = entry

        return {
            "merged_entries": list(merged.values()),
            "entries_added": entries_added,
            "entries_updated": entries_updated,
            "entries_removed": len(existing) - len(merged) + entries_added
        }

    def _is_entry_newer(self, new_entry: dict, old_entry: dict) -> bool:
        """Check if new entry is more recent than old entry"""
        new_time = new_entry.get("last_updated") or new_entry.get("first_seen", "")
        old_time = old_entry.get("last_updated") or old_entry.get("first_seen", "")

        if not new_time:
            return False
        if not old_time:
            return True

        try:
            # Simple string comparison for ISO format dates
            return new_time > old_time
        except (TypeError, ValueError):
            # Handle cases where timestamps are not comparable strings
            return False

    def _merge_entry(self, new_entry: dict, old_entry: dict) -> dict:
        """Merge new entry with old entry, preserving user fields"""
        merged = old_entry.copy()
        merged.update(new_entry)
        return merged

    def _save_database(self, source_type: str, entries: list) -> None:
        """Save updated database to disk

        Args:
            source_type: Type of database
            entries: List of entries to save
        """
        file_map = {
            "domains": "domains.json",
            "hashes": "hashes.json",
            "vulnerabilities": "vulnerabilities.json"
        }

        filename = file_map[source_type]
        filepath = os.path.join(self.security_db_dir, filename)

        # Sort entries for consistent output
        entries_sorted = sorted(entries, key=lambda e: str(e))

        data = {
            "entries": entries_sorted,
            "last_updated": datetime.now(timezone.utc).isoformat()
        }

        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        tmp_path = filepath + ".tmp"
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, filepath)

        self.logger.info(f"Saved {len(entries)} entries to {filename}")

    def _update_metadata(
        self,
        source_type: str,
        source_url: str,
        remote_data: dict
    ) -> None:
        """Update metadata after successful fetch

        Args:
            source_type: Type of database updated
            source_url: Source URL
            remote_data: Response data from remote fetch
        """
        metadata = DatabaseMetadata(
            last_updated=datetime.now(timezone.utc).isoformat(),
            etag=remote_data.get("etag", ""),
            last_modified=remote_data.get("last_modified", ""),
            source_url=source_url,
            entry_count=len(remote_data.get("entries", []))
        )

        with self._cache_lock:
            self._metadata[source_type] = metadata
        self._save_metadata(source_type, metadata)

    def _load_metadata(self, source_type: str) -> DatabaseMetadata:
        """Load metadata from disk

        Args:
            source_type: Type of database

        Returns:
            DatabaseMetadata object
        """
        with self._cache_lock:
            if source_type in self._metadata:
                return self._metadata[source_type]

        # Load from disk
        metadata_file = os.path.join(self.metadata_dir, f"{source_type}.json")

        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                metadata = DatabaseMetadata.from_dict(data)
                with self._cache_lock:
                    self._metadata[source_type] = metadata
                return metadata
            except (json.JSONDecodeError, OSError) as e:
                self.logger.warning(f"Failed to load metadata for {source_type}: {e}")

        return DatabaseMetadata()

    def _save_metadata(self, source_type: str, metadata: DatabaseMetadata) -> None:
        """Save metadata to disk

        Args:
            source_type: Type of database
            metadata: Metadata to save
        """
        metadata_file = os.path.join(self.metadata_dir, f"{source_type}.json")
        tmp_path = metadata_file + ".tmp"

        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(metadata.to_dict(), f, indent=2)
            os.replace(tmp_path, metadata_file)
        except OSError as e:
            self.logger.warning(f"Failed to save metadata for {source_type}: {e}")
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _refresh_cache(self, source_type: str, entries: list) -> None:
        """Refresh in-memory cache after update

        Args:
            source_type: Type of database
            entries: Updated entries
        """
        if source_type == "domains":
            new_domain_db: Set[str] = set()
            new_domain_map: Dict[str, ThreatDomain] = {}
            for entry in entries:
                threat_domain = ThreatDomain.from_dict(entry)
                decoded = decode_domain(threat_domain.domain)
                new_domain_db.add(decoded)
                new_domain_map[decoded] = threat_domain
            with self._cache_lock:
                self._domain_db = new_domain_db
                self._domain_map = new_domain_map

        elif source_type == "hashes":
            new_hash_db: Dict[str, MaliciousHash] = {}
            for entry in entries:
                mal_hash = MaliciousHash.from_dict(entry)
                for hash_val in [mal_hash.md5, mal_hash.sha1, mal_hash.sha256]:
                    if hash_val:
                        new_hash_db[hash_val.lower()] = mal_hash
            with self._cache_lock:
                self._hash_db = new_hash_db

        elif source_type == "vulnerabilities":
            new_vuln_db: Dict[str, Vulnerability] = {}
            for entry in entries:
                vuln = Vulnerability.from_dict(entry)
                new_vuln_db[vuln.cve_id] = vuln
            with self._cache_lock:
                self._vuln_db = new_vuln_db

        self.logger.info(f"Refreshed in-memory cache for {source_type}")


# Global singleton instance (lazy initialization)
_security_db_manager: Optional[SecurityDBManager] = None
_security_db_lock = threading.Lock()


def get_security_db_manager(assets_dir: Optional[str] = None) -> SecurityDBManager:
    """Get or create global SecurityDBManager instance
    
    Args:
        assets_dir: Path to assets directory (optional, uses default if not provided)
        
    Returns:
        SecurityDBManager instance
    """
    global _security_db_manager

    if _security_db_manager is None:
        with _security_db_lock:
            if _security_db_manager is None:
                if assets_dir is None:
                    from .path_resolver import get_assets_dir
                    assets_dir = get_assets_dir()
                _security_db_manager = SecurityDBManager(assets_dir)

    return _security_db_manager
