"""Evidence Correlator - Correlates evidences by IP, user, process, time"""
import re
from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime
from .evidence import Evidence


class EvidenceCorrelator:
    """证据关联分析器
    
    Correlates evidences across multiple dimensions:
    - IP addresses
    - Usernames
    - Process IDs
    - File paths
    - Time windows (adjacent events)
    """

    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    
    USER_PATTERN = re.compile(
        r'(?:user(?:name)?|uid)\s*[=:]\s*["\']?([a-zA-Z_][a-zA-Z0-9_-]*)["\']?',
        re.IGNORECASE
    )
    
    PID_PATTERN = re.compile(
        r'(?:pid|process\s*(?:id)?)\s*[=:]\s*(\d+)',
        re.IGNORECASE
    )
    
    PATH_PATTERN = re.compile(
        r'(?:/[a-zA-Z0-9._\-/]+)',
        re.IGNORECASE
    )

    def __init__(self, time_window_seconds: int = 300):
        """Initialize correlator
        
        Args:
            time_window_seconds: Time window for temporal correlation (default: 5 minutes)
        """
        self.time_window = time_window_seconds

    def correlate(self, evidences: List[Evidence]) -> Dict[str, Dict[str, List[str]]]:
        """Correlate evidences across multiple dimensions
        
        Args:
            evidences: List of Evidence objects
            
        Returns:
            Correlation dict:
            {
                "by_ip": {"192.168.1.100": ["ev-001", "ev-003"]},
                "by_user": {"www-data": ["ev-001", "ev-002"]},
                "by_process": {"12345": ["ev-002", "ev-004"]},
                "by_path": {"/etc/passwd": ["ev-001", "ev-005"]},
                "by_time": {"ev-001": ["ev-002"]}
            }
        """
        if not evidences:
            return {"by_ip": {}, "by_user": {}, "by_process": {}, "by_path": {}, "by_time": {}}
        
        result = {
            "by_ip": defaultdict(list),
            "by_user": defaultdict(list),
            "by_process": defaultdict(list),
            "by_path": defaultdict(list),
            "by_time": defaultdict(list)
        }
        
        # Extract entities from each evidence
        evidence_entities = {}
        for evidence in evidences:
            entities = self._extract_entities(evidence)
            evidence_entities[evidence.id] = entities
            
            # Group by IP
            for ip in entities.get("ips", []):
                result["by_ip"][ip].append(evidence.id)
            
            # Group by user
            for user in entities.get("users", []):
                result["by_user"][user].append(evidence.id)
            
            # Group by process
            for pid in entities.get("pids", []):
                result["by_process"][pid].append(evidence.id)
            
            # Group by path
            for path in entities.get("paths", []):
                result["by_path"][path].append(evidence.id)
        
        # Convert defaultdict to regular dict
        for key in ["by_ip", "by_user", "by_process", "by_path"]:
            result[key] = dict(result[key])
        
        # Temporal correlation (events within time window)
        result["by_time"] = self._correlate_by_time(evidences)
        
        return result

    def _extract_entities(self, evidence: Evidence) -> Dict[str, List[str]]:
        """Extract entities from evidence
        
        Args:
            evidence: Evidence object
            
        Returns:
            Dict with lists of extracted entities:
            {
                "ips": [...],
                "users": [...],
                "pids": [...],
                "paths": [...]
            }
        """
        entities = {
            "ips": [],
            "users": [],
            "pids": [],
            "paths": []
        }
        
        # Extract from raw_data first (structured data)
        raw_data = evidence.raw_data or {}
        
        # IPs
        for key, value in raw_data.items():
            if isinstance(value, str):
                entities["ips"].extend(self.IP_PATTERN.findall(value))
        
        # Users
        user_keys = ["user", "username", "uid", "account"]
        for key in user_keys:
            if key in raw_data and raw_data[key]:
                entities["users"].append(str(raw_data[key]))
        
        # PIDs
        pid_keys = ["pid", "process_id", "ppid"]
        for key in pid_keys:
            if key in raw_data and raw_data[key]:
                entities["pids"].append(str(raw_data[key]))
        
        # Paths
        path_keys = ["path", "file", "source_path", "target_path"]
        for key in path_keys:
            if key in raw_data and raw_data[key]:
                path_value = str(raw_data[key])
                if path_value.startswith("/"):
                    entities["paths"].append(path_value)
        
        # Also extract from title and description using regex
        text = f"{evidence.title} {evidence.description}"
        
        if not entities["ips"]:
            entities["ips"].extend(self.IP_PATTERN.findall(text))
        
        if not entities["users"]:
            entities["users"].extend(m.group(1) for m in self.USER_PATTERN.finditer(text))
        
        if not entities["pids"]:
            entities["pids"].extend(m.group(1) for m in self.PID_PATTERN.finditer(text))
        
        # Deduplicate
        for key in entities:
            entities[key] = list(set(entities[key]))
        
        return entities

    def _correlate_by_time(self, evidences: List[Evidence]) -> Dict[str, List[str]]:
        """Correlate evidences by time proximity
        
        Args:
            evidences: List of Evidence objects
            
        Returns:
            Dict mapping evidence ID to list of temporally adjacent evidence IDs
        """
        if not evidences:
            return {}
        
        # Parse timestamps and sort
        timed_evidences = []
        for e in evidences:
            try:
                ts = self._parse_timestamp(e.timestamp)
                if ts:
                    timed_evidences.append((e.id, ts))
            except (ValueError, TypeError):
                continue
        
        if len(timed_evidences) < 2:
            return {}
        
        timed_evidences.sort(key=lambda x: x[1])

        result = defaultdict(list)

        max_comparisons = 500_000
        comparisons = 0
        for i, (id1, ts1) in enumerate(timed_evidences):
            for j in range(i + 1, len(timed_evidences)):
                comparisons += 1
                if comparisons > max_comparisons:
                    break
                id2, ts2 = timed_evidences[j]
                delta = (ts2 - ts1).total_seconds()

                if delta > self.time_window:
                    break

                if delta >= 0:
                    result[id1].append(id2)
                    result[id2].append(id1)
            if comparisons > max_comparisons:
                break

        return dict(result)

    def _parse_timestamp(self, timestamp: str) -> datetime:
        """Parse timestamp string to datetime
        
        Args:
            timestamp: Timestamp string
            
        Returns:
            datetime object or None
        """
        if not timestamp:
            return None
        
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp, fmt)
            except ValueError:
                continue
        
        return None

    def get_correlation_groups(self, correlations: Dict[str, Dict[str, List[str]]]) -> List[Dict[str, Any]]:
        """Get correlation groups for analysis
        
        Args:
            correlations: Output from correlate() method
            
        Returns:
            List of correlation groups with metadata
        """
        groups = []
        
        for corr_type, corr_data in correlations.items():
            if not isinstance(corr_data, dict):
                continue
            
            for entity, evidence_ids in corr_data.items():
                if len(evidence_ids) > 1:
                    groups.append({
                        "type": corr_type.replace("by_", ""),
                        "entity": entity,
                        "evidence_count": len(evidence_ids),
                        "evidence_ids": evidence_ids
                    })
        
        # Sort by evidence count (descending)
        groups.sort(key=lambda x: x["evidence_count"], reverse=True)
        
        return groups
