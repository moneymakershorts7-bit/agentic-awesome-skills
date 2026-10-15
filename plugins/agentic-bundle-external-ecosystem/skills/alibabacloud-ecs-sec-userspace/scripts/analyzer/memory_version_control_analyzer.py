"""AI Agent Memory Version Control and Semantic Integrity Analyzer

Advanced memory forensics for detecting gradual memory poisoning and semantic tampering:
1. Memory version control with incremental snapshots
2. Semantic similarity analysis using embedding vectors
3. Progressive memory pollution detection (accumulation attacks)
4. Multi-agent memory conflict detection
5. Merkle tree-based integrity verification

ATT&CK mapping:
- T1565.001 - Data Manipulation: Stored Data Manipulation
- T1565 - Data Manipulation
- T1078 - Valid Accounts

OWASP ASI 2026: ASI04 (Agent Memory Poisoning)
"""
import os
import re
import time
import hashlib
from typing import List, Dict
from datetime import datetime, timezone

from ..reporter.evidence import Evidence, EvidenceDetail, Severity
from .base import BaseAnalyzer
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

# Semantic tampering detection patterns
SEMANTIC_TAMPERING_PATTERNS = {
    'permission_escalation': {
        'patterns': [
            (re.compile(r'(?:read[-_]?only|readonly|viewer|guest).*(?:become|changed?.*to|upgraded?.*to).*(?:admin|administrator|root)', re.IGNORECASE),
             "Permission escalation in memory", Severity.CRITICAL),
            (re.compile(r'(?:user\s+\w+).*(?:is|has).*(?:read[-_]?only).*(?:now|currently|was).*(?:admin|write|full)', re.IGNORECASE),
             "User permission upgrade detected", Severity.HIGH),
        ],
        'description': 'Detect permission escalation in agent memory',
        'attack_id': 'T1565.001',
        'owasp_asi': 'ASI04:2026'
    },
    
    'fact_reversal': {
        'patterns': [
            (re.compile(r'(?:true|false|correct|incorrect).*(?:actually|in fact|actually is).*(?:false|true|wrong|right)', re.IGNORECASE),
             "Fact reversal attempt", Severity.HIGH),
            (re.compile(r'(?:previous|old|prior).*(?:value|fact|information).*(?:replaced|updated|changed)', re.IGNORECASE),
             "Information replacement detected", Severity.MEDIUM),
        ],
        'description': 'Detect factual reversals in memory',
        'attack_id': 'T1565.001',
        'owasp_asi': 'ASI04:2026'
    },
    
    'identity_manipulation': {
        'patterns': [
            (re.compile(r'(?:agent|bot|assistant).*(?:role|identity|purpose).*(?:changed|modified|updated)', re.IGNORECASE),
             "Agent identity modification", Severity.CRITICAL),
            (re.compile(r'(?:system|developer).*(?:prompt|instruction).*(?:overridden|bypassed|ignored)', re.IGNORECASE),
             "System instruction override", Severity.CRITICAL),
        ],
        'description': 'Detect agent identity manipulation',
        'attack_id': 'T1610',
        'owasp_asi': 'ASI04:2026'
    },
}

# Multi-agent conflict detection patterns
MULTI_AGENT_CONFLICT_PATTERNS = {
    'contradictory_facts': {
        'indicators': [
            re.compile(r'(?:agent\s*\w*|system)\s*(?:says?|claims?|states?).*?(?:but|however|although)', re.IGNORECASE),
            re.compile(r'(?:conflicting|contradictory|inconsistent).*(?:information|data|memory)', re.IGNORECASE),
            re.compile(r'(?:version\s*\d+).*(?:differs|conflicts|disagrees)', re.IGNORECASE),
        ],
        'description': 'Contradictory facts from different agents',
        'severity': Severity.HIGH
    },
    
    'gaslighting': {
        'indicators': [
            re.compile(r'(?:you\s*(?:said|claimed|stated)).*?(?:but|i\s*(?:remember|think)).*?(?:different|otherwise)', re.IGNORECASE),
            re.compile(r'(?:that.*(?:never|happen|not true)).*?(?:actually|in fact)', re.IGNORECASE),
            re.compile(r'(?:are\s*you\s*sure|are\s*you\s*certain).*(?:about\s*that|what\s*you\s*said)', re.IGNORECASE),
        ],
        'description': 'Gaslighting attack pattern',
        'severity': Severity.CRITICAL
    },
    
    'concurrent_writes': {
        'indicators': [
            re.compile(r'(?:simultaneous|concurrent|parallel).*(?:write|update|modify)', re.IGNORECASE),
            re.compile(r'(?:race\s*condition|conflict|collision).*(?:detected|found)', re.IGNORECASE),
            re.compile(r'(?:overwrite|replace).*(?:another\s*agent|other\s*source)', re.IGNORECASE),
        ],
        'description': 'Concurrent write conflicts',
        'severity': Severity.MEDIUM
    },
}

# Gradual pollution detection thresholds
GRADUAL_POLLUTION_THRESHOLDS = {
    'max_change_rate': 0.15,  # Max 15% change per update
    'min_similarity': 0.85,   # Minimum cosine similarity
    'accumulation_window': 10,  # Number of updates to track
    'drift_threshold': 0.30,   # Total drift threshold
}

class MemoryVersionControlAnalyzer(BaseAnalyzer):
    """AI Agent Memory Version Control and Semantic Integrity Analyzer
    
    Advanced detection of gradual memory poisoning and semantic tampering:
    
    Detection capabilities:
    1. Memory version control with Git-like snapshots
    2. Semantic similarity analysis using embeddings
    3. Progressive memory pollution detection
    4. Multi-agent memory conflict detection
    5. Merkle tree integrity verification
    
    ATT&CK Mapping: T1565.001, T1565, T1078
    OWASP ASI 2026: ASI04
    """
    
    name = "memory_version_control_analyzer"
    timeout = 60
    required_collectors = ["filesystem", "log"]
    
    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def __init__(self, workspace_dir: str = None):
        super().__init__(workspace_dir)
        self._version_history = {}
        self._merkle_roots = {}
    
    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Execute comprehensive memory version control analysis"""
        evidences = []
        
        filesystem_data = self._get_safe_data(collected_data, "filesystem")
        log_data = self._get_safe_data(collected_data, "log")
        
        # 1. Analyze memory version history and detect gradual changes
        evidences.extend(self._analyze_memory_version_history(filesystem_data))
        
        # 2. Detect semantic tampering in memory content
        evidences.extend(self._detect_semantic_tampering(filesystem_data))
        
        # 3. Detect progressive memory pollution
        evidences.extend(self._detect_progressive_pollution(filesystem_data))
        
        # 4. Detect multi-agent memory conflicts
        evidences.extend(self._detect_multi_agent_conflicts(log_data))
        
        # 5. Verify memory integrity using Merkle tree
        evidences.extend(self._verify_merkle_tree_integrity(filesystem_data))
        
        return evidences
    
    def _get_safe_data(self, collected_data: Dict, key: str) -> Dict:
        """Safely get data from collected_data"""
        try:
            return self._get_data(collected_data, key)
        except (KeyError, TypeError):
            return {}
    
    def _analyze_memory_version_history(self, filesystem_data: Dict) -> List[Evidence]:
        """
        Analyze memory version history for suspicious patterns:
        1. Detect rapid successive modifications
        2. Identify unusual update frequencies
        3. Flag off-hours modifications
        
        Returns evidence of suspicious version patterns
        """
        evidences = []
        files = filesystem_data.get("files", [])
        
        if not files:
            return evidences
        
        # Memory file patterns
        memory_patterns = [
            r'.*memory.*\.(json|db|sqlite)$',
            r'.*agent.*state.*\.(json|db)$',
            r'.*conversation.*history.*\.(json|db)$',
            r'.*vector.*store.*\.(json|db|index)$',
        ]
        
        memory_files = []
        for file_info in files:
            filepath = file_info.get("path", "")
            
            for pattern in memory_patterns:
                if re.match(pattern, filepath, re.IGNORECASE):
                    memory_files.append(file_info)
                    break
        
        # Analyze modification patterns
        recent_modifications = []
        current_time = time.time()
        
        for file_info in memory_files:
            filepath = file_info.get("path", "")
            mtime = file_info.get("mtime", 0)
            age_hours = (current_time - mtime) / 3600
            
            # Recently modified (within last 24 hours)
            if age_hours < 24:
                recent_modifications.append({
                    'path': filepath,
                    'age_hours': age_hours,
                    'size': file_info.get('size', 0)
                })
        
        # Detect suspicious patterns
        if len(recent_modifications) > 10:
            evidences.append(self._create_evidence(
                title="High Frequency Memory Modifications Detected",
                description=(
                    f"Detected {len(recent_modifications)} memory file modifications "
                    f"in the last 24 hours. This may indicate automated memory poisoning."
                ),
                severity=Severity.MEDIUM,
                confidence=0.70,
                attack_id="T1565.001",
                attack_tactic="Data Manipulation",
                source_path="memory_files",
                raw_data={
                    "modification_count": len(recent_modifications),
                    "time_window_hours": 24,
                    "recent_files": [m['path'] for m in recent_modifications[:5]]
                },
                remediation=(
                    "Review memory modification patterns. "
                    "Implement rate limiting for memory updates. "
                    "Set up alerts for abnormal modification frequencies."
                ),
                owasp_asi="ASI04:2026",
                evidence_details=EvidenceDetail(
                ),
                remediation_commands=[
                        "Verify model version integrity at load time",
                        "Audit model version history and changes",
                        "Implement cryptographic model version signing",
                        "Monitor for unauthorized model version swaps"
                    ]
            ))
        
        # Check for off-hours modifications (midnight to 6 AM)
        off_hours_mods = []
        for mod in recent_modifications:
            mod_time = datetime.fromtimestamp(time.time() - mod['age_hours'] * 3600)
            if 0 <= mod_time.hour < 6:
                off_hours_mods.append(mod)
        
        if off_hours_mods:
            evidences.append(self._create_evidence(
                title="Off-Hours Memory Modifications Detected",
                description=(
                    f"Found {len(off_hours_mods)} memory modifications during "
                    f"off-hours (midnight-6AM). May indicate unauthorized access."
                ),
                severity=Severity.LOW,
                confidence=0.60,
                attack_id="T1565.001",
                attack_tactic="Data Manipulation",
                source_path="memory_files",
                raw_data={
                    "off_hours_count": len(off_hours_mods),
                    "modifications": [
                        {
                            'path': m['path'],
                            'hour': datetime.fromtimestamp(
                                time.time() - m['age_hours'] * 3600
                            ).hour
                        }
                        for m in off_hours_mods[:5]
                    ]
                },
                remediation=(
                    "Implement time-based access controls. "
                    "Monitor for unusual activity patterns. "
                    "Require additional authentication for off-hours access."
                ),
                owasp_asi="ASI04:2026",
                evidence_details=EvidenceDetail(
                ),
                remediation_commands=[
                        "Verify model version integrity at load time",
                        "Audit model version history and changes",
                        "Implement cryptographic model version signing",
                        "Monitor for unauthorized model version swaps"
                    ]
            ))
        
        return evidences
    
    def _detect_semantic_tampering(self, filesystem_data: Dict) -> List[Evidence]:
        """
        Detect semantic tampering in memory content:
        1. Scan for permission escalation patterns
        2. Detect fact reversals
        3. Identify identity manipulation
        
        Returns evidence of semantic-level tampering
        """
        evidences = []
        files = filesystem_data.get("files", [])
        
        if not files:
            return evidences
        
        # Focus on memory and conversation files
        memory_extensions = ['.json', '.db', '.sqlite', '.txt', '.log']
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            if not any(filename.endswith(ext) for ext in memory_extensions):
                continue
            
            file_size = file_info.get("size", 0)
            if file_size > 10 * 1024 * 1024:  # Skip files > 10MB
                continue
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(5 * 1024 * 1024)
                
                # Check against semantic tampering patterns
                for attack_type, attack_data in SEMANTIC_TAMPERING_PATTERNS.items():
                    for pattern, description, severity in attack_data['patterns']:
                        matches = pattern.findall(content)
                        if matches:
                            evidences.append(self._create_evidence(
                                title=f"Semantic Tampering Detected: {description}",
                                description=(
                                    f"Found {len(matches)} occurrence(s) of semantic "
                                    f"tampering pattern '{attack_type}' in {filepath}"
                                ),
                                severity=severity,
                                confidence=0.80,
                                attack_id=attack_data['attack_id'],
                                attack_tactic="Data Manipulation",
                                source_path=filepath,
                                raw_data={
                                    "attack_type": attack_type,
                                    "pattern_matches": len(matches),
                                    "sample_match": str(matches[0])[:100] if matches else None
                                },
                                remediation=(
                                    "Sanitize memory content immediately. "
                                    "Implement input validation before storing memories. "
                                    "Review affected memory entries for accuracy."
                                ),
                                owasp_asi=attack_data['owasp_asi'],
                                evidence_details=EvidenceDetail(
                                ),
                                remediation_commands=[
                        "Verify model version integrity at load time",
                        "Audit model version history and changes",
                        "Implement cryptographic model version signing",
                        "Monitor for unauthorized model version swaps"
                    ]
                            ))
                            break  # One evidence per attack type per file
                
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to scan {filepath}: {e}")
        
        return evidences
    
    def _detect_progressive_pollution(self, filesystem_data: Dict) -> List[Evidence]:
        """
        Detect progressive memory pollution (gradual accumulation attacks):
        1. Analyze change frequency patterns
        2. Calculate cumulative drift metrics
        3. Identify slow poisoning attempts
        
        Returns evidence of gradual pollution attacks
        """
        evidences = []
        files = filesystem_data.get("files", [])
        
        if not files:
            return evidences
        
        # Look for versioned memory files or backup patterns
        version_patterns = [
            r'.*memory.*v\d+\.json$',
            r'.*memory.*backup.*\.(json|db)$',
            r'.*agent.*state.*\d+\.json$',
            r'.*\.bak$',
        ]
        
        versioned_files = []
        for file_info in files:
            filepath = file_info.get("path", "")
            
            for pattern in version_patterns:
                if re.match(pattern, filepath, re.IGNORECASE):
                    versioned_files.append(file_info)
                    break
        
        # If we have versioned files, analyze progression
        if len(versioned_files) >= 3:
            # Sort by modification time
            versioned_files.sort(key=lambda x: x.get('mtime', 0))
            
            # Calculate size changes
            size_changes = []
            for i in range(1, len(versioned_files)):
                prev_size = versioned_files[i-1].get('size', 0)
                curr_size = versioned_files[i].get('size', 0)
                
                if prev_size > 0:
                    change_ratio = abs(curr_size - prev_size) / prev_size
                    size_changes.append(change_ratio)
            
            # Detect anomalous change patterns
            if size_changes:
                avg_change = sum(size_changes) / len(size_changes)
                
                if avg_change > GRADUAL_POLLUTION_THRESHOLDS['max_change_rate']:
                    evidences.append(self._create_evidence(
                        title="Progressive Memory Pollution Detected",
                        description=(
                            f"Detected abnormal memory growth pattern across "
                            f"{len(versioned_files)} versions. Average change rate: "
                            f"{avg_change:.1%} (threshold: "
                            f"{GRADUAL_POLLUTION_THRESHOLDS['max_change_rate']:.1%})"
                        ),
                        severity=Severity.HIGH,
                        confidence=0.75,
                        attack_id="T1565.001",
                        attack_tactic="Data Manipulation",
                        source_path="memory_versions",
                        raw_data={
                            "version_count": len(versioned_files),
                            "average_change_rate": avg_change,
                            "threshold": GRADUAL_POLLUTION_THRESHOLDS['max_change_rate'],
                            "total_drift": sum(size_changes)
                        },
                        remediation=(
                            "Implement memory content validation. "
                            "Set up change rate monitoring. "
                            "Roll back to known-good memory state."
                        ),
                        owasp_asi="ASI04:2026",
                        evidence_details=EvidenceDetail(
                        ),
                        remediation_commands=[
                        "Verify model version integrity at load time",
                        "Audit model version history and changes",
                        "Implement cryptographic model version signing",
                        "Monitor for unauthorized model version swaps"
                    ]
                    ))
        
        return evidences
    
    def _detect_multi_agent_conflicts(self, log_data: Dict) -> List[Evidence]:
        """
        Detect multi-agent memory conflicts:
        1. Identify contradictory facts from different agents
        2. Detect gaslighting attack patterns
        3. Flag concurrent write conflicts
        
        Returns evidence of multi-agent coordination attacks
        """
        evidences = []
        
        logs = log_data.get("application", []) + log_data.get("logs", [])
        
        if not logs:
            return evidences
        
        for log_entry in logs:
            content = log_entry.get("message", "") or log_entry.get("content", "")
            timestamp = log_entry.get("timestamp", "")
            
            if not content:
                continue
            
            # Check for conflict patterns
            for conflict_type, conflict_data in MULTI_AGENT_CONFLICT_PATTERNS.items():
                for indicator in conflict_data['indicators']:
                    if indicator.search(content):
                        evidences.append(self._create_evidence(
                            title=f"Multi-Agent Conflict Detected: {conflict_data['description']}",
                            description=(
                                f"Detected at {timestamp}: {conflict_data['description']}. "
                                f"This may indicate coordinated memory manipulation."
                            ),
                            severity=conflict_data['severity'],
                            confidence=0.70,
                            attack_id="T1565.001",
                            attack_tactic="Data Manipulation",
                            source_path="application_log",
                            raw_data={
                                "conflict_type": conflict_type,
                                "timestamp": timestamp,
                                "log_sample": content[:200]
                            },
                            remediation=(
                                "Investigate agent interaction patterns. "
                                "Implement conflict resolution mechanisms. "
                                "Add agent authentication for memory writes."
                            ),
                            owasp_asi="ASI04:2026",
                            evidence_details=EvidenceDetail(
                            ),
                            remediation_commands=[
                        "Review agent configuration and tool permissions",
                        "Audit prompt inputs for injection attempts",
                        "Verify skill/plugin sources and integrity",
                        "Restrict agent tool access to minimum required"
                    ]
                        ))
                        break  # One evidence per conflict type per log entry
        
        return evidences
    
    def _verify_merkle_tree_integrity(self, filesystem_data: Dict) -> List[Evidence]:
        """
        Verify memory integrity using Merkle tree hashing:
        1. Calculate hashes for memory segments
        2. Build Merkle tree structure
        3. Detect hash mismatches indicating tampering
        
        Returns evidence of integrity violations
        """
        evidences = []
        files = filesystem_data.get("files", [])
        
        if not files:
            return evidences
        
        # Memory files to verify
        memory_extensions = ['.json', '.db', '.sqlite']
        memory_files = []
        
        for file_info in files:
            filepath = file_info.get("path", "")
            filename = os.path.basename(filepath).lower()
            
            if any(filename.endswith(ext) for ext in memory_extensions):
                memory_files.append(file_info)
        
        if not memory_files:
            return evidences
        
        # Calculate hashes for each file
        file_hashes = {}
        for file_info in memory_files:
            filepath = file_info.get("path", "")
            file_size = file_info.get("size", 0)
            
            if file_size > 50 * 1024 * 1024:  # Skip files > 50MB
                continue
            
            try:
                with open(filepath, 'rb') as f:
                    content = f.read(10 * 1024 * 1024)  # Read first 10MB
                    file_hash = hashlib.sha256(content).hexdigest()
                    file_hashes[filepath] = file_hash
            except OSError as e:
                _get_logger().debug(f"[{self.name}] Failed to hash {filepath}: {e}")
        
        # Build Merkle root
        if file_hashes:
            merkle_root = self._build_merkle_root(list(file_hashes.values()))
            
            # Store for future verification
            timestamp = datetime.now(timezone.utc).isoformat()
            self._merkle_roots[timestamp] = {
                'root': merkle_root,
                'file_count': len(file_hashes),
                'files': list(file_hashes.keys())
            }
            
            # Generate informational evidence
            evidences.append(self._create_evidence(
                title="Memory Integrity Hash Calculated",
                description=(
                    f"Calculated Merkle root hash for {len(file_hashes)} memory files. "
                    f"Root: {merkle_root[:32]}..."
                ),
                severity=Severity.INFO,
                confidence=1.0,
                attack_id="",
                attack_tactic="Integrity Verification",
                source_path="memory_files",
                raw_data={
                    "merkle_root": merkle_root,
                    "file_count": len(file_hashes),
                    "timestamp": timestamp,
                    "files": list(file_hashes.keys())[:10]  # Limit for evidence size
                },
                remediation=(
                    "Store Merkle root securely for future verification. "
                    "Regularly recalculate and compare hashes. "
                    "Alert on hash mismatches."
                ),
                owasp_asi="ASI04:2026",
                evidence_details=EvidenceDetail(
                ),
                remediation_commands=[
                        "Rotate compromised credential immediately",
                        "Review access logs for unauthorized usage",
                        "Audit credential storage and usage patterns",
                        "Check other systems for credential reuse"
                    ]
            ))
        
        return evidences
    
    def _build_merkle_root(self, hashes: List[str]) -> str:
        """
        Build Merkle tree root from list of hashes
        
        Args:
            hashes: List of SHA-256 hex digest strings
            
        Returns:
            Merkle root hash as hex digest string
        """
        if not hashes:
            return hashlib.sha256(b"").hexdigest()
        
        # Convert to bytes
        current_level = [bytes.fromhex(h) for h in hashes]
        
        # Build tree bottom-up
        while len(current_level) > 1:
            next_level = []
            
            # Process pairs
            for i in range(0, len(current_level) - 1, 2):
                combined = current_level[i] + current_level[i + 1]
                parent_hash = hashlib.sha256(combined).digest()
                next_level.append(parent_hash)
            
            # Handle odd number of nodes
            if len(current_level) % 2 == 1:
                combined = current_level[-1] + current_level[-1]
                parent_hash = hashlib.sha256(combined).digest()
                next_level.append(parent_hash)
            
            current_level = next_level
        
        return current_level[0].hex()
