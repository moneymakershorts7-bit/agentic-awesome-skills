"""Unified Evidence Deduplicator

Consolidated deduplication module combining features from:
- reporter/deduplicator.py (path normalization, exact match)
- unification/deduplicator.py (multiple strategies, duplicate groups)

Deduplication strategies:
1. EXACT: Exact match on module + normalized source_path + title
2. HASH: Hash-based comparison using key fields
3. FUZZY: Fuzzy matching with normalized paths and titles

Usage:
    from scripts.utils.deduplicator import (
        EvidenceDeduplicator,
        DeduplicationStrategy,
        DeduplicationResult,
        deduplicate_evidences,
    )
"""
import hashlib
import json
import logging

from typing import List, Dict, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum


logger = logging.getLogger("sec-userspace")


class DeduplicationStrategy(Enum):
    """Deduplication strategies"""
    EXACT = "exact"
    HASH = "hash"
    FUZZY = "fuzzy"


@dataclass
class DeduplicationResult:
    """Result of deduplication process"""
    original_count: int
    deduplicated_count: int
    duplicates_removed: int
    strategy_used: DeduplicationStrategy
    duplicate_groups: List[List[str]] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            "original_count": self.original_count,
            "deduplicated_count": self.deduplicated_count,
            "duplicates_removed": self.duplicates_removed,
            "strategy_used": self.strategy_used.value,
            "duplicate_groups_count": len(self.duplicate_groups),
        }
        result.update(self.stats)
        return result


class EvidenceDeduplicator:
    """Unified evidence deduplication manager

    Supports multiple deduplication strategies with path normalization
    and duplicate group tracking.

    Args:
        strategy: Deduplication strategy to use (default: HASH)

    Attributes:
        strategy: Current deduplication strategy
        _seen_hashes: Set of seen evidence fingerprints
        _evidence_map: Map of fingerprint to evidence
        _duplicate_groups: Groups of duplicate evidence IDs
        _stats: Deduplication statistics
    """

    def __init__(self, strategy: DeduplicationStrategy = DeduplicationStrategy.HASH):
        self.strategy = strategy
        self._seen_hashes: Set[str] = set()
        self._evidence_map: Dict[str, Any] = {}
        self._duplicate_groups: List[List[str]] = []
        self._fp_to_group: Dict[str, int] = {}
        self._stats = {
            "total": 0,
            "duplicates_exact": 0,
            "duplicates_fuzzy": 0,
            "unique": 0,
        }

    def _normalize_path(self, path: str) -> str:
        """Normalize file path for comparison

        - Convert to lowercase
        - Remove trailing slashes
        - Collapse multiple slashes
        """
        if not path:
            return ""

        normalized = path.lower()

        while "//" in normalized:
            normalized = normalized.replace("//", "/")

        normalized = normalized.rstrip("/")

        return normalized

    def _compute_fingerprint(self, evidence: Any) -> str:
        """Compute fingerprint based on current strategy

        Returns:
            SHA256 hex string
        """
        if self.strategy == DeduplicationStrategy.EXACT:
            return self._exact_fingerprint(evidence)
        elif self.strategy == DeduplicationStrategy.HASH:
            return self._hash_fingerprint(evidence)
        elif self.strategy == DeduplicationStrategy.FUZZY:
            return self._fuzzy_fingerprint(evidence)
        else:
            return self._hash_fingerprint(evidence)

    def _exact_fingerprint(self, evidence: Any) -> str:
        """Compute exact match fingerprint

        Uses module + normalized source_path + title + attack_id + severity + description
        """
        key_data = json.dumps({
            "module": getattr(evidence, 'module', ''),
            "source_path": self._normalize_path(getattr(evidence, 'source_path', '')),
            "title": getattr(evidence, 'title', ''),
            "attack_id": getattr(evidence, 'attack_id', ''),
            "severity": str(getattr(evidence, 'severity', '')),
            "description": getattr(evidence, 'description', ''),
        }, sort_keys=True)

        return hashlib.sha256(key_data.encode()).hexdigest()

    def _hash_fingerprint(self, evidence: Any) -> str:
        """Compute hash-based fingerprint using key fields"""
        key_fields = {}

        if hasattr(evidence, 'module'):
            key_fields['module'] = evidence.module
        if hasattr(evidence, 'title'):
            key_fields['title'] = evidence.title
        if hasattr(evidence, 'source_path'):
            key_fields['source_path'] = self._normalize_path(evidence.source_path)
        if hasattr(evidence, 'severity'):
            key_fields['severity'] = str(evidence.severity)
        if hasattr(evidence, 'attack_id'):
            key_fields['attack_id'] = evidence.attack_id

        if hasattr(evidence, 'raw_data') and evidence.raw_data:
            if isinstance(evidence.raw_data, dict):
                key_fields['data_hash'] = hashlib.sha256(
                    json.dumps(evidence.raw_data, sort_keys=True, default=str).encode()
                ).hexdigest()[:8]

        data = str(sorted(key_fields.items()))
        return hashlib.sha256(data.encode()).hexdigest()

    def _fuzzy_fingerprint(self, evidence: Any) -> str:
        """Compute fuzzy fingerprint (similarity-preserving)"""
        key_fields = []

        if hasattr(evidence, 'module'):
            key_fields.append(str(evidence.module).lower())
        if hasattr(evidence, 'title'):
            title = str(evidence.title).lower()
            title = ''.join(c for c in title if c.isalpha() or c.isspace())
            key_fields.append(title)
        if hasattr(evidence, 'source_path'):
            path = str(evidence.source_path).lower().rstrip('/')
            key_fields.append(path)

        data = '|'.join(key_fields)
        return hashlib.md5(data.encode(), usedforsecurity=False).hexdigest()

    def _get_evidence_id(self, evidence: Any) -> str:
        """Get evidence identifier"""
        if hasattr(evidence, 'id'):
            return str(evidence.id)
        elif hasattr(evidence, 'logid'):
            return str(evidence.logid)
        else:
            return self._compute_fingerprint(evidence)[:16]

    def is_duplicate(self, evidence: Any) -> bool:
        """Check if evidence is duplicate

        Args:
            evidence: Evidence to check

        Returns:
            True if duplicate, False if unique
        """
        fp = self._compute_fingerprint(evidence)
        return fp in self._seen_hashes

    def add(self, evidence: Any) -> bool:
        """Add evidence if not duplicate

        Args:
            evidence: Evidence to add

        Returns:
            True if added (not duplicate), False if duplicate
        """
        self._stats["total"] += 1

        fp = self._compute_fingerprint(evidence)

        if fp in self._seen_hashes:
            self._stats["duplicates_exact"] += 1

            ev_id = self._get_evidence_id(evidence)

            if fp in self._fp_to_group:
                group_idx = self._fp_to_group[fp]
                if ev_id not in self._duplicate_groups[group_idx]:
                    self._duplicate_groups[group_idx].append(ev_id)
            else:
                group_idx = len(self._duplicate_groups)
                self._fp_to_group[fp] = group_idx
                orig_id = self._get_evidence_id(self._evidence_map[fp])
                self._duplicate_groups.append([orig_id, ev_id])

            logger.debug(f"[deduplicator] Duplicate: {getattr(evidence, 'module', 'unknown')}:{getattr(evidence, 'title', 'unknown')}")
            return False

        self._seen_hashes.add(fp)
        self._evidence_map[fp] = evidence
        self._stats["unique"] += 1

        logger.debug(f"[deduplicator] Added unique: {getattr(evidence, 'module', 'unknown')}:{getattr(evidence, 'title', 'unknown')}")
        return True

    def deduplicate_batch(self, evidences: List[Any]) -> List[Any]:
        """Deduplicate a batch of evidences

        Args:
            evidences: List of evidences to deduplicate

        Returns:
            List of unique evidences (preserving order)
        """
        self._seen_hashes.clear()
        self._evidence_map.clear()
        self._duplicate_groups.clear()
        self._fp_to_group.clear()
        self._stats = {
            "total": 0,
            "duplicates_exact": 0,
            "duplicates_fuzzy": 0,
            "unique": 0,
        }

        result = []
        for e in evidences:
            if self.add(e):
                result.append(e)

        logger.info(
            f"[deduplicator] Batch deduplication complete: "
            f"{len(result)}/{len(evidences)} unique "
            f"(removed {len(evidences) - len(result)} duplicates)"
        )

        return result

    def deduplicate(self, evidences: List[Any]) -> Tuple[List[Any], DeduplicationResult]:
        """Deduplicate evidences and return result

        Args:
            evidences: List of evidence objects

        Returns:
            Tuple of (deduplicated_evidences, result)
        """
        unique_evidences = self.deduplicate_batch(evidences)

        result = DeduplicationResult(
            original_count=len(evidences),
            deduplicated_count=len(unique_evidences),
            duplicates_removed=len(evidences) - len(unique_evidences),
            strategy_used=self.strategy,
            duplicate_groups=[g.copy() for g in self._duplicate_groups],
            stats=self._stats.copy(),
        )

        return unique_evidences, result

    def get_stats(self) -> dict:
        """Get deduplication statistics

        Returns:
            Dict with statistics
        """
        return self._stats.copy()

    def get_duplicate_groups(self) -> List[List[str]]:
        """Get groups of duplicate evidence IDs"""
        return [g.copy() for g in self._duplicate_groups]

    def change_strategy(self, strategy: DeduplicationStrategy) -> None:
        """Change deduplication strategy"""
        self.strategy = strategy
        logger.info(f"Deduplication strategy changed to {strategy.value}")

    def reset(self):
        """Reset deduplicator state"""
        self._seen_hashes.clear()
        self._evidence_map.clear()
        self._duplicate_groups.clear()
        self._fp_to_group.clear()
        self._stats = {
            "total": 0,
            "duplicates_exact": 0,
            "duplicates_fuzzy": 0,
            "unique": 0,
        }


def deduplicate_evidences(
    evidences: List[Any],
    strategy: DeduplicationStrategy = DeduplicationStrategy.HASH
) -> Tuple[List[Any], Dict[str, Any]]:
    """Convenience function to deduplicate evidences

    Args:
        evidences: List of evidences to deduplicate
        strategy: Deduplication strategy (default: HASH)

    Returns:
        (deduplicated_evidences, stats_dict)
    """
    deduplicator = EvidenceDeduplicator(strategy=strategy)
    result = deduplicator.deduplicate_batch(evidences)
    return result, deduplicator.get_stats()


