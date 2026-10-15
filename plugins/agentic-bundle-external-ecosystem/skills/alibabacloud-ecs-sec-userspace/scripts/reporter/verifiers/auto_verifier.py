"""AutoVerifier - Automatic false positive verification engine

This module implements automatic verification of security alerts
to filter false positives before generating final reports.

Verification is automatic - no user interaction required.
"""
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from enum import Enum

from ..evidence import Evidence
from .process_verifier import ProcessVerifier
from .file_verifier import FileVerifier
from .network_verifier import NetworkVerifier
from .config_verifier import ConfigVerifier
from .behavior_verifier import BehaviorVerifier

logger = logging.getLogger("sec-userspace")


class VerificationStatus(Enum):
    """Verification result status"""
    CONFIRMED = "confirmed"  # Confirmed as real threat
    LIKELY_TRUE = "likely_true"  # Highly suspicious, lacks absolute evidence
    LIKELY_FP = "likely_fp"  # Likely false positive
    FALSE_POSITIVE = "false_positive"  # Confirmed false positive


@dataclass
class VerificationResult:
    """Result of auto-verification"""
    evidence: Evidence
    status: VerificationStatus
    reason: str
    verifiers_used: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "evidence_id": self.evidence.id,
            "status": self.status.value,
            "reason": self.reason,
            "verifiers_used": self.verifiers_used,
            "details": self.details,
        }


class AutoVerifier:
    """Automatically verify alerts and filter false positives
    
    Verification flow:
    1. Read all CRITICAL/HIGH/MEDIUM alerts from scan results
    2. Execute multiple verification checks for each alert
    3. Classify each alert based on verification results
    4. Filter out confirmed false positives from final report
    5. Output only CONFIRMED and LIKELY_TRUE alerts
    
    Verification is automatic - no user interaction required.
    """
    
    def __init__(self, collected_data: Optional[Dict] = None):
        """Initialize auto-verifier
        
        Args:
            collected_data: Optional collected data from collectors
        """
        self.collected_data = collected_data or {}
        
        # Initialize verifiers
        self.process_verifier = ProcessVerifier(collected_data)
        self.file_verifier = FileVerifier(collected_data)
        self.network_verifier = NetworkVerifier(collected_data)
        self.config_verifier = ConfigVerifier(collected_data)
        self.behavior_verifier = BehaviorVerifier(collected_data)
        
        # Verification results cache
        self.results: Dict[str, VerificationResult] = {}
    
    def verify_alerts(self, evidences: List[Evidence]) -> List[Evidence]:
        """Verify all alerts automatically
        
        Args:
            evidences: List of evidence to verify
            
        Returns:
            List[Evidence]: Filtered list containing only CONFIRMED/LIKELY_TRUE
        """
        logger.info(f"[VERIFY] Starting auto-verification for {len(evidences)} alerts")
        
        confirmed_count = 0
        likely_true_count = 0
        fp_count = 0
        
        # Cross-verify evidence if we have multiple alerts
        if len(evidences) > 1:
            self._cross_verify_evidences(evidences)
        
        for evidence in evidences:
            result = self._verify_single_alert(evidence)
            self.results[evidence.id] = result
            
            # Log verification result
            if result.status == VerificationStatus.CONFIRMED:
                logger.info(f"[VERIFY] {evidence.id}: CONFIRMED - {result.reason}")
                confirmed_count += 1
            elif result.status == VerificationStatus.LIKELY_TRUE:
                logger.info(f"[VERIFY] {evidence.id}: LIKELY_TRUE - {result.reason}")
                likely_true_count += 1
            elif result.status == VerificationStatus.FALSE_POSITIVE:
                logger.info(f"[VERIFY] {evidence.id}: FALSE_POSITIVE - {result.reason}")
                fp_count += 1
            else:  # LIKELY_FP
                logger.info(f"[VERIFY] {evidence.id}: LIKELY_FP - {result.reason}")
                fp_count += 1
            
            # Update evidence with verification status
            self._apply_verification_to_evidence(evidence, result)
        
        # Filter to only include CONFIRMED and LIKELY_TRUE
        filtered = [
            e for e in evidences 
            if self.results.get(e.id) and 
            self.results[e.id].status in (VerificationStatus.CONFIRMED, VerificationStatus.LIKELY_TRUE)
        ]
        
        logger.info(
            f"[VERIFY] Verification complete: {confirmed_count} confirmed, "
            f"{likely_true_count} likely true, {fp_count} false positives"
        )
        
        return filtered
    
    def _verify_single_alert(self, evidence: Evidence) -> VerificationResult:
        """Verify a single alert using multiple checks
        
        Args:
            evidence: Evidence to verify
            
        Returns:
            VerificationResult: Verification result
        """
        # Special handling for dependency confusion alerts
        if evidence.module == "agent_dependency_confusion":
            result = self._verify_dependency_confusion_alert(evidence)
            if result:
                return result
        
        verifiers = self._get_verifiers_for_evidence(evidence)
        
        # If no verifiers apply, check if it's an isolated alert
        if not verifiers:
            # Isolated alerts without related evidence are more likely FP
            if not self._has_related_evidence(evidence):
                return VerificationResult(
                    evidence=evidence,
                    status=VerificationStatus.LIKELY_FP,
                    reason="Isolated alert with no related evidence and no applicable verification",
                    verifiers_used=[]
                )
            return VerificationResult(
                evidence=evidence,
                status=VerificationStatus.LIKELY_TRUE,
                reason="No applicable verification checks",
                verifiers_used=[]
            )
        
        # Run all applicable verifiers
        fp_confirmed = False
        confirmed_threat = False
        reasons = []
        verifier_names = []
        
        for verifier in verifiers:
            verifier_names.append(verifier.__class__.__name__)
            
            try:
                check_result = verifier.verify(evidence)
                
                if check_result.is_false_positive:
                    fp_confirmed = True
                    reasons.append(check_result.reason)
                    break  # Short-circuit on FP confirmation
                
                if check_result.is_confirmed_threat:
                    confirmed_threat = True
                    reasons.append(check_result.reason)
                    
            except (OSError, ValueError, KeyError, TypeError) as e:
                logger.debug(f"Verifier {verifier.__class__.__name__} failed: {e}")
                continue
        
        # Determine final status
        if fp_confirmed:
            return VerificationResult(
                evidence=evidence,
                status=VerificationStatus.FALSE_POSITIVE,
                reason="; ".join(reasons),
                verifiers_used=verifier_names,
                details={"fp_reasons": reasons}
            )
        
        if confirmed_threat:
            return VerificationResult(
                evidence=evidence,
                status=VerificationStatus.CONFIRMED,
                reason="; ".join(reasons),
                verifiers_used=verifier_names,
                details={"threat_indicators": reasons}
            )
        
        # Default to LIKELY_TRUE if no definitive conclusion
        return VerificationResult(
            evidence=evidence,
            status=VerificationStatus.LIKELY_TRUE,
            reason="No conclusive verification result",
            verifiers_used=verifier_names
        )
    
    def _verify_dependency_confusion_alert(self, evidence: Evidence) -> Optional[VerificationResult]:
        """Special verification for dependency confusion alerts
        
        Dependency confusion alerts need context-aware verification:
        1. Check if alert is from development environment
        2. Check if package is a known infrastructure package
        3. Check if risk indicators are weak (only 2 indicators)
        4. Check if confidence is low (< 0.7)
        
        Args:
            evidence: Evidence to verify
            
        Returns:
            VerificationResult if applicable, None otherwise
        """
        raw_data = evidence.raw_data or {}
        risk_indicators = raw_data.get("risk_indicators", [])
        
        # Check if this is a weak alert (only 2 indicators, low confidence)
        if len(risk_indicators) == 2 and evidence.confidence < 0.75:
            # Check for common weak indicator combinations
            weak_combinations = [
                {"unknown_author", "suspicious_version"},  # CalVer packages
                {"unknown_author", "low_downloads"},  # Niche but legitimate packages
                {"low_downloads", "external_url"},  # Packages with docs
            ]
            
            indicator_set = set(risk_indicators)
            for weak_combo in weak_combinations:
                if indicator_set == weak_combo:
                    logger.debug(
                        f"[VERIFY] Dependency confusion alert '{evidence.title}' "
                        f"matches weak indicator pattern: {weak_combo}"
                    )
                    return VerificationResult(
                        evidence=evidence,
                        status=VerificationStatus.LIKELY_FP,
                        reason=f"Weak indicator combination ({', '.join(risk_indicators)}) common in legitimate packages",
                        verifiers_used=["dependency_context_verifier"],
                        details={
                            "risk_indicators": risk_indicators,
                            "confidence": evidence.confidence,
                            "pattern_matched": list(weak_combo),
                        }
                    )
        
        # No special handling needed, fall back to generic verification
        return None
    
    def _get_verifiers_for_evidence(self, evidence: Evidence) -> List:
        """Get applicable verifiers for an evidence
        
        Args:
            evidence: Evidence to check
            
        Returns:
            List of applicable verifier instances
        """
        verifiers = []
        
        # Check evidence type and select appropriate verifiers
        raw_data = evidence.raw_data or {}
        
        # Process-related indicators
        if any(key in raw_data for key in ["pid", "process", "cmdline", "ppid"]):
            verifiers.append(self.process_verifier)
        
        # File-related indicators
        if any(key in raw_data for key in ["path", "file", "hash", "filename"]):
            verifiers.append(self.file_verifier)
        
        # Network-related indicators
        if any(key in raw_data for key in ["ip", "port", "domain", "connection", "dst"]):
            verifiers.append(self.network_verifier)
        
        # Configuration-related indicators
        if any(key in raw_data for key in ["config", "setting", "permission", "mode"]):
            verifiers.append(self.config_verifier)
        
        # Behavior-related indicators (always applicable as fallback)
        if evidence.module in ["process_analyzer", "network_analyzer", "auth_analyzer"]:
            verifiers.append(self.behavior_verifier)
        
        # Add dependency confusion verifier for relevant modules
        if evidence.module == "agent_dependency_confusion":
            # For dependency confusion, use behavior verifier as fallback
            # since we don't have a dedicated dependency verifier yet
            if not verifiers:
                verifiers.append(self.behavior_verifier)
        
        return verifiers
    
    def _apply_verification_to_evidence(self, evidence: Evidence, result: VerificationResult):
        """Apply verification result to evidence object
        
        Args:
            evidence: Evidence to update
            result: Verification result
        """
        # Map verification status to evidence verified_status
        status_map = {
            VerificationStatus.CONFIRMED: "confirmed_tp",
            VerificationStatus.LIKELY_TRUE: "pending",  # Keep as pending for manual review
            VerificationStatus.LIKELY_FP: "likely_fp",
            VerificationStatus.FALSE_POSITIVE: "whitelisted",
        }
        
        evidence.verified_status = status_map[result.status]
        
        # Store verification details in raw_data
        if evidence.raw_data is None:
            evidence.raw_data = {}
        
        evidence.raw_data["verification"] = {
            "status": result.status.value,
            "reason": result.reason,
            "verifiers": result.verifiers_used,
        }
    
    def get_verification_stats(self) -> dict:
        """Get verification statistics
        
        Returns:
            dict: Verification statistics
        """
        total = len(self.results)
        if total == 0:
            return {"total": 0}
        
        confirmed = sum(1 for r in self.results.values() if r.status == VerificationStatus.CONFIRMED)
        likely_true = sum(1 for r in self.results.values() if r.status == VerificationStatus.LIKELY_TRUE)
        likely_fp = sum(1 for r in self.results.values() if r.status == VerificationStatus.LIKELY_FP)
        false_positive = sum(1 for r in self.results.values() if r.status == VerificationStatus.FALSE_POSITIVE)
        
        return {
            "total": total,
            "confirmed": confirmed,
            "likely_true": likely_true,
            "likely_fp": likely_fp,
            "false_positive": false_positive,
            "filtered_out": likely_fp + false_positive,
        }
    
    def _cross_verify_evidences(self, evidences: List[Evidence]):
        """Cross-verify evidence with other alerts to find correlations
        
        Args:
            evidences: List of all evidences from scan
        """
        logger.debug(f"[VERIFY] Cross-verifying {len(evidences)} evidences")
        
        for evidence in evidences:
            related = self._find_related_evidence(evidence, evidences)
            
            # Store correlation info in evidence raw_data
            if evidence.raw_data is None:
                evidence.raw_data = {}
            
            evidence.raw_data["correlation"] = {
                "has_related": len(related) > 0,
                "related_count": len(related),
                "related_ids": [e.id for e in related],
                "forms_attack_chain": self._forms_attack_chain([evidence] + related),
            }
    
    def _find_related_evidence(self, evidence: Evidence, all_evidences: List[Evidence]) -> List[Evidence]:
        """Find evidence related to the given evidence
        
        Args:
            evidence: Reference evidence
            all_evidences: All evidences to search
            
        Returns:
            List of related evidences
        """
        related = []
        raw_data = evidence.raw_data or {}
        
        for other in all_evidences:
            if other.id == evidence.id:
                continue
            
            other_raw = other.raw_data or {}
            
            # Check for common IP addresses
            ip = raw_data.get('ip') or raw_data.get('dst_ip') or raw_data.get('src_ip')
            other_ip = other_raw.get('ip') or other_raw.get('dst_ip') or other_raw.get('src_ip')
            if ip and ip == other_ip:
                related.append(other)
                continue
            
            # Check for common domain
            domain = raw_data.get('domain') or raw_data.get('dst_domain')
            other_domain = other_raw.get('domain') or other_raw.get('dst_domain')
            if domain and domain == other_domain:
                related.append(other)
                continue
            
            # Check for common process
            pid = raw_data.get('pid') or raw_data.get('process_id')
            other_pid = other_raw.get('pid') or other_raw.get('process_id')
            if pid and pid == other_pid:
                related.append(other)
                continue
            
            # Check for same analyzer module
            if evidence.module == other.module:
                related.append(other)
                continue
        
        return related
    
    def _has_related_evidence(self, evidence: Evidence) -> bool:
        """Check if evidence has related evidence
        
        Args:
            evidence: Evidence to check
            
        Returns:
            bool: Whether evidence has related evidence
        """
        # This is a simplified check - full correlation happens in _cross_verify_evidences
        raw_data = evidence.raw_data or {}
        
        # If correlation info already exists, use it
        if "correlation" in raw_data:
            return raw_data["correlation"].get("has_related", False)
        
        # Otherwise, assume no related evidence (conservative)
        return False
    
    def _forms_attack_chain(self, evidences: List[Evidence]) -> bool:
        """Check if multiple evidences form an attack chain
        
        Args:
            evidences: List of related evidences
            
        Returns:
            bool: Whether evidences form an attack chain
        """
        if len(evidences) < 2:
            return False
        
        # Attack chain indicators:
        # 1. Multiple different analyzer types involved
        modules = set(e.module for e in evidences)
        if len(modules) >= 3:
            return True
        
        # 2. Mix of CRITICAL/HIGH severity
        severity_names = {e.severity.name for e in evidences}
        if 'CRITICAL' in severity_names and 'HIGH' in severity_names:
            return True
        
        # 3. Network + File + Process combination (lateral movement pattern)
        module_types = set()
        for e in evidences:
            if 'network' in e.module.lower():
                module_types.add('network')
            elif 'file' in e.module.lower():
                module_types.add('file')
            elif 'process' in e.module.lower():
                module_types.add('process')
        
        if len(module_types) >= 2:
            return True
        
        return False
