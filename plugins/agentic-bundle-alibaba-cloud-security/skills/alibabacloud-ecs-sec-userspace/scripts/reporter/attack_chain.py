"""Attack Chain Builder - Builds attack chain from correlated evidences"""
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from .evidence import Evidence
from ..utils.datetime_compat import fromisoformat
from .attack_phase import AttackPhaseClassifier
from .evidence_correlator import EvidenceCorrelator


@dataclass
class AttackChainNode:
    """攻击链节点"""
    id: str
    phase: str
    phase_name: str
    phase_name_cn: str
    timestamp: str
    title: str
    severity: str
    attack_id: str
    attack_tactic: str
    description: str
    source_path: str
    related_evidence: List[str] = field(default_factory=list)
    correlations: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dictionary"""
        return {
            "id": self.id,
            "phase": self.phase,
            "phase_name": self.phase_name,
            "phase_name_cn": self.phase_name_cn,
            "timestamp": self.timestamp,
            "title": self.title,
            "severity": self.severity,
            "attack_id": self.attack_id,
            "attack_tactic": self.attack_tactic,
            "description": self.description,
            "source_path": self.source_path,
            "related_evidence": self.related_evidence,
            "correlations": self.correlations
        }


@dataclass
class AttackChain:
    """攻击链"""
    chain_id: str
    start_time: str
    end_time: str
    duration_seconds: int
    phases: List[str]
    nodes: List[AttackChainNode]
    attackers: List[Dict[str, Any]]
    targets: List[Dict[str, Any]]
    risk_score: float
    narrative: str

    def to_dict(self) -> dict:
        """Serialize to dictionary"""
        return {
            "chain_id": self.chain_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "phases": self.phases,
            "nodes": [n.to_dict() for n in self.nodes],
            "attackers": self.attackers,
            "targets": self.targets,
            "risk_score": self.risk_score,
            "narrative": self.narrative
        }


class AttackChainBuilder:
    """攻击链构建器
    
    Builds attack chain from evidences:
    1. Sort by time
    2. Classify into attack phases
    3. Correlate evidences (IP, user, process)
    4. Build attack chain nodes
    5. Generate narrative
    """

    PHASE_ORDER = [
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact"
    ]

    def __init__(self, evidences: List[Evidence]):
        """Initialize builder
        
        Args:
            evidences: List of Evidence objects
        """
        self.evidences = evidences
        self.classifier = AttackPhaseClassifier()
        self.correlator = EvidenceCorrelator()

    def build(self) -> Optional[AttackChain]:
        """Build attack chain
        
        Returns:
            AttackChain object or None if no evidences
        """
        if not self.evidences:
            return None
        
        # 1. Sort by time
        sorted_evidences = self._sort_by_time()
        
        # 2. Classify into attack phases
        phase_groups = self.classifier.classify_all(sorted_evidences)
        
        # 3. Correlation analysis
        correlations = self.correlator.correlate(sorted_evidences)
        
        # 4. Build attack chain nodes
        nodes = self._build_nodes(sorted_evidences, correlations)
        
        if not nodes:
            return None
        
        # 5. Determine phase order
        phases = self._determine_phase_order(phase_groups)
        
        # 6. Extract attackers and targets
        attackers, targets = self._extract_entities(sorted_evidences, correlations)
        
        # 7. Generate narrative
        narrative = self._generate_narrative(nodes, phases)
        
        # 8. Calculate risk score
        risk_score = self._calculate_risk_score(sorted_evidences)
        
        # 9. Calculate duration
        duration = self._calculate_duration(nodes)
        
        return AttackChain(
            chain_id=self._generate_chain_id(),
            start_time=nodes[0].timestamp if nodes else "",
            end_time=nodes[-1].timestamp if nodes else "",
            duration_seconds=duration,
            phases=phases,
            nodes=nodes,
            attackers=attackers,
            targets=targets,
            risk_score=risk_score,
            narrative=narrative
        )

    def _sort_by_time(self) -> List[Evidence]:
        """Sort evidences by timestamp.
        
        Handles both timezone-aware and timezone-naive datetimes by
        normalizing all to UTC-aware datetimes.
        """
        from datetime import timezone
        
        def parse_ts(e: Evidence):
            try:
                if e.timestamp:
                    dt = fromisoformat(e.timestamp)
                    # Ensure timezone-aware (some parsed strings may be naive)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
            except (ValueError, TypeError):
                pass
            # Use timezone-aware min datetime
            return datetime.min.replace(tzinfo=timezone.utc)
        
        return sorted(self.evidences, key=parse_ts)

    def _build_nodes(self, evidences: List[Evidence], 
                     correlations: Dict[str, Any]) -> List[AttackChainNode]:
        """Build attack chain nodes from evidences"""
        nodes = []
        
        for evidence in evidences:
            phase = self.classifier.classify(evidence)
            phase_info = self.classifier.get_phase_info(phase)
            
            # Find related evidences from correlations
            related = self._find_related(evidence.id, correlations)
            
            # Get correlation details for this evidence
            evidence_correlations = {}
            for corr_type, corr_data in correlations.items():
                if isinstance(corr_data, dict):
                    for entity, ev_ids in corr_data.items():
                        if evidence.id in ev_ids:
                            if corr_type not in evidence_correlations:
                                evidence_correlations[corr_type] = []
                            evidence_correlations[corr_type].append(entity)
            
            node = AttackChainNode(
                id=evidence.id,
                phase=phase,
                phase_name=phase_info.get("name", "Unknown"),
                phase_name_cn=phase_info.get("name_cn", "未知"),
                timestamp=evidence.timestamp or "",
                title=evidence.title or "",
                severity=evidence.severity.name if evidence.severity else "UNKNOWN",
                attack_id=evidence.attack_id or "",
                attack_tactic=evidence.attack_tactic or "",
                description=evidence.description or "",
                source_path=evidence.source_path or "",
                related_evidence=related,
                correlations=evidence_correlations
            )
            nodes.append(node)
        
        return nodes

    def _find_related(self, evidence_id: str, 
                      correlations: Dict[str, Any]) -> List[str]:
        """Find related evidence IDs for given evidence"""
        related = set()
        
        for corr_type, corr_data in correlations.items():
            if isinstance(corr_data, dict):
                for entity, ev_ids in corr_data.items():
                    if evidence_id in ev_ids:
                        related.update(ev_ids)
        
        related.discard(evidence_id)
        return list(related)

    def _determine_phase_order(self, 
                               phase_groups: Dict[str, List[Evidence]]) -> List[str]:
        """Determine ordered list of attack phases present"""
        present_phases = [
            phase for phase, evidences in phase_groups.items() 
            if len(evidences) > 0
        ]
        
        # Sort by predefined phase order
        def phase_key(p):
            try:
                return self.PHASE_ORDER.index(p)
            except ValueError:
                return len(self.PHASE_ORDER)
        
        return sorted(present_phases, key=phase_key)

    def _extract_entities(self, evidences: List[Evidence],
                         correlations: Dict[str, Any]) -> Tuple[List[Dict], List[Dict]]:
        """Extract attacker and target information"""
        attackers = []
        targets = []
        
        seen_attackers = set()
        seen_targets = set()
        
        # Extract from correlations
        for ip in correlations.get("by_ip", {}).keys():
            if self._is_external_ip(ip):
                if ip not in seen_attackers:
                    attackers.append({
                        "type": "ip",
                        "value": ip,
                        "role": "source"
                    })
                    seen_attackers.add(ip)
        
        for user in correlations.get("by_user", {}).keys():
            if user not in seen_attackers:
                attackers.append({
                    "type": "user",
                    "value": user,
                    "role": "compromised"
                })
                seen_attackers.add(user)
        
        # Extract targets from evidences
        for e in evidences:
            hostname = e.raw_data.get("hostname") if e.raw_data else None
            if hostname and hostname not in seen_targets:
                targets.append({
                    "type": "host",
                    "value": hostname,
                    "role": "target"
                })
                seen_targets.add(hostname)
        
        return attackers, targets

    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (not private)"""
        if not ip:
            return False
        
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False
        
        # Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
        if octets[0] == 10:
            return False
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return False
        if octets[0] == 192 and octets[1] == 168:
            return False
        if octets[0] == 127:
            return False
        
        return True

    def _generate_narrative(self, nodes: List[AttackChainNode], 
                           phases: List[str]) -> str:
        """Generate attack narrative
        
        Creates a coherent story of the attack based on the chain
        """
        if not nodes:
            return ""
        
        lines = []
        
        # Opening
        first_node = nodes[0]
        lines.append(
            f"The attack began at {first_node.timestamp} with {first_node.phase_name} "
            f"via {first_node.title}."
        )
        
        # Phase progression
        prev_phase = None
        for node in nodes:
            if node.phase != prev_phase:
                phase_info = self.classifier.get_phase_info(node.phase)
                lines.append(
                    f"At {node.timestamp}, the attacker progressed to "
                    f"{phase_info.get('name_cn', node.phase_name)} phase: {node.title}."
                )
                prev_phase = node.phase
        
        # Closing
        last_node = nodes[-1]
        lines.append(
            f"The attack chain concluded at {last_node.timestamp} with "
            f"{len(nodes)} detected events across {len(phases)} attack phases."
        )
        
        return " ".join(lines)

    def _calculate_risk_score(self, evidences: List[Evidence]) -> float:
        """Calculate overall risk score (0-100)"""
        if not evidences:
            return 0.0
        
        total_score = sum(
            e.severity.score * e.confidence 
            for e in evidences 
            if e.severity
        )
        
        # Normalize to 0-100
        max_possible = len(evidences) * 10.0 * 1.0
        if max_possible > 0:
            normalized = (total_score / max_possible) * 100
        else:
            normalized = 0.0
        
        # Bonus for multiple phases
        phase_count = len(set(
            self.classifier.classify(e) 
            for e in evidences
        ))
        phase_bonus = min(phase_count * 5, 20)
        
        return min(normalized + phase_bonus, 100.0)

    def _calculate_duration(self, nodes: List[AttackChainNode]) -> int:
        """Calculate attack duration in seconds"""
        if len(nodes) < 2:
            return 0
        
        try:
            start = fromisoformat(nodes[0].timestamp)
            end = fromisoformat(nodes[-1].timestamp)
            return int((end - start).total_seconds())
        except (TypeError, ValueError):
            return 0

    def _generate_chain_id(self) -> str:
        """Generate unique chain ID"""
        timestamp = datetime.now(timezone.utc).isoformat()
        content = f"{timestamp}-{len(self.evidences)}"
        return f"ac-{hashlib.sha256(content.encode()).hexdigest()[:12]}"


def analyze_attack_chains(evidences: List[Evidence]) -> Optional[Dict[str, Any]]:
    """Convenience function to analyze and build attack chains.
    
    Args:
        evidences: List of Evidence objects
        
    Returns:
        Dictionary with 'chains' key containing chain data, or None
    """
    if not evidences:
        return None
    
    builder = AttackChainBuilder(evidences)
    chain = builder.build()
    
    if chain is None:
        return None
    
    return {
        'chains': [chain],
        'chain_count': 1,
        'risk_score': chain.risk_score,
        'narrative': chain.narrative
    }
