"""Temporal Correlation Engine for Multi-Stage Attack Detection"""
from typing import List, Dict
from ..reporter.evidence import Evidence, Severity
from ..utils.remediation_generator import generate_generic_remediation
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

class TemporalCorrelator(BaseAnalyzer):
    """Correlate events across analyzers to detect multi-stage attack patterns"""
    name = 'temporal_correlator'
    timeout = 30
    required_collectors = []
    estimated_time = 10.0
    analyzer_type = BaseAnalyzer.IMPORTANT
    ATTACK_CHAINS = {'reconnaissance_to_exploitation': {'stages': [{'tactic': 'Reconnaissance', 'techniques': ['T1592', 'T1590']}, {'tactic': 'Resource Development', 'techniques': ['T1587', 'T1588']}, {'tactic': 'Initial Access', 'techniques': ['T1190', 'T1133']}], 'description': 'Multi-stage attack from reconnaissance to exploitation', 'severity': Severity.CRITICAL, 'confidence_boost': 0.15}, 'lateral_movement_chain': {'stages': [{'tactic': 'Execution', 'techniques': ['T1059', 'T1053']}, {'tactic': 'Persistence', 'techniques': ['T1547', 'T1098']}, {'tactic': 'Lateral Movement', 'techniques': ['T1021', 'T1570']}], 'description': 'Lateral movement with persistence establishment', 'severity': Severity.CRITICAL, 'confidence_boost': 0.2}, 'privilege_escalation_chain': {'stages': [{'tactic': 'Initial Access', 'techniques': ['T1078', 'T1133']}, {'tactic': 'Privilege Escalation', 'techniques': ['T1548', 'T1068']}, {'tactic': 'Defense Evasion', 'techniques': ['T1070', 'T1078']}], 'description': 'Privilege escalation with defense evasion', 'severity': Severity.CRITICAL, 'confidence_boost': 0.15}, 'data_exfiltration_chain': {'stages': [{'tactic': 'Collection', 'techniques': ['T1005', 'T1560']}, {'tactic': 'Command and Control', 'techniques': ['T1071', 'T1571']}, {'tactic': 'Exfiltration', 'techniques': ['T1041', 'T1048']}], 'description': 'Data staging and exfiltration via C2 channel', 'severity': Severity.CRITICAL, 'confidence_boost': 0.2}}
    CORRELATION_WINDOWS = {'short': 300, 'medium': 900, 'long': 3600}

    def analyze(self, collected_data: Dict) -> List[Evidence]:
        """Analyze cross-analyzer evidence for correlated attack patterns"""
        evidences = []
        all_evidences = self._collect_all_evidences(collected_data)
        if not all_evidences:
            _get_logger().info(f'[{self.name}] No evidences to correlate')
            return evidences
        try:
            for chain_name, chain_config in self.ATTACK_CHAINS.items():
                chain_evidences = self._detect_attack_chain(all_evidences, chain_name, chain_config)
                evidences.extend(chain_evidences)
            technique_cluster_evidences = self._detect_technique_clusters(all_evidences)
            evidences.extend(technique_cluster_evidences)
            if evidences:
                _get_logger().info(f'[{self.name}] Detected {len(evidences)} correlated attack patterns')
            else:
                _get_logger().info(f'[{self.name}] No correlated attack patterns detected')
        except (OSError, ValueError, KeyError, TypeError) as e:
            _get_logger().error(f'[{self.name}] Error during correlation analysis: {e}', exc_info=True)
        return evidences

    def should_skip(self) -> tuple:
        """Check if analyzer should skip based on environment."""
        return False, ""

    def _collect_all_evidences(self, collected_data: Dict) -> List[Dict]:
        """Collect evidences from all analyzer results in collected_data"""
        all_evidences = []
        if isinstance(collected_data, dict):
            for key in collected_data:
                try:
                    result_data = self._get_data(collected_data, key, default=None, strict=False)
                    if isinstance(result_data, dict) and 'evidences' in result_data:
                        all_evidences.extend(result_data['evidences'])
                except KeyError:
                    continue
        _get_logger().debug(f'[{self.name}] Collected {len(all_evidences)} evidences for correlation')
        return all_evidences

    def _detect_attack_chain(self, all_evidences: List[Dict], chain_name: str, chain_config: Dict) -> List[Evidence]:
        """Detect if evidence matches an attack chain pattern"""
        evidences = []
        stages = chain_config.get('stages', [])
        if not stages:
            return evidences
        matched_stages = []
        stage_evidences = []
        for evidence in all_evidences:
            if not isinstance(evidence, dict):
                continue
            attack_id = evidence.get('attack_id', '')
            attack_tactic = evidence.get('attack_tactic', '')
            for idx, stage in enumerate(stages):
                stage_tactics = stage.get('tactic', '')
                stage_techniques = stage.get('techniques', [])
                if attack_tactic.lower() == stage_tactics.lower() or attack_id in stage_techniques:
                    matched_stages.append(idx)
                    stage_evidences.append(evidence)
        unique_stages = len(set(matched_stages))
        total_stages = len(stages)
        if unique_stages >= 2 and unique_stages >= total_stages * 0.5:
            base_confidence = min(0.95, 0.6 + unique_stages / total_stages * 0.3)
            confidence_boost = chain_config.get('confidence_boost', 0.1)
            final_confidence = min(0.95, base_confidence + confidence_boost)
            involved_attacks = list(set([ev.get('attack_id', 'N/A') for ev in stage_evidences if isinstance(ev, dict)]))
            chain_tactic = stages[0].get('tactic', 'Multi-Stage Attack') if stages else 'Multi-Stage Attack'
            evidence = self._create_evidence(title=f"Correlated Attack Chain: {chain_config['description']}", description=f"Detected multi-stage attack pattern:\n  Chain: {chain_name}\n  Stages matched: {unique_stages}/{total_stages}\n  ATT&CK techniques: {', '.join(involved_attacks)}\n  Confidence boost: +{int(confidence_boost * 100)}%\n\nEvidence details:\n" + '\n'.join([f"  - [{ev.get('severity', 'N/A')}] {ev.get('title', 'N/A')}" for ev in stage_evidences[:5] if isinstance(ev, dict)]), severity=chain_config.get('severity', Severity.HIGH), confidence=final_confidence, attack_id=involved_attacks[0] if involved_attacks else chain_name, attack_tactic=chain_tactic, source_path='temporal_correlation', raw_data={'chain_name': chain_name, 'stages_matched': unique_stages, 'total_stages': total_stages, 'involved_attacks': involved_attacks, 'top_indicators': [ev.get('title', '') for ev in stage_evidences[:5]]}, remediation=f'Multi-stage attack chain detected ({chain_name}). Investigate all {unique_stages} matched stages and determine if this is a coordinated attack. Consider blocking associated IOCs at network perimeter.', evidence_details=self._create_evidence_details(service_type='temporal_correlation'), remediation_commands=generate_generic_remediation(attack_id=involved_attacks[0] if involved_attacks else 'TBD', context={'analyzer': 'temporal_correlator'}))
            evidences.append(evidence)
        return evidences

    def _detect_technique_clusters(self, all_evidences: List[Dict]) -> List[Evidence]:
        """Detect clusters of related ATT&CK techniques indicating focused attack effort"""
        evidences = []
        tactic_groups: Dict[str, List[Dict]] = {}
        for ev in all_evidences:
            if not isinstance(ev, dict):
                continue
            tactic = ev.get('attack_tactic', '')
            if tactic:
                tactic_groups.setdefault(tactic, []).append(ev)
        for tactic, evs in tactic_groups.items():
            if len(evs) < 3:
                continue
            unique_techniques = set(ev.get('attack_id', '') for ev in evs if ev.get('attack_id'))
            if len(unique_techniques) < 2:
                continue
            confidence = min(0.9, 0.5 + len(unique_techniques) * 0.1)
            evidences.append(self._create_evidence(
                title=f"Technique Cluster: {tactic} ({len(unique_techniques)} techniques)",
                description=f"High concentration of {tactic} activities detected:\n  Unique techniques: {len(unique_techniques)}\n  Total indicators: {len(evs)}\n\nTop indicators:\n" + '\n'.join([f"  - [{ev.get('severity', 'N/A')}] {ev.get('title', 'N/A')}" for ev in evs[:5]]),
                severity=Severity.HIGH,
                confidence=confidence,
                attack_id='CLUSTER',
                attack_tactic=tactic,
                source_path='technique_clustering',
                raw_data={'tactic': tactic, 'indicator_count': len(evs), 'unique_techniques': list(unique_techniques), 'top_indicators': [ev.get('title', '') for ev in evs[:5]]},
                remediation=f'High concentration of {tactic} activities suggests focused attack effort. Investigate all indicators and determine if this is targeted attack.',
                evidence_details=self._create_evidence_details(service_type='temporal_correlation'),
                remediation_commands=generate_generic_remediation(attack_id='TBD', context={'analyzer': 'temporal_correlator'})))
        return evidences