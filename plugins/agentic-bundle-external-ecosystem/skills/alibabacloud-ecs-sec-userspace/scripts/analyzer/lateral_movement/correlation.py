"""Lateral Movement Correlation Wrapper.

Provides temporal correlation engine integration for multi-stage campaign
detection in the LateralMovementAnalyzer.

Extracted from lateral_movement_analyzer.py - zero functional change.
"""
from typing import List, Dict
from ...reporter.evidence import Evidence


class LateralCorrelationMixin:
    """Mixin providing temporal correlation for multi-stage campaign detection."""

    def _run_temporal_correlation(self, collected_data: Dict) -> List[Evidence]:
        """Run temporal correlation engine for multi-stage campaign detection"""
        try:
            from ..lateral_movement_correlator import LateralMovementCorrelator

            correlator = LateralMovementCorrelator(workspace_dir=self.workspace_dir)
            return correlator.analyze(collected_data)
        except (ImportError, OSError, ValueError, KeyError, TypeError) as e:
            self._get_logger().warning(f"Temporal correlation error: {e}")
            return []
