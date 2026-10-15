"""Detection feedback loop and self-evolution engine.

Provides scan history persistence, confidence self-adaptation,
pattern learning, and evolution reporting for sec-userspace analyzers.
"""

from .scan_history import ScanHistoryStore
from .confidence_adjuster import ConfidenceAdjuster
from .pattern_learner import PatternLearner
from .evolution_reporter import EvolutionReporter

__all__ = [
    'ScanHistoryStore',
    'ConfidenceAdjuster',
    'PatternLearner',
    'EvolutionReporter',
]
